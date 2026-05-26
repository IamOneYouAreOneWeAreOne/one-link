"""v0.21.x daemon.send_files_batched — FILE_OFFER_BATCH on the send path.

Coverage:
  - Builds correct N inner FILE_OFFERs with rel_path + CDC manifest
  - Sends FILE_OFFER_BATCH frame upfront (collapses N round-trips → 1)
  - Splits across multiple frames at FILE_OFFER_BATCH_V1 cap (256)
  - Handles FILE_WANTS responses per file
  - Streams chunks via FILE_CDC_CHUNK + awaits ACK
  - Counts dedup correctly (empty FILE_WANTS = chunk-level dedup)
  - Awaits FILE_DONE per file
  - Refuses without FILES capability
  - Handles offer rejections + timeouts gracefully

Uses a FakeChannel that simulates a receiver: collects sent frames,
returns canned responses on recv(). The actual send_file pipeline is
not exercised; this isolates the new batched method.
"""
from __future__ import annotations

import asyncio
import base64
from collections import deque
from pathlib import Path
from types import SimpleNamespace

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.blobstore import BlobStore
from one_link.daemon import Daemon, decode_msg, encode_msg
from one_link.identity import Identity, fingerprint_of
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    return Identity(
        private=sk, public=sk.public_key(), public_bytes=pub,
        fingerprint=fingerprint_of(pub), short_id=fingerprint_of(pub)[:8],
        hostname="batched-host",
    )


class FakeChannel:
    """Simulates a receiver: records every send, replies via recv()
    from a queue of pre-canned responses (or a per-message callback).
    """
    def __init__(self):
        self.sent_frames: list[dict] = []
        self.reply_queue: deque[bytes] = deque()
        self.on_send = None  # callable(msg, FakeChannel) -> None
        self.peer_caps = None

    async def send(self, payload: bytes) -> None:
        m = decode_msg(payload)
        self.sent_frames.append(m)
        if self.on_send is not None:
            self.on_send(m, self)

    async def recv(self) -> bytes:
        if not self.reply_queue:
            # Block forever (test should arrange replies up-front
            # or via on_send so we never starve here).
            await asyncio.sleep(60)
        return self.reply_queue.popleft()

    def enqueue(self, msg: dict) -> None:
        self.reply_queue.append(encode_msg(msg))


@pytest_asyncio.fixture
async def batched_daemon(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "s.db")
    blob_store = BlobStore(root=tmp_path / "blobs")
    daemon = Daemon(me)
    daemon.state = state
    daemon.blob_store = blob_store
    daemon._capability_allowed = lambda fp, cap: True
    daemon._check_outbound_trust = lambda peer: None
    peer_fp = "aa" * 32
    fake_peer = SimpleNamespace(
        short_id=peer_fp[:8], ed_pub_hex=peer_fp,
    )
    daemon._peer_fp_from_peer = lambda p: peer_fp if p is fake_peer else None
    chan = FakeChannel()
    sess = SimpleNamespace(
        channel=chan, lock=asyncio.Lock(), peer_fp=peer_fp,
        regime="lan",
    )

    async def fake_get_session(peer):
        return sess
    daemon._get_outbound_session = fake_get_session
    yield {
        "daemon": daemon, "state": state, "peer": fake_peer,
        "peer_fp": peer_fp, "chan": chan, "sess": sess,
        "tmp_path": tmp_path,
    }
    state.close()


def _make_file(root: Path, name: str, contents: bytes) -> Path:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(contents)
    return p


# ── happy path ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_batched_sends_one_FILE_OFFER_BATCH_frame_for_N_files(
    batched_daemon, tmp_path,
):
    """N=3 files should produce ONE FILE_OFFER_BATCH frame with 3
    inner offers, NOT 3 separate FILE_OFFER frames."""
    root = tmp_path / "src"
    files = [
        (_make_file(root, "a.txt", b"alpha"), "a.txt"),
        (_make_file(root, "b.txt", b"beta"), "b.txt"),
        (_make_file(root, "c.txt", b"gamma"), "c.txt"),
    ]
    chan = batched_daemon["chan"]
    daemon = batched_daemon["daemon"]

    # Wire the fake channel: on every FILE_OFFER_BATCH frame we
    # receive, queue a FILE_WANTS reply for each inner offer with
    # empty wants (full dedup) + a FILE_DONE per offer.
    def respond(msg, ch):
        if msg["t"] == "FILE_OFFER_BATCH":
            for inner in msg["offers"]:
                ch.enqueue({
                    "t": "FILE_WANTS", "of": inner["id"],
                    "wants": [], "from": batched_daemon["peer_fp"][:8],
                })
            for inner in msg["offers"]:
                ch.enqueue({
                    "t": "FILE_DONE", "blob": inner["blob"], "ok": True,
                    "from": batched_daemon["peer_fp"][:8],
                })
    chan.on_send = respond
    result = await daemon.send_files_batched(batched_daemon["peer"], files)
    assert result["ok"] is True
    assert result["sent"] == 3
    assert result["failed"] == 0
    # Exactly one FILE_OFFER_BATCH frame, no individual FILE_OFFERs.
    batch_frames = [m for m in chan.sent_frames if m["t"] == "FILE_OFFER_BATCH"]
    individual_offers = [m for m in chan.sent_frames if m["t"] == "FILE_OFFER"]
    assert len(batch_frames) == 1
    assert len(individual_offers) == 0
    # That one batch frame carried all 3 inner offers.
    assert len(batch_frames[0]["offers"]) == 3
    # Each inner offer has the correct shape (rel_path, blob, size).
    rel_paths = sorted(o["rel_path"] for o in batch_frames[0]["offers"])
    assert rel_paths == ["a.txt", "b.txt", "c.txt"]


@pytest.mark.asyncio
async def test_batched_counts_dedup_on_empty_wants(batched_daemon, tmp_path):
    """Files where FILE_WANTS comes back empty are counted as dedup
    + their bytes attributed to dedup_bytes."""
    root = tmp_path / "src"
    files = [
        # Unique content per file so each has a distinct BLAKE3.
        (_make_file(root, f"f{i}.txt", f"unique-content-{i}".encode() + b"x" * 100), f"f{i}.txt")
        for i in range(5)
    ]
    chan = batched_daemon["chan"]

    def respond(msg, ch):
        if msg["t"] == "FILE_OFFER_BATCH":
            for inner in msg["offers"]:
                ch.enqueue({
                    "t": "FILE_WANTS", "of": inner["id"], "wants": [],
                })
            for inner in msg["offers"]:
                ch.enqueue({
                    "t": "FILE_DONE", "blob": inner["blob"], "ok": True,
                })
    chan.on_send = respond
    result = await batched_daemon["daemon"].send_files_batched(
        batched_daemon["peer"], files,
    )
    assert result["sent"] == 5
    assert result["dedup_files"] == 5
    # Dedup_bytes is the sum of file sizes; each file is
    # 16 bytes prefix + 100 bytes filler = 117 bytes (the f-string
    # gives 14 chars "unique-content-" + 1 digit = 15, plus the 100).
    # Just assert it's positive and matches the file sizes.
    expected = sum(p.stat().st_size for p, _ in files)
    assert result["dedup_bytes"] == expected


@pytest.mark.asyncio
async def test_batched_handles_offer_rejection(batched_daemon, tmp_path):
    """An ACK with rejected={reason} marks that file as failed
    without aborting the rest of the batch."""
    root = tmp_path / "src"
    files = [
        (_make_file(root, "ok.txt", b"ok"), "ok.txt"),
        (_make_file(root, "bad.txt", b"bad"), "bad.txt"),
    ]
    chan = batched_daemon["chan"]

    def respond(msg, ch):
        if msg["t"] == "FILE_OFFER_BATCH":
            for inner in msg["offers"]:
                if inner["name"] == "bad.txt":
                    ch.enqueue({
                        "t": "ACK", "of": inner["id"],
                        "rejected": "auto_accept_size",
                    })
                else:
                    ch.enqueue({
                        "t": "FILE_WANTS", "of": inner["id"], "wants": [],
                    })
                    ch.enqueue({
                        "t": "FILE_DONE", "blob": inner["blob"], "ok": True,
                    })
    chan.on_send = respond
    result = await batched_daemon["daemon"].send_files_batched(
        batched_daemon["peer"], files,
    )
    assert result["sent"] == 1
    assert result["failed"] == 1
    bad_result = next(r for r in result["results"] if r["rel_path"] == "bad.txt")
    assert bad_result["ok"] is False
    assert "auto_accept_size" in bad_result["error"]


# ── splitting across multiple frames ─────────────────────────────


@pytest.mark.asyncio
async def test_batched_splits_at_256_offer_cap(batched_daemon, tmp_path):
    """N > 256 files should produce multiple FILE_OFFER_BATCH frames
    (each <= 256 inner offers) because the receiver caps a single
    frame at MAX_BATCH_OFFERS."""
    root = tmp_path / "many"
    files = [
        (_make_file(root, f"f{i:04d}.txt", b"."), f"f{i:04d}.txt")
        for i in range(257)
    ]
    chan = batched_daemon["chan"]

    def respond(msg, ch):
        if msg["t"] == "FILE_OFFER_BATCH":
            for inner in msg["offers"]:
                ch.enqueue({
                    "t": "FILE_WANTS", "of": inner["id"], "wants": [],
                })
                ch.enqueue({
                    "t": "FILE_DONE", "blob": inner["blob"], "ok": True,
                })
    chan.on_send = respond
    result = await batched_daemon["daemon"].send_files_batched(
        batched_daemon["peer"], files,
    )
    assert result["sent"] == 257
    batch_frames = [m for m in chan.sent_frames if m["t"] == "FILE_OFFER_BATCH"]
    assert len(batch_frames) == 2
    assert len(batch_frames[0]["offers"]) == 256
    assert len(batch_frames[1]["offers"]) == 1


# ── chunk streaming ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_batched_streams_chunks_for_non_empty_wants(
    batched_daemon, tmp_path,
):
    """Files with non-empty FILE_WANTS get FILE_CDC_CHUNK frames
    sent for the requested indexes; each chunk gets ACK'd."""
    root = tmp_path / "src"
    contents = b"x" * 1024  # small file → 1 CDC chunk
    p = _make_file(root, "leaf.bin", contents)
    chan = batched_daemon["chan"]

    def respond(msg, ch):
        if msg["t"] == "FILE_OFFER_BATCH":
            for inner in msg["offers"]:
                # Receiver "needs" chunk 0.
                ch.enqueue({
                    "t": "FILE_WANTS", "of": inner["id"], "wants": [0],
                })
        elif msg["t"] == "FILE_CDC_CHUNK":
            # ACK the chunk, then queue the DONE.
            ch.enqueue({"t": "ACK", "of": msg["id"]})
            # Lazily queue FILE_DONE on the FIRST chunk ACK so the
            # sender doesn't see it before it's done streaming.
            if not getattr(ch, "_done_sent", False):
                ch._done_sent = True
                ch.enqueue({
                    "t": "FILE_DONE", "blob": msg["blob"], "ok": True,
                })
    chan.on_send = respond
    result = await batched_daemon["daemon"].send_files_batched(
        batched_daemon["peer"], [(p, "leaf.bin")],
    )
    assert result["sent"] == 1
    assert result["failed"] == 0
    # Exactly one FILE_CDC_CHUNK was sent.
    chunks_sent = [m for m in chan.sent_frames if m["t"] == "FILE_CDC_CHUNK"]
    assert len(chunks_sent) == 1
    assert chunks_sent[0]["index"] == 0
    # The chunk payload matches the file bytes.
    sent_data = base64.b64decode(chunks_sent[0]["data"])
    assert sent_data == contents


# ── capability + trust gates ────────────────────────────────────


@pytest.mark.asyncio
async def test_batched_refuses_without_files_capability(batched_daemon, tmp_path):
    """If the peer's FILES capability is off, the batched send must
    refuse before opening the session — no FILE_OFFER_BATCH frame
    sent."""
    batched_daemon["daemon"]._capability_allowed = lambda fp, cap: False
    p = _make_file(tmp_path / "src", "a.txt", b"x")
    with pytest.raises(RuntimeError, match="files capability"):
        await batched_daemon["daemon"].send_files_batched(
            batched_daemon["peer"], [(p, "a.txt")],
        )
    assert not batched_daemon["chan"].sent_frames


@pytest.mark.asyncio
async def test_batched_refuses_when_outbound_trust_blocks(batched_daemon, tmp_path):
    """Trust block (peer rejected / un-pinned) refuses upfront."""
    batched_daemon["daemon"]._check_outbound_trust = lambda peer: "peer not pinned"
    p = _make_file(tmp_path / "src", "a.txt", b"x")
    with pytest.raises(RuntimeError, match="peer not pinned"):
        await batched_daemon["daemon"].send_files_batched(
            batched_daemon["peer"], [(p, "a.txt")],
        )
    assert not batched_daemon["chan"].sent_frames


@pytest.mark.asyncio
async def test_batched_empty_file_specs_returns_immediately(batched_daemon):
    result = await batched_daemon["daemon"].send_files_batched(
        batched_daemon["peer"], [],
    )
    assert result == {
        "ok": True, "sent": 0, "failed": 0,
        "dedup_files": 0, "dedup_bytes": 0, "results": [],
    }
    assert not batched_daemon["chan"].sent_frames


# ── sanitization ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_batched_drops_bad_rel_path_silently(batched_daemon, tmp_path):
    """A spec with a malformed rel_path still gets sent (with flat
    placement on receiver side), not rejected. The inner offer just
    won't carry rel_path."""
    p = _make_file(tmp_path / "src", "a.txt", b"x")
    chan = batched_daemon["chan"]

    def respond(msg, ch):
        if msg["t"] == "FILE_OFFER_BATCH":
            for inner in msg["offers"]:
                ch.enqueue({
                    "t": "FILE_WANTS", "of": inner["id"], "wants": [],
                })
                ch.enqueue({
                    "t": "FILE_DONE", "blob": inner["blob"], "ok": True,
                })
    chan.on_send = respond
    await batched_daemon["daemon"].send_files_batched(
        batched_daemon["peer"], [(p, "../escape.txt")],
    )
    batch = next(m for m in chan.sent_frames if m["t"] == "FILE_OFFER_BATCH")
    inner = batch["offers"][0]
    # Bad rel_path stripped — receiver will place flat.
    assert "rel_path" not in inner
