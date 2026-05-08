from __future__ import annotations

import asyncio
import time
from pathlib import Path

import blake3
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.capabilities import CHAT, FILES
from one_link.daemon import Daemon, OutboundSession
from one_link.discovery import Peer
from one_link.identity import Identity, fingerprint_of
from one_link.state import State
from one_link.transfer_intent import FileChunkManifest, FileManifest
from one_link.wire import decode_msg, encode_msg, make_msg


def _new_identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="x",
    )


class _FakeChannel:
    def __init__(self, *, peer_ed_pub: bytes, peer_short_id: str):
        self.peer_ed_pub = peer_ed_pub
        self.peer_short_id = peer_short_id
        self.peer_caps = {"features": [CHAT, FILES], "app_version": "0.9.0"}
        self.sent: list[dict] = []
        self._replies: asyncio.Queue[bytes] = asyncio.Queue()

    async def send(self, payload: bytes) -> None:
        self.sent.append(decode_msg(payload))

    async def recv(self) -> bytes:
        return await self._replies.get()

    def queue_reply(self, msg: dict) -> None:
        self._replies.put_nowait(encode_msg(msg))


def test_state_records_and_queries_chunk_availability(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    h1 = "aa" * 32
    h2 = "bb" * 32
    state.record_chunk_available(h1, 10, blob_hash="cc" * 32, chunk_index=0)
    assert state.has_chunk(h1)
    assert state.chunks_available([h2, h1]) == [h1]
    rows = state.list_chunks_for_blob("cc" * 32)
    assert rows[0]["chunk_hash"] == h1
    assert rows[0]["chunk_index"] == 0
    state.close()


@pytest.mark.asyncio
async def test_chunk_query_reports_only_cached_authorized_chunks(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(fingerprint=them.fingerprint, short_id=them.short_id, pubkey=them.public_bytes)
    state.set_peer_trust(them.fingerprint, "pinned")
    state.set_peer_capability_policy(them.fingerprint, [CHAT, FILES])
    payload = b"piece"
    h = blake3.blake3(payload).hexdigest()
    daemon._store_chunk_cache(h, payload, blob_hash="cc" * 32, chunk_index=0)
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)

    await daemon._on_peer_message(
        chan,
        make_msg("CHUNK_QUERY", them.short_id, hashes=[h, "dd" * 32]),
    )
    reply = chan.sent[-1]
    assert reply["t"] == "CHUNK_HAVE"
    assert reply["hashes"] == [h]
    state.close()


@pytest.mark.asyncio
async def test_chunk_pull_returns_verified_chunk_data(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(fingerprint=them.fingerprint, short_id=them.short_id, pubkey=them.public_bytes)
    state.set_peer_trust(them.fingerprint, "pinned")
    state.set_peer_capability_policy(them.fingerprint, [CHAT, FILES])
    payload = b"piece" * 100
    h = blake3.blake3(payload).hexdigest()
    daemon._store_chunk_cache(h, payload)
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)

    await daemon._on_peer_message(chan, make_msg("CHUNK_PULL", them.short_id, hash=h))
    reply = chan.sent[-1]
    assert reply["t"] == "CHUNK_DATA"
    assert reply["hash"] == h
    assert reply["size"] == len(payload)
    data = daemon._decode_payload(
        reply["enc"],
        __import__("base64").b64decode(reply["data"]),
        max_bytes=1024 * 1024,
    )
    assert data == payload
    state.close()


@pytest.mark.asyncio
async def test_outbound_query_and_pull_store_remote_chunk(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(fingerprint=them.fingerprint, short_id=them.short_id, pubkey=them.public_bytes)
    state.set_peer_trust(them.fingerprint, "pinned")
    state.set_peer_capability_policy(them.fingerprint, [CHAT, FILES])
    peer = Peer(them.short_id, "them", "127.0.0.1", 1234, them.public_bytes.hex())
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    sess = OutboundSession(
        peer_fp=them.fingerprint,
        peer=peer,
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess
    payload = b"remote-piece"
    h = blake3.blake3(payload).hexdigest()
    chan.queue_reply(make_msg("CHUNK_HAVE", them.short_id, hashes=[h]))
    assert await daemon.query_peer_chunks(peer, [h]) == {"ok": True, "hashes": [h], "rejected": None}
    enc, wire = daemon._encode_payload(payload)
    chan.queue_reply(make_msg(
        "CHUNK_DATA",
        them.short_id,
        hash=h,
        enc=enc,
        wire_size=len(wire),
        size=len(payload),
        data=__import__("base64").b64encode(wire).decode("ascii"),
    ))
    pulled = await daemon.pull_peer_chunk(peer, h)
    assert pulled["ok"] is True
    assert daemon._read_chunk_cache(h) == payload
    state.close()


@pytest.mark.asyncio
async def test_swarm_source_query_batches_large_manifests(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _new_identity()
    them = _new_identity()
    daemon = Daemon(me)
    peer = Peer(them.short_id, "source", "127.0.0.1", 12345, them.public_bytes.hex())
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    daemon._outbound_sessions[them.fingerprint] = OutboundSession(
        peer_fp=them.fingerprint,
        peer=peer,
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    hashes = [f"{i:064x}" for i in range(2053)]
    chan.queue_reply(make_msg("CHUNK_HAVE", them.short_id, hashes=[hashes[0]]))
    chan.queue_reply(make_msg("CHUNK_HAVE", them.short_id, hashes=[hashes[2048], hashes[-1]]))

    claims = await daemon.query_swarm_chunk_sources([peer], hashes)

    assert claims[them.fingerprint] == {hashes[0], hashes[2048], hashes[-1]}
    sent_queries = [m for m in chan.sent if m["t"] == "CHUNK_QUERY"]
    assert len(sent_queries) == 2
    assert len(sent_queries[0]["hashes"]) == 2048
    assert len(sent_queries[1]["hashes"]) == 5


@pytest.mark.asyncio
async def test_swarm_pull_fetches_missing_chunks_from_multiple_sources(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _new_identity()
    p1_id = _new_identity()
    p2_id = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    peers = []
    payloads = [b"first-swarm-piece", b"second-swarm-piece"]
    hashes = [blake3.blake3(p).hexdigest() for p in payloads]
    chunks = tuple(
        FileChunkManifest(index=i, start=i * 16, end=(i + 1) * 16, size=len(payloads[i]), hash=hashes[i])
        for i in range(2)
    )
    manifest = FileManifest(
        name="x.bin",
        size=sum(len(p) for p in payloads),
        blob_hash=blake3.blake3(b"".join(payloads)).hexdigest(),
        chunks=chunks,
    )

    for ident, payload, h in ((p1_id, payloads[0], hashes[0]), (p2_id, payloads[1], hashes[1])):
        state.upsert_peer(fingerprint=ident.fingerprint, short_id=ident.short_id, pubkey=ident.public_bytes)
        state.set_peer_trust(ident.fingerprint, "pinned")
        state.set_peer_capability_policy(ident.fingerprint, [CHAT, FILES])
        peer = Peer(ident.short_id, "them", "127.0.0.1", 1234, ident.public_bytes.hex())
        peers.append(peer)
        chan = _FakeChannel(peer_ed_pub=ident.public_bytes, peer_short_id=ident.short_id)
        sess = OutboundSession(
            peer_fp=ident.fingerprint,
            peer=peer,
            channel=chan,  # type: ignore[arg-type]
            lock=asyncio.Lock(),
            last_used=time.time(),
            regime="lan",
        )
        daemon._outbound_sessions[ident.fingerprint] = sess
        chan.queue_reply(make_msg("CHUNK_HAVE", ident.short_id, hashes=[h]))
        enc, wire = daemon._encode_payload(payload)
        chan.queue_reply(make_msg(
            "CHUNK_DATA",
            ident.short_id,
            hash=h,
            enc=enc,
            wire_size=len(wire),
            size=len(payload),
            data=__import__("base64").b64encode(wire).decode("ascii"),
        ))

    pulled = await daemon.pull_swarm_missing_chunks(
        peers=peers,
        manifest=manifest,
        needed_indexes=[0, 1],
    )
    assert pulled["ok"] is True
    assert pulled["pulled"] == 2
    assert daemon._read_chunk_cache(hashes[0]) == payloads[0]
    assert daemon._read_chunk_cache(hashes[1]) == payloads[1]
    assert set(pulled["sources"].values()) == {1}
    assert pulled["assigned_bytes"] == manifest.size
    assert pulled["missing_bytes"] == 0
    assert set(pulled["schedule"]) == {0, 1}
    state.close()


@pytest.mark.asyncio
async def test_swarm_pull_retries_alternate_source_when_best_source_fails(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _new_identity()
    fast_id = _new_identity()
    backup_id = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state

    payload = b"same-chunk-from-the-mesh"
    h = blake3.blake3(payload).hexdigest()
    manifest = FileManifest(
        name="x.bin",
        size=len(payload),
        blob_hash=blake3.blake3(payload).hexdigest(),
        chunks=(FileChunkManifest(
            index=0,
            start=0,
            end=len(payload),
            size=len(payload),
            hash=h,
        ),),
    )
    peers = []
    channels = {}
    for ident, bw in ((fast_id, 2_000_000_000), (backup_id, 100_000_000)):
        state.upsert_peer(
            fingerprint=ident.fingerprint,
            short_id=ident.short_id,
            pubkey=ident.public_bytes,
        )
        state.set_peer_trust(ident.fingerprint, "pinned")
        state.set_peer_capability_policy(ident.fingerprint, [CHAT, FILES])
        daemon._stamp_pair_health(
            ident.fingerprint,
            latency_ms=2.0,
            bandwidth_bps=bw,
            reliability=1.0,
        )
        peer = Peer(ident.short_id, "them", "127.0.0.1", 1234, ident.public_bytes.hex())
        peers.append(peer)
        chan = _FakeChannel(peer_ed_pub=ident.public_bytes, peer_short_id=ident.short_id)
        channels[ident.fingerprint] = chan
        daemon._outbound_sessions[ident.fingerprint] = OutboundSession(
            peer_fp=ident.fingerprint,
            peer=peer,
            channel=chan,  # type: ignore[arg-type]
            lock=asyncio.Lock(),
            last_used=time.time(),
            regime="lan",
        )
        chan.queue_reply(make_msg("CHUNK_HAVE", ident.short_id, hashes=[h]))

    bad_payload = b"corrupt"
    bad_enc, bad_wire = daemon._encode_payload(bad_payload)
    channels[fast_id.fingerprint].queue_reply(make_msg(
        "CHUNK_DATA",
        fast_id.short_id,
        hash=h,
        enc=bad_enc,
        wire_size=len(bad_wire),
        size=len(bad_payload),
        data=__import__("base64").b64encode(bad_wire).decode("ascii"),
    ))
    enc, wire = daemon._encode_payload(payload)
    channels[backup_id.fingerprint].queue_reply(make_msg(
        "CHUNK_DATA",
        backup_id.short_id,
        hash=h,
        enc=enc,
        wire_size=len(wire),
        size=len(payload),
        data=__import__("base64").b64encode(wire).decode("ascii"),
    ))

    pulled = await daemon.pull_swarm_missing_chunks(
        peers=peers,
        manifest=manifest,
        needed_indexes=[0],
    )

    assert pulled["ok"] is True
    assert pulled["pulled"] == 1
    assert pulled["retried"] == 1
    assert pulled["healed"] == 1
    assert daemon._read_chunk_cache(h) == payload
    assert h in pulled["candidate_sources"]
    state.close()


@pytest.mark.asyncio
async def test_inbound_file_offer_pulls_available_chunk_from_swarm_before_wants(
    tmp_path: Path, monkeypatch,
):
    """When another trusted device already has a needed CDC chunk, the
    receiver should fetch it before replying FILE_WANTS to the sender.
    The sender then only ships what the swarm could not satisfy.
    """
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _new_identity()
    sender = _new_identity()
    source = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state

    state.upsert_peer(
        fingerprint=sender.fingerprint,
        short_id=sender.short_id,
        pubkey=sender.public_bytes,
    )
    state.set_peer_trust(sender.fingerprint, "pinned")
    state.upsert_peer(
        fingerprint=source.fingerprint,
        short_id=source.short_id,
        pubkey=source.public_bytes,
        hostname="source",
        address="127.0.0.1",
        port=12345,
    )
    state.set_peer_trust(source.fingerprint, "pinned")

    pieces = [b"swarm-has-this", b"sender-still-needed"]
    hashes = [blake3.blake3(p).hexdigest() for p in pieces]
    blob = blake3.blake3(b"".join(pieces)).hexdigest()
    chunks = [
        {"index": 0, "start": 0, "end": len(pieces[0]), "size": len(pieces[0]), "hash": hashes[0]},
        {
            "index": 1,
            "start": len(pieces[0]),
            "end": len(pieces[0]) + len(pieces[1]),
            "size": len(pieces[1]),
            "hash": hashes[1],
        },
    ]

    source_peer = Peer(
        source.short_id,
        "source",
        "127.0.0.1",
        12345,
        source.public_bytes.hex(),
    )
    source_chan = _FakeChannel(
        peer_ed_pub=source.public_bytes,
        peer_short_id=source.short_id,
    )
    daemon._outbound_sessions[source.fingerprint] = OutboundSession(
        peer_fp=source.fingerprint,
        peer=source_peer,
        channel=source_chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    source_chan.queue_reply(make_msg("CHUNK_HAVE", source.short_id, hashes=[hashes[0]]))
    enc, wire = daemon._encode_payload(pieces[0])
    source_chan.queue_reply(make_msg(
        "CHUNK_DATA",
        source.short_id,
        hash=hashes[0],
        enc=enc,
        wire_size=len(wire),
        size=len(pieces[0]),
        data=__import__("base64").b64encode(wire).decode("ascii"),
    ))

    sender_chan = _FakeChannel(
        peer_ed_pub=sender.public_bytes,
        peer_short_id=sender.short_id,
    )
    await daemon._on_peer_message(
        sender_chan,
        make_msg(
            "FILE_OFFER",
            sender.short_id,
            name="swarm.bin",
            size=sum(len(p) for p in pieces),
            blob=blob,
            chunks=chunks,
            mode="cdc",
        ),
    )

    reply = sender_chan.sent[-1]
    row = state.get_transfer(f"in:{blob}")
    assert reply["t"] == "FILE_WANTS"
    assert reply["wants"] == [1]
    assert daemon._read_chunk_cache(hashes[0]) == pieces[0]
    assert row.metadata["swarm_assist"]["pulled"] == 1
    assert row.metadata["swarm_assist"]["source_count"] == 1
    assert row.metadata["swarm_assist"]["assisted_bytes"] == len(pieces[0])
    assert row.metadata["swarm_assist"]["missing_before"] == [0, 1]
    assert row.metadata["swarm_assist"]["missing_after"] == [1]
    assert row.metadata["swarm_assist"]["strategy"] == "multi_source_chunk_pull"
    assert "trusted device" in row.metadata["swarm_assist"]["user_message"]
    assert row.metadata["missing_chunks"] == 1
    state.close()
