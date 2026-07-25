"""v0.7.0 "Linked Mesh" tests.

Pin behaviors that the v0.7 architectural rewrite introduced:

  - ENDPOINT_UPDATE flow: pinned peers can push fresh endpoint info
    over an already-encrypted channel; non-pinned peers cannot.
  - send_file reuses the persistent OutboundSession instead of opening
    a fresh TCP handshake per send.
  - revoke_peer is a unified tear-down: trust=rejected drops the
    session, fails in-flight transfers, clears group sender chains,
    and broadcasts a peer_trust UI event.
  - Per-pairing health: _stamp_pair_health updates last_alive_ms and
    EWMA-blends latency; get_pair_health surfaces both; /api/peers
    serializes them (NaN-guarded).
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
import secrets
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import blake3
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import channel as ch
from one_link.daemon import (
    BINARY_FRAME_MAGIC,
    Daemon,
    IncomingFile,
    OutboundSession,
    _align_cdc_pipeline_profile,
    _bloom_manifest_binding,
    _decode_binary_frame,
    _final_stream_ack_deadline,
    _fast_fixed_chunk_size_for_peer,
    _stream_transfer_profile,
)
from one_link.capabilities import (
    BLOOM_INIT_EXACT_V2,
    BLOOM_INIT_V1,
    CHAT,
    FILES,
    FILE_ACK_BATCH,
    FILE_BINARY_FRAME,
    FILE_CDC,
    FILE_CDC_BINARY_FRAME,
    FILE_COMMIT_RECEIPT_V1,
    FRAME_PROVENANCE_V1,
    NATIVE_TRANSFER_INDEXED_V1,
)
from one_link.discovery import Peer
from one_link.identity import Identity, fingerprint_of
from one_link.state import State
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


@pytest.fixture(scope="module")
def module_scope_runtime_home_probe() -> tuple[Path, Path, Path]:
    """A higher-scoped fixture must be contained before function setup."""

    session_home = Path(os.environ["ONE_LINK_HOME"]).resolve()
    daemon = Daemon(_new_identity())
    return (
        session_home,
        daemon._resume_metadata_root.resolve(),
        daemon._resume_registry.inbox_root.resolve(),
    )


def test_pytest_session_home_guard_contains_module_fixture(
    module_scope_runtime_home_probe: tuple[Path, Path, Path],
):
    session_home, resume_root, inbox_root = module_scope_runtime_home_probe
    assert session_home.name == "home"
    assert session_home.parent.name.startswith("one-link-pytest-session-")
    assert resume_root == session_home / "data" / "transfer_resume"
    assert inbox_root == session_home / "data" / "inbox"


def test_pytest_runtime_home_guard_contains_unannotated_daemon(tmp_path: Path):
    """An ordinary Daemon test cannot resolve paths into the real profile."""

    expected_home = tmp_path / "one-link-pytest-home"
    assert Path(os.environ["ONE_LINK_HOME"]) == expected_home
    daemon = Daemon(_new_identity())
    assert daemon._resume_metadata_root == expected_home / "data" / "transfer_resume"
    assert daemon._resume_registry.inbox_root == expected_home / "data" / "inbox"


class _FakeChannel:
    """Stand-in for ch.Channel that records sent frames and serves
    queued replies. Used to isolate the send_file/lock path from real
    TCP + handshake plumbing.
    """

    def __init__(self, *, peer_ed_pub: bytes, peer_short_id: str):
        self.peer_ed_pub = peer_ed_pub
        self.peer_short_id = peer_short_id
        self.peer_caps: dict | None = None
        self.sent: list[dict] = []
        self._replies: asyncio.Queue[bytes] = asyncio.Queue()
        # Tests historically pre-staged shorthand replies without ``of``.
        # Production now requires exact request correlation, so bind those
        # fixture replies at receive time to the earliest outstanding request.
        # This keeps the fake protocol-realistic without forcing each test to
        # predict UUIDs generated later inside send_file().
        self._fixture_replied_ids: set[str] = set()
        self.closed = False

    async def send(self, payload: bytes) -> None:
        if self.closed:
            raise RuntimeError("channel closed")
        if payload.startswith(BINARY_FRAME_MAGIC):
            self.sent.append(_decode_binary_frame(payload))
        else:
            self.sent.append(decode_msg(payload))

    async def recv(self) -> bytes:
        if self.closed:
            raise RuntimeError("channel closed")
        payload = await self._replies.get()
        reply = decode_msg(payload)
        reply_type = str(reply.get("t") or "")
        if reply_type == "FILE_ACK_BATCH":
            self._fixture_replied_ids.update(
                str(value) for value in (reply.get("ofs") or []) if value
            )
            return payload
        if reply_type in {
            "ACK",
            "FILE_WANTS",
            "FILE_OFFER_HELD",
            "FILE_COMMIT",
        }:
            response_to = reply.get("of")
            if response_to is None:
                if reply_type == "FILE_COMMIT":
                    offer_request = next(
                        request for request in reversed(self.sent)
                        if request.get("t") == "FILE_OFFER"
                    )
                    response_to = str(offer_request["id"])
                    reply["of"] = response_to
                preferred_type = (
                    "FILE_OFFER"
                    if reply_type in {
                        "FILE_WANTS",
                        "FILE_OFFER_HELD",
                        "FILE_COMMIT",
                    }
                    else None
                )
                for request in (self.sent if response_to is None else ()):
                    request_id = str(request.get("id") or "")
                    if (
                        request_id
                        and request_id not in self._fixture_replied_ids
                        and request.get("t") != "FILE_PROVENANCE"
                        and (
                            preferred_type is None
                            or request.get("t") == preferred_type
                        )
                    ):
                        response_to = request_id
                        reply["of"] = request_id
                        break
            if reply_type == "FILE_COMMIT":
                offer = next(
                    request for request in self.sent
                    if request.get("t") == "FILE_OFFER"
                    and str(request.get("id") or "") == str(response_to or "")
                )
                reply.update({
                    "receipt_version": 1,
                    "blob": offer["blob"],
                    "size": offer["size"],
                    "mode": "cdc" if offer.get("chunks") is not None else "stream",
                    "delivery_id": offer["delivery_id"],
                    "delivery_name": offer["name"],
                    "delivery_rel_path": offer.get("rel_path", ""),
                    "delivery_kind": "file",
                    "ok": True,
                    "durable": True,
                    "committed_bytes": offer["size"],
                    "verified_hash": offer["blob"],
                    "reason": "",
                    "retryable": False,
                })
            # HELD is an intermediate state; the same FILE_OFFER later
            # receives FILE_WANTS/ACK after the user accepts it.
            if response_to is not None and reply_type != "FILE_OFFER_HELD":
                self._fixture_replied_ids.add(str(response_to))
            return encode_msg(reply)
        return payload

    async def close(self) -> None:
        self.closed = True

    def queue_reply(self, msg: dict) -> None:
        self._replies.put_nowait(encode_msg(msg))


class _TracingFakeChannel(_FakeChannel):
    def __init__(self, *, peer_ed_pub: bytes, peer_short_id: str):
        super().__init__(peer_ed_pub=peer_ed_pub, peer_short_id=peer_short_id)
        self.recv_sent_counts: list[int] = []

    async def recv(self) -> bytes:
        self.recv_sent_counts.append(len(self.sent))
        return await super().recv()


class _BatchAckFakeChannel(_TracingFakeChannel):
    def __init__(
        self,
        *,
        peer_ed_pub: bytes,
        peer_short_id: str,
        chunk_type: str = "FILE_CHUNK",
    ):
        super().__init__(peer_ed_pub=peer_ed_pub, peer_short_id=peer_short_id)
        self.chunk_type = chunk_type
        self._acked: set[str] = set()

    async def recv(self) -> bytes:
        if self._replies.empty():
            chunks = [
                m for m in self.sent
                if m.get("t") == self.chunk_type
                and m.get("id") not in self._acked
            ]
            if chunks:
                batch = chunks[:2]
                ids = [str(m["id"]) for m in batch]
                self._acked.update(ids)
                self.queue_reply(make_msg(
                    "FILE_ACK_BATCH",
                    self.peer_short_id,
                    ofs=ids,
                    count=len(ids),
                ))
        return await super().recv()


# ─── ENDPOINT_UPDATE: pinned-only ─────────────────────────────────


@pytest.mark.asyncio
async def test_inbound_ephemeral_source_port_never_overwrites_durable_endpoint(
    tmp_path: Path,
):
    """An inbound client's TCP source port is not a peer dial target."""
    receiver = _new_identity()
    initiator = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(receiver)
    daemon.state = state
    state.upsert_peer(
        fingerprint=initiator.fingerprint,
        short_id=initiator.short_id,
        pubkey=initiator.public_bytes,
        hostname="known-peer",
        address="192.0.2.44",
        port=42424,
    )
    state.set_peer_trust(initiator.fingerprint, "pinned")

    server = await asyncio.start_server(
        daemon._handle_peer, host="127.0.0.1", port=0,
    )
    listen_port = server.sockets[0].getsockname()[1]
    channel = None
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
        source_port = writer.get_extra_info("sockname")[1]
        assert source_port != 42424
        channel = await ch.initiate(
            reader,
            writer,
            initiator,
            expected_responder_ed_pub=receiver.public_bytes,
        )
        deadline = time.monotonic() + 2.0
        while initiator.fingerprint not in daemon._inbound_live_channels:
            assert time.monotonic() < deadline
            await asyncio.sleep(0.01)

        rec = state.get_peer(initiator.fingerprint)
        assert rec is not None
        assert rec.last_address == "192.0.2.44"
        assert rec.last_port == 42424
    finally:
        if channel is not None:
            await channel.close()
        server.close()
        await server.wait_closed()
        state.close()

@pytest.mark.asyncio
async def test_endpoint_update_from_pinned_peer_queues_verified_promotion(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    queued = []

    async def _fake_verify(peer_fp, peer_sid, host, port, **_kwargs):
        queued.append((peer_fp, peer_sid, host, port))

    daemon._verify_and_promote_endpoint = _fake_verify  # type: ignore[method-assign]
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
        hostname="them-host", address="10.0.0.1", port=5000,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    msg = make_msg(
        "ENDPOINT_UPDATE", them.short_id,
        endpoints=[{"host": "192.168.1.42", "port": 6000}],
    )
    await daemon._handle_endpoint_update(chan, msg, them.fingerprint, them.short_id)
    await asyncio.sleep(0)

    rec = state.get_peer(them.fingerprint)
    assert rec.last_address == "10.0.0.1"
    assert rec.last_port == 5000
    assert queued == [
        (them.fingerprint, them.short_id, "192.168.1.42", 6000)
    ]

    # ACK was sent
    assert any(s.get("t") == "ACK" for s in chan.sent)
    state.close()


@pytest.mark.asyncio
async def test_endpoint_candidate_promotes_after_verified_handshake(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
        hostname="them-host",
        address="10.0.0.1",
        port=5000,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    them_daemon = Daemon(them)
    them_daemon.state = State(db_path=tmp_path / "them.db")
    server = await asyncio.start_server(
        them_daemon._handle_peer, host="127.0.0.1", port=0
    )
    port = server.sockets[0].getsockname()[1]
    try:
        await daemon._verify_and_promote_endpoint(
            them.fingerprint, them.short_id, "127.0.0.1", port
        )
        rec = state.get_peer(them.fingerprint)
        assert rec.last_address == "127.0.0.1"
        assert rec.last_port == port
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()
        state.close()
        them_daemon.state.close()


@pytest.mark.asyncio
async def test_endpoint_update_from_non_pinned_peer_ignored(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    # Insert as 'pending' (default) — NOT pinned.
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
        hostname="them-host", address="10.0.0.1", port=5000,
    )
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    msg = make_msg(
        "ENDPOINT_UPDATE", them.short_id,
        endpoints=[{"host": "192.168.1.42", "port": 6000}],
    )
    await daemon._handle_endpoint_update(chan, msg, them.fingerprint, them.short_id)

    rec = state.get_peer(them.fingerprint)
    # Address NOT updated; original 10.0.0.1 / 5000 still there
    assert rec.last_address == "10.0.0.1"
    assert rec.last_port == 5000
    # And no ACK was sent (the non-pinned path early-returns)
    assert not any(s.get("t") == "ACK" for s in chan.sent)
    state.close()


@pytest.mark.asyncio
async def test_endpoint_update_caps_at_max_endpoints(tmp_path: Path):
    """A peer flooding us with 100 junk endpoints should only have the
    first MAX_ENDPOINTS_PER_ANNOUNCEMENT considered. The receiver picks
    one as the 'most likely reachable' anchor — confirm no crash and
    that the picked one is from the capped slice."""
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    queued = []

    async def _fake_verify(peer_fp, peer_sid, host, port, **_kwargs):
        queued.append((host, port))

    daemon._verify_and_promote_endpoint = _fake_verify  # type: ignore[method-assign]
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    flood = [{"host": f"10.0.0.{i}", "port": 5000 + i} for i in range(100)]
    msg = make_msg("ENDPOINT_UPDATE", them.short_id, endpoints=flood)
    await daemon._handle_endpoint_update(chan, msg, them.fingerprint, them.short_id)
    await asyncio.sleep(0)

    rec = state.get_peer(them.fingerprint)
    assert rec.last_address is None
    assert rec.last_port is None
    assert len(queued) == daemon.MAX_ENDPOINTS_PER_ANNOUNCEMENT
    assert queued[0] == ("10.0.0.0", 5000)
    state.close()


@pytest.mark.asyncio
async def test_endpoint_update_rejects_garbage_endpoints(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
        hostname="them", address="10.0.0.1", port=5000,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    msg = make_msg(
        "ENDPOINT_UPDATE", them.short_id,
        endpoints=[
            {"host": 12345, "port": 6000},        # bad host type
            {"host": "ok.example", "port": "x"},  # bad port type
            {"host": "", "port": 6000},           # empty host
            {"host": "ok2.example", "port": 0},   # invalid port
            {"host": "ok2.example", "port": 70000},  # invalid port (high)
        ],
    )
    await daemon._handle_endpoint_update(chan, msg, them.fingerprint, them.short_id)

    rec = state.get_peer(them.fingerprint)
    # Original address preserved — every endpoint was junk.
    assert rec.last_address == "10.0.0.1"
    assert rec.last_port == 5000
    state.close()


@pytest.mark.asyncio
async def test_endpoint_update_empty_list_ignored(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
        address="10.0.0.1", port=5000,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    msg = make_msg("ENDPOINT_UPDATE", them.short_id, endpoints=[])
    await daemon._handle_endpoint_update(chan, msg, them.fingerprint, them.short_id)

    rec = state.get_peer(them.fingerprint)
    assert rec.last_address == "10.0.0.1"
    state.close()


# ─── send_file: session reuse ──────────────────────────────────────

@pytest.mark.asyncio
async def test_send_file_reuses_existing_outbound_session(
    tmp_path: Path, monkeypatch
):
    """The v0.7.0 payoff: when a paired peer already has an alive
    OutboundSession, send_file MUST send through it instead of
    dialing+handshaking afresh. We assert that no fresh dial happens
    and the session's channel actually carried the FILE_OFFER."""
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    chan.peer_caps = {
        "features": [FILES, FILE_CDC, FRAME_PROVENANCE_V1],
    }
    sess = OutboundSession(
        peer_fp=them.fingerprint, peer=Peer(
            short_id=them.short_id, hostname="them",
            address="127.0.0.1", port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),  # fresh — won't trigger PING-probe
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess

    # Trip the dial path so we'd notice if reuse failed.
    dial_attempts = 0

    async def _explode(*a, **kw):
        nonlocal dial_attempts
        dial_attempts += 1
        raise AssertionError("send_file dialed instead of reusing session")

    monkeypatch.setattr(daemon, "_dial_peer", _explode)
    monkeypatch.setattr(daemon, "_dial_peer_with_regime", _explode)

    f = tmp_path / "tiny.txt"
    f.write_bytes(b"abc")  # one CDC chunk

    # Pre-stage replies. send_file will:
    #   send FILE_OFFER → expect FILE_WANTS
    #   send FILE_CDC_CHUNK → expect ACK
    chan.queue_reply(make_msg("FILE_WANTS", them.short_id, wants=[0]))
    chan.queue_reply(make_msg("ACK", them.short_id))

    peer = sess.peer
    result = await daemon.send_file(peer, f)

    assert dial_attempts == 0
    assert result["chunks"] == 1
    # FILE_OFFER + its exact provenance + one chunk on the existing channel.
    sent_types = [s.get("t") for s in chan.sent]
    assert sent_types[:3] == [
        "FILE_OFFER",
        "FILE_PROVENANCE",
        "FILE_CDC_CHUNK",
    ]
    offer = chan.sent[0]
    provenance_message = chan.sent[1]
    assert offer["blob"] == blake3.blake3(b"abc").hexdigest()
    assert provenance_message["blob"] == offer["blob"]
    from one_link.provenance_wiring import (
        parse_inbound_provenance_msg,
        verify_inbound,
    )

    parsed = parse_inbound_provenance_msg(provenance_message)
    assert verify_inbound(parsed, me.public_bytes) is True
    outbound_provenance = daemon._provenance_store.get_outbound(offer["blob"])
    assert outbound_provenance is not None
    assert outbound_provenance.provenance.segment_hash.hex() == offer["blob"]
    # Session counters bumped.
    assert sess.messages_sent == 1
    # Session NOT closed — kept for next reuse.
    assert chan.closed is False
    # Session still in the map.
    assert them.fingerprint in daemon._outbound_sessions
    state.close()


@pytest.mark.asyncio
async def test_send_file_honors_lossless_bloom_response_end_to_end(
    tmp_path: Path, monkeypatch
):
    """Bloom honor sends the exact delta and never trusts false positives."""

    from one_link import bloom_init

    if not bloom_init.HAS_NATIVE:
        pytest.skip("native Bloom runtime is unavailable")

    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    class _BloomChannel(_FakeChannel):
        async def send(self, payload: bytes) -> None:
            await super().send(payload)
            sent = self.sent[-1]
            if sent.get("t") == "FILE_OFFER":
                chunks = list(sent["chunks"])
                assert len(chunks) > 1
                known = bytes.fromhex(chunks[0]["hash"])
                wire = bloom_init.build_receiver_bloom([known])
                decoded = bloom_init.decode_receiver_bloom(wire)
                corrections = [
                    int(chunk["index"])
                    for chunk in chunks[1:]
                    if decoded.contains(bytes.fromhex(chunk["hash"]))
                ]
                self.queue_reply(make_msg(
                    "BLOOM_INIT_FILTER",
                    them.short_id,
                    of=sent["id"],
                    blob=sent["blob"],
                    bloom=base64.b64encode(wire).decode("ascii"),
                    n_known=1,
                    manifest_count=len(chunks),
                    manifest_binding=_bloom_manifest_binding(chunks),
                    corrections=corrections,
                ))
            elif sent.get("t") == "FILE_CDC_CHUNK":
                self.queue_reply(make_msg(
                    "ACK",
                    them.short_id,
                    of=sent["id"],
                ))

    channel = _BloomChannel(
        peer_ed_pub=them.public_bytes,
        peer_short_id=them.short_id,
    )
    channel.peer_caps = {
        "features": [FILES, FILE_CDC, BLOOM_INIT_V1, BLOOM_INIT_EXACT_V2],
    }
    session = OutboundSession(
        peer_fp=them.fingerprint,
        peer=Peer(
            short_id=them.short_id,
            hostname="them",
            address="127.0.0.1",
            port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=channel,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = session

    async def _unexpected_dial(*_args, **_kwargs):
        raise AssertionError("Bloom transfer opened a second session")

    monkeypatch.setattr(daemon, "_dial_peer", _unexpected_dial)
    monkeypatch.setattr(daemon, "_dial_peer_with_regime", _unexpected_dial)
    source = tmp_path / "bloom-delta.bin"
    source.write_bytes(b"".join(
        blake3.blake3(i.to_bytes(4, "little")).digest()
        for i in range(32_768)
    ))

    result = await daemon.send_file(session.peer, source)

    offer = next(msg for msg in channel.sent if msg.get("t") == "FILE_OFFER")
    chunk_indexes = {
        int(msg["index"])
        for msg in channel.sent
        if msg.get("t") == "FILE_CDC_CHUNK"
    }
    expected = {int(chunk["index"]) for chunk in offer["chunks"]} - {0}
    assert chunk_indexes == expected
    assert result["cdc"] is True
    assert result["chunks"] == len(expected)
    assert result["cdc_skipped"] == 1
    transfer = state.get_transfer(result["transfer_id"])
    assert transfer is not None
    assert transfer.metadata["actual_method"] == "file_cdc_bloom"
    state.close()


@pytest.mark.asyncio
async def test_single_file_sender_waits_after_offer_held(tmp_path: Path):
    """FILE_OFFER_HELD is a state transition, not an ignorable frame."""
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    chan.peer_caps = {
        "features": [FILES, FILE_CDC, FILE_COMMIT_RECEIPT_V1],
    }
    sess = OutboundSession(
        peer_fp=them.fingerprint,
        peer=Peer(
            short_id=them.short_id, hostname="them", address="127.0.0.1",
            port=12345, ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(), last_used=time.time(), regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess
    src = tmp_path / "held.bin"
    src.write_bytes(b"held-content")
    chan.queue_reply(make_msg("FILE_OFFER_HELD", them.short_id))
    chan.queue_reply(make_msg("FILE_WANTS", them.short_id, wants=[0]))
    chan.queue_reply(make_msg("ACK", them.short_id))
    chan.queue_reply(make_msg("FILE_COMMIT", them.short_id))

    recv_calls = 0
    original_recv = chan.recv

    async def _recv_with_state_assertion() -> bytes:
        nonlocal recv_calls
        recv_calls += 1
        if recv_calls == 2:
            row = state.list_transfers(limit=1)[0]
            assert row.status == "offered"
            assert row.metadata["delivery_state"] == "awaiting_remote_acceptance"
        return await original_recv()

    chan.recv = _recv_with_state_assertion  # type: ignore[method-assign]
    result = await daemon.send_file(sess.peer, src)

    assert result["chunks"] == 1
    assert recv_calls >= 3
    assert state.list_transfers(limit=1)[0].status == "complete"
    state.close()


@pytest.mark.asyncio
async def test_retry_reuses_recorded_fixed_chunk_boundaries(
    tmp_path: Path, monkeypatch,
):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    # This regression exercises CDC retry boundaries specifically.  Declare
    # the peer capability explicitly so the test cannot fall back to the
    # baseline stream path when another test changes compatibility defaults.
    chan.peer_caps = {"features": [FILES, FILE_CDC]}
    sess = OutboundSession(
        peer_fp=them.fingerprint,
        peer=Peer(
            short_id=them.short_id, hostname="them", address="127.0.0.1",
            port=12345, ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(), last_used=time.time(), regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess
    src = tmp_path / "stable.bin"
    src.write_bytes(b"stable-boundaries" * 8192)
    transfer_id = "out:stable"
    state.upsert_transfer(
        id=transfer_id, direction="out", peer_fp=them.fingerprint,
        kind="file", name=src.name, size=src.stat().st_size, status="paused",
        progress_bytes=0, total_bytes=src.stat().st_size,
        chunks_done=0, chunks_total=2,
        metadata={"path": str(src), "mode": "cdc", "fixed_chunk_size": 96 * 1024},
    )
    monkeypatch.setattr("one_link.daemon.CDC_AUTO_INDEX_MAX_BYTES", 1)
    monkeypatch.setattr("one_link.daemon.FAST_FIXED_INDEX_MIN_BYTES", 1)
    from one_link import daemon as daemon_module
    real_fixed_index = daemon_module.fixed_index_file
    observed: list[int] = []

    def _capture_fixed_index(
        handle, *, size: int, chunk_size: int, read_size: int = 1024 * 1024,
    ):
        observed.append(chunk_size)
        return real_fixed_index(
            handle,
            size=size,
            chunk_size=chunk_size,
            read_size=read_size,
        )

    monkeypatch.setattr("one_link.daemon.fixed_index_file", _capture_fixed_index)
    chan.queue_reply(make_msg("FILE_WANTS", them.short_id, wants=[]))

    await daemon.send_file(sess.peer, src, transfer_id=transfer_id)

    assert observed == [96 * 1024]
    assert chan.sent[0]["chunks"][0]["size"] == 96 * 1024
    state.close()


@pytest.mark.asyncio
async def test_empty_file_uses_canonical_stream_eof_not_zero_length_cdc(
    tmp_path: Path,
):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    channel = _FakeChannel(
        peer_ed_pub=them.public_bytes,
        peer_short_id=them.short_id,
    )
    channel.peer_caps = {"features": [FILES, FILE_CDC]}
    peer = Peer(
        short_id=them.short_id,
        hostname="them",
        address="127.0.0.1",
        port=12345,
        ed_pub_hex=them.public_bytes.hex(),
    )
    daemon._outbound_sessions[them.fingerprint] = OutboundSession(
        peer_fp=them.fingerprint,
        peer=peer,
        channel=channel,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    source = tmp_path / "empty.bin"
    source.write_bytes(b"")
    channel.queue_reply(make_msg("ACK", them.short_id))
    channel.queue_reply(make_msg("ACK", them.short_id))

    result = await daemon.send_file(peer, source)

    offer = next(frame for frame in channel.sent if frame["t"] == "FILE_OFFER")
    payload = next(frame for frame in channel.sent if frame["t"] == "FILE_CHUNK")
    assert result["cdc"] is False
    assert offer["mode"] == "stream"
    assert "chunks" not in offer
    assert payload["data"] == ""
    assert payload["eof"] is True
    terminal = state.list_transfers(limit=1)[0]
    assert terminal.status == "failed"
    assert terminal.metadata["delivery_state"] == "sent_unconfirmed"
    state.close()


@pytest.mark.asyncio
async def test_direct_send_preparation_runs_off_event_loop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    channel = _FakeChannel(
        peer_ed_pub=them.public_bytes,
        peer_short_id=them.short_id,
    )
    channel.peer_caps = {"features": [FILES]}
    peer = Peer(
        short_id=them.short_id,
        hostname="them",
        address="127.0.0.1",
        port=12345,
        ed_pub_hex=them.public_bytes.hex(),
    )
    daemon._outbound_sessions[them.fingerprint] = OutboundSession(
        peer_fp=them.fingerprint,
        peer=peer,
        channel=channel,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    source = tmp_path / "slow-plan.bin"
    source.write_bytes(b"off-loop planning")
    real_prepare = daemon.prepare_file_for_transfer
    preparation_threads: list[int] = []

    def _slow_prepare(*args, **kwargs):
        preparation_threads.append(threading.get_ident())
        time.sleep(0.25)
        return real_prepare(*args, **kwargs)

    monkeypatch.setattr(daemon, "prepare_file_for_transfer", _slow_prepare)
    channel.queue_reply(make_msg("ACK", them.short_id))
    channel.queue_reply(make_msg("ACK", them.short_id))
    main_thread = threading.get_ident()
    send_task = asyncio.create_task(daemon.send_file(peer, source))
    loop = asyncio.get_running_loop()
    started = loop.time()
    await asyncio.sleep(0.03)

    assert loop.time() - started < 0.12
    assert not send_task.done()
    await asyncio.wait_for(send_task, timeout=1.0)
    assert preparation_threads and preparation_threads[0] != main_thread
    state.close()


@pytest.mark.asyncio
async def test_send_file_baseline_peer_gets_legacy_stream_offer(
    tmp_path: Path, monkeypatch
):
    """If a paired peer advertises files but not CDC, send_file skips
    the CDC manifest and uses the old ACK + FILE_CHUNK stream path.
    """
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    chan.peer_caps = {
        "protocol": "OL1.2",
        "features": [CHAT, FILES],
        "from": them.short_id,
        "app_version": "0.6.0",
    }
    sess = OutboundSession(
        peer_fp=them.fingerprint, peer=Peer(
            short_id=them.short_id, hostname="them",
            address="127.0.0.1", port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess
    monkeypatch.setattr(
        daemon, "_dial_peer_with_regime",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("no dial")),
    )
    monkeypatch.setattr(
        "one_link.daemon.index_path",
        lambda *a, **kw: (_ for _ in ()).throw(
            AssertionError("baseline peer should not pay CDC indexing cost")
        ),
    )

    f = tmp_path / "legacy.txt"
    f.write_bytes(b"legacy stream")
    chan.queue_reply(make_msg("ACK", them.short_id))
    chan.queue_reply(make_msg("ACK", them.short_id))

    result = await daemon.send_file(sess.peer, f)
    offer = chan.sent[0]
    sent_types = [s.get("t") for s in chan.sent]
    row = state.list_transfers(limit=1)[0]

    assert result["cdc"] is False
    assert offer["t"] == "FILE_OFFER"
    assert offer["mode"] == "stream"
    assert "chunks" not in offer
    assert "FILE_CHUNK" in sent_types
    assert "FILE_CDC_CHUNK" not in sent_types
    assert row.metadata["compatibility"]["transfer_mode"] == "baseline_file"
    assert row.metadata["actual_method"] == "file_baseline"
    state.close()


@pytest.mark.asyncio
async def test_send_file_unknown_peer_probes_cdc_then_stream_fallback(
    tmp_path: Path, monkeypatch
):
    """Peers with no CAPS yet get one smart CDC probe. If they reply with
    a legacy ACK, the same durable transfer falls back to stream.
    """
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    sess = OutboundSession(
        peer_fp=them.fingerprint, peer=Peer(
            short_id=them.short_id, hostname="them",
            address="127.0.0.1", port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess
    monkeypatch.setattr(
        daemon, "_dial_peer_with_regime",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("no dial")),
    )

    f = tmp_path / "probe.txt"
    f.write_bytes(b"probe fallback")
    chan.queue_reply(make_msg("ACK", them.short_id))
    chan.queue_reply(make_msg("ACK", them.short_id))

    result = await daemon.send_file(sess.peer, f)
    offer = chan.sent[0]
    row = state.list_transfers(limit=1)[0]

    assert result["cdc"] is False
    assert offer["mode"] == "cdc"
    assert isinstance(offer.get("chunks"), list)
    assert row.metadata["compatibility"]["mode"] == "legacy_unknown"
    assert row.metadata["protocol_attempts"][-1]["method"] == "file_baseline"
    assert row.metadata["protocol_attempts"][-1]["state"] == "fallback"
    state.close()


@pytest.mark.asyncio
async def test_send_file_large_cdc_peer_uses_fast_stream_lane(
    tmp_path: Path, monkeypatch
):
    """Large first-time sends must not crawl through Python CDC just because
    the peer supports it. The product promise is fast automatic delivery.
    """
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    chan.peer_caps = {
        "protocol": "OL1.2",
        "features": [CHAT, FILES, FILE_CDC],
        "from": them.short_id,
        "app_version": "0.11.0",
    }
    sess = OutboundSession(
        peer_fp=them.fingerprint, peer=Peer(
            short_id=them.short_id, hostname="them",
            address="127.0.0.1", port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess
    monkeypatch.setattr(
        "one_link.daemon.index_path",
        lambda *a, **kw: (_ for _ in ()).throw(
            AssertionError("large first-time send should not build Python CDC")
        ),
    )
    monkeypatch.setattr(
        "one_link.daemon.native_cdc_status",
        lambda: SimpleNamespace(
            available=False,
            engine="python",
            reason="disabled for test",
            library="",
        ),
    )

    f = tmp_path / "video.bin"
    f.write_bytes(b"x" * 1024)
    monkeypatch.setattr("one_link.daemon.CDC_AUTO_INDEX_MAX_BYTES", 512)
    chan.queue_reply(make_msg("ACK", them.short_id))
    chan.queue_reply(make_msg("ACK", them.short_id))

    result = await daemon.send_file(sess.peer, f)
    offer = chan.sent[0]
    row = state.list_transfers(limit=1)[0]

    assert result["cdc"] is False
    assert offer["mode"] == "stream"
    assert "chunks" not in offer
    assert row.metadata["cdc_decision_reason"] == "large_file_fast_lane_until_native_cdc"
    state.close()


@pytest.mark.asyncio
async def test_send_file_large_cdc_peer_uses_native_prior_knowledge_lane(
    tmp_path: Path, monkeypatch
):
    """With the native CDC scanner active, large sends should advertise a
    manifest so peers can skip already-known bytes instead of wasting wire.
    """
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    chan.peer_caps = {
        "protocol": "OL1.2",
        "features": [CHAT, FILES, FILE_CDC],
        "from": them.short_id,
        "app_version": "0.14.3",
    }
    sess = OutboundSession(
        peer_fp=them.fingerprint, peer=Peer(
            short_id=them.short_id, hostname="them",
            address="127.0.0.1", port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess
    monkeypatch.setattr(
        "one_link.daemon.native_cdc_status",
        lambda: SimpleNamespace(
            available=True,
            engine="ctypes-c",
            reason="",
            library="test-native",
        ),
    )

    f = tmp_path / "huge-known-video.bin"
    f.write_bytes(b"known-video" * 256)
    monkeypatch.setattr("one_link.daemon.CDC_AUTO_INDEX_MAX_BYTES", 512)
    monkeypatch.setattr("one_link.daemon.FAST_FIXED_INDEX_MIN_BYTES", 512)
    chan.queue_reply(make_msg("FILE_WANTS", them.short_id, wants=[]))

    result = await daemon.send_file(sess.peer, f)
    offer = chan.sent[0]
    row = state.list_transfers(limit=1)[0]

    assert result["cdc"] is True
    assert result["wire_bytes_sent"] == 0
    assert offer["mode"] == "cdc"
    assert isinstance(offer.get("chunks"), list)
    assert row.metadata["cdc_decision_reason"] == "native_cdc_fast_lane:ctypes-c"
    assert row.metadata["cdc_engine"].startswith("native_ctypes-c")
    assert row.metadata["transfer_report"]["bandwidth_savings_ratio"] == 1.0
    assert result["transfer_report"]["wire_bytes_sent"] == 0
    assert result["transfer_engine_oracle"]["cdc"]["samples"] == 1
    state.close()


@pytest.mark.asyncio
async def test_send_file_reuses_cached_file_index_without_rehashing(
    tmp_path: Path, monkeypatch
):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    f = tmp_path / "repeat-video.bin"
    payload = b"unchanged media payload" * 1024
    f.write_bytes(payload)
    blob = blake3.blake3(payload).hexdigest()
    chunk_hash = blake3.blake3(payload).hexdigest()
    state.record_file_index_cache(
        **daemon._file_cache_signature(f),
        blob_hash=blob,
        index_kind="fixed",
        chunks=[{
            "index": 0,
            "start": 0,
            "end": len(payload),
            "size": len(payload),
            "hash": chunk_hash,
        }],
    )

    chan = _TracingFakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    chan.peer_caps = {
        "protocol": "OL1.2",
        "features": [CHAT, FILES, FILE_CDC],
        "from": them.short_id,
        "app_version": "0.12.4",
    }
    sess = OutboundSession(
        peer_fp=them.fingerprint,
        peer=Peer(
            short_id=them.short_id, hostname="them",
            address="127.0.0.1", port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess
    monkeypatch.setattr(
        "one_link.daemon.hash_path",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("rehash")),
    )
    monkeypatch.setattr(
        "one_link.daemon.index_path",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("reindex")),
    )
    monkeypatch.setattr(
        "one_link.daemon.fixed_index_path",
        lambda *a, **kw: (_ for _ in ()).throw(AssertionError("fixed reindex")),
    )
    chan.queue_reply(make_msg("FILE_WANTS", them.short_id, wants=[]))

    result = await daemon.send_file(sess.peer, f)
    offer = chan.sent[0]
    row = state.list_transfers(limit=1)[0]

    assert result["chunks"] == 0
    assert result["cdc"] is True
    assert offer["blob"] == blob
    assert offer["chunks"][0]["hash"] == chunk_hash
    assert row.metadata["file_index_cache"] == "hit"
    assert row.metadata["file_index_kind"] == "fixed"
    assert row.metadata["prior_hit_rate_actual"] == 1.0
    # Fresh peer with no transfer history: bandit hasn't yet collected
    # enough evidence to upgrade past either CONSTRAINED (reliability <
    # 0.60 default) or OBSERVING (confidence < 0.35). Both are valid
    # backoff/probe states; the regulator's exact pick depends on
    # bandit init defaults (`_regulate` in transfer_brain.py).
    assert row.metadata["pipeline_tuning"]["reason"] in (
        "observing_probe", "constrained_backoff",
    )
    assert row.metadata["pipeline_tuning"]["window_chunks"] >= 1
    assert row.metadata["transfer_report"]["effective_payload_bytes"] == len(payload)
    assert row.metadata["transfer_report"]["wire_bytes_sent"] == 0
    assert row.metadata["transfer_report"]["bandwidth_savings_ratio"] == 1.0
    state.close()


@pytest.mark.asyncio
async def test_resolve_for_send_uses_trusted_last_known_lan_route(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
        hostname="Computer 2",
        address="192.168.1.26",
        port=61221,
        trust_default="pinned",
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    peer = await daemon.resolve_for_send(them.short_id)

    assert peer is not None
    assert peer.short_id == them.short_id
    assert peer.hostname == "Computer 2"
    assert peer.address == "192.168.1.26"
    assert peer.port == 61221
    assert peer.ed_pub_hex == them.public_bytes.hex()
    state.close()


def test_stream_transfer_profile_scales_window_safely():
    small = _stream_transfer_profile(2 * 1024 * 1024)
    big = _stream_transfer_profile(4 * 1024 * 1024 * 1024)

    assert small["chunk_size"] == 256 * 1024
    assert small["window_chunks"] >= 1
    assert big["chunk_size"] == 4 * 1024 * 1024
    assert big["window_bytes"] <= 24 * 1024 * 1024
    assert big["window_chunks"] <= 16


def test_385_mib_field_chunks_preserve_fresh_window_bytes_at_high_rtt():
    """250 kB ratchet chunks must not turn a 4 MiB window into 1 MiB."""

    size = 403_387_968
    cadence_chunk = 250_000
    chunk_count = (size + cadence_chunk - 1) // cadence_chunk
    chunks = (
        SimpleNamespace(size=cadence_chunk),
        SimpleNamespace(size=size % cadence_chunk),
    )

    aligned = _align_cdc_pipeline_profile(
        _stream_transfer_profile(size),
        chunks,  # type: ignore[arg-type]
        size=size,
        fresh_content=True,
    )

    assert chunk_count == 1_614
    assert aligned["chunk_size"] == cadence_chunk
    assert aligned["window_chunks"] == 16
    assert aligned["window_bytes"] == 4_000_000
    assert aligned["window_bytes"] <= 4 * 1024 * 1024
    # At the reported ~596 ms RTT, count-only clamping needed 404 ACK
    # flights. Byte-aligned clamping needs 101: the ratchet cadence remains
    # unchanged while the avoidable high-latency amplification disappears.
    old_ack_flights = (chunk_count + 4 - 1) // 4
    aligned_ack_flights = (
        chunk_count + aligned["window_chunks"] - 1
    ) // aligned["window_chunks"]
    assert old_ack_flights == 404
    assert aligned_ack_flights == 101
    assert aligned_ack_flights * 0.596 < old_ack_flights * 0.596 / 3.9


def test_final_stream_ack_deadline_gives_legacy_receivers_cache_grace():
    medium = _final_stream_ack_deadline(256 * 1024 * 1024)
    huge = _final_stream_ack_deadline(10 * 1024 * 1024 * 1024)

    assert medium >= 120.0
    assert huge == 600.0


def test_fast_fixed_chunk_size_is_version_gated():
    assert _fast_fixed_chunk_size_for_peer(None) == 256 * 1024
    assert _fast_fixed_chunk_size_for_peer("0.12.4") == 256 * 1024
    assert _fast_fixed_chunk_size_for_peer("0.12.5") == 1024 * 1024
    assert _fast_fixed_chunk_size_for_peer("v0.13.0") == 1024 * 1024
    assert _fast_fixed_chunk_size_for_peer(
        None,
        size=1024 * 1024 * 1024,
        peer_features=["file_cdc_binary_frame"],
    ) == 2 * 1024 * 1024
    assert _fast_fixed_chunk_size_for_peer(
        "v0.20.0",
        size=4 * 1024 * 1024 * 1024,
    ) == 4 * 1024 * 1024


def test_normalize_cdc_chunks_accepts_fast_fixed_chunk_size(tmp_path: Path):
    daemon = Daemon(_new_identity())
    chunks = daemon._normalize_cdc_chunks(
        [{
            "index": 0,
            "start": 0,
            "end": 1024 * 1024,
            "size": 1024 * 1024,
            "hash": "aa" * 32,
        }],
        declared_size=1024 * 1024,
    )
    assert chunks is not None
    assert chunks[0]["size"] == 1024 * 1024


@pytest.mark.parametrize(
    "chunks",
    [
        # Gap.
        [
            {"index": 0, "start": 0, "end": 4, "size": 4, "hash": "a" * 64},
            {"index": 1, "start": 5, "end": 8, "size": 3, "hash": "b" * 64},
        ],
        # Overlap.
        [
            {"index": 0, "start": 0, "end": 5, "size": 5, "hash": "a" * 64},
            {"index": 1, "start": 4, "end": 8, "size": 4, "hash": "b" * 64},
        ],
        # Reordered/duplicate wire index.
        [
            {"index": 1, "start": 0, "end": 4, "size": 4, "hash": "a" * 64},
            {"index": 0, "start": 4, "end": 8, "size": 4, "hash": "b" * 64},
        ],
        # Zero-sized entry.
        [
            {"index": 0, "start": 0, "end": 0, "size": 0, "hash": "a" * 64},
            {"index": 1, "start": 0, "end": 8, "size": 8, "hash": "b" * 64},
        ],
        # Does not cover the declared tail.
        [
            {"index": 0, "start": 0, "end": 7, "size": 7, "hash": "a" * 64},
        ],
    ],
)
def test_normalize_cdc_chunks_rejects_non_partition_manifests(
    tmp_path: Path, chunks: list[dict],
):
    daemon = Daemon(_new_identity())
    assert daemon._normalize_cdc_chunks(chunks, declared_size=8) is None


@pytest.mark.asyncio
async def test_send_file_ignores_fast_cache_for_legacy_peer(tmp_path: Path, monkeypatch):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    payload = b"a" * (1024 * 1024)
    f = tmp_path / "legacy-repeat.bin"
    f.write_bytes(payload)
    state.record_file_index_cache(
        **daemon._file_cache_signature(f),
        blob_hash=blake3.blake3(payload).hexdigest(),
        index_kind="fixed",
        chunks=[{
            "index": 0,
            "start": 0,
            "end": len(payload),
            "size": len(payload),
            "hash": blake3.blake3(payload).hexdigest(),
        }],
    )

    chan = _TracingFakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    chan.peer_caps = {
        "protocol": "OL1.2",
        "features": [CHAT, FILES, FILE_CDC],
        "from": them.short_id,
        "app_version": "0.12.4",
    }
    sess = OutboundSession(
        peer_fp=them.fingerprint,
        peer=Peer(
            short_id=them.short_id, hostname="them",
            address="127.0.0.1", port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess
    monkeypatch.setattr("one_link.daemon.FAST_FIXED_INDEX_MIN_BYTES", 1)
    chan.queue_reply(make_msg("FILE_WANTS", them.short_id, wants=[]))

    result = await daemon.send_file(sess.peer, f)
    offer = chan.sent[0]
    row = state.list_transfers(limit=1)[0]

    assert result["chunks"] == 0
    assert len(offer["chunks"]) == 4
    assert max(c["size"] for c in offer["chunks"]) == 256 * 1024
    assert row.metadata["file_index_kind"] == "fixed"
    assert row.metadata["fixed_chunk_size"] == 256 * 1024
    state.close()


@pytest.mark.asyncio
async def test_send_file_upgrades_small_fixed_cache_for_modern_peer(
    tmp_path: Path, monkeypatch
):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    payload = b"abcd" * (1024 * 1024)
    f = tmp_path / "modern-repeat.bin"
    f.write_bytes(payload)
    old_chunks = []
    for i in range(16):
        start = i * 256 * 1024
        data = payload[start:start + 256 * 1024]
        old_chunks.append({
            "index": i,
            "start": start,
            "end": start + len(data),
            "size": len(data),
            "hash": blake3.blake3(data).hexdigest(),
        })
    state.record_file_index_cache(
        **daemon._file_cache_signature(f),
        blob_hash=blake3.blake3(payload).hexdigest(),
        index_kind="fixed",
        chunks=old_chunks,
    )

    chan = _TracingFakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    chan.peer_caps = {
        "protocol": "OL1.2",
        "features": [CHAT, FILES, FILE_CDC],
        "from": them.short_id,
        "app_version": "0.12.5",
    }
    sess = OutboundSession(
        peer_fp=them.fingerprint,
        peer=Peer(
            short_id=them.short_id,
            hostname="them",
            address="127.0.0.1",
            port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess
    monkeypatch.setattr("one_link.daemon.FAST_FIXED_INDEX_MIN_BYTES", 1)
    chan.queue_reply(make_msg("FILE_WANTS", them.short_id, wants=[]))

    result = await daemon.send_file(sess.peer, f)
    offer = chan.sent[0]
    row = state.list_transfers(limit=1)[0]

    assert result["chunks"] == 0
    assert len(offer["chunks"]) == 4
    assert max(c["size"] for c in offer["chunks"]) == 1024 * 1024
    assert row.metadata["file_index_kind"] == "fixed"
    assert row.metadata["fixed_chunk_size"] == 1024 * 1024
    state.close()


@pytest.mark.asyncio
async def test_send_file_cdc_chunks_are_pipelined(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "home"))
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    daemon._stamp_pair_health(them.fingerprint, latency_ms=596.0)

    chan = _TracingFakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    chan.peer_caps = {
        "protocol": "OL1.2",
        "features": [CHAT, FILES, FILE_CDC],
        "from": them.short_id,
        "app_version": "0.12.5",
    }
    sess = OutboundSession(
        peer_fp=them.fingerprint,
        peer=Peer(
            short_id=them.short_id, hostname="them",
            address="127.0.0.1", port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess
    monkeypatch.setattr("one_link.daemon.STREAM_MIN_CHUNK_SIZE", 2)
    monkeypatch.setattr("one_link.daemon.STREAM_PIPELINE_TARGET_BYTES", 6)
    monkeypatch.setattr("one_link.daemon.STREAM_PIPELINE_MAX_CHUNKS", 3)

    f = tmp_path / "cdc-pipeline.bin"
    f.write_bytes(b"0123456789")
    chunks = []
    for i in range(5):
        start = i * 2
        data = f.read_bytes()[start:start + 2]
        chunks.append({
            "index": i,
            "start": start,
            "end": start + len(data),
            "size": len(data),
            "hash": blake3.blake3(data).hexdigest(),
        })
    state.record_file_index_cache(
        **daemon._file_cache_signature(f),
        blob_hash=blake3.blake3(f.read_bytes()).hexdigest(),
        index_kind="fixed",
        chunks=chunks,
    )
    chan.queue_reply(make_msg("FILE_WANTS", them.short_id, wants=[0, 1, 2, 3, 4]))
    for _ in range(5):
        chan.queue_reply(make_msg("ACK", them.short_id))

    result = await daemon.send_file(sess.peer, f)
    sent_chunks = [m for m in chan.sent if m.get("t") == "FILE_CDC_CHUNK"]
    row = state.list_transfers(limit=1)[0]

    assert result["chunks"] == 5
    assert result["raw_bytes_sent"] == f.stat().st_size
    assert result["wire_bytes_sent"] == f.stat().st_size
    assert [c["index"] for c in sent_chunks] == [0, 1, 2, 3, 4]
    assert max(chan.recv_sent_counts) >= 3
    assert row.metadata["cdc_engine"].endswith("pipelined_chunks_v3") or (
        row.metadata["cdc_engine"] == "pipelined_chunks_v2"
    )
    assert row.metadata["cdc_window_chunks"] == 2
    # Fresh peer with no transfer history: bandit hasn't yet collected
    # enough evidence to upgrade past either CONSTRAINED (reliability <
    # 0.60 default) or OBSERVING (confidence < 0.35). Both are valid
    # backoff/probe states; the regulator's exact pick depends on
    # bandit init defaults (`_regulate` in transfer_brain.py).
    assert row.metadata["pipeline_tuning"]["reason"] in (
        "observing_probe", "constrained_backoff",
    )
    assert row.metadata["transfer_report"]["wire_efficiency_ratio"] == 1.0
    assert row.metadata["adaptive_scheduler"]["ack_count"] == 5
    assert row.metadata["adaptive_scheduler"]["target_ack_ms"] == 1490.0
    assert row.metadata["adaptive_scheduler"]["timeline"][0]["event"] == "start"
    assert all(not daemon._chunk_cache_path(c["hash"]).is_file() for c in chunks)
    assert state.chunks_sourced([c["hash"] for c in chunks]) == [c["hash"] for c in chunks]
    state.close()


@pytest.mark.asyncio
async def test_send_file_cdc_ignores_stale_chunk_acks(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "home"))
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _TracingFakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    chan.peer_caps = {
        "protocol": "OL1.2",
        "features": [CHAT, FILES, FILE_CDC],
        "from": them.short_id,
        "app_version": "0.12.5",
    }
    sess = OutboundSession(
        peer_fp=them.fingerprint,
        peer=Peer(
            short_id=them.short_id, hostname="them",
            address="127.0.0.1", port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess
    monkeypatch.setattr("one_link.daemon.STREAM_MIN_CHUNK_SIZE", 2)
    monkeypatch.setattr("one_link.daemon.STREAM_PIPELINE_TARGET_BYTES", 4)
    monkeypatch.setattr("one_link.daemon.STREAM_PIPELINE_MAX_CHUNKS", 2)

    f = tmp_path / "cdc-stale-acks.bin"
    f.write_bytes(b"abcdefgh")
    chunks = []
    for i in range(4):
        start = i * 2
        data = f.read_bytes()[start:start + 2]
        chunks.append({
            "index": i,
            "start": start,
            "end": start + len(data),
            "size": len(data),
            "hash": blake3.blake3(data).hexdigest(),
        })
    state.record_file_index_cache(
        **daemon._file_cache_signature(f),
        blob_hash=blake3.blake3(f.read_bytes()).hexdigest(),
        index_kind="fixed",
        chunks=chunks,
    )
    chan.queue_reply(make_msg("FILE_WANTS", them.short_id, wants=[0, 1, 2, 3]))
    for i in range(4):
        chan.queue_reply(make_msg("ACK", them.short_id, of=f"old-chunk-{i}"))
        chan.queue_reply(make_msg("ACK", them.short_id))

    result = await daemon.send_file(sess.peer, f)

    assert result["chunks"] == 4
    assert chan._replies.qsize() == 0
    assert state.list_transfers(limit=1)[0].metadata["adaptive_scheduler"]["ack_count"] == 4
    state.close()


@pytest.mark.asyncio
async def test_send_file_cdc_uses_binary_frames_when_peer_supports_them(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "home"))
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _TracingFakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    chan.peer_caps = {
        "protocol": "OL1.2",
        "features": [CHAT, FILES, FILE_CDC, FILE_BINARY_FRAME, FILE_CDC_BINARY_FRAME],
        "from": them.short_id,
        "app_version": "0.15.1",
    }
    sess = OutboundSession(
        peer_fp=them.fingerprint,
        peer=Peer(
            short_id=them.short_id,
            hostname="them",
            address="127.0.0.1",
            port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess

    f = tmp_path / "cdc-binary.bin"
    f.write_bytes(b"0123456789abcdef")
    payload = f.read_bytes()
    chunks = [{
        "index": 0,
        "start": 0,
        "end": len(payload),
        "size": len(payload),
        "hash": blake3.blake3(payload).hexdigest(),
    }]
    state.record_file_index_cache(
        **daemon._file_cache_signature(f),
        blob_hash=blake3.blake3(payload).hexdigest(),
        index_kind="fixed",
        chunks=chunks,
    )
    chan.queue_reply(make_msg("FILE_WANTS", them.short_id, wants=[0]))
    chan.queue_reply(make_msg("ACK", them.short_id))

    result = await daemon.send_file(sess.peer, f)
    sent_chunks = [m for m in chan.sent if m.get("t") == "FILE_CDC_CHUNK"]
    row = state.list_transfers(limit=1)[0]

    assert result["cdc"] is True
    assert len(sent_chunks) == 1
    assert sent_chunks[0]["_binary_data"] == payload
    assert "data" not in sent_chunks[0]
    assert row.metadata["binary_frame"] is True
    state.close()


@pytest.mark.asyncio
async def test_send_file_cdc_keeps_json_for_stream_binary_only_peers(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "home"))
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _TracingFakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    chan.peer_caps = {
        "protocol": "OL1.2",
        "features": [CHAT, FILES, FILE_CDC, FILE_BINARY_FRAME],
        "from": them.short_id,
        "app_version": "0.15.1",
    }
    sess = OutboundSession(
        peer_fp=them.fingerprint,
        peer=Peer(
            short_id=them.short_id,
            hostname="them",
            address="127.0.0.1",
            port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess
    f = tmp_path / "cdc-json-compat.bin"
    payload = b"compat-cdc-json"
    f.write_bytes(payload)
    state.record_file_index_cache(
        **daemon._file_cache_signature(f),
        blob_hash=blake3.blake3(payload).hexdigest(),
        index_kind="fixed",
        chunks=[{
            "index": 0,
            "start": 0,
            "end": len(payload),
            "size": len(payload),
            "hash": blake3.blake3(payload).hexdigest(),
        }],
    )
    chan.queue_reply(make_msg("FILE_WANTS", them.short_id, wants=[0]))
    chan.queue_reply(make_msg("ACK", them.short_id))

    await daemon.send_file(sess.peer, f)
    sent_chunks = [m for m in chan.sent if m.get("t") == "FILE_CDC_CHUNK"]
    row = state.list_transfers(limit=1)[0]

    assert "_binary_data" not in sent_chunks[0]
    assert sent_chunks[0]["data"]
    assert row.metadata["binary_frame"] is False
    state.close()


@pytest.mark.asyncio
async def test_send_file_cdc_disables_compression_after_incompressible_chunks(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "home"))
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _TracingFakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    chan.peer_caps = {
        "protocol": "OL1.2",
        "features": [CHAT, FILES, FILE_CDC],
        "from": them.short_id,
        "app_version": "0.12.5",
    }
    sess = OutboundSession(
        peer_fp=them.fingerprint,
        peer=Peer(
            short_id=them.short_id,
            hostname="them",
            address="127.0.0.1",
            port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess

    f = tmp_path / "incompressible-video-ish.bin"
    f.write_bytes(os.urandom(5 * 4096))
    payload = f.read_bytes()
    chunks = []
    for i in range(5):
        start = i * 4096
        data = payload[start:start + 4096]
        chunks.append({
            "index": i,
            "start": start,
            "end": start + len(data),
            "size": len(data),
            "hash": blake3.blake3(data).hexdigest(),
        })
    state.record_file_index_cache(
        **daemon._file_cache_signature(f),
        blob_hash=blake3.blake3(payload).hexdigest(),
        index_kind="fixed",
        chunks=chunks,
    )
    chan.queue_reply(make_msg("FILE_WANTS", them.short_id, wants=[0, 1, 2, 3, 4]))
    for _ in range(5):
        chan.queue_reply(make_msg("ACK", them.short_id))

    import one_link.daemon as daemon_mod

    real_compress = daemon_mod.zlib.compress
    calls = 0

    def counted_compress(data, level=1):
        nonlocal calls
        calls += 1
        return real_compress(data, level=level)

    monkeypatch.setattr(daemon_mod.zlib, "compress", counted_compress)

    result = await daemon.send_file(sess.peer, f)

    assert result["chunks"] == 5
    assert result["compressed_chunks"] == 0
    assert calls == 3
    state.close()


@pytest.mark.asyncio
async def test_receive_empty_cdc_wants_schedules_finish_after_reply(
    tmp_path: Path, monkeypatch
):
    runtime_home = tmp_path / "cached-receive-home"
    monkeypatch.setenv("ONE_LINK_HOME", str(runtime_home))
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    assert daemon._resume_metadata_root == runtime_home / "data" / "transfer_resume"
    assert daemon._resume_registry.inbox_root == runtime_home / "data" / "inbox"
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    payload = b"already cached"
    chunk_hash = blake3.blake3(payload).hexdigest()
    blob = blake3.blake3(payload).hexdigest()
    daemon._store_chunk_cache(chunk_hash, payload, blob_hash=blob, chunk_index=0)
    scheduled: list[str] = []

    def _schedule(blob_hex, peer_fp, peer_sid, src_msg, *, channel=None):
        scheduled.append(blob_hex)

    monkeypatch.setattr(daemon, "_schedule_finish_cdc_file", _schedule)
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)

    await daemon._on_peer_message(
        chan,
        make_msg(
            "FILE_OFFER",
            them.short_id,
            name="cached.bin",
            size=len(payload),
            blob=blob,
            chunks=[{
                "index": 0,
                "start": 0,
                "end": len(payload),
                "size": len(payload),
                "hash": chunk_hash,
            }],
        ),
    )

    assert chan.sent[-1]["t"] == "FILE_WANTS"
    assert chan.sent[-1]["wants"] == []
    assert scheduled == [blob]
    state.close()


@pytest.mark.asyncio
async def test_receive_empty_cdc_wants_uses_durable_sources_after_cache_prune(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    payload = b"already assembled large chunk" * 8192
    source = tmp_path / "received-large.bin"
    source.write_bytes(payload)
    chunk_hash = blake3.blake3(payload).hexdigest()
    blob = chunk_hash
    state.record_chunk_source(
        chunk_hash,
        path=str(source),
        start=0,
        size=len(payload),
        mtime_ms=int(source.stat().st_mtime * 1000),
        file_size=source.stat().st_size,
        source="received_cdc",
    )
    assert not daemon._chunk_cache_path(chunk_hash).is_file()
    scheduled: list[str] = []
    monkeypatch.setattr(
        daemon,
        "_schedule_finish_cdc_file",
        lambda blob_hex, *_args, **_kwargs: scheduled.append(blob_hex),
    )
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)

    await daemon._on_peer_message(
        chan,
        make_msg(
            "FILE_OFFER",
            them.short_id,
            name="repeat-large.bin",
            size=len(payload),
            blob=blob,
            chunks=[{
                "index": 0,
                "start": 0,
                "end": len(payload),
                "size": len(payload),
                "hash": chunk_hash,
            }],
        ),
    )

    assert chan.sent[-1]["t"] == "FILE_WANTS"
    assert chan.sent[-1]["wants"] == []
    assert scheduled == [blob]
    assert daemon._chunk_cache_path(chunk_hash).is_file()
    assert daemon._read_chunk_cache(chunk_hash) == payload
    state.close()


@pytest.mark.asyncio
async def test_cdc_finalize_cache_miss_re_requests_and_surfaces_paused_state(
    tmp_path: Path,
    monkeypatch,
):
    """Eviction between FILE_WANTS=[] and assembly is recoverable, not silent."""

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "home"))
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    cached = b"cache-still-present"
    evicted = b"cache-evicted-before-finalize"
    payload = cached + evicted
    blob = blake3.blake3(payload).hexdigest()
    cached_hash = blake3.blake3(cached).hexdigest()
    evicted_hash = blake3.blake3(evicted).hexdigest()
    daemon._store_chunk_cache(cached_hash, cached, blob_hash=blob, chunk_index=0)

    out_path = tmp_path / "cache-race.partial"
    handle = open(out_path, "x+b")
    handle.truncate(len(payload))
    transfer_id = f"in:{blob}"
    chunks = [
        {
            "index": 0,
            "start": 0,
            "end": len(cached),
            "size": len(cached),
            "hash": cached_hash,
        },
        {
            "index": 1,
            "start": len(cached),
            "end": len(payload),
            "size": len(evicted),
            "hash": evicted_hash,
        },
    ]
    daemon._incoming_files[blob] = IncomingFile(
        name="cache-race.bin",
        size=len(payload),
        blob_hex=blob,
        out_path=out_path,
        handle=handle,
        hasher=blake3.blake3(),
        cdc_chunks=chunks,
        # The offer-time cache check believed both indices were available.
        cdc_missing=set(),
        cdc_parts={},
        cdc_done_bytes=len(payload),
        transfer_id=transfer_id,
        acceptance_granted=True,
    )
    state.upsert_transfer(
        id=transfer_id,
        direction="in",
        peer_fp=them.fingerprint,
        kind="file",
        name="cache-race.bin",
        size=len(payload),
        blob_hash=blob,
        status="active",
        progress_bytes=len(payload),
        total_bytes=len(payload),
        chunks_done=2,
        chunks_total=2,
        metadata={"mode": "cdc", "path": str(out_path)},
    )
    channel = _FakeChannel(
        peer_ed_pub=them.public_bytes,
        peer_short_id=them.short_id,
    )
    source_offer = make_msg(
        "FILE_OFFER",
        them.short_id,
        id="offer-cache-race",
        blob=blob,
    )

    await daemon._finish_cdc_file(
        blob,
        them.fingerprint,
        them.short_id,
        source_offer,
        channel=channel,  # type: ignore[arg-type]
    )

    incoming = daemon._incoming_files[blob]
    assert incoming.cdc_missing == {1}
    assert incoming.cdc_done_bytes == len(cached)
    assert not incoming.handle.closed
    incoming.handle.seek(0)
    assert incoming.handle.read(len(cached)) == cached
    recovery = channel.sent[-1]
    assert recovery["t"] == "FILE_WANTS"
    assert recovery["of"] == "offer-cache-race"
    assert recovery["wants"] == [1]
    assert recovery["recovery"] == "cache_miss_during_finalize"
    row = state.get_transfer(transfer_id)
    assert row is not None
    assert row.status == "paused"
    assert row.progress_bytes == len(cached)
    assert row.metadata["delivery_state"] == "recovering_cache_miss"
    assert row.metadata["error_class"] == "ChunkCacheMiss"

    incoming.handle.close()
    state.close()


@pytest.mark.asyncio
async def test_file_offer_absurd_size_is_rejected_before_opening_file(
    tmp_path: Path,
):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    blob = "a" * 64

    await daemon._on_peer_message(
        chan,
        make_msg(
            "FILE_OFFER",
            them.short_id,
            name="10000tb.bin",
            size=10_000 * 1024 * 1024 * 1024 * 1024,
            blob=blob,
            chunks=[],
        ),
    )

    assert chan.sent[-1]["t"] == "ACK"
    assert chan.sent[-1]["rejected"] == "admission_declared_size_too_large"
    assert not any(tmp_path.glob("*10000tb.bin"))
    row = state.get_transfer(f"in:{blob}")
    assert row is not None
    assert row.status == "failed"
    assert row.metadata["delivery_state"] == "blocked"
    state.close()


@pytest.mark.asyncio
async def test_huge_stream_offer_requires_resumable_chunk_map(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    daemon._transfer_admission_policy = daemon._transfer_admission_policy.__class__(
        max_declared_bytes=2 * 1024 * 1024 * 1024,
        min_free_reserve_bytes=0,
        free_reserve_ratio=0,
    )
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    blob = "b" * 64

    await daemon._on_peer_message(
        chan,
        make_msg(
            "FILE_OFFER",
            them.short_id,
            name="large-stream.bin",
            size=1024 * 1024 * 1024 + 1,
            blob=blob,
        ),
    )

    assert chan.sent[-1]["rejected"] == "admission_stream_offer_too_large"
    assert not any(tmp_path.glob("*large-stream.bin"))
    state.close()


@pytest.mark.asyncio
async def test_file_offer_malformed_size_is_rejected_not_raised(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    blob = "c" * 64

    await daemon._on_peer_message(
        chan,
        make_msg(
            "FILE_OFFER",
            them.short_id,
            name="bad-size.bin",
            size="not-a-number",
            blob=blob,
        ),
    )

    assert chan.sent[-1]["t"] == "ACK"
    assert chan.sent[-1]["rejected"] == "admission_invalid_size"
    assert state.get_transfer(f"in:{blob}").metadata["delivery_state"] == "blocked"
    state.close()


@pytest.mark.asyncio
async def test_file_offer_rejects_coercible_size_spoofs(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)

    for spoofed in (True, 1.5, "1"):
        await daemon._on_peer_message(
            chan,
            make_msg(
                "FILE_OFFER",
                them.short_id,
                name="coercible-size.bin",
                size=spoofed,
                blob=secrets.token_hex(32),
            ),
        )
        assert chan.sent[-1]["rejected"] == "admission_invalid_size"

    assert daemon._transfer_reservation_ledger().snapshot() == ()
    state.close()


@pytest.mark.asyncio
async def test_file_offer_global_reservation_released_on_abort(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _new_identity()
    first_peer = _new_identity()
    second_peer = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    for peer in (first_peer, second_peer):
        state.upsert_peer(
            fingerprint=peer.fingerprint,
            short_id=peer.short_id,
            pubkey=peer.public_bytes,
        )
        state.set_peer_trust(peer.fingerprint, "pinned")
    daemon._transfer_admission_policy = daemon._transfer_admission_policy.__class__(
        min_free_reserve_bytes=0,
        free_reserve_ratio=0,
        max_active_inbound_transfers_per_peer=3,
        max_active_inbound_bytes_per_peer=1024,
        max_active_inbound_transfers=1,
        max_active_inbound_bytes=1024,
    )
    first_chan = _FakeChannel(
        peer_ed_pub=first_peer.public_bytes,
        peer_short_id=first_peer.short_id,
    )
    second_chan = _FakeChannel(
        peer_ed_pub=second_peer.public_bytes,
        peer_short_id=second_peer.short_id,
    )
    first_blob = blake3.blake3(b"a").hexdigest()
    second_blob = blake3.blake3(b"b").hexdigest()

    await daemon._on_peer_message(
        first_chan,
        make_msg(
            "FILE_OFFER", first_peer.short_id,
            name="first.bin", size=1, blob=first_blob,
        ),
    )
    assert first_chan.sent[-1]["t"] == "ACK"
    assert len(daemon._transfer_reservation_ledger().snapshot()) == 1

    second_offer = make_msg(
        "FILE_OFFER", second_peer.short_id,
        name="second.bin", size=1, blob=second_blob,
    )
    await daemon._on_peer_message(second_chan, second_offer)
    assert second_chan.sent[-1]["rejected"] == (
        "admission_global_inbound_transfer_quota"
    )

    first = daemon._incoming_files[first_blob]
    daemon._abort_incoming_file(first_blob, first)
    assert daemon._transfer_reservation_ledger().snapshot() == ()

    await daemon._on_peer_message(second_chan, second_offer)
    assert second_chan.sent[-1]["t"] == "ACK"
    second = daemon._incoming_files[second_blob]
    daemon._abort_incoming_file(second_blob, second)
    assert daemon._transfer_reservation_ledger().snapshot() == ()
    state.close()


@pytest.mark.asyncio
async def test_inbound_reservation_released_when_disk_write_fails(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    daemon._transfer_admission_policy = daemon._transfer_admission_policy.__class__(
        min_free_reserve_bytes=0,
        free_reserve_ratio=0,
    )
    channel = _FakeChannel(
        peer_ed_pub=them.public_bytes,
        peer_short_id=them.short_id,
    )
    payload = b"write failure"
    blob = blake3.blake3(payload).hexdigest()
    await daemon._on_peer_message(
        channel,
        make_msg(
            "FILE_OFFER", them.short_id,
            name="write-fail.bin", size=len(payload), blob=blob,
        ),
    )
    incoming = daemon._incoming_files[blob]
    incoming.handle.close()

    class _FailingHandle:
        def write(self, _data):
            raise OSError("simulated disk full")

        def close(self):
            return None

    incoming.handle = _FailingHandle()  # type: ignore[assignment]

    await daemon._on_peer_message(
        channel,
        make_msg(
            "FILE_CHUNK",
            them.short_id,
            blob=blob,
            seq=0,
            data=base64.b64encode(payload).decode("ascii"),
            eof=True,
        ),
    )

    assert channel.sent[-1]["rejected"] == "receiver_disk_write_failed"
    assert blob not in daemon._incoming_files
    assert daemon._transfer_reservation_ledger().snapshot() == ()
    state.close()


@pytest.mark.asyncio
async def test_inbound_blob_owner_cannot_be_hijacked_for_quota_or_chunks(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _new_identity()
    owner = _new_identity()
    interloper = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    for peer in (owner, interloper):
        state.upsert_peer(
            fingerprint=peer.fingerprint,
            short_id=peer.short_id,
            pubkey=peer.public_bytes,
        )
        state.set_peer_trust(peer.fingerprint, "pinned")
    daemon._transfer_admission_policy = daemon._transfer_admission_policy.__class__(
        min_free_reserve_bytes=0,
        free_reserve_ratio=0,
    )
    owner_channel = _FakeChannel(
        peer_ed_pub=owner.public_bytes,
        peer_short_id=owner.short_id,
    )
    interloper_channel = _FakeChannel(
        peer_ed_pub=interloper.public_bytes,
        peer_short_id=interloper.short_id,
    )
    payload = b"owner-bound"
    blob = blake3.blake3(payload).hexdigest()
    await daemon._on_peer_message(
        owner_channel,
        make_msg(
            "FILE_OFFER", owner.short_id,
            name="owned.bin", size=len(payload), blob=blob,
        ),
    )

    await daemon._on_peer_message(
        interloper_channel,
        make_msg(
            "FILE_OFFER", interloper.short_id,
            name="same-hash.bin", size=len(payload), blob=blob,
        ),
    )
    assert interloper_channel.sent[-1]["rejected"] == (
        "admission_blob_in_use_by_another_peer"
    )
    await daemon._on_peer_message(
        interloper_channel,
        make_msg(
            "FILE_CHUNK",
            interloper.short_id,
            blob=blob,
            seq=0,
            data=base64.b64encode(payload).decode("ascii"),
            eof=True,
        ),
    )
    assert interloper_channel.sent[-1]["rejected"] == (
        "file_transfer_owner_mismatch"
    )
    assert daemon._incoming_files[blob].peer_fp == owner.fingerprint
    reservations = daemon._transfer_reservation_ledger().snapshot()
    assert len(reservations) == 1
    assert reservations[0].peer_fp == owner.fingerprint
    daemon._abort_incoming_file(blob, daemon._incoming_files[blob])
    state.close()


@pytest.mark.asyncio
async def test_stream_offer_retry_reuses_empty_writer_then_restarts_without_leak(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    daemon._transfer_admission_policy = daemon._transfer_admission_policy.__class__(
        min_free_reserve_bytes=0,
        free_reserve_ratio=0,
    )
    channel = _FakeChannel(
        peer_ed_pub=them.public_bytes,
        peer_short_id=them.short_id,
    )
    payload = b"restart a legacy stream safely"
    first_part = payload[:11]
    blob = blake3.blake3(payload).hexdigest()

    def _offer(name: str = "original.bin") -> dict:
        return make_msg(
            "FILE_OFFER",
            them.short_id,
            name=name,
            size=len(payload),
            blob=blob,
        )

    await daemon._on_peer_message(channel, _offer())
    initial = daemon._incoming_files[blob]
    initial_path = initial.out_path
    inbound_transfer_id = initial.transfer_id

    # A retry before byte zero is the same transfer and must not allocate a
    # second path/handle or accept a sender-provided rename.
    await daemon._on_peer_message(channel, _offer())
    assert daemon._incoming_files[blob] is initial
    assert daemon._incoming_files[blob].name == "original.bin"
    assert len(daemon._transfer_reservation_ledger().snapshot()) == 1

    await daemon._on_peer_message(
        channel,
        make_msg(
            "FILE_CHUNK",
            them.short_id,
            blob=blob,
            seq=0,
            data=base64.b64encode(first_part).decode("ascii"),
            eof=False,
        ),
    )
    before_retry = daemon._transfer_reservation_ledger().get(inbound_transfer_id)
    assert before_retry is not None
    assert before_retry.remaining_bytes == len(payload) - len(first_part)

    # Legacy stream mode has no offset manifest. A reconnect after progress
    # restarts from zero, closes and removes the superseded partial, and
    # restores a full reservation for the replacement writer.
    await daemon._on_peer_message(channel, _offer())
    replacement = daemon._incoming_files[blob]
    assert replacement is not initial
    assert replacement.name == "original.bin"
    assert initial.handle.closed
    assert not initial_path.exists()
    reservation = daemon._transfer_reservation_ledger().get(inbound_transfer_id)
    assert reservation is not None
    assert reservation.remaining_bytes == len(payload)

    await daemon._on_peer_message(
        channel,
        make_msg(
            "FILE_CHUNK",
            them.short_id,
            blob=blob,
            seq=0,
            data=base64.b64encode(payload).decode("ascii"),
            eof=True,
        ),
    )
    assert blob not in daemon._incoming_files
    assert replacement.out_path.read_bytes() == payload
    assert daemon._transfer_reservation_ledger().snapshot() == ()
    state.close()


@pytest.mark.asyncio
async def test_cached_chunks_cannot_spoof_destination_disk_reservation(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    monkeypatch.setattr(
        "one_link.transfer_safety._disk_free_bytes",
        lambda _path: 100,
    )
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    daemon._transfer_admission_policy = daemon._transfer_admission_policy.__class__(
        min_free_reserve_bytes=10,
        free_reserve_ratio=0,
    )
    payload = b"x" * 100
    blob = blake3.blake3(payload).hexdigest()
    daemon._store_chunk_cache(blob, payload, blob_hash=blob, chunk_index=0)
    channel = _FakeChannel(
        peer_ed_pub=them.public_bytes,
        peer_short_id=them.short_id,
    )

    await daemon._on_peer_message(
        channel,
        make_msg(
            "FILE_OFFER",
            them.short_id,
            name="cache-hit.bin",
            size=len(payload),
            blob=blob,
            chunks=[{
                "index": 0,
                "start": 0,
                "end": len(payload),
                "size": len(payload),
                "hash": blob,
            }],
        ),
    )

    assert channel.sent[-1]["rejected"] == "admission_insufficient_disk_space"
    assert blob not in daemon._incoming_files
    assert daemon._transfer_reservation_ledger().snapshot() == ()
    state.close()


@pytest.mark.asyncio
async def test_cdc_admission_reserves_and_consumes_cache_plus_output(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    daemon._transfer_admission_policy = daemon._transfer_admission_policy.__class__(
        min_free_reserve_bytes=0,
        free_reserve_ratio=0,
    )
    monkeypatch.setattr(daemon, "_schedule_finish_cdc_file", lambda *_a, **_k: None)
    payload = b"cache and destination"
    blob = blake3.blake3(payload).hexdigest()
    channel = _FakeChannel(
        peer_ed_pub=them.public_bytes,
        peer_short_id=them.short_id,
    )
    await daemon._on_peer_message(
        channel,
        make_msg(
            "FILE_OFFER",
            them.short_id,
            name="dual.bin",
            size=len(payload),
            blob=blob,
            chunks=[{
                "index": 0,
                "start": 0,
                "end": len(payload),
                "size": len(payload),
                "hash": blob,
            }],
        ),
    )
    reservation = daemon._transfer_reservation_ledger().snapshot()[0]
    assert reservation.remaining_bytes == 2 * len(payload)

    await daemon._on_peer_message(
        channel,
        make_msg(
            "FILE_CDC_CHUNK",
            them.short_id,
            blob=blob,
            index=0,
            data=base64.b64encode(payload).decode("ascii"),
        ),
    )

    reservation = daemon._transfer_reservation_ledger().snapshot()[0]
    assert reservation.remaining_bytes == 0
    daemon._abort_incoming_file(blob, daemon._incoming_files[blob])
    state.close()


@pytest.mark.asyncio
async def test_cdc_cache_eviction_atomically_expands_storage_promise(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    daemon._transfer_admission_policy = daemon._transfer_admission_policy.__class__(
        min_free_reserve_bytes=0,
        free_reserve_ratio=0,
    )
    monkeypatch.setattr(daemon, "_schedule_finish_cdc_file", lambda *_a, **_k: None)
    payload = b"evicted after offer"
    blob = blake3.blake3(payload).hexdigest()
    daemon._store_chunk_cache(blob, payload, blob_hash=blob, chunk_index=0)
    channel = _FakeChannel(
        peer_ed_pub=them.public_bytes,
        peer_short_id=them.short_id,
    )
    offer = make_msg(
        "FILE_OFFER",
        them.short_id,
        id="eviction-offer",
        name="eviction.bin",
        size=len(payload),
        blob=blob,
        chunks=[{
            "index": 0,
            "start": 0,
            "end": len(payload),
            "size": len(payload),
            "hash": blob,
        }],
    )
    await daemon._on_peer_message(channel, offer)
    assert daemon._transfer_reservation_ledger().snapshot()[0].remaining_bytes == (
        len(payload)
    )
    daemon._chunk_cache_path(blob).unlink()

    await daemon._finish_cdc_file(
        blob,
        them.fingerprint,
        them.short_id,
        offer,
        channel=channel,  # type: ignore[arg-type]
    )

    incoming = daemon._incoming_files[blob]
    assert incoming.cdc_missing == {0}
    assert daemon._transfer_reservation_ledger().snapshot()[0].remaining_bytes == (
        2 * len(payload)
    )
    assert channel.sent[-1]["t"] == "FILE_WANTS"
    assert channel.sent[-1]["wants"] == [0]
    daemon._abort_incoming_file(blob, incoming)
    state.close()


@pytest.mark.asyncio
async def test_cdc_uses_independent_ledgers_for_separate_cache_volume(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    monkeypatch.setattr("one_link.daemon.same_storage_volume", lambda *_a: False)
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    daemon._transfer_admission_policy = daemon._transfer_admission_policy.__class__(
        min_free_reserve_bytes=0,
        free_reserve_ratio=0,
    )
    monkeypatch.setattr(daemon, "_schedule_finish_cdc_file", lambda *_a, **_k: None)
    payload = b"two physical volumes"
    blob = blake3.blake3(payload).hexdigest()
    channel = _FakeChannel(
        peer_ed_pub=them.public_bytes,
        peer_short_id=them.short_id,
    )
    await daemon._on_peer_message(
        channel,
        make_msg(
            "FILE_OFFER",
            them.short_id,
            name="split-volume.bin",
            size=len(payload),
            blob=blob,
            chunks=[{
                "index": 0,
                "start": 0,
                "end": len(payload),
                "size": len(payload),
                "hash": blob,
            }],
        ),
    )
    primary = daemon._transfer_reservation_ledger()
    cache = daemon._cache_reservation_ledger()
    assert cache is not primary
    assert primary.snapshot()[0].remaining_bytes == len(payload)
    assert cache.snapshot()[0].remaining_bytes == len(payload)

    await daemon._on_peer_message(
        channel,
        make_msg(
            "FILE_CDC_CHUNK",
            them.short_id,
            blob=blob,
            index=0,
            data=base64.b64encode(payload).decode("ascii"),
        ),
    )
    assert primary.snapshot()[0].remaining_bytes == 0
    assert cache.snapshot()[0].remaining_bytes == 0
    daemon._abort_incoming_file(blob, daemon._incoming_files[blob])
    assert primary.snapshot() == ()
    assert cache.snapshot() == ()
    state.close()


@pytest.mark.asyncio
async def test_cache_volume_admission_failure_rolls_back_inbox_promise(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    monkeypatch.setattr("one_link.daemon.same_storage_volume", lambda *_a: False)
    monkeypatch.setattr(
        "one_link.transfer_safety._disk_free_bytes",
        lambda path: 0 if Path(path).name == "file_chunks" else 1_000_000,
    )
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    daemon._transfer_admission_policy = daemon._transfer_admission_policy.__class__(
        min_free_reserve_bytes=0,
        free_reserve_ratio=0,
    )
    payload = b"cache disk full"
    blob = blake3.blake3(payload).hexdigest()
    channel = _FakeChannel(
        peer_ed_pub=them.public_bytes,
        peer_short_id=them.short_id,
    )

    await daemon._on_peer_message(
        channel,
        make_msg(
            "FILE_OFFER",
            them.short_id,
            name="cache-full.bin",
            size=len(payload),
            blob=blob,
            chunks=[{
                "index": 0,
                "start": 0,
                "end": len(payload),
                "size": len(payload),
                "hash": blob,
            }],
        ),
    )

    assert channel.sent[-1]["rejected"] == "admission_insufficient_disk_space"
    assert blob not in daemon._incoming_files
    assert daemon._transfer_reservation_ledger().snapshot() == ()
    assert daemon._cache_reservation_ledger().snapshot() == ()
    state.close()


@pytest.mark.asyncio
async def test_file_offer_malformed_chunk_map_is_rejected_not_stream_downgraded(
    tmp_path: Path,
):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    blob = "d" * 64

    await daemon._on_peer_message(
        chan,
        make_msg(
            "FILE_OFFER",
            them.short_id,
            name="bad-map.bin",
            size=1024,
            blob=blob,
            chunks=[{"hash": "e" * 64, "start": "nope", "end": 10, "size": 10}],
        ),
    )

    assert chan.sent[-1]["t"] == "ACK"
    assert chan.sent[-1]["rejected"] == "admission_invalid_chunk_map"
    assert blob not in daemon._incoming_files
    row = state.get_transfer(f"in:{blob}")
    assert row.status == "failed"
    assert row.metadata["error"] == "invalid_chunk_map"
    state.close()


@pytest.mark.asyncio
async def test_bad_cdc_chunk_is_rejected_and_partial_file_removed(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    daemon._transfer_admission_policy = daemon._transfer_admission_policy.__class__(
        min_free_reserve_bytes=0,
        free_reserve_ratio=0,
    )
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    chunk = b"verified piece"
    chunk_hash = blake3.blake3(chunk).hexdigest()
    blob = blake3.blake3(chunk).hexdigest()

    await daemon._on_peer_message(
        chan,
        make_msg(
            "FILE_OFFER",
            them.short_id,
            name="cdc.bin",
            size=len(chunk),
            blob=blob,
            chunks=[{
                "hash": chunk_hash,
                "start": 0,
                "end": len(chunk),
                "size": len(chunk),
            }],
        ),
    )
    assert chan.sent[-1]["t"] == "FILE_WANTS"
    assert blob in daemon._incoming_files
    inbound_transfer_id = daemon._incoming_files[blob].transfer_id

    await daemon._on_peer_message(
        chan,
        make_msg(
            "FILE_CDC_CHUNK",
            them.short_id,
            blob=blob,
            index="not-an-index",
            data="",
        ),
    )

    assert chan.sent[-1]["t"] == "ACK"
    assert chan.sent[-1]["rejected"] == "bad_cdc_chunk_index"
    assert blob not in daemon._incoming_files
    assert state.get_transfer(inbound_transfer_id).status == "failed"
    state.close()


@pytest.mark.asyncio
async def test_send_file_stream_pipelines_bounded_ack_window(
    tmp_path: Path, monkeypatch
):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _TracingFakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    chan.peer_caps = {
        "protocol": "OL1.2",
        "features": [CHAT, FILES],
        "from": them.short_id,
        "app_version": "0.11.2",
    }
    sess = OutboundSession(
        peer_fp=them.fingerprint, peer=Peer(
            short_id=them.short_id, hostname="them",
            address="127.0.0.1", port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess
    monkeypatch.setattr("one_link.daemon.STREAM_MIN_CHUNK_SIZE", 2)
    monkeypatch.setattr("one_link.daemon.STREAM_PIPELINE_TARGET_BYTES", 6)
    monkeypatch.setattr("one_link.daemon.STREAM_PIPELINE_MAX_CHUNKS", 3)

    f = tmp_path / "pipeline.bin"
    f.write_bytes(b"0123456789")
    chan.queue_reply(make_msg("ACK", them.short_id))  # offer ACK
    for _ in range(5):
        chan.queue_reply(make_msg("ACK", them.short_id))

    result = await daemon.send_file(sess.peer, f)
    chunks = [m for m in chan.sent if m.get("t") == "FILE_CHUNK"]
    row = state.list_transfers(limit=1)[0]

    assert result["chunks"] == 5
    assert [c["seq"] for c in chunks] == [0, 1, 2, 3, 4]
    assert max(chan.recv_sent_counts) >= 3  # offer + conservative probe window before ACK drain
    assert row.metadata["stream_engine"] == "pipelined_json_v1"
    assert row.metadata["stream_window_chunks"] == 2
    # Fresh peer with no transfer history: bandit hasn't yet collected
    # enough evidence to upgrade past either CONSTRAINED (reliability <
    # 0.60 default) or OBSERVING (confidence < 0.35). Both are valid
    # backoff/probe states; the regulator's exact pick depends on
    # bandit init defaults (`_regulate` in transfer_brain.py).
    assert row.metadata["pipeline_tuning"]["reason"] in (
        "observing_probe", "constrained_backoff",
    )
    assert row.metadata["adaptive_scheduler"]["ack_count"] == 5
    assert row.metadata["adaptive_scheduler"]["timeline"][0]["event"] == "start"
    state.close()


@pytest.mark.asyncio
async def test_native_stream_clamps_adaptive_chunks_and_metadata_to_aead_limit(
    tmp_path: Path,
    monkeypatch,
):
    """A multi-MiB adaptive profile cannot overflow a native AEAD record."""

    from one_link.native_transfer import MAX_CHUNK_PLAINTEXT_LEN

    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    class _NativeRecorder:
        def __init__(self) -> None:
            self.plaintext_lengths: list[int] = []

        def encrypt_chunk_bytes(self, data: bytes, *, address_kind: str):
            assert address_kind in {"raw", "convergent"}
            # This assertion is the native envelope's production contract.
            assert len(data) <= MAX_CHUNK_PLAINTEXT_LEN
            index = len(self.plaintext_lengths)
            self.plaintext_lengths.append(len(data))
            return SimpleNamespace(
                chunk_index=index,
                chunk_id=bytes([index + 1]) * 32,
                plaintext_len=len(data),
                ciphertext=b"encrypted:" + data,
            )

    native_session = _NativeRecorder()
    channel = _TracingFakeChannel(
        peer_ed_pub=them.public_bytes,
        peer_short_id=them.short_id,
    )
    channel.peer_caps = {
        "protocol": "OL1.2",
        "features": [CHAT, FILES, NATIVE_TRANSFER_INDEXED_V1],
        "from": them.short_id,
        "app_version": "0.21.0",
    }
    channel.get_or_create_native_transfer_session = lambda: native_session  # type: ignore[attr-defined]
    session = OutboundSession(
        peer_fp=them.fingerprint,
        peer=Peer(
            short_id=them.short_id,
            hostname="them",
            address="127.0.0.1",
            port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=channel,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = session
    monkeypatch.setattr(
        "one_link.daemon.adapt_pipeline_profile",
        lambda _profile, _decision: {
            "chunk_size": 1024 * 1024,
            "window_chunks": 2,
            "window_bytes": 2 * 1024 * 1024,
            "reason": "test_oversized_native_profile",
        },
    )

    source = tmp_path / "native-profile.bin"
    source.write_bytes(os.urandom(MAX_CHUNK_PLAINTEXT_LEN * 2 + 17))
    channel.queue_reply(make_msg("ACK", them.short_id))
    for _ in range(3):
        channel.queue_reply(make_msg("ACK", them.short_id))

    result = await daemon.send_file(session.peer, source)

    native_chunks = [
        frame for frame in channel.sent
        if frame.get("t") == "FILE_NATIVE_CHUNK"
    ]
    assert result["chunks"] == 3
    assert native_session.plaintext_lengths == [
        MAX_CHUNK_PLAINTEXT_LEN,
        MAX_CHUNK_PLAINTEXT_LEN,
        17,
    ]
    assert [frame["plaintext_len"] for frame in native_chunks] == (
        native_session.plaintext_lengths
    )
    row = state.list_transfers(limit=1)[0]
    tuning = row.metadata["pipeline_tuning"]
    assert row.metadata["stream_chunk_size"] == MAX_CHUNK_PLAINTEXT_LEN
    assert tuning["chunk_size"] == MAX_CHUNK_PLAINTEXT_LEN
    assert tuning["native_chunk_max_bytes"] == MAX_CHUNK_PLAINTEXT_LEN
    assert tuning["native_chunk_size_capped"] is True
    assert tuning["window_bytes"] == (
        tuning["window_chunks"] * tuning["chunk_size"]
    )
    assert row.metadata["stream_window_bytes"] == tuning["window_bytes"]
    state.close()


@pytest.mark.asyncio
async def test_send_file_accepts_batched_chunk_acks_for_capable_peer(
    tmp_path: Path, monkeypatch
):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _BatchAckFakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    chan.peer_caps = {
        "protocol": "OL1.2",
        "features": [CHAT, FILES, FILE_ACK_BATCH],
        "from": them.short_id,
        "app_version": "0.12.0",
    }
    sess = OutboundSession(
        peer_fp=them.fingerprint,
        peer=Peer(
            short_id=them.short_id,
            hostname="them",
            address="127.0.0.1",
            port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess
    monkeypatch.setattr("one_link.daemon.STREAM_MIN_CHUNK_SIZE", 2)
    monkeypatch.setattr("one_link.daemon.STREAM_PIPELINE_TARGET_BYTES", 6)
    monkeypatch.setattr("one_link.daemon.STREAM_PIPELINE_MAX_CHUNKS", 3)
    monkeypatch.setattr(
        "one_link.daemon.build_transfer_autopilot_plan",
        lambda **_kw: SimpleNamespace(to_dict=lambda: {
            "ack_batch": 4,
            "frame_kind": "json",
            "retry_posture": "auto_resume",
            "estimated_savings_ratio": 0.0,
            "reasons": ["test_ack_batch"],
        }),
    )

    f = tmp_path / "batch-send.bin"
    f.write_bytes(b"abcdef")
    chan.queue_reply(make_msg("ACK", them.short_id))

    result = await daemon.send_file(sess.peer, f)
    chunks = [m for m in chan.sent if m.get("t") == "FILE_CHUNK"]
    row = state.list_transfers(limit=1)[0]

    assert result["chunks"] == 3
    assert [c["seq"] for c in chunks] == [0, 1, 2]
    assert [c.get("ack_batch") for c in chunks] == [2, 2, None]
    assert row.metadata["ack_batch"] == 4
    assert row.metadata["adaptive_scheduler"]["ack_count"] == 3
    state.close()


@pytest.mark.asyncio
async def test_send_file_uses_binary_stream_for_capable_peer(
    tmp_path: Path, monkeypatch
):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _TracingFakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    chan.peer_caps = {
        "protocol": "OL1.2",
        "features": [CHAT, FILES, FILE_BINARY_FRAME],
        "from": them.short_id,
        "app_version": "0.11.6",
    }
    sess = OutboundSession(
        peer_fp=them.fingerprint,
        peer=Peer(
            short_id=them.short_id, hostname="them",
            address="127.0.0.1", port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess
    monkeypatch.setattr("one_link.daemon.STREAM_MIN_CHUNK_SIZE", 4)
    monkeypatch.setattr("one_link.daemon.STREAM_PIPELINE_TARGET_BYTES", 8)
    monkeypatch.setattr("one_link.daemon.STREAM_PIPELINE_MAX_CHUNKS", 2)

    f = tmp_path / "binary-stream.bin"
    f.write_bytes(b"abcdefghij")
    chan.queue_reply(make_msg("ACK", them.short_id))
    for _ in range(3):
        chan.queue_reply(make_msg("ACK", them.short_id))

    result = await daemon.send_file(sess.peer, f)
    chunks = [m for m in chan.sent if m.get("t") == "FILE_BIN_CHUNK"]
    row = state.list_transfers(limit=1)[0]

    assert result["chunks"] == 3
    assert [c["seq"] for c in chunks] == [0, 1, 2]
    assert b"".join(c["_binary_data"] for c in chunks) == b"abcdefghij"
    assert all("data" not in c for c in chunks)
    assert row.metadata["stream_engine"] == "pipelined_binary_v1"
    assert row.metadata["actual_method"] == "file_binary_frame"
    state.close()


@pytest.mark.asyncio
async def test_stream_receiver_acks_final_chunk_before_cache_warm(
    tmp_path: Path, monkeypatch
):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    content = b"final ack must not wait for chunk cache"
    blob = blake3.blake3(content).hexdigest()
    out_path = tmp_path / "received.bin"
    transfer_id = "in:test-final-ack"
    state.upsert_transfer(
        id=transfer_id,
        direction="in",
        peer_fp=them.fingerprint,
        kind="file",
        name=out_path.name,
        size=len(content),
        blob_hash=blob,
        status="offered",
        progress_bytes=0,
        total_bytes=len(content),
        chunks_done=0,
        chunks_total=1,
        metadata={"mode": "stream", "path": str(out_path)},
    )
    daemon._incoming_files[blob] = IncomingFile(
        name=out_path.name,
        size=len(content),
        blob_hex=blob,
        out_path=out_path,
        handle=open(out_path, "wb"),
        hasher=blake3.blake3(),
        transfer_id=transfer_id,
    )
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    cache_checked: list[bool] = []

    def _cache_after_ack(path: Path, **_kwargs) -> None:
        assert any(
            m.get("t") == "ACK" and m.get("of") == "final-chunk"
            for m in chan.sent
        )
        cache_checked.append(True)

    monkeypatch.setattr(daemon, "_cache_file_chunks", _cache_after_ack)
    await daemon._on_peer_message(
        chan,
        make_msg(
            "FILE_CHUNK",
            them.short_id,
            id="final-chunk",
            blob=blob,
            seq=0,
            data=base64.b64encode(content).decode("ascii"),
            eof=True,
        ),
    )

    assert cache_checked == [True]
    assert chan.sent[-1]["t"] == "ACK"
    assert state.get_transfer(transfer_id).status == "complete"
    state.close()


@pytest.mark.asyncio
async def test_binary_stream_receiver_writes_raw_payload_and_acks(
    tmp_path: Path, monkeypatch
):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    content = b"raw payload no base64"
    blob = blake3.blake3(content).hexdigest()
    out_path = tmp_path / "binary-received.bin"
    transfer_id = "in:test-binary-final"
    state.upsert_transfer(
        id=transfer_id,
        direction="in",
        peer_fp=them.fingerprint,
        kind="file",
        name=out_path.name,
        size=len(content),
        blob_hash=blob,
        status="offered",
        progress_bytes=0,
        total_bytes=len(content),
        chunks_done=0,
        chunks_total=1,
        metadata={"mode": "stream", "path": str(out_path)},
    )
    daemon._incoming_files[blob] = IncomingFile(
        name=out_path.name,
        size=len(content),
        blob_hex=blob,
        out_path=out_path,
        handle=open(out_path, "wb"),
        hasher=blake3.blake3(),
        transfer_id=transfer_id,
    )
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    monkeypatch.setattr(
        daemon, "_cache_file_chunks", lambda path, **_kwargs: None,
    )

    await daemon._on_peer_message(
        chan,
        {
            **make_msg(
                "FILE_BIN_CHUNK",
                them.short_id,
                id="binary-final",
                blob=blob,
                seq=0,
                eof=True,
            ),
            "_binary_data": content,
        },
    )

    assert out_path.read_bytes() == content
    assert chan.sent[-1]["t"] == "ACK"
    assert chan.sent[-1]["of"] == "binary-final"
    assert state.get_transfer(transfer_id).status == "complete"
    state.close()


@pytest.mark.asyncio
async def test_stream_receiver_batches_chunk_acks_when_sender_opts_in(
    tmp_path: Path, monkeypatch
):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chunks = [b"aa", b"bb", b"cc"]
    content = b"".join(chunks)
    blob = blake3.blake3(content).hexdigest()
    out_path = tmp_path / "batched-received.bin"
    transfer_id = "in:test-batched-acks"
    state.upsert_transfer(
        id=transfer_id,
        direction="in",
        peer_fp=them.fingerprint,
        kind="file",
        name=out_path.name,
        size=len(content),
        blob_hash=blob,
        status="offered",
        progress_bytes=0,
        total_bytes=len(content),
        chunks_done=0,
        chunks_total=3,
        metadata={"mode": "stream", "path": str(out_path)},
    )
    daemon._incoming_files[blob] = IncomingFile(
        name=out_path.name,
        size=len(content),
        blob_hex=blob,
        out_path=out_path,
        handle=open(out_path, "wb"),
        hasher=blake3.blake3(),
        transfer_id=transfer_id,
    )
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    monkeypatch.setattr(
        daemon, "_cache_file_chunks", lambda path, **_kwargs: None,
    )

    for seq, data in enumerate(chunks[:2]):
        await daemon._on_peer_message(
            chan,
            make_msg(
                "FILE_CHUNK",
                them.short_id,
                id=f"chunk-{seq}",
                blob=blob,
                seq=seq,
                data=base64.b64encode(data).decode("ascii"),
                eof=False,
                ack_batch=2,
            ),
        )

    assert [m.get("t") for m in chan.sent] == ["FILE_ACK_BATCH"]
    assert chan.sent[-1]["ofs"] == ["chunk-0", "chunk-1"]

    await daemon._on_peer_message(
        chan,
        make_msg(
            "FILE_CHUNK",
            them.short_id,
            id="chunk-2",
            blob=blob,
            seq=2,
            data=base64.b64encode(chunks[2]).decode("ascii"),
            eof=True,
            ack_batch=2,
        ),
    )

    assert out_path.read_bytes() == content
    assert chan.sent[-1]["t"] == "ACK"
    assert chan.sent[-1]["of"] == "chunk-2"
    assert state.get_transfer(transfer_id).status == "complete"
    state.close()


@pytest.mark.asyncio
async def test_cdc_final_chunk_ack_schedules_finish_without_blocking(
    tmp_path: Path, monkeypatch
):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    content = b"cdc final ack must not wait for file rebuild"
    blob = blake3.blake3(content).hexdigest()
    chunk_hash = blake3.blake3(content).hexdigest()
    out_path = tmp_path / "cdc-received.bin"
    transfer_id = "in:test-cdc-final-ack"
    state.upsert_transfer(
        id=transfer_id,
        direction="in",
        peer_fp=them.fingerprint,
        kind="file",
        name=out_path.name,
        size=len(content),
        blob_hash=blob,
        status="offered",
        progress_bytes=0,
        total_bytes=len(content),
        chunks_done=0,
        chunks_total=1,
        metadata={"mode": "cdc", "path": str(out_path)},
    )
    handle = open(out_path, "wb")
    daemon._incoming_files[blob] = IncomingFile(
        name=out_path.name,
        size=len(content),
        blob_hex=blob,
        out_path=out_path,
        handle=handle,
        hasher=blake3.blake3(),
        cdc_chunks=[{
            "index": 0,
            "start": 0,
            "end": len(content),
            "size": len(content),
            "hash": chunk_hash,
        }],
        cdc_missing={0},
        cdc_parts={},
        transfer_id=transfer_id,
    )
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    scheduled: list[str] = []

    def _schedule(
        blob_arg: str,
        peer_fp: str,
        peer_sid: str,
        src_msg: dict,
        *,
        channel=None,
    ) -> None:
        assert any(
            m.get("t") == "ACK" and m.get("of") == "cdc-final"
            for m in chan.sent
        )
        assert state.get_transfer(transfer_id).status == "active"
        scheduled.append(blob_arg)

    monkeypatch.setattr(daemon, "_schedule_finish_cdc_file", _schedule)
    await daemon._on_peer_message(
        chan,
        make_msg(
            "FILE_CDC_CHUNK",
            them.short_id,
            id="cdc-final",
            blob=blob,
            index=0,
            hash=chunk_hash,
            enc="raw",
            wire_size=len(content),
            data=base64.b64encode(content).decode("ascii"),
        ),
    )

    assert chan.sent[-1]["t"] == "ACK"
    assert scheduled == [blob]
    with contextlib.suppress(Exception):
        handle.close()
    state.close()


@pytest.mark.asyncio
async def test_cdc_receive_accepts_binary_payload_frame(tmp_path: Path, monkeypatch):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    content = b"binary cdc payload without base64"
    blob = blake3.blake3(content).hexdigest()
    chunk_hash = blake3.blake3(content).hexdigest()
    out_path = tmp_path / "cdc-binary-received.bin"
    transfer_id = "in:test-cdc-binary"
    state.upsert_transfer(
        id=transfer_id,
        direction="in",
        peer_fp=them.fingerprint,
        kind="file",
        name=out_path.name,
        size=len(content),
        blob_hash=blob,
        status="offered",
        progress_bytes=0,
        total_bytes=len(content),
        chunks_done=0,
        chunks_total=1,
        metadata={"mode": "cdc", "path": str(out_path)},
    )
    handle = open(out_path, "wb")
    daemon._incoming_files[blob] = IncomingFile(
        name=out_path.name,
        size=len(content),
        blob_hex=blob,
        out_path=out_path,
        handle=handle,
        hasher=blake3.blake3(),
        cdc_chunks=[{
            "index": 0,
            "start": 0,
            "end": len(content),
            "size": len(content),
            "hash": chunk_hash,
        }],
        cdc_missing={0},
        cdc_parts={},
        transfer_id=transfer_id,
    )
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    scheduled: list[str] = []
    monkeypatch.setattr(
        daemon,
        "_schedule_finish_cdc_file",
        lambda blob_arg, *_args, **_kwargs: scheduled.append(blob_arg),
    )

    await daemon._on_peer_message(
        chan,
        make_msg(
            "FILE_CDC_CHUNK",
            them.short_id,
            id="cdc-binary",
            blob=blob,
            index=0,
            hash=chunk_hash,
            enc="raw",
            wire_size=len(content),
            _binary_data=content,
        ),
    )

    assert daemon._read_chunk_cache(chunk_hash) == content
    assert chan.sent[-1]["t"] == "ACK"
    assert scheduled == [blob]
    with contextlib.suppress(Exception):
        handle.close()
    state.close()


@pytest.mark.asyncio
async def test_send_file_failure_drops_session(tmp_path: Path, monkeypatch):
    """A mid-stream failure must drop the session — leaving it cached
    risks the next send inheriting a poisoned read state."""
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    sess = OutboundSession(
        peer_fp=them.fingerprint, peer=Peer(
            short_id=them.short_id, hostname="them",
            address="127.0.0.1", port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon._outbound_sessions[them.fingerprint] = sess

    monkeypatch.setattr(daemon, "_dial_peer_with_regime", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("no dial")))

    # Compress per-ACK deadline so the test runs fast.
    monkeypatch.setattr("one_link.daemon.FILE_ACK_DEADLINE_S", 0.5)

    f = tmp_path / "tiny.txt"
    f.write_bytes(b"abc")

    # Don't queue any reply — _await_ack will time out.
    with pytest.raises(RuntimeError, match="did not ACK"):
        await daemon.send_file(sess.peer, f)

    # Session was dropped from the map.
    assert them.fingerprint not in daemon._outbound_sessions
    state.close()


# ─── revoke_peer: unified tear-down ────────────────────────────────

@pytest.mark.asyncio
async def test_revoke_peer_drops_session_and_fails_transfers(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    # Pre-existing session
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    sess = OutboundSession(
        peer_fp=them.fingerprint, peer=Peer(
            short_id=them.short_id, hostname="them",
            address="127.0.0.1", port=12345,
            ed_pub_hex=them.public_bytes.hex(),
        ),
        channel=chan,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
    )
    daemon._outbound_sessions[them.fingerprint] = sess

    # Two in-flight transfers (one offered, one active) — both must
    # transition to 'failed' on revoke.
    state.upsert_transfer(
        id="xfer-A", direction="out",
        peer_fp=them.fingerprint, kind="file", name="a.bin",
        size=10, status="offered",
        progress_bytes=0, total_bytes=10,
        chunks_done=0, chunks_total=1,
    )
    state.upsert_transfer(
        id="xfer-B", direction="out",
        peer_fp=them.fingerprint, kind="file", name="b.bin",
        size=20, status="active",
        progress_bytes=5, total_bytes=20,
        chunks_done=1, chunks_total=4,
    )
    # And one already-complete that must NOT be touched.
    state.upsert_transfer(
        id="xfer-C", direction="in",
        peer_fp=them.fingerprint, kind="file", name="c.bin",
        size=5, status="complete",
        progress_bytes=5, total_bytes=5,
        chunks_done=1, chunks_total=1,
    )

    # UI event collector
    ui_events: list[dict] = []
    daemon.ui_server = SimpleNamespace(
        broadcast=lambda evt: ui_events.append(evt),
    )

    await daemon.revoke_peer(them.fingerprint, actor="test", note="audit")

    # Trust is rejected.
    rec = state.get_peer(them.fingerprint)
    assert rec.trust == "rejected"

    # Session was dropped.
    assert them.fingerprint not in daemon._outbound_sessions
    assert chan.closed is True

    # Transfers updated correctly.
    rows = {r.id: r for r in state.list_transfers(limit=10)}
    assert rows["xfer-A"].status == "failed"
    assert rows["xfer-A"].metadata.get("error") == "peer revoked"
    assert rows["xfer-B"].status == "failed"
    # Already-complete row was NOT modified.
    assert rows["xfer-C"].status == "complete"

    # UI got a peer_trust event.
    assert any(
        e.get("type") == "peer_trust"
        and e.get("fingerprint") == them.fingerprint
        and e.get("trust") == "rejected"
        for e in ui_events
    )
    state.close()


@pytest.mark.asyncio
async def test_revoke_peer_idempotent_on_already_rejected(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "rejected")

    # Should not raise even with no session, no transfers, no UI.
    await daemon.revoke_peer(them.fingerprint, actor="test")
    rec = state.get_peer(them.fingerprint)
    assert rec.trust == "rejected"
    state.close()


@pytest.mark.asyncio
async def test_revoke_peer_unknown_fp_is_noop(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    # Unknown peer — should not raise.
    await daemon.revoke_peer("zz" * 32, actor="test")
    state.close()


@pytest.mark.asyncio
async def test_revoke_peer_flushes_cap_store(tmp_path: Path):
    """Regression test for audit C3 (May 14 2026): revoke_peer MUST
    drop every capability grant involving the revoked peer. Otherwise
    a reconnecting "rejected" peer still passes _capability_allowed
    via the stale grant — bypassing the entire revocation UX until
    the grant's TTL elapses.
    """
    from one_link import caps_grants

    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    # Mint a grant from me to them and stash it in _cap_store.
    base_now = int(time.time() * 1000)
    blob = caps_grants.encode_grant(
        granter_priv_seed=me.private.private_bytes_raw(),
        granter_pub=me.public_bytes,
        subject_pub=them.public_bytes,
        capabilities=["files:read"],
        not_before_ms=base_now,
        not_after_ms=base_now + 3_600_000,  # 1 hour
        scope=b"",
    )
    daemon._cap_store.accept(blob, expected_subject_pub=them.public_bytes)
    assert daemon._cap_store.has_capability(
        granter_pub=me.public_bytes,
        subject_pub=them.public_bytes,
        capability="files:read",
    ), "pre-revoke grant must be recognized"

    # Revoke.
    await daemon.revoke_peer(them.fingerprint, actor="test", note="audit-c3")

    # The grant must no longer be honoured.
    assert not daemon._cap_store.has_capability(
        granter_pub=me.public_bytes,
        subject_pub=them.public_bytes,
        capability="files:read",
    ), "C3 regression: revoke_peer left a stale grant in _cap_store"
    state.close()


# ─── per-pairing health metrics ────────────────────────────────────

def test_stamp_pair_health_creates_entry_with_nan_latency():
    me = _new_identity()
    daemon = Daemon(me)
    fp = "aa" * 32
    daemon._stamp_pair_health(fp)
    h = daemon.get_pair_health(fp)
    assert h is not None
    assert h["last_alive_ms"] > 0
    # NaN-init when no latency provided yet
    assert h["latency_ewma_ms"] != h["latency_ewma_ms"]


def test_stamp_pair_health_updates_last_alive_ms():
    me = _new_identity()
    daemon = Daemon(me)
    fp = "aa" * 32
    daemon._stamp_pair_health(fp)
    first = daemon.get_pair_health(fp)["last_alive_ms"]
    time.sleep(0.005)
    daemon._stamp_pair_health(fp)
    second = daemon.get_pair_health(fp)["last_alive_ms"]
    assert second >= first


def test_stamp_pair_health_latency_ewma_initial_value():
    """First latency sample replaces NaN directly (no blend)."""
    me = _new_identity()
    daemon = Daemon(me)
    fp = "aa" * 32
    daemon._stamp_pair_health(fp, latency_ms=42.0)
    h = daemon.get_pair_health(fp)
    assert h["latency_ewma_ms"] == 42.0


def test_stamp_pair_health_latency_ewma_blends_subsequent():
    """alpha=0.3 → second sample is 0.7*prev + 0.3*new."""
    me = _new_identity()
    daemon = Daemon(me)
    fp = "aa" * 32
    daemon._stamp_pair_health(fp, latency_ms=100.0)
    daemon._stamp_pair_health(fp, latency_ms=200.0)
    h = daemon.get_pair_health(fp)
    # 0.7*100 + 0.3*200 = 70 + 60 = 130.0
    assert abs(h["latency_ewma_ms"] - 130.0) < 1e-6


def test_stamp_pair_health_empty_fp_is_noop():
    me = _new_identity()
    daemon = Daemon(me)
    daemon._stamp_pair_health("")
    assert daemon.get_pair_health("") is None


def test_get_pair_health_returns_copy_not_alias():
    """Mutating the returned dict must not corrupt the daemon's state."""
    me = _new_identity()
    daemon = Daemon(me)
    fp = "aa" * 32
    daemon._stamp_pair_health(fp, latency_ms=50.0)
    h = daemon.get_pair_health(fp)
    h["latency_ewma_ms"] = 9999.0
    h2 = daemon.get_pair_health(fp)
    assert h2["latency_ewma_ms"] == 50.0


@pytest.mark.asyncio
async def test_api_peers_surfaces_pair_health(tmp_path: Path):
    """The /api/peers serializer must emit health fields when set,
    and emit `health: None` when never-contacted."""
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "state.db")
    pub_hex = "bb" * 32
    peer_fp = fingerprint_of(bytes.fromhex(pub_hex))
    state.upsert_peer(
        fingerprint=peer_fp, short_id="bbbbbbbb",
        pubkey=bytes.fromhex(pub_hex),
        trust_default="pinned",
    )

    health_store = {peer_fp: {"last_alive_ms": 12345, "latency_ewma_ms": 42.5}}

    daemon = SimpleNamespace(
        state=state,
        discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
        _outbound_sessions={},
        _inbound_regime={},
        get_pair_health=lambda fp: health_store.get(fp),
    )
    server = UIServer(daemon)

    class _Req:
        query: dict = {}
        match_info: dict = {}

    resp = await server.api_peers(_Req())
    body = json.loads(resp.text)
    peers = {p["fingerprint"]: p for p in body["peers"]}
    h = peers[peer_fp]["health"]
    assert h["last_alive_ms"] == 12345
    assert h["latency_ewma_ms"] == 42.5
    state.close()


@pytest.mark.asyncio
async def test_api_peers_health_nan_serialized_as_none(tmp_path: Path):
    """latency_ewma_ms can be NaN before any PING measures it. JSON
    can't carry NaN safely (some parsers reject it); must be None."""
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "state.db")
    pub_hex = "bb" * 32
    peer_fp = fingerprint_of(bytes.fromhex(pub_hex))
    state.upsert_peer(
        fingerprint=peer_fp, short_id="bbbbbbbb",
        pubkey=bytes.fromhex(pub_hex),
        trust_default="pinned",
    )
    health_store = {peer_fp: {"last_alive_ms": 999, "latency_ewma_ms": float("nan")}}
    daemon = SimpleNamespace(
        state=state,
        discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
        _outbound_sessions={},
        _inbound_regime={},
        get_pair_health=lambda fp: health_store.get(fp),
    )
    server = UIServer(daemon)

    class _Req:
        query: dict = {}
        match_info: dict = {}

    resp = await server.api_peers(_Req())
    body = json.loads(resp.text)
    peers = {p["fingerprint"]: p for p in body["peers"]}
    h = peers[peer_fp]["health"]
    assert h["last_alive_ms"] == 999
    assert h["latency_ewma_ms"] is None
    state.close()


@pytest.mark.asyncio
async def test_api_peers_health_none_when_never_contacted(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "state.db")
    pub_hex = "bb" * 32
    peer_fp = fingerprint_of(bytes.fromhex(pub_hex))
    state.upsert_peer(
        fingerprint=peer_fp, short_id="bbbbbbbb",
        pubkey=bytes.fromhex(pub_hex),
        trust_default="pinned",
    )
    daemon = SimpleNamespace(
        state=state,
        discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
        _outbound_sessions={},
        _inbound_regime={},
        get_pair_health=lambda fp: None,
    )
    server = UIServer(daemon)

    class _Req:
        query: dict = {}
        match_info: dict = {}

    resp = await server.api_peers(_Req())
    body = json.loads(resp.text)
    peers = {p["fingerprint"]: p for p in body["peers"]}
    assert peers[peer_fp]["health"] is None
    state.close()


# ─── max-endpoints constant exposed ────────────────────────────────

def test_max_endpoints_constant_sane():
    assert Daemon.MAX_ENDPOINTS_PER_ANNOUNCEMENT > 0
    # Defends against bloat: more than 32 IPs on a sane LAN is a smell.
    assert Daemon.MAX_ENDPOINTS_PER_ANNOUNCEMENT <= 32
