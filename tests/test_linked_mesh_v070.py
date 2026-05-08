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
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import blake3
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import (
    BINARY_FRAME_MAGIC,
    Daemon,
    IncomingFile,
    OutboundSession,
    _decode_binary_frame,
    _final_stream_ack_deadline,
    _fast_fixed_chunk_size_for_peer,
    _stream_transfer_profile,
)
from one_link.capabilities import CHAT, FILES, FILE_BINARY_FRAME, FILE_CDC
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
        return await self._replies.get()

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


# ─── ENDPOINT_UPDATE: pinned-only ─────────────────────────────────

@pytest.mark.asyncio
async def test_endpoint_update_from_pinned_peer_queues_verified_promotion(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    queued = []

    async def _fake_verify(peer_fp, peer_sid, host, port):
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

    async def _fake_verify(peer_fp, peer_sid, host, port):
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
    # FILE_OFFER + 1 chunk on the existing channel.
    sent_types = [s.get("t") for s in chan.sent]
    assert "FILE_OFFER" in sent_types
    assert "FILE_CDC_CHUNK" in sent_types
    # Session counters bumped.
    assert sess.messages_sent == 1
    # Session NOT closed — kept for next reuse.
    assert chan.closed is False
    # Session still in the map.
    assert them.fingerprint in daemon._outbound_sessions
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
    st = f.stat()
    blob = blake3.blake3(payload).hexdigest()
    chunk_hash = blake3.blake3(payload).hexdigest()
    state.record_file_index_cache(
        path=str(f.resolve()),
        size=st.st_size,
        mtime_ns=st.st_mtime_ns,
        ctime_ns=st.st_ctime_ns,
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
    st = f.stat()
    state.record_file_index_cache(
        path=str(f.resolve()),
        size=st.st_size,
        mtime_ns=st.st_mtime_ns,
        ctime_ns=st.st_ctime_ns,
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
    st = f.stat()
    state.record_file_index_cache(
        path=str(f.resolve()),
        size=st.st_size,
        mtime_ns=st.st_mtime_ns,
        ctime_ns=st.st_ctime_ns,
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
        path=str(f.resolve()),
        size=f.stat().st_size,
        mtime_ns=f.stat().st_mtime_ns,
        ctime_ns=f.stat().st_ctime_ns,
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
    assert max(chan.recv_sent_counts) >= 4
    assert row.metadata["cdc_engine"] == "pipelined_chunks_v2"
    assert row.metadata["cdc_window_chunks"] == 3
    assert all(not daemon._chunk_cache_path(c["hash"]).is_file() for c in chunks)
    assert state.chunks_sourced([c["hash"] for c in chunks]) == [c["hash"] for c in chunks]
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
        path=str(f.resolve()),
        size=f.stat().st_size,
        mtime_ns=f.stat().st_mtime_ns,
        ctime_ns=f.stat().st_ctime_ns,
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

    payload = b"already cached"
    chunk_hash = blake3.blake3(payload).hexdigest()
    blob = blake3.blake3(payload).hexdigest()
    daemon._store_chunk_cache(chunk_hash, payload, blob_hash=blob, chunk_index=0)
    scheduled: list[str] = []

    def _schedule(blob_hex, peer_fp, peer_sid, src_msg):
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
    assert max(chan.recv_sent_counts) >= 4  # offer + three chunks before stream ACK drain
    assert row.metadata["stream_engine"] == "pipelined_json_v1"
    assert row.metadata["stream_window_chunks"] == 3
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

    def _cache_after_ack(path: Path) -> None:
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
    monkeypatch.setattr(daemon, "_cache_file_chunks", lambda path: None)

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
