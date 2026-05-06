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
import contextlib
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import (
    Daemon,
    OutboundSession,
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
        self.sent.append(decode_msg(payload))

    async def recv(self) -> bytes:
        if self.closed:
            raise RuntimeError("channel closed")
        return await self._replies.get()

    async def close(self) -> None:
        self.closed = True

    def queue_reply(self, msg: dict) -> None:
        self._replies.put_nowait(encode_msg(msg))


# ─── ENDPOINT_UPDATE: pinned-only ─────────────────────────────────

@pytest.mark.asyncio
async def test_endpoint_update_from_pinned_peer_updates_state(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
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

    rec = state.get_peer(them.fingerprint)
    assert rec.last_address == "192.168.1.42"
    assert rec.last_port == 6000

    # ACK was sent
    assert any(s.get("t") == "ACK" for s in chan.sent)
    state.close()


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
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    flood = [{"host": f"10.0.0.{i}", "port": 5000 + i} for i in range(100)]
    msg = make_msg("ENDPOINT_UPDATE", them.short_id, endpoints=flood)
    await daemon._handle_endpoint_update(chan, msg, them.fingerprint, them.short_id)

    rec = state.get_peer(them.fingerprint)
    # The picked anchor is the first valid entry within the capped slice.
    assert rec.last_address == "10.0.0.0"
    assert rec.last_port == 5000
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
