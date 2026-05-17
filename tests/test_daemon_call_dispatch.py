"""Daemon dispatch tests for CALL_* / RECORDING_* / CAPSULE_*.

Verifies that an inbound CALL_INVITE wire message arriving at the
daemon's ``_on_peer_message`` causes:
  - A new CallManager to be opened in the registry
  - The lifecycle phase to transition to RINGING
  - A tail event broadcast to the WebSocket UI subscribers
  - The local action SHOW_RING to be requested

These tests instantiate the real :class:`Daemon` class (no
sockets, no network), feed wire messages through the dispatch,
and assert on the manager state + broadcast tail events.
"""

from __future__ import annotations

import asyncio

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import blake3

from one_link.call_manager import ManagerEventKind
from one_link.call_signaling import CALL_ACCEPT, CALL_INVITE, CallPhase
from one_link.daemon import Daemon
from one_link.identity import Identity
from one_link.recording_consent import RECORDING_GRANT, RECORDING_REQUEST
from one_link.wire import decode_msg


# ---------------------------------------------------------------------------
# Helpers (mirroring the daemon-frame-provenance-dispatch tests)
# ---------------------------------------------------------------------------

def _make_identity(name: str) -> Identity:
    seed = blake3.blake3(name.encode()).digest()[:32]
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fp = blake3.blake3(pub_bytes).hexdigest()
    return Identity(
        private=priv, public=priv.public_key(), public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname=name,
    )


class _FakePeerRecord:
    def __init__(self, ed_pub_hex: str) -> None:
        self.ed_pub_hex = ed_pub_hex
        self.pubkey = bytes.fromhex(ed_pub_hex)
        self.short_id = blake3.blake3(self.pubkey).hexdigest()[:8]
        self.hostname = "peer"
        self.verified_at_ms = None
        self.verified_method = None
        self.verified_note = None
        self.trust = "pinned"

    @property
    def is_verified(self) -> bool:
        return self.verified_at_ms is not None


class _FakeState:
    def __init__(self, peer_pub_hex_by_fp: dict[str, str]) -> None:
        self._peers = {
            fp: _FakePeerRecord(pub) for fp, pub in peer_pub_hex_by_fp.items()
        }

    def get_peer(self, peer_fp: str):
        return self._peers.get(peer_fp)

    def set_peer_verified(self, peer_fp: str, *, method: str, note=None, actor=None):
        rec = self._peers.get(peer_fp)
        if rec is None:
            return None
        if method not in ("sas-digits", "sas-qr", "sas-audio", "manual"):
            raise ValueError("bad method")
        rec.verified_at_ms = 1234
        rec.verified_method = method
        rec.verified_note = note
        return rec

    def clear_peer_verified(self, peer_fp: str, *, actor=None, note=None):
        rec = self._peers.get(peer_fp)
        if rec is None:
            return None
        rec.verified_at_ms = None
        rec.verified_method = None
        rec.verified_note = None
        return rec


class _FakeChannel:
    def __init__(self, peer_ed_pub: bytes, peer_short_id: str) -> None:
        self.peer_ed_pub = peer_ed_pub
        self.peer_short_id = peer_short_id
        self.peer_caps = {"features": ["chat", "frame_provenance_v1"]}
        self.sent: list[bytes] = []

    async def send(self, payload: bytes) -> None:
        self.sent.append(payload)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def alice() -> Identity:
    return _make_identity("alice-dispatch")


@pytest.fixture
def mom() -> Identity:
    return _make_identity("mom-dispatch")


@pytest.fixture
def mom_daemon(mom: Identity, alice: Identity) -> Daemon:
    d = Daemon(me=mom)
    d.state = _FakeState({alice.fingerprint: alice.public_bytes.hex()})
    return d


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_daemon_initialises_call_registry(mom: Identity) -> None:
    """A fresh Daemon has an empty CallManagerRegistry ready."""
    d = Daemon(me=mom)
    assert hasattr(d, "_call_registry")
    assert len(d._call_registry) == 0


def test_inbound_call_invite_opens_manager_and_rings(
    mom_daemon: Daemon, alice: Identity, mom: Identity,
) -> None:
    """Alice sends CALL_INVITE. Mom's daemon dispatches → opens
    a manager → lifecycle goes to RINGING → tail event broadcast."""
    msg = {
        "t": "CALL_INVITE",
        "id": "msg-1",
        "ts": 1_700_000_000_000,
        "from": alice.short_id,
        "call_id": "demo-call-1",
        "originator_role": "caller",
        "ttl_ms": 30_000,
    }
    channel = _FakeChannel(
        peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id,
    )
    tail_events: list[dict] = []
    mom_daemon._broadcast_tail = lambda ev: tail_events.append(ev)  # type: ignore

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(
            mom_daemon._on_peer_message(channel, msg)
        )
    finally:
        loop.close()

    # Manager opened
    mgr = mom_daemon._call_registry.get("demo-call-1")
    assert mgr is not None
    assert mgr.phase == CallPhase.RINGING
    # Tail event broadcast
    ring_events = [e for e in tail_events if e.get("tail_kind") == "show_ring"]
    assert len(ring_events) >= 1
    ack = decode_msg(channel.sent[-1])
    assert ack["t"] == "ACK"
    assert ack["of"] == "msg-1"
    assert ack["ok"] is True


def test_inbound_call_accept_advances_to_active(
    mom_daemon: Daemon, alice: Identity, mom: Identity,
) -> None:
    """Alice sends INVITE then ACCEPT (as if she's the recipient
    accepting our invite — flow modeled from her perspective)."""
    # Open a manager as ORIGINATOR (so we can test inbound ACCEPT).
    mgr = mom_daemon._call_registry.open(
        call_id="demo-call-2",
        peer_master_vk_hex=alice.fingerprint,
        local_role="originator",
        local_master_vk_hex=mom.fingerprint,
        started_at_ms=1_000,
    )
    # Mom's side sent the invite already
    from one_link.call_manager import ManagerEvent
    mgr.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    assert mgr.phase == CallPhase.INVITING

    # Alice's CALL_ACCEPT arrives
    msg = {
        "t": "CALL_ACCEPT",
        "id": "msg-2",
        "ts": 1_700_000_000_000,
        "from": alice.short_id,
        "call_id": "demo-call-2",
    }
    channel = _FakeChannel(
        peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id,
    )
    tail_events: list[dict] = []
    mom_daemon._broadcast_tail = lambda ev: tail_events.append(ev)  # type: ignore

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(
            mom_daemon._on_peer_message(channel, msg)
        )
    finally:
        loop.close()

    assert mgr.phase == CallPhase.ACTIVE


def test_inbound_verify_notice_marks_peer_verified_and_acks(
    mom_daemon: Daemon, alice: Identity,
) -> None:
    msg = {
        "t": "PEER_VERIFY_NOTICE",
        "id": "verify-1",
        "ts": 1_700_000_000_000,
        "from": alice.short_id,
        "action": "set",
        "method": "sas-digits",
        "note": "same room",
    }
    channel = _FakeChannel(
        peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id,
    )
    tail_events: list[dict] = []
    mom_daemon.ui_server = type(
        "_UI", (), {"broadcast": lambda self, ev: tail_events.append(ev)}
    )()

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(mom_daemon._on_peer_message(channel, msg))
    finally:
        loop.close()

    rec = mom_daemon.state.get_peer(alice.fingerprint)
    assert rec.is_verified is True
    assert rec.verified_method == "sas-digits"
    assert tail_events[-1]["type"] == "peer_verified"
    assert tail_events[-1]["is_verified"] is True
    ack = decode_msg(channel.sent[-1])
    assert ack["t"] == "ACK"
    assert ack["of"] == "verify-1"
    assert ack["ok"] is True


def test_inbound_recording_request_routes_to_consent_fsm(
    mom_daemon: Daemon, alice: Identity, mom: Identity,
) -> None:
    # First open a call + bring it to ACTIVE
    mgr = mom_daemon._call_registry.open(
        call_id="demo-call-3",
        peer_master_vk_hex=alice.fingerprint,
        local_role="recipient",
        local_master_vk_hex=mom.fingerprint,
        started_at_ms=1_000,
    )
    from one_link.call_manager import ManagerEvent
    mgr.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_INVITE, 1_000))
    mgr.handle(ManagerEvent(ManagerEventKind.USER_ACCEPT, 2_000))
    assert mgr.phase == CallPhase.ACTIVE

    # Alice sends RECORDING_REQUEST
    msg = {
        "t": "RECORDING_REQUEST",
        "id": "msg-3",
        "ts": 1_700_000_000_000,
        "from": alice.short_id,
        "call_id": "demo-call-3",
    }
    channel = _FakeChannel(
        peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id,
    )
    tail_events: list[dict] = []
    mom_daemon._broadcast_tail = lambda ev: tail_events.append(ev)  # type: ignore

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(
            mom_daemon._on_peer_message(channel, msg)
        )
    finally:
        loop.close()

    # The consent FSM transitioned to AWAITING_LOCAL_RESPONSE
    from one_link.recording_consent import ConsentPhase
    assert mgr.consent_phase == ConsentPhase.AWAITING_LOCAL_RESPONSE
    # UI tail event broadcast for the recording-state change
    rec_events = [
        e for e in tail_events
        if e.get("tail_kind") == "recording_state_changed"
    ]
    assert len(rec_events) >= 1


def test_message_with_missing_call_id_is_dropped_gracefully(
    mom_daemon: Daemon, alice: Identity,
) -> None:
    """A CALL_* message with no call_id must not crash."""
    msg = {
        "t": "CALL_INVITE",
        "id": "msg-bad",
        "ts": 1,
        "from": alice.short_id,
        # Missing call_id
    }
    channel = _FakeChannel(
        peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id,
    )
    mom_daemon._broadcast_tail = lambda ev: None  # type: ignore

    loop = asyncio.new_event_loop()
    try:
        # Must not raise
        loop.run_until_complete(
            mom_daemon._on_peer_message(channel, msg)
        )
    finally:
        loop.close()
    # No manager created
    assert len(mom_daemon._call_registry) == 0


def test_inbound_call_end_for_unknown_call_is_dropped(
    mom_daemon: Daemon, alice: Identity,
) -> None:
    """CALL_END arrives for a call we never knew about (stale
    from prior session). Drop silently."""
    msg = {
        "t": "CALL_END",
        "id": "msg-stale",
        "ts": 1,
        "from": alice.short_id,
        "call_id": "ghost-call",
        "reason": "hangup",
    }
    channel = _FakeChannel(
        peer_ed_pub=alice.public_bytes, peer_short_id=alice.short_id,
    )
    mom_daemon._broadcast_tail = lambda ev: None  # type: ignore

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(
            mom_daemon._on_peer_message(channel, msg)
        )
    finally:
        loop.close()
    # No manager created (only CALL_INVITE opens a new manager)
    assert mom_daemon._call_registry.get("ghost-call") is None


def test_outbound_messages_flow_back_to_channel(
    mom_daemon: Daemon, alice: Identity, mom: Identity,
) -> None:
    """When the lifecycle transitions in response to a wire message,
    any outbound message (e.g. CALL_ACCEPT on USER_ACCEPT) flows
    back to the channel.

    Here: simulate Mom receiving an INVITE, then her user accepting.
    The dispatch case for USER_ACCEPT isn't a wire message (it's a
    UI action), so we test it directly via the manager instead.
    """
    mgr = mom_daemon._call_registry.open(
        call_id="demo-call-4",
        peer_master_vk_hex=alice.fingerprint,
        local_role="recipient",
        local_master_vk_hex=mom.fingerprint,
        started_at_ms=1_000,
    )
    from one_link.call_manager import ManagerEvent
    mgr.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_INVITE, 1_000))
    out = mgr.handle(ManagerEvent(ManagerEventKind.USER_ACCEPT, 2_000))
    # CallManager emits a CALL_ACCEPT to send to peer.
    assert len(out.outbound_msgs) == 1
    assert out.outbound_msgs[0].type == CALL_ACCEPT
