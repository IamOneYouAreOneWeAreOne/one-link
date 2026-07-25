"""End-to-end test for Tier β rolling-window FrameProvenance.

Verifies:
  - POST /api/v1/calls action=attest_frame builds + signs a
    FrameProvenance using the daemon's identity key + ships
    CALL_FRAME_ATTEST to the peer.
  - Daemon inbound dispatch on CALL_FRAME_ATTEST verifies the
    signature + broadcasts a ``frame_attestation`` tail event.
  - Malformed input (wrong-length hash, missing fields, ghost
    call_id) is refused gracefully.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from unittest.mock import AsyncMock

import blake3
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from one_link.daemon import Daemon
from one_link.identity import Identity


# ---------------------------------------------------------------------------
# Scaffolding (mirrors test_server_sdp_ice_routes)
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


class _FakePeer:
    def __init__(self, ed_pub_hex: str) -> None:
        self.ed_pub_hex = ed_pub_hex
        self.trust = "pinned"


class _FakeState:
    def __init__(self, peers: dict[str, str]) -> None:
        self._peers = {fp: _FakePeer(pub) for fp, pub in peers.items()}

    def get_peer(self, fp: str):
        return self._peers.get(fp)


class _FakeRequest:
    def __init__(self, body: dict) -> None:
        self._body = body

    async def json(self) -> dict:
        return self._body


class _FakeChannel:
    def __init__(self, peer_ed_pub: bytes, peer_short_id: str) -> None:
        self.peer_ed_pub = peer_ed_pub
        self.peer_short_id = peer_short_id
        self.peer_caps = {"features": []}
        self.sent: list[bytes] = []

    async def send(self, payload: bytes) -> None:
        self.sent.append(payload)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def me() -> Identity:
    return _make_identity("att-me")


@pytest.fixture
def peer() -> Identity:
    return _make_identity("att-peer")


@pytest.fixture
def server(me: Identity, peer: Identity):
    from one_link.server import UIServer
    d = Daemon(me=me)
    d.state = _FakeState({peer.fingerprint: peer.public_bytes.hex()})
    d._call_registry.open(
        call_id="frame-call-1",
        peer_master_vk_hex=peer.fingerprint,
        local_role="originator",
        local_master_vk_hex=me.fingerprint,
        started_at_ms=1_000,
    )
    d.send_to = AsyncMock()
    s = UIServer.__new__(UIServer)
    s.daemon = d
    s._lp_call_api_cached = None
    return s


# ---------------------------------------------------------------------------
# attest_frame action
# ---------------------------------------------------------------------------

def test_attest_frame_signs_and_dispatches(server) -> None:
    seg = hashlib.sha256(b"window-bytes").hexdigest()
    req = _FakeRequest({
        "action": "attest_frame",
        "call_id": "frame-call-1",
        "segment_hash_hex": seg,
        "timestamp_us": 1_700_000_000_000_000,
        "path_class": "lan",
        "recording_state": "none",
    })
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is True
    assert server.daemon.send_to.await_count == 1
    msgs = server.daemon.send_to.await_args.args[1]
    assert len(msgs) == 1
    wire = msgs[0]
    assert wire["t"] == "CALL_FRAME_ATTEST"
    assert wire["call_id"] == "frame-call-1"
    assert isinstance(wire["attestation"], dict)
    # Schema version is the live variant (SHA-256-based)
    assert wire["attestation"]["v"] == 2


def test_attest_frame_rejects_short_hash(server) -> None:
    req = _FakeRequest({
        "action": "attest_frame",
        "call_id": "frame-call-1",
        "segment_hash_hex": "deadbeef",  # too short
        "timestamp_us": 0,
    })
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is False
    assert server.daemon.send_to.await_count == 0


def test_attest_frame_rejects_non_hex_hash(server) -> None:
    req = _FakeRequest({
        "action": "attest_frame",
        "call_id": "frame-call-1",
        "segment_hash_hex": "z" * 64,
        "timestamp_us": 0,
    })
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is False


def test_attest_frame_for_unknown_call_refused(server) -> None:
    seg = hashlib.sha256(b"x").hexdigest()
    req = _FakeRequest({
        "action": "attest_frame",
        "call_id": "ghost-call",
        "segment_hash_hex": seg,
        "timestamp_us": 0,
    })
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is False


# ---------------------------------------------------------------------------
# Daemon inbound dispatch
# ---------------------------------------------------------------------------

def test_inbound_call_frame_attest_broadcasts_tail_event(
    me: Identity, peer: Identity,
) -> None:
    """An inbound CALL_FRAME_ATTEST signed by the peer must verify
    + emit a ``frame_attestation`` tail event with verified=True."""
    from one_link.frame_provenance import PathClass, RecordingState, to_wire_dict
    from one_link.live_frame_provenance import sign_browser_window

    # Build a signed attestation as the peer would.
    seg = hashlib.sha256(b"window-bytes").digest()
    signed = sign_browser_window(
        signing_key=peer.private,
        device_id=peer.fingerprint[:8],
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        segment_hash=seg,
        timestamp_us=1_700_000_000_000_000,
    )

    d = Daemon(me=me)
    d.state = _FakeState({peer.fingerprint: peer.public_bytes.hex()})
    d._call_registry.open(
        call_id="frame-call-2",
        peer_master_vk_hex=peer.fingerprint,
        local_role="recipient",
        local_master_vk_hex=me.fingerprint,
        started_at_ms=1_000,
    )

    tail: list[dict] = []
    d._broadcast_tail = lambda ev: tail.append(ev)  # type: ignore

    msg = {
        "t": "CALL_FRAME_ATTEST",
        "id": "att1",
        "ts": 0,
        "from": peer.short_id,
        "call_id": "frame-call-2",
        "attestation": to_wire_dict(signed),
    }
    channel = _FakeChannel(peer_ed_pub=peer.public_bytes, peer_short_id=peer.short_id)
    _run(d._on_peer_message(channel, msg))

    events = [e for e in tail if e.get("tail_kind") == "frame_attestation"]
    assert len(events) == 1
    ev = events[0]
    assert ev["call_id"] == "frame-call-2"
    assert ev["verified"] is True
    # Doctrine — plain language UI words.
    assert ev["kind"] == "Original"


def test_inbound_call_frame_attest_with_forged_sig_marks_unverified(
    me: Identity, peer: Identity,
) -> None:
    """A peer-impersonator signs with a different key. The daemon
    must mark the attestation unverified — UI will show the Reality
    dot as 'verification pending' / unverified."""
    from one_link.frame_provenance import PathClass, RecordingState, to_wire_dict
    from one_link.live_frame_provenance import sign_browser_window

    attacker = _make_identity("attacker")
    seg = hashlib.sha256(b"x").digest()
    forged = sign_browser_window(
        signing_key=attacker.private,
        device_id=peer.fingerprint[:8],  # claim to be peer
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        segment_hash=seg,
        timestamp_us=0,
    )

    d = Daemon(me=me)
    d.state = _FakeState({peer.fingerprint: peer.public_bytes.hex()})
    d._call_registry.open(
        call_id="frame-call-3",
        peer_master_vk_hex=peer.fingerprint,
        local_role="recipient",
        local_master_vk_hex=me.fingerprint,
        started_at_ms=1_000,
    )

    tail: list[dict] = []
    d._broadcast_tail = lambda ev: tail.append(ev)  # type: ignore

    msg = {
        "t": "CALL_FRAME_ATTEST",
        "id": "att2",
        "ts": 0,
        "from": peer.short_id,
        "call_id": "frame-call-3",
        "attestation": to_wire_dict(forged),
    }
    # Channel reports the REAL peer's pubkey (envelope is verified
    # before _on_peer_message runs).
    channel = _FakeChannel(peer_ed_pub=peer.public_bytes, peer_short_id=peer.short_id)
    _run(d._on_peer_message(channel, msg))

    events = [e for e in tail if e.get("tail_kind") == "frame_attestation"]
    assert len(events) == 1
    assert events[0]["verified"] is False


def test_inbound_call_frame_attest_malformed_is_dropped(
    me: Identity, peer: Identity,
) -> None:
    d = Daemon(me=me)
    d.state = _FakeState({peer.fingerprint: peer.public_bytes.hex()})
    d._call_registry.open(
        call_id="frame-call-4",
        peer_master_vk_hex=peer.fingerprint,
        local_role="recipient",
        local_master_vk_hex=me.fingerprint,
        started_at_ms=1_000,
    )
    tail: list[dict] = []
    d._broadcast_tail = lambda ev: tail.append(ev)  # type: ignore

    msg = {
        "t": "CALL_FRAME_ATTEST",
        "id": "att3",
        "ts": 0,
        "from": peer.short_id,
        "call_id": "frame-call-4",
        "attestation": {"garbage": True},
    }
    channel = _FakeChannel(peer_ed_pub=peer.public_bytes, peer_short_id=peer.short_id)
    # Must not raise.
    _run(d._on_peer_message(channel, msg))
    events = [e for e in tail if e.get("tail_kind") == "frame_attestation"]
    assert events == []
