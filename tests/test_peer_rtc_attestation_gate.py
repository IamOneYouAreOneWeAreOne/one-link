"""Tests for the Row 10 attestation gate.

When ``daemon.require_attested_peers`` is True, the peer-RTC
manager drops app-layer DC messages from peers that haven't
completed the attestation handshake. Control-plane messages
(ping/pong, attest_challenge, attest_response) bypass the gate so
the handshake itself can run.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
import blake3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.confidential_native import HAS_NATIVE, SealedMasterIdentity
from one_link.identity import Identity
from one_link.peer_rtc import (
    PEER_DC_PROTOCOL_VERSION,
    BrowserPeer,
    BrowserPeerManager,
)

pytestmark = pytest.mark.skipif(
    not HAS_NATIVE,
    reason="one_link_native.confidential not built; run `maturin develop --release`",
)


class _StubDC:
    def __init__(self) -> None:
        self.readyState = "open"
        self.sent: list[str] = []

    def send(self, data: str) -> None:
        self.sent.append(data)


def _make_daemon(
    require_attested: bool = False,
    sealed_master: SealedMasterIdentity | None = None,
) -> object:
    return SimpleNamespace(
        require_attested_peers=require_attested,
        sealed_master=sealed_master,
        _gate_drop_count=0,
    )


def _make_peer(attested: bool = False) -> BrowserPeer:
    p = BrowserPeer(fingerprint="sha256:test", pubkey_bytes=bytes(32))
    p.control_dc = _StubDC()
    p.bulk_dc = _StubDC()
    if attested:
        p.attested_ms = 1
        p.peer_master_vk = bytes(1984)
    return p


def _identity(hostname: str) -> Identity:
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    public_bytes = public.public_bytes_raw()
    fp = blake3.blake3(public_bytes).hexdigest()
    return Identity(
        private=private,
        public=public,
        public_bytes=public_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname=hostname,
    )


def _app_envelope() -> dict:
    return {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "chat_msg",
        "body": "hello",
    }


def test_daemon_attestation_gate_defaults_off(monkeypatch):
    from one_link.daemon import Daemon

    monkeypatch.delenv("ONE_LINK_REQUIRE_ATTESTED_PEERS", raising=False)
    d = Daemon(_identity("gate-default"))
    assert d.require_attested_peers is False
    assert d._control_status()["peer_rtc_attestation"] == {
        "require_attested_peers": False,
        "gate_drop_count": 0,
    }


def test_daemon_attestation_gate_env_enables(monkeypatch):
    from one_link.daemon import Daemon

    monkeypatch.setenv("ONE_LINK_REQUIRE_ATTESTED_PEERS", "required")
    d = Daemon(_identity("gate-required"))
    d._gate_drop_count = 7
    assert d.require_attested_peers is True
    assert d._control_status()["peer_rtc_attestation"] == {
        "require_attested_peers": True,
        "gate_drop_count": 7,
    }


# ── Gate off (default) ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_gate_off_lets_unattested_app_message_through():
    daemon = _make_daemon(require_attested=False)
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer(attested=False)
    fan_out_received = []

    async def listener(p, kind, msg_t, env):
        fan_out_received.append((kind, msg_t))

    mgr.add_dc_listener(listener)
    # Raw JSON message goes through _dispatch_dc.
    await mgr._dispatch_dc(peer, "control", json.dumps(_app_envelope()))
    assert fan_out_received == [("control", "chat_msg")]
    assert daemon._gate_drop_count == 0


# ── Gate on, peer not attested ───────────────────────────────────


@pytest.mark.asyncio
async def test_gate_on_blocks_unattested_app_message():
    daemon = _make_daemon(require_attested=True)
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer(attested=False)
    fan_out_received = []

    async def listener(p, kind, msg_t, env):
        fan_out_received.append((kind, msg_t))

    mgr.add_dc_listener(listener)
    await mgr._dispatch_dc(peer, "control", json.dumps(_app_envelope()))
    assert fan_out_received == []
    assert daemon._gate_drop_count == 1


# ── Gate on, peer attested ──────────────────────────────────────


@pytest.mark.asyncio
async def test_gate_on_lets_attested_app_message_through():
    daemon = _make_daemon(require_attested=True)
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer(attested=True)
    fan_out_received = []

    async def listener(p, kind, msg_t, env):
        fan_out_received.append((kind, msg_t))

    mgr.add_dc_listener(listener)
    await mgr._dispatch_dc(peer, "control", json.dumps(_app_envelope()))
    assert fan_out_received == [("control", "chat_msg")]
    assert daemon._gate_drop_count == 0


# ── Control-plane bypass ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_gate_on_lets_ping_through_unattested():
    daemon = _make_daemon(require_attested=True)
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer(attested=False)
    fan_out_received = []

    async def listener(p, kind, msg_t, env):
        fan_out_received.append((kind, msg_t))

    mgr.add_dc_listener(listener)
    ping = {"v": PEER_DC_PROTOCOL_VERSION, "t": "ping", "ts": 0}
    await mgr._dispatch_dc(peer, "control", json.dumps(ping))
    # ping is handled built-in (NOT fanned out) but it must NOT
    # increment the drop counter.
    assert daemon._gate_drop_count == 0
    # peer.control_dc should have a pong queued.
    assert any("pong" in s for s in peer.control_dc.sent)


@pytest.mark.asyncio
async def test_gate_on_lets_attest_challenge_through_unattested():
    """The handshake itself must not be gated."""
    seed = bytes([0x42] * 32)
    sealed = SealedMasterIdentity.from_seed_bytes(seed)
    daemon = _make_daemon(require_attested=True, sealed_master=sealed)
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer(attested=False)
    import base64

    challenge = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "attest_challenge",
        "challenge_b64": base64.b64encode(bytes(32)).decode("ascii"),
    }
    await mgr._dispatch_dc(peer, "control", json.dumps(challenge))
    # The daemon should have queued an attest_response on the
    # control DC.
    assert any("attest_response" in s for s in peer.control_dc.sent)
    assert daemon._gate_drop_count == 0


# ── Drop counter accumulates ─────────────────────────────────────


@pytest.mark.asyncio
async def test_drop_counter_accumulates_across_messages():
    daemon = _make_daemon(require_attested=True)
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer(attested=False)
    for _ in range(5):
        await mgr._dispatch_dc(
            peer, "control", json.dumps(_app_envelope())
        )
    assert daemon._gate_drop_count == 5
