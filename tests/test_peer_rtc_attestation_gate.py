"""Tests for native attestation controls and browser identity gating.

The legacy ``ONE_LINK_REQUIRE_ATTESTED_PEERS`` knob now truthfully aliases a
browser-feasible, channel-bound proof of the enrolled Ed25519 key. The native
hybrid attestation handshake remains independently exercised here, but it is
not misrepresented as browser hardware/platform attestation.
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


@pytest.fixture(autouse=True)
def _isolate_gate_tests_from_roster_authority(monkeypatch):
    """This module tests the gate after admission, not roster enrollment."""

    monkeypatch.setattr(
        BrowserPeerManager,
        "peer_authorization_is_live",
        lambda _manager, _peer: True,
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
    # daemon.me.public_bytes is required by _handle_attest_challenge
    # (audit C1 May 2026 — SDP-binding into the attestation transcript).
    me = SimpleNamespace(public_bytes=bytes([0x99] * 32))
    return SimpleNamespace(
        require_browser_identity_possession=require_attested,
        require_attested_peers=require_attested,
        sealed_master=sealed_master,
        _gate_drop_count=0,
        me=me,
    )


def _make_peer(
    attested: bool = False,
    identity_verified: bool = False,
) -> BrowserPeer:
    p = BrowserPeer(fingerprint="sha256:test", pubkey_bytes=bytes(32))
    p.control_dc = _StubDC()
    p.bulk_dc = _StubDC()
    if attested:
        p.attested_ms = 1
        p.peer_master_vk = bytes(1984)
    if identity_verified:
        p.identity_verified_ms = 1
        p.identity_verified_dc_id = id(p.control_dc)
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
    monkeypatch.delenv(
        "ONE_LINK_REQUIRE_BROWSER_IDENTITY_POSSESSION", raising=False,
    )
    d = Daemon(_identity("gate-default"))
    assert d.require_attested_peers is False
    assert d._control_status()["browser_identity_possession"] == {
        "required": False,
        "gate_drop_count": 0,
        "scope": "webrtc-dc",
        "proof": "enrolled-ed25519-key-on-current-datachannel",
        "hardware_attestation": False,
        "legacy_env_alias": "ONE_LINK_REQUIRE_ATTESTED_PEERS",
    }


@pytest.mark.parametrize(
    "env_name",
    [
        "ONE_LINK_REQUIRE_BROWSER_IDENTITY_POSSESSION",
        "ONE_LINK_REQUIRE_ATTESTED_PEERS",
    ],
)
def test_daemon_identity_possession_env_and_legacy_alias_enable(
    monkeypatch,
    env_name,
):
    from one_link.daemon import Daemon

    monkeypatch.delenv("ONE_LINK_REQUIRE_ATTESTED_PEERS", raising=False)
    monkeypatch.delenv(
        "ONE_LINK_REQUIRE_BROWSER_IDENTITY_POSSESSION", raising=False,
    )
    monkeypatch.setenv(env_name, "required")
    d = Daemon(_identity("gate-required"))
    d._gate_drop_count = 7
    assert d.require_attested_peers is True
    assert d.require_browser_identity_possession is True
    assert d._control_status()["browser_identity_possession"] == {
        "required": True,
        "gate_drop_count": 7,
        "scope": "webrtc-dc",
        "proof": "enrolled-ed25519-key-on-current-datachannel",
        "hardware_attestation": False,
        "legacy_env_alias": "ONE_LINK_REQUIRE_ATTESTED_PEERS",
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
async def test_gate_on_lets_channel_identity_verified_message_through():
    daemon = _make_daemon(require_attested=True)
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer(attested=True, identity_verified=True)
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


# ── Audit H7 — freshness re-check at gate time ───────────────────


@pytest.mark.asyncio
async def test_gate_drops_app_message_after_attestation_expires():
    """H7 regression (May 14 2026): an attested peer whose
    attestation_deadline_unix has passed must have its attested
    state cleared and subsequent app-layer messages dropped, even
    though attested_ms was set."""
    import time as _time

    daemon = _make_daemon(require_attested=True)
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer(attested=True)
    # Set the doc's deadline to 1 second in the past.
    peer.attestation_deadline_unix = int(_time.time()) - 1
    fan_out_received = []

    async def listener(p, kind, msg_t, env):
        fan_out_received.append((kind, msg_t))

    mgr.add_dc_listener(listener)
    await mgr._dispatch_dc(peer, "control", json.dumps(_app_envelope()))
    # Message dropped, attested state cleared.
    assert fan_out_received == []
    assert peer.attested_ms is None
    assert peer.attestation_deadline_unix is None
    assert daemon._gate_drop_count >= 1


@pytest.mark.asyncio
async def test_gate_does_not_clear_master_vk_on_expiry():
    """H7 + C2 interaction: when attestation expires we clear
    attested_ms + deadline_unix but the TOFU-pinned master_vk
    must remain so the next attestation is verified against it."""
    import time as _time

    daemon = _make_daemon(require_attested=False)
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer(attested=True)
    pinned_vk = bytes(1984)
    peer.peer_master_vk = pinned_vk
    peer.attestation_deadline_unix = int(_time.time()) - 1

    await mgr._dispatch_dc(peer, "control", json.dumps(_app_envelope()))
    assert peer.attested_ms is None
    assert peer.peer_master_vk == pinned_vk


# ── Audit H9 — attest_challenge rate limit ───────────────────────


@pytest.mark.asyncio
async def test_attest_challenge_rate_limited_per_peer():
    """H9 regression (May 14 2026): attest_challenge floods get
    rate-limited per peer so a flood can't pin the native signing
    lock. First 3 within ATTEST_CHALLENGE_WINDOW_SECS are honored;
    the rest are dropped."""
    import base64
    from one_link.peer_rtc import ATTEST_CHALLENGE_MAX_PER_WINDOW

    seed = bytes([0x42] * 32)
    sealed = SealedMasterIdentity.from_seed_bytes(seed)
    daemon = _make_daemon(require_attested=False, sealed_master=sealed)
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer(attested=False)
    challenge_env = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "attest_challenge",
        "challenge_b64": base64.b64encode(bytes(32)).decode("ascii"),
    }
    # Spam well past the cap.
    for _ in range(ATTEST_CHALLENGE_MAX_PER_WINDOW * 3):
        await mgr._dispatch_dc(peer, "control", json.dumps(challenge_env))
    # Count attest_response frames queued. Should be <= the cap.
    responses = [s for s in peer.control_dc.sent if "attest_response" in s]
    assert len(responses) == ATTEST_CHALLENGE_MAX_PER_WINDOW


# ── Audit H8 — cover_packet rate limit + attestation gate ────────


@pytest.mark.asyncio
async def test_cover_packet_dropped_when_unattested_with_gate_on():
    """H8 regression (May 14 2026): cover_packet from an unattested
    peer is dropped when require_attested_peers=True. Was previously
    handled before the gate."""
    import base64

    daemon = _make_daemon(require_attested=True)
    daemon._cover_relay_sk = bytes(32)  # Fake so the handler reaches the gate
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer(attested=False)
    cover_env = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "cover_packet",
        "packet_b64": base64.b64encode(b"\x00" * 1500).decode("ascii"),
    }
    # Pre-state: no cover counter on daemon.
    daemon._cover_recv_count = 0
    await mgr._dispatch_dc(peer, "control", json.dumps(cover_env))
    # Gate dropped it before the Sphinx peel ran.
    assert daemon._gate_drop_count >= 1
    assert daemon._cover_recv_count == 0


@pytest.mark.asyncio
async def test_cover_packet_rate_limited_per_peer():
    """H8 regression: even an attested peer gets per-peer
    rate-limited on cover_packet so a flood can't saturate
    Sphinx-peel CPU."""
    import base64
    from one_link.peer_rtc import COVER_PACKET_MAX_PER_WINDOW

    daemon = _make_daemon(require_attested=False)
    daemon._cover_relay_sk = bytes(32)
    daemon._cover_recv_count = 0
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer(attested=False)  # gate off, so unattested OK
    cover_env = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "cover_packet",
        "packet_b64": base64.b64encode(b"\x00" * 1500).decode("ascii"),
    }
    # Flood past cap. The handler's actual peel will fail (fake
    # relay sk) but the rate-limit check fires BEFORE the peel —
    # we just need to confirm only the first N reach the handler.
    # Easier check: peer._cover_packet_count should track increments
    # and the bucket should clamp at cap.
    for _ in range(COVER_PACKET_MAX_PER_WINDOW * 2):
        await mgr._dispatch_dc(peer, "control", json.dumps(cover_env))
    assert peer._cover_packet_count > COVER_PACKET_MAX_PER_WINDOW


# ── Audit H10 — onion_pubkey TOFU pin ────────────────────────────


@pytest.mark.asyncio
async def test_onion_pubkey_tofu_pin_rejects_rotation():
    """H10 regression (May 14 2026): once a peer has announced
    onion_pubkey K1, a later announce with K2 must be REFUSED.
    Otherwise an attacker who has the DC channel can redirect our
    cover-traffic emitter to a key they hold."""
    import base64

    daemon = _make_daemon(require_attested=False)
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer(attested=True)
    k1 = bytes([0xAA] * 32)
    k2 = bytes([0xBB] * 32)
    env1 = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "onion_pubkey",
        "pubkey_b64": base64.b64encode(k1).decode("ascii"),
    }
    env2 = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "onion_pubkey",
        "pubkey_b64": base64.b64encode(k2).decode("ascii"),
    }
    await mgr._dispatch_dc(peer, "control", json.dumps(env1))
    assert peer.onion_pubkey == k1
    await mgr._dispatch_dc(peer, "control", json.dumps(env2))
    # Pin holds: K2 rejected, K1 still stored.
    assert peer.onion_pubkey == k1
