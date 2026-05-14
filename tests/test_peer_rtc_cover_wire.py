"""Tests for the Row 6/7 wire-level cover-packet flow.

End-to-end: peer A announces its onion pubkey; peer B records it
and uses it as the destination for a real Sphinx cover packet sent
over the DC; peer A receives the packet, peels with its relay sk,
verifies the cover sentinel, drops.
"""

from __future__ import annotations

import asyncio
import base64
import json
from types import SimpleNamespace

import pytest

try:
    from one_link_native import sphinx as _native_sphinx
    HAS_NATIVE: bool = True
except ImportError:
    HAS_NATIVE = False
    _native_sphinx = None  # type: ignore[assignment]

from one_link.peer_rtc import (
    PEER_DC_PROTOCOL_VERSION,
    BrowserPeer,
    BrowserPeerManager,
)

pytestmark = pytest.mark.skipif(
    not HAS_NATIVE,
    reason="one_link_native.sphinx not built; run `maturin develop --release`",
)


class _StubDC:
    """Minimal RTCDataChannel stub used to capture sent envelopes."""

    def __init__(self) -> None:
        self.readyState = "open"
        self.sent: list[str] = []

    def send(self, data: str) -> None:
        self.sent.append(data)


def _make_daemon_with_relay() -> object:
    """Build a daemon-like with a freshly minted Sphinx relay keypair
    + cover-recv counter."""
    sk, pk = _native_sphinx.generate_keypair()
    return SimpleNamespace(
        _cover_relay_sk=sk,
        _cover_relay_pk=pk,
        _cover_recv_count=0,
    )


def _make_peer(fp: str = "sha256:test") -> BrowserPeer:
    p = BrowserPeer(fingerprint=fp, pubkey_bytes=bytes(32))
    p.control_dc = _StubDC()
    p.bulk_dc = _StubDC()
    return p


# ── onion_pubkey announce ───────────────────────────────────────


def test_browser_peer_onion_pubkey_state_defaults_to_none():
    p = _make_peer()
    assert p.onion_pubkey is None
    assert p.onion_pubkey_received_ms is None


def test_init_onion_announce_sends_pubkey():
    daemon = _make_daemon_with_relay()
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()
    ok = mgr.init_onion_announce(peer)
    assert ok is True
    sent = peer.control_dc.sent
    assert len(sent) == 1
    env = json.loads(sent[0])
    assert env["t"] == "onion_pubkey"
    assert env["v"] == PEER_DC_PROTOCOL_VERSION
    pk = base64.b64decode(env["pubkey_b64"])
    assert pk == daemon._cover_relay_pk


def test_init_onion_announce_without_relay_returns_false():
    daemon = SimpleNamespace()  # no _cover_relay_pk
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()
    assert mgr.init_onion_announce(peer) is False
    assert peer.control_dc.sent == []


@pytest.mark.asyncio
async def test_handle_onion_pubkey_records_pubkey():
    daemon = _make_daemon_with_relay()
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()
    # Construct an incoming onion_pubkey envelope.
    incoming_pk = _native_sphinx.generate_keypair()[1]
    env = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "onion_pubkey",
        "pubkey_b64": base64.b64encode(incoming_pk).decode("ascii"),
    }
    await mgr._handle_onion_pubkey(peer, env)
    assert peer.onion_pubkey == incoming_pk
    assert peer.onion_pubkey_received_ms is not None


@pytest.mark.asyncio
async def test_handle_onion_pubkey_rejects_wrong_length():
    daemon = _make_daemon_with_relay()
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()
    env = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "onion_pubkey",
        "pubkey_b64": base64.b64encode(bytes(16)).decode("ascii"),  # too short
    }
    await mgr._handle_onion_pubkey(peer, env)
    assert peer.onion_pubkey is None


# ── cover_packet receipt ────────────────────────────────────────


@pytest.mark.asyncio
async def test_handle_cover_packet_real_round_trip():
    """Build a real Sphinx cover packet bound for the daemon's relay,
    feed it through the handler, confirm the recv counter ticks."""
    daemon = _make_daemon_with_relay()
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()
    # Build a 1-hop cover packet bound for the daemon's pubkey.
    eph_sk, _eph_pk = _native_sphinx.generate_keypair()
    circuit = [(bytes(32), daemon._cover_relay_pk)]
    packet = _native_sphinx.build_cover_packet(eph_sk, circuit, 512)
    env = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "cover_packet",
        "packet_b64": base64.b64encode(packet).decode("ascii"),
    }
    await mgr._handle_cover_packet(peer, env)
    # Real cover packet → recv counter ticked.
    assert daemon._cover_recv_count == 1


@pytest.mark.asyncio
async def test_handle_cover_packet_wrong_sentinel_dropped():
    """A Sphinx packet that peels but lacks the cover sentinel
    (i.e., a real app-layer packet) must NOT increment the cover
    recv counter."""
    daemon = _make_daemon_with_relay()
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()
    # Build a non-cover Sphinx packet via build_sphinx.
    eph_sk, _eph_pk = _native_sphinx.generate_keypair()
    circuit = [(bytes(32), daemon._cover_relay_pk)]
    packet = _native_sphinx.build_sphinx(eph_sk, circuit, b"real payload here")
    env = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "cover_packet",
        "packet_b64": base64.b64encode(packet).decode("ascii"),
    }
    await mgr._handle_cover_packet(peer, env)
    # Sentinel absent → recv counter stays at 0.
    assert daemon._cover_recv_count == 0


@pytest.mark.asyncio
async def test_handle_cover_packet_malformed_dropped_silently():
    daemon = _make_daemon_with_relay()
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()
    env = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "cover_packet",
        "packet_b64": "not-real-base64!!!",
    }
    # Must not raise.
    await mgr._handle_cover_packet(peer, env)
    assert daemon._cover_recv_count == 0


@pytest.mark.asyncio
async def test_handle_cover_packet_no_relay_skips():
    """A daemon without a cover relay (e.g., cover-traffic disabled)
    silently drops incoming cover packets."""
    daemon = SimpleNamespace()  # no _cover_relay_sk
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()
    env = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "cover_packet",
        "packet_b64": base64.b64encode(bytes(2000)).decode("ascii"),
    }
    await mgr._handle_cover_packet(peer, env)
    # No assert needed beyond not-raising.


# ── Full round trip: announce → build → send → peel ─────────────


@pytest.mark.asyncio
async def test_full_wire_cover_round_trip_two_daemons():
    """Two daemon stubs A + B exchange onion pubkeys; A builds a
    cover packet to B; B receives + peels + drops; B's recv
    counter ticks."""
    daemon_a = _make_daemon_with_relay()
    daemon_b = _make_daemon_with_relay()
    mgr_a = BrowserPeerManager(daemon_a)
    mgr_b = BrowserPeerManager(daemon_b)
    # A's view of B + B's view of A.
    a_view_of_b = _make_peer("sha256:b")
    b_view_of_a = _make_peer("sha256:a")

    # A announces its pubkey → B receives.
    mgr_a.init_onion_announce(a_view_of_b)
    announce_env = json.loads(a_view_of_b.control_dc.sent[0])
    await mgr_b._handle_onion_pubkey(b_view_of_a, announce_env)
    assert b_view_of_a.onion_pubkey == daemon_a._cover_relay_pk

    # B announces its pubkey → A receives.
    mgr_b.init_onion_announce(b_view_of_a)
    announce_env_b = json.loads(b_view_of_a.control_dc.sent[-1])
    await mgr_a._handle_onion_pubkey(a_view_of_b, announce_env_b)
    assert a_view_of_b.onion_pubkey == daemon_b._cover_relay_pk

    # Now A builds a real cover packet to B and sends it.
    eph_sk, _ = _native_sphinx.generate_keypair()
    circuit = [(bytes(32), a_view_of_b.onion_pubkey)]
    packet = _native_sphinx.build_cover_packet(eph_sk, circuit, 512)
    cover_env = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "cover_packet",
        "packet_b64": base64.b64encode(packet).decode("ascii"),
    }
    # B receives the packet via dispatch.
    await mgr_b._handle_cover_packet(b_view_of_a, cover_env)
    assert daemon_b._cover_recv_count == 1
