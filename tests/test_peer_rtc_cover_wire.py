from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import pytest

from one_link.peer_rtc import PEER_DC_PROTOCOL_VERSION, BrowserPeer, BrowserPeerManager

try:
    from one_link_native import sphinx as _native_sphinx
    HAS_NATIVE = True
except ImportError:
    HAS_NATIVE = False
    _native_sphinx = None  # type: ignore[assignment]


class _StubDC:
    def __init__(self) -> None:
        self.readyState = "open"
        self.sent: list[str] = []

    def send(self, data: str) -> None:
        self.sent.append(data)


def _make_peer() -> BrowserPeer:
    peer = BrowserPeer(fingerprint="sha256:peer", pubkey_bytes=bytes(32))
    peer.control_dc = _StubDC()
    return peer


def _make_daemon() -> SimpleNamespace:
    sk, pk = _native_sphinx.generate_keypair()
    return SimpleNamespace(
        _cover_relay_sk=sk,
        _cover_relay_pk=pk,
        _cover_recv_count=0,
    )


@pytest.mark.skipif(not HAS_NATIVE, reason="one_link_native.sphinx unavailable")
def test_init_onion_announce_sends_relay_pubkey():
    daemon = _make_daemon()
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()

    assert mgr.init_onion_announce(peer) is True
    env = json.loads(peer.control_dc.sent[0])
    assert env["v"] == PEER_DC_PROTOCOL_VERSION
    assert env["t"] == "onion_pubkey"
    assert base64.b64decode(env["pubkey_b64"]) == daemon._cover_relay_pk


def test_init_onion_announce_without_cover_key_returns_false():
    mgr = BrowserPeerManager(SimpleNamespace())
    peer = _make_peer()

    assert mgr.init_onion_announce(peer) is False
    assert peer.control_dc.sent == []


@pytest.mark.skipif(not HAS_NATIVE, reason="one_link_native.sphinx unavailable")
@pytest.mark.asyncio
async def test_handle_onion_pubkey_records_valid_key():
    mgr = BrowserPeerManager(_make_daemon())
    peer = _make_peer()
    _sk, pk = _native_sphinx.generate_keypair()

    await mgr._handle_onion_pubkey(peer, {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "onion_pubkey",
        "pubkey_b64": base64.b64encode(pk).decode("ascii"),
    })

    assert peer.onion_pubkey == pk
    assert peer.onion_pubkey_received_ms is not None


@pytest.mark.asyncio
async def test_handle_onion_pubkey_rejects_bad_length():
    mgr = BrowserPeerManager(SimpleNamespace())
    peer = _make_peer()

    await mgr._handle_onion_pubkey(peer, {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "onion_pubkey",
        "pubkey_b64": base64.b64encode(bytes(16)).decode("ascii"),
    })

    assert peer.onion_pubkey is None


@pytest.mark.skipif(not HAS_NATIVE, reason="one_link_native.sphinx unavailable")
@pytest.mark.asyncio
async def test_handle_cover_packet_real_round_trip_ticks_counter():
    daemon = _make_daemon()
    mgr = BrowserPeerManager(daemon)
    peer = _make_peer()
    eph_sk, _ = _native_sphinx.generate_keypair()
    packet = _native_sphinx.build_cover_packet(
        eph_sk,
        [(bytes(32), daemon._cover_relay_pk)],
        512,
    )

    await mgr._handle_cover_packet(peer, {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "cover_packet",
        "packet_b64": base64.b64encode(packet).decode("ascii"),
    })

    assert daemon._cover_recv_count == 1


@pytest.mark.asyncio
async def test_handle_cover_packet_malformed_is_safe_drop():
    daemon = SimpleNamespace(_cover_relay_sk=bytes(32), _cover_recv_count=0)
    mgr = BrowserPeerManager(daemon)

    await mgr._handle_cover_packet(_make_peer(), {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "cover_packet",
        "packet_b64": "not base64",
    })

    assert daemon._cover_recv_count == 0
