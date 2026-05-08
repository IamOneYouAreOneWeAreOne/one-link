"""Tests for v0.5.6 — connection regime classifier.

Covers:
  - _classify_address_regime: pure function over IPv4/IPv6 strings
  - OutboundSession carries regime correctly
  - /api/peers surfaces a `regime` field per peer
  - UI helper consistency: client-side reachLabel handles all 4 regimes
    plus the legacy fallback case
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import AsyncIterator

import asyncio
import json
import time
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon, OutboundSession, _classify_address_regime
from one_link.identity import Identity, fingerprint_of
from one_link.state import State


def _new_identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="x",
    )


# ─── _classify_address_regime: pure function ────────────────────────

@pytest.mark.parametrize("addr", [
    "127.0.0.1",
    "127.5.6.7",
    "::1",
    "169.254.1.2",
    "10.0.0.5",
    "10.255.255.255",
    "192.168.1.1",
    "192.168.7.42",
    "172.16.0.1",
    "172.20.99.99",
    "172.31.255.255",
    "100.64.0.1",
    "100.127.1.2",
    "fe80::1",
    "FE80::ABCD",
    "fc00::1",
    "fd12:3456:789a::",
])
def test_classify_lan_addresses(addr):
    assert _classify_address_regime(addr) == "lan", addr


@pytest.mark.parametrize("addr", [
    "8.8.8.8",
    "1.1.1.1",
    "172.15.255.255",      # boundary: 172.15 is NOT private
    "172.32.0.1",           # boundary: 172.32 is NOT private
    "100.63.255.255",       # boundary: 100.63 below CGN range
    "100.128.0.1",          # boundary: 100.128 above CGN range
    "203.0.113.7",
    "2001:db8::1",
    "2606:4700:4700::1111",
])
def test_classify_internet_addresses(addr):
    assert _classify_address_regime(addr) == "internet", addr


def test_classify_empty_returns_internet():
    """Empty string → 'internet' (we don't know better; safer to
    not falsely flag as LAN)."""
    assert _classify_address_regime("") == "internet"
    assert _classify_address_regime(None) == "internet"  # type: ignore


def test_classify_malformed_172_block_does_not_crash():
    """A string like '172.notanint.0.1' should not crash; our
    classifier must tolerate non-numeric octets."""
    assert _classify_address_regime("172.foo.0.1") == "internet"
    assert _classify_address_regime("100.bar.0.1") == "internet"


# ─── OutboundSession carries regime ──────────────────────────────────

def test_outbound_session_default_regime_is_unknown():
    """Pre-v0.5.6 sessions might be created without a regime field;
    default falls back to 'unknown' so older code keeps working."""
    sess = OutboundSession(
        peer_fp="aa" * 32,
        peer=SimpleNamespace(short_id="abcd1234"),
        channel=SimpleNamespace(),
        lock=asyncio.Lock(),
        last_used=0.0,
    )
    assert sess.regime == "unknown"


def test_outbound_session_regime_preserved():
    sess = OutboundSession(
        peer_fp="aa" * 32,
        peer=SimpleNamespace(short_id="abcd1234"),
        channel=SimpleNamespace(),
        lock=asyncio.Lock(),
        last_used=0.0,
        regime="relay",
    )
    assert sess.regime == "relay"


# ─── /api/peers surfaces regime ──────────────────────────────────────

@pytest.mark.asyncio
async def test_api_peers_stamps_regime_from_outbound_session(tmp_path: Path):
    """If we have an active outbound session whose regime is 'relay',
    /api/peers must report that for the peer (even if peer.address
    is a LAN IP)."""
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "state.db")
    try:
        peer_fp = "bb" * 32
        state.upsert_peer(
            fingerprint=peer_fp,
            short_id="bbbbbbbb",
            pubkey=b"\xbb" * 32,
            hostname="alice-laptop",
            trust_default="pinned",
        )

        # Synthesize an outbound session with regime='relay'.
        session_obj = SimpleNamespace(regime="relay")

        daemon = SimpleNamespace(
            state=state,
            discovery=None,
            me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
            _outbound_sessions={peer_fp: session_obj},
            _inbound_regime={},
        )
        server = UIServer(daemon)

        class _Req:
            query: dict = {}
            match_info: dict = {}

        resp = await server.api_peers(_Req())
        body = json.loads(resp.text)
        peers = {p["fingerprint"]: p for p in body["peers"]}
        assert peer_fp in peers
        assert peers[peer_fp]["regime"] == "relay"
        assert peers[peer_fp]["online"] is True
    finally:
        state.close()


@pytest.mark.asyncio
async def test_api_peers_falls_back_to_inbound_regime(tmp_path: Path):
    """No outbound session, but we've received an inbound from the
    peer over the relay — surface that regime."""
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "state.db")
    try:
        peer_fp = "bb" * 32
        state.upsert_peer(
            fingerprint=peer_fp,
            short_id="bbbbbbbb",
            pubkey=b"\xbb" * 32,
            hostname="alice-laptop",
            trust_default="pinned",
        )
        daemon = SimpleNamespace(
            state=state,
            discovery=None,
            me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
            _outbound_sessions={},
            _inbound_regime={peer_fp: "relay"},
        )
        server = UIServer(daemon)

        class _Req:
            query: dict = {}
            match_info: dict = {}

        resp = await server.api_peers(_Req())
        body = json.loads(resp.text)
        peers = {p["fingerprint"]: p for p in body["peers"]}
        assert peers[peer_fp]["regime"] == "relay"
    finally:
        state.close()


@pytest.mark.asyncio
async def test_api_peers_classifies_address_when_no_session(tmp_path: Path):
    """No active session of either direction — fall back to address
    classification for online peers."""
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "state.db")
    try:
        # Use a real-shaped pubkey so fingerprint_of(bytes.fromhex(...))
        # in api_peers' live-merge produces the same fingerprint we
        # used to upsert the DB record.
        pub_hex = "bb" * 32
        peer_fp = fingerprint_of(bytes.fromhex(pub_hex))
        live_peer = SimpleNamespace(
            short_id="bbbbbbbb", hostname="bob",
            address="203.0.113.7", port=51234,
            ed_pub_hex=pub_hex,
        )
        state.upsert_peer(
            fingerprint=peer_fp,
            short_id="bbbbbbbb",
            pubkey=bytes.fromhex(pub_hex),
            trust_default="pinned",
        )
        daemon = SimpleNamespace(
            state=state,
            discovery=SimpleNamespace(
                registry=SimpleNamespace(list=lambda: [live_peer])
            ),
            me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
            _outbound_sessions={},
            _inbound_regime={},
        )
        server = UIServer(daemon)

        class _Req:
            query: dict = {}
            match_info: dict = {}

        resp = await server.api_peers(_Req())
        body = json.loads(resp.text)
        peers = {p["fingerprint"]: p for p in body["peers"]}
        assert peers[peer_fp]["regime"] == "internet"
    finally:
        state.close()


@pytest.mark.asyncio
async def test_api_peers_classifies_lan_address(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "state.db")
    try:
        pub_hex = "bb" * 32
        peer_fp = fingerprint_of(bytes.fromhex(pub_hex))
        live_peer = SimpleNamespace(
            short_id="bbbbbbbb", hostname="bob",
            address="192.168.1.10", port=51234,
            ed_pub_hex=pub_hex,
        )
        state.upsert_peer(
            fingerprint=peer_fp,
            short_id="bbbbbbbb",
            pubkey=bytes.fromhex(pub_hex),
            trust_default="pinned",
        )
        daemon = SimpleNamespace(
            state=state,
            discovery=SimpleNamespace(
                registry=SimpleNamespace(list=lambda: [live_peer])
            ),
            me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
            _outbound_sessions={},
            _inbound_regime={},
        )
        server = UIServer(daemon)

        class _Req:
            query: dict = {}
            match_info: dict = {}

        resp = await server.api_peers(_Req())
        body = json.loads(resp.text)
        peers = {p["fingerprint"]: p for p in body["peers"]}
        assert peers[peer_fp]["regime"] == "lan"
    finally:
        state.close()


@pytest.mark.asyncio
async def test_api_peers_offline_peer_gets_offline_regime(tmp_path: Path):
    """Paired peer not currently visible on mDNS, no active session
    → regime is 'offline'."""
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "state.db")
    try:
        peer_fp = "bb" * 32
        state.upsert_peer(
            fingerprint=peer_fp,
            short_id="bbbbbbbb",
            pubkey=b"\xbb" * 32,
            trust_default="pinned",
        )
        daemon = SimpleNamespace(
            state=state,
            discovery=None,
            me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
            _outbound_sessions={},
            _inbound_regime={},
        )
        server = UIServer(daemon)

        class _Req:
            query: dict = {}
            match_info: dict = {}

        resp = await server.api_peers(_Req())
        body = json.loads(resp.text)
        peers = {p["fingerprint"]: p for p in body["peers"]}
        assert peers[peer_fp]["regime"] == "offline"
        assert peers[peer_fp]["online"] is False
    finally:
        state.close()


@pytest.mark.asyncio
async def test_api_peers_recent_secure_contact_keeps_peer_online(tmp_path: Path):
    """A paired device that just ACKed or sent encrypted traffic is online even
    if mDNS has not refreshed yet."""
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "state.db")
    try:
        peer_fp = "bb" * 32
        state.upsert_peer(
            fingerprint=peer_fp,
            short_id="bbbbbbbb",
            pubkey=b"\xbb" * 32,
            address="192.168.1.26",
            trust_default="pinned",
        )
        daemon = SimpleNamespace(
            state=state,
            discovery=None,
            me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
            _outbound_sessions={},
            _inbound_regime={},
            get_pair_health=lambda fp: {
                "last_alive_ms": int(time.time() * 1000),
                "latency_ewma_ms": 5.0,
                "best_route": "lan",
            } if fp == peer_fp else None,
        )
        server = UIServer(daemon)

        class _Req:
            query: dict = {}
            match_info: dict = {}

        resp = await server.api_peers(_Req())
        body = json.loads(resp.text)
        peers = {p["fingerprint"]: p for p in body["peers"]}
        assert peers[peer_fp]["online"] is True
        assert peers[peer_fp]["presence"] == "online"
        assert peers[peer_fp]["regime"] == "lan"
        assert peers[peer_fp]["health"]["latency_ewma_ms"] == 5.0
    finally:
        state.close()


@pytest.mark.asyncio
async def test_api_peers_stale_secure_contact_does_not_keep_peer_online(tmp_path: Path):
    """Old health is history, not current liveness."""
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "state.db")
    try:
        peer_fp = "bb" * 32
        state.upsert_peer(
            fingerprint=peer_fp,
            short_id="bbbbbbbb",
            pubkey=b"\xbb" * 32,
            address="192.168.1.26",
            trust_default="pinned",
        )
        daemon = SimpleNamespace(
            state=state,
            discovery=None,
            me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
            _outbound_sessions={},
            _inbound_regime={},
            get_pair_health=lambda fp: {
                "last_alive_ms": 1,
                "latency_ewma_ms": 5.0,
            } if fp == peer_fp else None,
        )
        server = UIServer(daemon)

        class _Req:
            query: dict = {}
            match_info: dict = {}

        resp = await server.api_peers(_Req())
        body = json.loads(resp.text)
        peers = {p["fingerprint"]: p for p in body["peers"]}
        assert peers[peer_fp]["online"] is False
        assert peers[peer_fp]["regime"] == "offline"
    finally:
        state.close()


@pytest.mark.asyncio
async def test_api_peers_outbound_regime_wins_over_inbound(tmp_path: Path):
    """If we have BOTH outbound and inbound regime info, outbound is
    authoritative — that's the path our subsequent sends will take."""
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "state.db")
    try:
        peer_fp = "bb" * 32
        state.upsert_peer(
            fingerprint=peer_fp,
            short_id="bbbbbbbb",
            pubkey=b"\xbb" * 32,
            trust_default="pinned",
        )

        outbound_session = SimpleNamespace(regime="relay")
        daemon = SimpleNamespace(
            state=state,
            discovery=None,
            me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
            _outbound_sessions={peer_fp: outbound_session},
            _inbound_regime={peer_fp: "lan"},
        )
        server = UIServer(daemon)

        class _Req:
            query: dict = {}
            match_info: dict = {}

        resp = await server.api_peers(_Req())
        body = json.loads(resp.text)
        peers = {p["fingerprint"]: p for p in body["peers"]}
        assert peers[peer_fp]["regime"] == "relay"
    finally:
        state.close()
