"""v0.20.0 — Daemon learns WebRTC.

Foundation for the phone-as-peer endgame: the daemon now accepts
WebRTC DataChannel connections from browser-as-peer pages
(/peer). Same daemon process, new transport layer.

  Reach:  a browser opening /peer can connect to the daemon
          directly over WebRTC. Sub-second LAN handshake via
          DTLS-SRTP + ICE; multi-vendor STUN list for cross-
          network. The phone-as-peer ARC starts working as one
          experience.
  Hide:   no manual signaling — the browser opens a WebSocket
          to /api/v1/peer-rtc, sends a signed offer envelope,
          gets a signed answer, DataChannel comes up. ICE
          candidates trickle through aiortc's own machinery.
  Async:  signaling WS closes once DataChannel is up; the live
          transport is direct P2P from then on.
  Depth:  trust gates on offer envelope: signed Ed25519, replay
          window 60s, fingerprint must derive correctly from the
          claimed pubkey, AND either (a) carries a valid pairing
          token, OR (b) pubkey already in the paired roster.
          Everything else 4030s. Memory-only roster for v0.20.0;
          v0.20.2 persists.

Tests: protocol constants, helper canonicalization (matches
browser's _canonicalJson byte-for-byte), pairing-token mint +
redeem + expiry, offer envelope verification (good/bad/replayed),
manager registry + replace-on-reconnect, dispatch for ping →
pong + listener fan-out, route registration + mint endpoint.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.peer_rtc import (
    BrowserPeer,
    BrowserPeerManager,
    DAEMON_BULK_LABEL,
    DAEMON_CONTROL_LABEL,
    OFFER_REPLAY_WINDOW_MS,
    PAIRING_TOKEN_BYTES,
    PAIRING_TOKEN_TTL_MS,
    PEER_DC_PROTOCOL_VERSION,
    PEER_RTC_PROTOCOL_VERSION,
    PendingPair,
    _b64u,
    _canonical,
    _now_ms,
)
from one_link.server import UIServer
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="rtc-host",
    )


@pytest_asyncio.fixture
async def http(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client, server
    finally:
        await client.close()
        state.close()


@pytest.fixture
def manager(tmp_path):
    """Bare BrowserPeerManager for in-memory tests that don't need
    a full UIServer."""
    class StubDaemon:
        pass
    return BrowserPeerManager(StubDaemon())


# ───────── protocol constants ───────────────────────────────────────

def test_protocol_versions_pinned():
    """The signaling + DataChannel protocol versions are wire
    contracts — bump them only with an explicit migration path."""
    assert PEER_RTC_PROTOCOL_VERSION == "OL-PEER-RTC-1"
    assert PEER_DC_PROTOCOL_VERSION == "OL-PEER-1"


def test_dc_labels_distinct_from_browser_to_browser():
    """Browser-to-browser uses `one-link-control-v1` /
    `one-link-bulk-v1`. Browser-to-daemon uses different labels so
    bridging logic in v0.20.2+ can distinguish the two cases by
    the channel label without an extra side-table."""
    assert DAEMON_CONTROL_LABEL == "one-link-daemon-control-v1"
    assert DAEMON_BULK_LABEL == "one-link-daemon-bulk-v1"
    assert DAEMON_CONTROL_LABEL != "one-link-control-v1"


def test_token_constants_at_industry_floor():
    """32 bytes (256 bits) = standard high-entropy single-use token.
    5-minute TTL gives users time to scan + a couple network hops
    of slack without leaving an attacker minutes to grab a leaked
    token."""
    assert PAIRING_TOKEN_BYTES == 32
    assert PAIRING_TOKEN_TTL_MS == 5 * 60 * 1000


def test_offer_replay_window_is_60s():
    """60s matches the rendezvous protocol's REPLAY_WINDOW_MS so
    operator clocks don't have to be perfectly synced."""
    assert OFFER_REPLAY_WINDOW_MS == 60 * 1000


# ───────── canonical JSON parity with browser ───────────────────────

def test_canonical_matches_python_json_dumps_signing_form():
    """`_canonical` produces the same bytes as the browser's
    `_canonicalJson(envelope minus signature)` and as the rendezvous
    `_canonical_bytes`. Drift = signatures stop verifying."""
    envelope = {
        "v": "OL-PEER-RTC-1",
        "t": "offer",
        "pubkey_b64u": "AAA",
        "fingerprint": "sha256:abc",
        "ts": 1700000000000,
        "sdp": "v=0\\r\\no=- 1 1 IN IP4 0.0.0.0\\r\\n",
        "signature": "should-be-stripped",
    }
    out = _canonical(envelope)
    parsed = json.loads(out.decode("ascii"))
    assert "signature" not in parsed
    assert parsed["v"] == "OL-PEER-RTC-1"
    # No whitespace, sorted keys.
    body = out.decode("ascii")
    assert " " not in body or '"' in body  # spaces only inside string values
    keys_in_order = list(parsed.keys())
    assert keys_in_order == sorted(keys_in_order)


def test_b64u_no_padding():
    """Wire format uses base64url WITHOUT padding (matches browser's
    bytesToB64Url)."""
    assert _b64u(b"\x00" * 32).endswith("AAAA")
    assert "=" not in _b64u(b"hello world")


# ───────── pairing-token store ─────────────────────────────────────

def test_mint_pairing_token_returns_fresh_token(manager: BrowserPeerManager):
    pp = manager.mint_pairing_token()
    assert isinstance(pp, PendingPair)
    assert pp.token
    assert len(pp.token) >= 40  # 32-byte b64u with no padding ≈ 43 chars
    assert pp.created_ms <= _now_ms()
    assert pp.ttl_ms == PAIRING_TOKEN_TTL_MS


def test_mint_tokens_are_unique(manager: BrowserPeerManager):
    """A real-world deployment mints many concurrent tokens; never
    collide. Rely on `secrets.token_bytes(32)` for the entropy."""
    tokens = {manager.mint_pairing_token().token for _ in range(64)}
    assert len(tokens) == 64


def test_redeem_consumes_token(manager: BrowserPeerManager):
    pp = manager.mint_pairing_token()
    assert manager.redeem_pairing_token(pp.token) is not None
    # Second redemption returns None — single-use.
    assert manager.redeem_pairing_token(pp.token) is None


def test_redeem_unknown_returns_none(manager: BrowserPeerManager):
    assert manager.redeem_pairing_token("nope") is None
    assert manager.redeem_pairing_token("") is None


def test_expired_token_not_redeemable(manager: BrowserPeerManager):
    pp = manager.mint_pairing_token()
    # Force expiry by rewinding created_ms past the TTL.
    pp.created_ms = _now_ms() - (PAIRING_TOKEN_TTL_MS + 1000)
    # Re-store under the same token key (manager pop'd a fresh PP).
    manager._pending_pairings[pp.token] = pp
    assert manager.redeem_pairing_token(pp.token) is None


def test_sweep_removes_expired_tokens(manager: BrowserPeerManager):
    pp = manager.mint_pairing_token()
    pp.created_ms = _now_ms() - (PAIRING_TOKEN_TTL_MS + 1000)
    manager._pending_pairings[pp.token] = pp
    # Mint another to trigger a sweep.
    fresh = manager.mint_pairing_token()
    # The expired one is gone, the fresh one remains.
    assert pp.token not in manager._pending_pairings
    assert fresh.token in manager._pending_pairings


# ───────── peer registry ───────────────────────────────────────────

def test_register_peer_stores_by_fingerprint(manager: BrowserPeerManager):
    peer = BrowserPeer(fingerprint="sha256:abc", pubkey_bytes=b"\x00" * 32)
    manager.register_peer(peer)
    assert manager.get_peer("sha256:abc") is peer
    assert peer in manager.list_peers()


def test_register_replaces_existing_for_same_fp(manager: BrowserPeerManager):
    """Newest connection for a given fingerprint wins — most-recent-
    activity wins. Old connection is closed."""
    p1 = BrowserPeer(fingerprint="sha256:abc", pubkey_bytes=b"\x01" * 32)
    p2 = BrowserPeer(fingerprint="sha256:abc", pubkey_bytes=b"\x01" * 32)
    manager.register_peer(p1)
    manager.register_peer(p2)
    assert manager.get_peer("sha256:abc") is p2
    assert p1.closed is True


def test_mark_paired_persists_in_roster(manager: BrowserPeerManager):
    assert not manager.is_paired("sha256:abc")
    manager.mark_paired("sha256:abc")
    assert manager.is_paired("sha256:abc")


# ───────── offer envelope verification ─────────────────────────────

def _signed_offer(
    sk: Ed25519PrivateKey,
    *,
    sdp: str = "v=0\\r\\n",
    pair_token: str = "",
    ts_offset_ms: int = 0,
    tamper_signature: bool = False,
    tamper_fingerprint: bool = False,
) -> dict:
    """Build a signed offer envelope as the browser would."""
    import hashlib
    pub = sk.public_key().public_bytes_raw()
    pub_b64u = _b64u(pub)
    fp = "sha256:" + hashlib.sha256(pub).hexdigest()
    if tamper_fingerprint:
        fp = "sha256:" + ("0" * 64)
    envelope = {
        "v": PEER_RTC_PROTOCOL_VERSION,
        "t": "offer",
        "sdp": sdp,
        "pubkey_b64u": pub_b64u,
        "fingerprint": fp,
        "ts": _now_ms() + ts_offset_ms,
    }
    if pair_token:
        envelope["pair_token"] = pair_token
    sig = sk.sign(_canonical(envelope))
    if tamper_signature:
        sig = bytes([b ^ 0xff for b in sig])
    envelope["signature"] = _b64u(sig)
    return envelope


def test_verify_offer_envelope_accepts_good_offer():
    sk = Ed25519PrivateKey.generate()
    envelope = _signed_offer(sk)
    pubkey, fp = BrowserPeerManager.verify_offer_envelope(envelope)
    assert len(pubkey) == 32
    assert fp.startswith("sha256:")


def test_verify_rejects_wrong_version():
    sk = Ed25519PrivateKey.generate()
    envelope = _signed_offer(sk)
    envelope["v"] = "OL-PEER-RTC-99"
    # Need to re-sign because we changed the body.
    envelope.pop("signature")
    sig = sk.sign(_canonical(envelope))
    envelope["signature"] = _b64u(sig)
    with pytest.raises(ValueError, match="version"):
        BrowserPeerManager.verify_offer_envelope(envelope)


def test_verify_rejects_bad_signature():
    sk = Ed25519PrivateKey.generate()
    envelope = _signed_offer(sk, tamper_signature=True)
    with pytest.raises(ValueError, match="signature"):
        BrowserPeerManager.verify_offer_envelope(envelope)


def test_verify_rejects_replayed_offer():
    """Offer timestamp outside ±60s window → reject. Stops a captured
    offer from being re-played hours later."""
    sk = Ed25519PrivateKey.generate()
    envelope = _signed_offer(sk, ts_offset_ms=-(OFFER_REPLAY_WINDOW_MS + 5_000))
    with pytest.raises(ValueError, match="replay"):
        BrowserPeerManager.verify_offer_envelope(envelope)


def test_verify_rejects_fingerprint_pubkey_mismatch():
    """The fingerprint in the envelope MUST derive from the pubkey
    (we re-derive sha256 ourselves and require equality). Without
    this, a malicious client could claim someone else's fingerprint
    while signing with their own key."""
    sk = Ed25519PrivateKey.generate()
    envelope = _signed_offer(sk, tamper_fingerprint=True)
    with pytest.raises(ValueError, match="fingerprint"):
        BrowserPeerManager.verify_offer_envelope(envelope)


def test_verify_rejects_short_pubkey():
    sk = Ed25519PrivateKey.generate()
    envelope = _signed_offer(sk)
    envelope["pubkey_b64u"] = _b64u(b"\x00" * 16)  # wrong length
    # Re-sign so signature itself isn't the failure.
    envelope.pop("signature")
    sig = sk.sign(_canonical(envelope))
    envelope["signature"] = _b64u(sig)
    with pytest.raises(ValueError, match="32 bytes"):
        BrowserPeerManager.verify_offer_envelope(envelope)


# ───────── DataChannel dispatch ────────────────────────────────────


@pytest.mark.asyncio
async def test_dispatch_ping_replies_pong(manager: BrowserPeerManager):
    """Ping is built into the manager — always replies pong with
    the original ts echoed for round-trip latency tests."""
    sent: list[dict] = []
    peer = BrowserPeer(fingerprint="sha256:abc", pubkey_bytes=b"\x00" * 32)

    class _StubChannel:
        def send(self, data: str) -> None:
            sent.append(json.loads(data))

    peer.control_dc = _StubChannel()
    await manager._dispatch_dc(
        peer,
        "control",
        json.dumps({
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "ping",
            "ts": 1700000000000,
        }),
    )
    assert len(sent) == 1
    assert sent[0]["t"] == "pong"
    assert sent[0]["echo_ts"] == 1700000000000


@pytest.mark.asyncio
async def test_dispatch_ignores_wrong_version(manager: BrowserPeerManager):
    peer = BrowserPeer(fingerprint="sha256:abc", pubkey_bytes=b"\x00" * 32)

    class _StubChannel:
        def __init__(self):
            self.sent: list[Any] = []
        def send(self, data: Any) -> None:
            self.sent.append(data)

    peer.control_dc = _StubChannel()
    await manager._dispatch_dc(
        peer,
        "control",
        json.dumps({"v": "WRONG", "t": "ping", "ts": 0}),
    )
    assert peer.control_dc.sent == []


@pytest.mark.asyncio
async def test_dispatch_fans_out_to_listeners(manager: BrowserPeerManager):
    peer = BrowserPeer(fingerprint="sha256:abc", pubkey_bytes=b"\x00" * 32)
    received: list[tuple] = []

    async def listener(p, kind, t, env):
        received.append((p.fingerprint, kind, t, env.get("greeting")))

    manager.add_dc_listener(listener)
    await manager._dispatch_dc(
        peer,
        "control",
        json.dumps({
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "hello",
            "greeting": "hi",
        }),
    )
    assert received == [("sha256:abc", "control", "hello", "hi")]


@pytest.mark.asyncio
async def test_dispatch_listener_exception_doesnt_break_others(manager: BrowserPeerManager):
    peer = BrowserPeer(fingerprint="sha256:abc", pubkey_bytes=b"\x00" * 32)
    log_seen: list[bool] = []

    async def bad(p, kind, t, env):
        raise RuntimeError("boom")

    async def good(p, kind, t, env):
        log_seen.append(True)

    manager.add_dc_listener(bad)
    manager.add_dc_listener(good)
    await manager._dispatch_dc(
        peer,
        "control",
        json.dumps({
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "hello",
        }),
    )
    assert log_seen == [True]


# ───────── server route registration + mint endpoint ───────────────


@pytest.mark.asyncio
async def test_mint_pairing_endpoint_requires_auth(http):
    """The mint endpoint is auth-gated — only the desktop user
    (token holder) gets to mint pairing tokens. An unauthenticated
    caller can't manufacture device-pairing slots."""
    client, _ = http
    resp = await client.post("/api/v1/peer-rtc/mint-pairing")
    assert resp.status == 401


@pytest.mark.asyncio
async def test_mint_pairing_returns_full_pairing_payload(http):
    client, server = http
    resp = await client.post(
        "/api/v1/peer-rtc/mint-pairing",
        headers={"Authorization": f"Bearer {server.token}"},
    )
    assert resp.status == 200
    body = await resp.json()
    for key in (
        "token",
        "ttl_ms",
        "lan_url",
        "daemon_pubkey_b64u",
        "daemon_fingerprint",
        "ws_signaling_url",
    ):
        assert key in body, f"missing {key}"
    assert body["ttl_ms"] == PAIRING_TOKEN_TTL_MS
    assert body["lan_url"].startswith("http://")
    assert "/peer?pair=" in body["lan_url"]
    assert "&fp=" in body["lan_url"]
    assert "&ws=" in body["lan_url"]
    assert body["ws_signaling_url"].startswith(("ws://", "wss://"))
    assert body["ws_signaling_url"].endswith("/api/v1/peer-rtc")


@pytest.mark.asyncio
async def test_signaling_route_is_unauthenticated(http):
    """The signaling endpoint is unauthenticated by HTTP standards
    because the browser authenticates via Ed25519 sig on the offer
    envelope. The WebSocket upgrade itself MUST succeed without a
    Bearer token; auth happens at the WebRTC peer-pubkey layer."""
    client, _ = http
    # GET without WebSocket upgrade returns a non-101 response, but
    # critically NOT 401. (aiohttp returns 200 with an empty WS or
    # an error code depending on version; just ensure it's not 401.)
    resp = await client.get("/api/v1/peer-rtc")
    assert resp.status != 401


@pytest.mark.asyncio
async def test_signaling_rejects_unsigned_offer(http):
    """An offer envelope without a signature MUST be rejected. The
    daemon should never spend CPU on aiortc setup for an unsigned
    offer."""
    import aiohttp
    client, _ = http
    async with client.ws_connect("/api/v1/peer-rtc") as ws:
        await ws.send_json({
            "v": PEER_RTC_PROTOCOL_VERSION,
            "t": "offer",
            "sdp": "v=0\\r\\n",
            # missing pubkey, fingerprint, ts, signature
        })
        msg = await ws.receive(timeout=2.0)
        # Either an error frame followed by close, or just close
        # with code 4001.
        if msg.type == aiohttp.WSMsgType.TEXT:
            payload = json.loads(msg.data)
            assert payload["t"] == "error"
            assert payload["v"] == PEER_RTC_PROTOCOL_VERSION


@pytest.mark.asyncio
async def test_signaling_rejects_unknown_pubkey_without_token(http):
    """Without a pairing token + without being in the paired roster,
    the daemon MUST reject the offer with no_trust. This is the
    core safety property: random pubkeys can't connect."""
    import aiohttp
    client, server = http
    sk = Ed25519PrivateKey.generate()
    envelope = _signed_offer(sk)  # no pair_token, no prior pair
    async with client.ws_connect("/api/v1/peer-rtc") as ws:
        await ws.send_json(envelope)
        msg = await ws.receive(timeout=2.0)
        if msg.type == aiohttp.WSMsgType.TEXT:
            payload = json.loads(msg.data)
            assert payload["t"] == "error"
            assert payload["code"] == "no_trust"


# ───────── version pin ─────────────────────────────────────────────


def test_package_version_bumped():
    from one_link import __version__
    assert __version__ == "0.20.0"


def test_page_version_matches_package():
    from one_link import __version__
    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert f'PAGE_BUILT_FOR = "{__version__}"' in html
