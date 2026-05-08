"""v0.20.1 — Pair-by-QR end-to-end.

Desktop UI mints a one-shot pairing token + renders a QR. Phone
scans QR with camera. Phone opens /peer with the token + daemon
fingerprint + signaling URL embedded as query params. Phone
auto-pairs silently — no manual SAS, no copy/paste, no URL
typing.

  Reach:  the user-facing flow is "tap one button on laptop, scan
          one QR with phone, done." That's the experience the user
          asked for from the beginning.
  Hide:   /peer detects the pair query and hides ALL the manual
          surfaces (identity card, rendezvous card, manual
          signaling, SAS art). One status pill. One status line.
  Async:  identity provision + WebRTC handshake + DataChannel up
          all happen behind the scenes. Final state: "Connected.
          Your phone is now paired with this laptop."
  Depth:  no SAS prompt because possession-of-fresh-token IS the
          trust ceremony. The QR was on the laptop's screen, the
          token is single-use + 5-min TTL. If the user can scan
          the QR they have visual confirmation of the laptop.

Tests cover: desktop QR-mint UI markup + JS wiring; daemon
qr.svg endpoint shape + auth-gate + URL cap; phone-side
auto-pair detection (?pair=&fp=&ws= → trigger); auto-pair
hides manual cards; auto-pair status flow; signed offer
envelope shape; test surface exposes the new helpers.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="qr-pair-host",
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


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def peer_html() -> str:
    return Path("src/one_link/web/peer.html").read_text(encoding="utf-8")


def _snippet(html: str, needle: str, size: int = 2400) -> str:
    idx = html.find(needle)
    assert idx >= 0, f"missing {needle!r}"
    return html[idx:idx + size]


# ───────── desktop UI: "Pair a phone" surface ──────────────────────


def test_pair_phone_section_present(index_html: str):
    """The desktop UI has a dedicated 'Pair a phone' section in
    Settings → About — separate from the legacy 'Open desktop UI'
    surface so the user has one obvious primary path."""
    assert 'id="pair-phone-section"' in index_html
    assert "Pair a phone" in index_html
    assert 'id="btn-mint-pair"' in index_html
    assert 'id="pair-phone-qr-wrap"' in index_html


def test_legacy_connect_info_demoted_to_advanced(index_html: str):
    """The v0.15.4 'Connect another device' (URL-only desktop-UI
    flow) MUST be demoted to advanced tier so the new pair-by-QR
    is the only surface a default user sees."""
    idx = index_html.find('id="connect-info-section"')
    assert idx >= 0
    open_start = index_html.rfind("<div", 0, idx)
    open_end = index_html.find(">", idx)
    tag = index_html[open_start:open_end + 1]
    assert 'data-tier="advanced"' in tag


def test_mint_pair_button_handler_calls_endpoint(index_html: str):
    """Clicking 'Generate pairing QR' MUST POST to
    /api/v1/peer-rtc/mint-pairing — that's the only way to mint
    a fresh single-use token. Don't let a refactor swap to the
    legacy /api/connect-info (which doesn't have the trust
    properties)."""
    idx = index_html.find('"#btn-mint-pair"')
    handler = index_html.find("addEventListener", idx)
    snippet = index_html[handler:handler + 4000]
    assert '"/api/v1/peer-rtc/mint-pairing"' in snippet
    assert "api.post(" in snippet


def test_mint_response_renders_qr_via_pair_qr_endpoint(index_html: str):
    """The QR image src MUST point at /api/v1/peer-rtc/qr.svg with
    the lan_url passed via `u=`. Saves shipping a JS QR library."""
    idx = index_html.find('"#btn-mint-pair"')
    handler = index_html.find("addEventListener", idx)
    snippet = index_html[handler:handler + 4000]
    assert "/api/v1/peer-rtc/qr.svg?u=" in snippet
    assert "encodeURIComponent(info.lan_url)" in snippet


def test_mint_response_surfaces_lan_url_for_copy(index_html: str):
    """If the QR fails to render or the user can't scan, the URL
    is also shown as text + a Copy URL button."""
    idx = index_html.find('"#btn-mint-pair"')
    handler = index_html.find("addEventListener", idx)
    snippet = index_html[handler:handler + 4000]
    assert "info.lan_url" in snippet
    assert "navigator.clipboard.writeText" in snippet


def test_pair_phone_card_resets_on_settings_open(index_html: str):
    """Tokens expire in 5 min. We don't want a stale QR sitting
    around from a previous Settings open."""
    snippet = _snippet(index_html, "function refreshSettingsAbout()", 1200)
    assert "_resetPairPhoneCard()" in snippet
    reset = _snippet(index_html, "function _resetPairPhoneCard", 1500)
    assert "_activePairToken = null" in reset
    assert 'wrap.style.display = "none"' in reset


# ───────── daemon QR endpoint ──────────────────────────────────────


@pytest.mark.asyncio
async def test_pair_qr_requires_auth(http):
    """Auth-gated — only the desktop user (token holder) can render
    QR codes. An unauthenticated caller can't make us encode
    arbitrary URLs into QRs."""
    client, _ = http
    resp = await client.get("/api/v1/peer-rtc/qr.svg?u=http://example.com")
    assert resp.status == 401


@pytest.mark.asyncio
async def test_pair_qr_renders_svg(http):
    client, server = http
    resp = await client.get(
        "/api/v1/peer-rtc/qr.svg?u=http://192.168.1.42:7117/peer?pair=abc",
        headers={"Authorization": f"Bearer {server.token}"},
    )
    assert resp.status == 200
    ct = resp.headers.get("Content-Type", "")
    assert "svg" in ct
    body = await resp.text()
    assert body.startswith("<?xml")
    assert "<svg" in body
    assert "<path" in body


@pytest.mark.asyncio
async def test_pair_qr_no_store_cache(http):
    client, server = http
    resp = await client.get(
        "/api/v1/peer-rtc/qr.svg?u=http://example.com",
        headers={"Authorization": f"Bearer {server.token}"},
    )
    cache = resp.headers.get("Cache-Control", "")
    assert "no-store" in cache


@pytest.mark.asyncio
async def test_pair_qr_rejects_missing_url(http):
    client, server = http
    resp = await client.get(
        "/api/v1/peer-rtc/qr.svg",
        headers={"Authorization": f"Bearer {server.token}"},
    )
    assert resp.status == 400
    body = await resp.json()
    assert body["error"] == "missing_u"


@pytest.mark.asyncio
async def test_pair_qr_rejects_oversize_url(http):
    """Caps at 2KB. A QR holding more than that won't scan reliably
    on a phone camera; better to reject than render an unscannable
    QR."""
    client, server = http
    resp = await client.get(
        "/api/v1/peer-rtc/qr.svg?u=http://x.com/" + ("a" * 3000),
        headers={"Authorization": f"Bearer {server.token}"},
    )
    assert resp.status == 413


# ───────── phone-side auto-pair flow ───────────────────────────────


def test_autopair_card_present(peer_html: str):
    assert 'id="autopair-card"' in peer_html
    assert 'id="autopair-status"' in peer_html
    assert 'id="autopair-pill"' in peer_html
    assert 'id="autopair-host"' in peer_html


def test_autopair_card_hidden_until_pair_query(peer_html: str):
    idx = peer_html.find('id="autopair-card"')
    open_start = peer_html.rfind("<div", 0, idx)
    open_end = peer_html.find(">", idx)
    tag = peer_html[open_start:open_end + 1]
    assert "hidden" in tag


def test_detect_pair_query_helper_present(peer_html: str):
    """Single source of truth for 'should we auto-pair?'. Reads the
    URL query, returns null if missing required params, returns the
    parsed object otherwise. Don't let a refactor parse the query
    from elsewhere — keep this surface tight."""
    snippet = _snippet(peer_html, "function _detectPairQuery", 1200)
    assert 'params.get("pair")' in snippet
    assert 'params.get("fp")' in snippet
    assert 'params.get("ws")' in snippet
    # All three required — return null otherwise.
    assert "if (!pair || !fp || !ws) return null" in snippet


def test_autopair_uses_daemon_specific_dc_labels(peer_html: str):
    """The phone-side DataChannels MUST use the daemon-specific
    labels so the daemon can distinguish browser-↔-daemon channels
    from browser-↔-browser channels (different label set)."""
    snippet = _snippet(peer_html, "AUTOPAIR_DAEMON_CONTROL_LABEL", 800)
    assert '"one-link-daemon-control-v1"' in snippet
    assert '"one-link-daemon-bulk-v1"' in snippet


def test_autopair_hide_manual_cards_helper_present(peer_html: str):
    """Auto-pair MUST hide every manual card (identity, rendezvous,
    manual signaling, SAS, peers list, chat). User sees one
    status line, no clutter."""
    snippet = _snippet(peer_html, "function _autopairHideManualCards", 1500)
    for card_id in (
        "#identity-card",
        "#status-card",
        "#actions-card",
        "#unlock-card",
        "#rdz-card",
        "#webrtc-card",
        "#pair-card",
        "#peers-card",
        "#chat-card",
    ):
        assert card_id in snippet, f"hide path missing {card_id}"


def test_autopair_waits_for_identity(peer_html: str):
    """Identity must be unlocked + loaded before we can sign the
    offer envelope. _waitForIdentity polls state.rec for up to 12s."""
    snippet = _snippet(peer_html, "async function _waitForIdentity", 1200)
    assert "state.rec" in snippet
    assert "deadline" in snippet


def test_autopair_signs_offer_envelope(peer_html: str):
    """The offer envelope MUST carry pubkey + fingerprint +
    pair_token + ts + signature. Daemon's verify_offer_envelope
    rejects anything missing any of these."""
    snippet = _snippet(peer_html, "async function _runAutoPairFlow", 6000)
    assert "pubkey_b64u: rec.public_key_b64u" in snippet
    assert "fingerprint: rec.fingerprint" in snippet
    assert "pair_token: pair.pair_token" in snippet
    assert "ts: Date.now()" in snippet
    assert "_signEd25519(" in snippet
    assert "offerEnvelope.signature = bytesToB64Url(sig)" in snippet


def test_autopair_waits_for_ice_gathering(peer_html: str):
    """Better LAN reliability if we wait for ICE gathering to
    complete (or 2s cap) before sending the offer — sends a fully-
    populated SDP rather than relying on trickle-only."""
    snippet = _snippet(peer_html, "async function _runAutoPairFlow", 6000)
    assert "iceGatheringState" in snippet
    assert "icegatheringstatechange" in snippet


def test_autopair_persists_daemon_as_peer(peer_html: str):
    """On control:open, the daemon's fingerprint MUST be saved as
    a paired peer in OPFS so future /peer visits without ?pair=
    can recognize this daemon."""
    snippet = _snippet(peer_html, "async function _runAutoPairFlow", 6000)
    assert "savePeer({" in snippet
    assert 'paired_via: "qr"' in snippet
    assert 'fingerprint: pair.daemon_fingerprint' in snippet


def test_autopair_surfaces_clear_failure_states(peer_html: str):
    """Every failure path (no identity, no WebRTC, sign fail, send
    fail, daemon error, connection failed) MUST update the status
    line to a specific message — never leave the user with a
    stuck spinner."""
    snippet = _snippet(peer_html, "async function _runAutoPairFlow", 8000)
    for failure_label in (
        "no identity",
        "no webrtc",
        "offer failed",
        "sign failed",
        "ws failed",
        "send failed",
        "answer failed",
        "failed",
    ):
        assert failure_label in snippet, f"missing failure label: {failure_label}"


def test_autopair_cancel_button_tears_down(peer_html: str):
    """The user can cancel mid-flight. Cancel MUST close the
    WebSocket + the RTCPeerConnection so we don't leak."""
    snippet = _snippet(peer_html, "async function _runAutoPairFlow", 8000)
    assert '"#btn-autopair-cancel"' in snippet
    assert "ws.close()" in snippet
    assert "pc.close()" in snippet


# ───────── boot dispatch ──────────────────────────────────────────


def test_boot_detects_pair_query_first(peer_html: str):
    """Pair-query detection MUST run BEFORE boot()'s render so the
    manual identity card never flashes visible during the auto-pair
    flow. The user should never see the manual UX in pair mode."""
    idx = peer_html.find("const _pairQuery = _detectPairQuery();")
    assert idx >= 0
    # And manual cards are hidden BEFORE boot is awaited.
    snippet = peer_html[idx:idx + 1500]
    assert "_autopairHideManualCards()" in snippet
    assert "boot()" in snippet


def test_boot_chains_autopair_after_identity(peer_html: str):
    """boot() resolves once identity is provisioned. Then we kick
    off the auto-pair flow if a pair query is present. Chaining via
    .then() rather than awaiting before boot is fine because boot
    is what gives us state.rec."""
    idx = peer_html.find("const _pairQuery = _detectPairQuery();")
    snippet = peer_html[idx:idx + 1500]
    assert "boot().then(" in snippet
    assert "_runAutoPairFlow(_pairQuery)" in snippet


# ───────── test surface ───────────────────────────────────────────


def test_test_surface_exposes_pair_helpers(peer_html: str):
    snippet = _snippet(peer_html, "window.__oneLinkPeer", 4000)
    assert "_detectPairQuery" in snippet
    assert "_runAutoPairFlow" in snippet


# ───────── version pin ────────────────────────────────────────────


def test_peer_version_bumped(peer_html: str):
    assert 'version: "0.20.1"' in peer_html


def test_page_version_matches_package():
    from one_link import __version__
    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert f'PAGE_BUILT_FOR = "{__version__}"' in html
