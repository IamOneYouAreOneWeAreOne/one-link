"""v0.15.4 — Connect-another-device QR code in About settings.

Ship-spec: scanning a QR with the phone's camera is much lower
friction than typing a 60-char URL with a 43-char token. The
desktop UI fetches /api/connect-info + /api/connect-info/qr.svg
and renders both in the About pane. Only renders when the daemon
is LAN-bound; loopback URLs are useless on a phone.

  Reach:  user opens settings, scans QR, phone loads One Link.
          No URL typing, no token paste-fumbling.
  Hide:   the section short-circuits to a "pass --lan" hint when
          the daemon's bound to 127.0.0.1. Don't tell users to
          scan a code that won't work.
  Async:  endpoints are auth-gated — they expose the token, only
          the already-authenticated UI sees them.
  Depth:  the SVG endpoint sets Cache-Control: no-store so a
          token rotation propagates immediately (browsers cache
          aggressively on Service-Worker-controlled origins).
          409 + JSON body on loopback so the client can render
          the hint instead of an empty <img>.

Tests cover: endpoint auth, JSON shape, SVG rendering, loopback
short-circuit, no-store header, UI markup wiring.
"""

from __future__ import annotations

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
        fingerprint=fp, short_id=fp[:8], hostname="qr-host",
    )


@pytest_asyncio.fixture
async def http_loopback(tmp_path: Path, monkeypatch):
    """Daemon bound to 127.0.0.1 — connect-info should return
    `lan_bound: false`."""
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    monkeypatch.delenv("ONE_LINK_BIND_HOST", raising=False)
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
    # Force the bind_host to 127.0.0.1 so the connect_info logic
    # treats this as loopback. We're using TestClient (not the real
    # listener) so we set the attribute directly.
    server.bind_host = "127.0.0.1"
    server.port = 7117  # any value; the URL just needs the field
    try:
        yield client, server
    finally:
        await client.close()
        state.close()


@pytest_asyncio.fixture
async def http_lan(tmp_path: Path, monkeypatch):
    """Daemon "bound" to 0.0.0.0 — connect-info should return
    `lan_bound: true` and the QR endpoint should serve SVG."""
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    monkeypatch.setenv("ONE_LINK_BIND_HOST", "0.0.0.0")
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
    server.bind_host = "0.0.0.0"
    server.port = 7117
    try:
        yield client, server
    finally:
        await client.close()
        state.close()


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── auth ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_connect_info_requires_auth(http_lan):
    """The endpoint MUST 401 without the token. It exposes the URL
    + token, so unauthenticated callers must not see it."""
    client, _ = http_lan
    resp = await client.get("/api/connect-info")
    assert resp.status == 401


@pytest.mark.asyncio
async def test_connect_qr_requires_auth(http_lan):
    """Same auth gate on the SVG endpoint."""
    client, _ = http_lan
    resp = await client.get("/api/connect-info/qr.svg")
    assert resp.status == 401


# ───────── JSON shape ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_connect_info_lan_shape(http_lan):
    """LAN-bound daemon: returns a fully-formed payload with the
    canonical keys the UI relies on."""
    client, server = http_lan
    resp = await client.get(
        "/api/connect-info",
        headers={"Authorization": f"Bearer {server.token}"},
    )
    assert resp.status == 200
    body = await resp.json()
    for key in (
        "lan_ip",
        "port",
        "token",
        "bind_host",
        "lan_bound",
        "lan_url",
    ):
        assert key in body, f"missing {key} in connect-info payload"
    assert body["bind_host"] == "0.0.0.0"
    assert body["token"] == server.token
    assert body["lan_url"].startswith("http://")
    assert f":{server.port}/?t={server.token}" in body["lan_url"]


@pytest.mark.asyncio
async def test_connect_info_loopback_shape(http_loopback):
    """Loopback-bound daemon: lan_bound MUST be false so the UI
    short-circuits to the "pass --lan" hint instead of rendering
    a useless QR."""
    client, server = http_loopback
    resp = await client.get(
        "/api/connect-info",
        headers={"Authorization": f"Bearer {server.token}"},
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["bind_host"] == "127.0.0.1"
    assert body["lan_bound"] is False
    # The URL still uses 127.0.0.1 — never accidentally leak a LAN
    # IP when the daemon is loopback.
    assert "127.0.0.1" in body["lan_url"]


# ───────── SVG rendering ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_connect_qr_returns_svg(http_lan):
    """LAN-bound: the QR endpoint MUST return a real SVG with
    image/svg+xml content type — not a placeholder, not JSON."""
    client, server = http_lan
    resp = await client.get(
        "/api/connect-info/qr.svg",
        headers={"Authorization": f"Bearer {server.token}"},
    )
    assert resp.status == 200
    ct = resp.headers.get("Content-Type", "")
    assert "svg" in ct
    body = await resp.text()
    # Real QR SVG starts with the XML preamble + an <svg ...> root.
    assert body.startswith("<?xml")
    assert "<svg" in body
    # And contains <path ...> data, the QR module rendering.
    assert "<path" in body


@pytest.mark.asyncio
async def test_connect_qr_no_store_cache(http_lan):
    """Token rotations MUST propagate immediately. Cache-Control
    no-store prevents browsers + intermediates from serving a
    stale QR encoding the previous token."""
    client, server = http_lan
    resp = await client.get(
        "/api/connect-info/qr.svg",
        headers={"Authorization": f"Bearer {server.token}"},
    )
    cache = resp.headers.get("Cache-Control", "")
    assert "no-store" in cache


@pytest.mark.asyncio
async def test_connect_qr_loopback_returns_409(http_loopback):
    """Loopback-only: the QR endpoint MUST 409 with a JSON hint so
    the UI knows to render the "pass --lan" message instead of an
    <img> with a broken src."""
    client, server = http_loopback
    resp = await client.get(
        "/api/connect-info/qr.svg",
        headers={"Authorization": f"Bearer {server.token}"},
    )
    assert resp.status == 409
    body = await resp.json()
    assert body["error"] == "loopback_only"
    assert "--lan" in body["hint"]


# ───────── UI wiring ────────────────────────────────────────────────

def test_connect_info_section_present(index_html: str):
    """The About pane keeps a hidden compatibility anchor, but the
    legacy body target is gone so the old QR cannot render visibly."""
    assert 'id="connect-info-section"' in index_html
    assert 'id="connect-info-body"' not in index_html


def test_refresh_connect_info_helper_present(index_html: str):
    """The single-source-of-truth refresh helper. Must call
    /api/connect-info AND fetch /api/connect-info/qr.svg."""
    assert "function _refreshConnectInfo()" in index_html or \
        "async function _refreshConnectInfo()" in index_html
    idx = index_html.find("_refreshConnectInfo")
    snippet = index_html[idx:idx + 4000]
    assert '/api/connect-info"' in snippet
    assert "/api/connect-info/qr.svg" in snippet


def test_refresh_connect_info_called_on_settings_open(index_html: str):
    """refreshSettingsAbout must not invoke the legacy connect-info
    renderer; Pair a phone is the visible onboarding path."""
    idx = index_html.find("function refreshSettingsAbout()")
    assert idx > 0
    snippet = index_html[idx:idx + 1200]
    assert "_refreshConnectInfo()" not in snippet


def test_connect_info_renders_loopback_hint(index_html: str):
    """When info.lan_bound is false the JS MUST render a hint
    pointing the user at `one-link app --lan` instead of a
    broken QR image."""
    idx = index_html.find("_refreshConnectInfo")
    snippet = index_html[idx:idx + 4000]
    assert "lan_bound" in snippet
    assert "--lan" in snippet


def test_connect_info_url_copy_button(index_html: str):
    """Copy-to-clipboard fallback for users who don't want to
    scan (or whose phone camera permission is denied)."""
    idx = index_html.find("_refreshConnectInfo")
    snippet = index_html[idx:idx + 4000]
    assert "navigator.clipboard.writeText" in snippet
    assert "Copy URL" in snippet


def test_connect_info_security_warning_present(index_html: str):
    """The token-in-URL warning MUST stay visible. Don't let a
    refactor strip the trust-boundary copy."""
    idx = index_html.find("_refreshConnectInfo")
    snippet = index_html[idx:idx + 4000]
    assert "token" in snippet
    assert "Wi-Fi" in snippet


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_matches_package(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
