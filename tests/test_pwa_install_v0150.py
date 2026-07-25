"""v0.15.0 — PWA install + Web App Manifest + install-prompt UX.

Ship-spec from `docs/ARCHITECTURE.md` v0.15.0:

  Reach:  Chrome / Edge / Samsung Internet / Brave users get the
          OS-native install prompt directly from the One Link
          About pane. iOS Safari + Firefox users get the standard
          add-to-home-screen path; the prompt button is hidden
          on those platforms (the `beforeinstallprompt` event
          never fires).
  Hide:   the install affordance is hidden when running inside
          the installed shell (display-mode: standalone). Don't
          tell the user to install the thing they're already
          inside.
  Async:  the SW shell-cache is bumped to v2, including the
          manifest + the maskable icon. SW activate handler
          evicts older `one-link-shell-*` caches.
  Depth:  manifest.json declares standalone display, dual icon
          purposes (any + maskable for adaptive launchers),
          theme color matched to the dark UI background, scope
          set to "/" so installed PWA covers all in-app routes.

Tests pin: manifest contents, server route, page link/handlers,
SW shell expansion, version bump.
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
        fingerprint=fp, short_id=fp[:8], hostname="pwa-host",
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
        yield client
    finally:
        await client.close()
        state.close()


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def sw_js() -> str:
    return Path("src/one_link/web/sw.js").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def manifest() -> dict:
    return json.loads(
        Path("src/one_link/web/manifest.json").read_text(encoding="utf-8")
    )


# ───────── manifest contents ────────────────────────────────────────

def test_manifest_has_name(manifest: dict):
    assert manifest["name"] == "One Link"


def test_manifest_has_short_name(manifest: dict):
    assert manifest["short_name"] == "One Link"


def test_manifest_display_is_standalone(manifest: dict):
    """Standalone strips browser chrome from the installed PWA.
    Anything else (browser, minimal-ui) leaves the URL bar visible
    and undermines the "feels like an app" goal."""
    assert manifest["display"] == "standalone"


def test_manifest_start_url_is_root(manifest: dict):
    assert manifest["start_url"] == "/"


def test_manifest_scope_is_root(manifest: dict):
    """Scope MUST be `/` so the installed PWA controls every route
    on the daemon (chat, files, folders, settings) — not just the
    landing page."""
    assert manifest["scope"] == "/"


def test_manifest_theme_color_matches_ui(manifest: dict):
    """Theme color MUST match the dark-bg `--bg-0` so the installed
    splash + status-bar tint matches the actual UI palette. Any
    drift means a flash of mismatched color on launch."""
    assert manifest["theme_color"] == "#0b0d12"


def test_manifest_background_color_matches_ui(manifest: dict):
    """Background color is what users see during the splash before
    the SPA paints. Same reasoning as theme_color."""
    assert manifest["background_color"] == "#0b0d12"


def test_manifest_has_maskable_icon(manifest: dict):
    """Adaptive launcher icons (Android, ChromeOS) require
    `purpose: "maskable"`. Without it the OS pads the bitmap with
    white and looks broken on dark wallpapers."""
    purposes = {ic.get("purpose") for ic in manifest["icons"]}
    assert "maskable" in purposes, (
        "manifest MUST include at least one icon with purpose: maskable"
    )


def test_manifest_has_any_icon(manifest: dict):
    """`purpose: "any"` covers the default browser tab + non-adaptive
    launchers."""
    purposes = {ic.get("purpose") for ic in manifest["icons"]}
    assert "any" in purposes


def test_manifest_icon_sources_exist(manifest: dict):
    """Every declared icon path must resolve to a real file in the
    web/assets/ tree. Otherwise the install prompt rejects with
    "manifest icons unreachable" and the install button never appears."""
    for ic in manifest["icons"]:
        src = ic["src"]
        # Strip leading /static/ to find on disk.
        rel = src.replace("/static/", "")
        path = Path("src/one_link/web/assets") / rel
        assert path.is_file(), f"manifest icon missing on disk: {src}"


# ───────── server route ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_manifest_route_serves_json(http):
    """`GET /manifest.json` MUST return 200 with the right
    content-type. Without `application/manifest+json` the install
    prompt declines on Firefox."""
    client = http
    resp = await client.get("/manifest.json")
    assert resp.status == 200
    ct = resp.headers.get("Content-Type", "")
    assert "manifest" in ct or "json" in ct
    body = await resp.json()
    assert body["name"] == "One Link"


@pytest.mark.asyncio
async def test_manifest_route_unauthenticated(http):
    """Manifest contains zero PII; serving it without auth lets the
    browser fetch it during the pre-install handshake (before any
    cookies are set if the user wipes site data)."""
    client = http
    resp = await client.get("/manifest.json")
    assert resp.status == 200


# ───────── page <head> wiring ───────────────────────────────────────

def test_index_links_to_manifest(index_html: str):
    """The page MUST include `<link rel="manifest" href="/manifest.json">`
    in the head — without it, the manifest is never fetched and the
    install prompt never fires."""
    assert '<link rel="manifest" href="/manifest.json"' in index_html


def test_index_has_apple_meta_tags(index_html: str):
    """iOS Safari uses Apple-specific meta tags instead of the
    manifest for add-to-home-screen behavior. Pin the trio that
    governs standalone mode + status bar tint + display name."""
    assert 'name="apple-mobile-web-app-capable"' in index_html
    assert 'name="apple-mobile-web-app-status-bar-style"' in index_html
    assert 'name="apple-mobile-web-app-title"' in index_html


# ───────── install-prompt JS handler ────────────────────────────────

def test_install_prompt_event_captured(index_html: str):
    """The page MUST listen for `beforeinstallprompt` and stash the
    event in state — that's the only way to trigger the prompt
    on user gesture later."""
    assert 'window.addEventListener("beforeinstallprompt"' in index_html
    assert "state.installPromptEvent" in index_html


def test_install_prompt_prevent_default(index_html: str):
    """preventDefault is what suppresses the browser's own install
    bar so we control where the prompt appears (in About, not as
    a top-of-page banner that fights with the chat surface)."""
    idx = index_html.find('"beforeinstallprompt"')
    snippet = index_html[idx:idx + 800]
    assert "e.preventDefault()" in snippet


def test_install_button_present(index_html: str):
    """The install button MUST exist in About and start hidden
    (browsers without `beforeinstallprompt` keep it hidden forever)."""
    idx = index_html.find('id="btn-install-pwa"')
    assert idx > 0
    open_start = index_html.rfind("<button", 0, idx)
    open_end = index_html.find(">", idx)
    button_tag = index_html[open_start:open_end + 1]
    # The wrapping row carries display:none; re-find its open tag.
    row_idx = index_html.find('id="install-pwa-row"')
    assert row_idx > 0
    row_open = index_html.rfind("<", 0, row_idx)
    row_end = index_html.find(">", row_idx)
    row_tag = index_html[row_open:row_end + 1]
    assert "display:none" in row_tag


def test_install_button_calls_prompt(index_html: str):
    """Clicking the button MUST call `.prompt()` on the deferred
    event — that's the actual install trigger. Plus the user choice
    must be awaited so we know whether to clear the affordance."""
    idx = index_html.find('"#btn-install-pwa"')
    snippet = index_html[idx:idx + 1500]
    assert "ev.prompt()" in snippet
    assert "ev.userChoice" in snippet


def test_appinstalled_clears_affordance(index_html: str):
    """When the install completes, hide the button so the user
    isn't told to install the thing they're already inside."""
    assert 'window.addEventListener("appinstalled"' in index_html
    idx = index_html.find('"appinstalled"')
    snippet = index_html[idx:idx + 600]
    assert "_hideInstallAffordance()" in snippet


def test_standalone_mode_hides_affordance(index_html: str):
    """If the page is already running inside the installed PWA
    (display-mode: standalone), suppress the install affordance
    immediately — no point asking the user to install what they
    already have."""
    assert "display-mode: standalone" in index_html
    idx = index_html.find("display-mode: standalone")
    snippet = index_html[idx:idx + 400]
    assert "_hideInstallAffordance()" in snippet


# ───────── SW shell expansion ───────────────────────────────────────

def test_sw_cache_name_bumped(sw_js: str):
    """Bumping the cache name forces the activate handler to evict
    older caches, including entries created before bearer-bearing request
    keys were excluded from caching."""
    assert 'CACHE_NAME = "one-link-shell-v4"' in sw_js


def test_sw_shell_files_include_manifest(sw_js: str):
    """The SW MUST precache /manifest.json so the install prompt
    works after a brief offline interval (browsers re-fetch the
    manifest before showing the prompt)."""
    assert '"/manifest.json"' in sw_js


def test_sw_shell_files_include_app_icon(sw_js: str):
    """The maskable adaptive icon must precache too — the install
    prompt declines if the icon's unreachable at prompt time."""
    assert '"/static/one-glyph-app.png"' in sw_js


def test_sw_fetch_handles_manifest_route(sw_js: str):
    """The fetch handler MUST treat /manifest.json as a cacheable
    static asset (cache-first) so it survives offline re-launches."""
    assert 'url.pathname === "/manifest.json"' in sw_js


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_matches_package(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html


def test_sw_incoming_call_notification_actions(sw_js: str):
    assert "incoming-call-notification" in sw_js
    assert "showNotification" in sw_js
    assert 'action: "accept-call"' in sw_js
    assert 'action: "message-peer"' in sw_js
    assert "notificationclick" in sw_js
    assert "call-notification-action" in sw_js
