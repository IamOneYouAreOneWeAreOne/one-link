"""v0.10.6 — clickable Activity tiles + folder-pane polish.

Clickable Activity tiles:
  - Each of the four mesh-summary tiles (nearby / moving now /
    saved chunks / secure links) now drills into a relevant
    surface instead of being inert numbers.
  - Keyboard accessible (Enter/Space) + focus ring.

Folder pane polish:
  - The hardcoded "C:\\Users\\Alex\\Documents\\One Link" example
    is replaced with a per-user path computed on the daemon
    (Path.home() / Documents / One Link) and surfaced via the
    new `suggested_folder` field on /api/me.
  - New POST /api/fs/pick-folder endpoint pops a native tk
    folder dialog. UI uses it to drive a new "Browse…" button
    next to the path input.
  - Refresh button replaced with a small ↻ icon button that
    spins while the fetch is in flight.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

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
        fingerprint=fp, short_id=fp[:8], hostname="folder-host",
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
        yield client, daemon, state, server.token
    finally:
        await client.close()
        state.close()


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── clickable Activity tiles: markup ─────────────────────────

def test_metric_tiles_are_clickable_buttons(index_html: str):
    """Each tile must carry role/tabindex/data-mesh-tile so it's
    keyboard accessible + JS-discoverable."""
    for kind in ("online", "active", "cache", "sessions"):
        marker = f'data-mesh-tile="{kind}"'
        assert marker in index_html, f"tile {kind!r} not wired"
    # role/tabindex on each.
    assert index_html.count('data-mesh-tile="') == 4


def test_metric_tiles_have_aria_labels(index_html: str):
    """Screen-reader users must hear what each tile does. The text
    label by itself ('5', '0') is meaningless without context."""
    idx = index_html.find('id="mesh-summary"')
    assert idx > 0
    snippet = index_html[idx:idx + 1500]
    assert 'aria-label="View peers in Chat"' in snippet
    assert 'aria-label="Open Files Sent tab"' in snippet
    assert 'aria-label="Filter activity to file transfers"' in snippet
    assert 'aria-label="Filter activity to trust events"' in snippet


def test_metric_tile_clickable_class_present(index_html: str):
    """The .clickable class is what carries the cursor + hover
    affordance; if it's missing the tiles look identical to dead
    counters."""
    idx = index_html.find('id="mesh-summary"')
    snippet = index_html[idx:idx + 1500]
    assert snippet.count('class="metric clickable"') == 4


def test_metric_clickable_css_defined(index_html: str):
    """Cursor + hover + focus-visible must all be defined or the
    tiles look identical to non-clickable ones."""
    assert ".metric.clickable {" in index_html
    assert ".metric.clickable:hover {" in index_html
    assert ".metric.clickable:focus-visible {" in index_html


# ───────── clickable Activity tiles: JS handlers ────────────────────

def test_tile_handler_branches_for_all_four_kinds(index_html: str):
    """The dispatch function must handle each kind explicitly so a
    silent fall-through doesn't leave a tile inert."""
    idx = index_html.find("function _handleMeshTile(")
    assert idx > 0, "_handleMeshTile not present"
    snippet = index_html[idx:idx + 1500]
    for kind in ("online", "active", "cache", "sessions"):
        assert f'kind === "{kind}"' in snippet, f"no branch for {kind}"


def test_tile_online_jumps_to_chat(index_html: str):
    idx = index_html.find("function _handleMeshTile(")
    snippet = index_html[idx:idx + 1500]
    online_idx = snippet.find('kind === "online"')
    assert online_idx > 0
    branch = snippet[online_idx:online_idx + 400]
    assert '[data-pane="convo"]' in branch


def test_tile_active_jumps_to_files_sent(index_html: str):
    idx = index_html.find("function _handleMeshTile(")
    snippet = index_html[idx:idx + 1500]
    active_idx = snippet.find('kind === "active"')
    branch = snippet[active_idx:active_idx + 400]
    assert '[data-pane="files"]' in branch
    assert '[data-files-mode="sent"]' in branch


def test_tile_cache_filters_activity_to_transfer(index_html: str):
    idx = index_html.find("function _handleMeshTile(")
    snippet = index_html[idx:idx + 1500]
    cache_idx = snippet.find('kind === "cache"')
    branch = snippet[cache_idx:cache_idx + 200]
    assert '_activateActivityFilter("transfer")' in branch


def test_tile_sessions_filters_activity_to_trust(index_html: str):
    idx = index_html.find("function _handleMeshTile(")
    snippet = index_html[idx:idx + 1500]
    sess_idx = snippet.find('kind === "sessions"')
    branch = snippet[sess_idx:sess_idx + 200]
    assert '_activateActivityFilter("trust")' in branch


def test_tiles_keyboard_accessible(index_html: str):
    """Enter and Space must both fire the same handler — that's
    the platform convention for role=button."""
    idx = index_html.find("data-mesh-tile")
    snippet = index_html[idx:]
    # Find the keydown wiring loop.
    kd_idx = snippet.find('addEventListener("keydown"')
    assert kd_idx > 0
    kd_branch = snippet[kd_idx:kd_idx + 400]
    assert 'ev.key === "Enter"' in kd_branch
    assert 'ev.key === " "' in kd_branch
    assert "preventDefault()" in kd_branch


# ───────── /api/me suggested_folder ─────────────────────────────────

@pytest.mark.asyncio
async def test_api_me_includes_suggested_folder(http):
    client, _, _, token = http
    resp = await client.get("/api/me", headers=_h(token))
    j = await resp.json()
    assert "suggested_folder" in j
    assert j["suggested_folder"]  # non-empty string


@pytest.mark.asyncio
async def test_suggested_folder_is_under_user_home(http):
    """The example must live under THIS user's home, not under
    Alex's hardcoded path."""
    client, _, _, token = http
    resp = await client.get("/api/me", headers=_h(token))
    j = await resp.json()
    suggested = Path(j["suggested_folder"])
    # On any platform Path.home() should be a strict prefix.
    home = Path.home()
    assert str(suggested).startswith(str(home))


# ───────── POST /api/fs/pick-folder ─────────────────────────────────

@pytest.mark.asyncio
async def test_pick_folder_endpoint_exists(http):
    """Endpoint registered. Response shape must match the contract
    even on a headless test runner where tk has no display."""
    client, _, _, token = http
    resp = await client.post("/api/fs/pick-folder", headers=_h(token), json={})
    # 200 (cancelled or path) or 500 (catastrophic). 404 would mean
    # the route isn't wired.
    assert resp.status in (200, 500)
    if resp.status == 200:
        j = await resp.json()
        assert "path" in j
        assert "cancelled" in j


@pytest.mark.asyncio
async def test_pick_folder_returns_user_selection(http, tmp_path):
    """When the OS picker resolves to a real path, the endpoint
    returns it verbatim with cancelled=False."""
    client, _, _, token = http
    chosen = str(tmp_path / "Picked")
    with patch("tkinter.filedialog.askdirectory", return_value=chosen), \
         patch("tkinter.Tk"):
        resp = await client.post("/api/fs/pick-folder", headers=_h(token), json={})
    assert resp.status == 200
    j = await resp.json()
    assert j["path"] == chosen
    assert j["cancelled"] is False


@pytest.mark.asyncio
async def test_pick_folder_cancellation_returns_null_path(http):
    """When the user closes the dialog without picking, askdirectory
    returns '' — endpoint must surface that as cancelled=True."""
    client, _, _, token = http
    with patch("tkinter.filedialog.askdirectory", return_value=""), \
         patch("tkinter.Tk"):
        resp = await client.post("/api/fs/pick-folder", headers=_h(token), json={})
    assert resp.status == 200
    j = await resp.json()
    assert j["path"] is None
    assert j["cancelled"] is True


# ───────── folder pane UI surface ───────────────────────────────────

def test_help_card_no_longer_hardcodes_josh_path(index_html: str):
    """The original example was 'C:\\Users\\Alex\\Documents\\One Link'.
    That username leak must be gone from the help-card."""
    # Find the folders help-card scope.
    idx = index_html.find('Folder location</strong>')
    assert idx > 0
    scope = index_html[idx:idx + 800]
    assert "Users\\Alex" not in scope


def test_help_card_example_has_id_for_dynamic_fill(index_html: str):
    """The example <code> needs an id so the JS can rewrite it
    once /api/me responds."""
    assert 'id="folder-path-example"' in index_html


def test_init_overwrites_example_with_suggested_folder(index_html: str):
    """The init() routine must apply me.suggested_folder to both
    the example node + the input placeholder."""
    idx = index_html.find("if (me.suggested_folder)")
    assert idx > 0
    snippet = index_html[idx:idx + 600]
    assert '#folder-path-example' in snippet
    assert '#folder-path' in snippet
    assert 'placeholder' in snippet


# ───────── Browse button ────────────────────────────────────────────

def test_browse_button_present(index_html: str):
    assert 'id="btn-browse-folder"' in index_html
    assert "Browse…" in index_html or "Browse..." in index_html


def test_browse_handler_posts_to_endpoint(index_html: str):
    """The click handler must POST to /api/fs/pick-folder and write
    the returned path into #folder-path."""
    idx = index_html.find('"#btn-browse-folder"')
    assert idx > 0
    snippet = index_html[idx:idx + 1200]
    assert "/api/fs/pick-folder" in snippet
    assert '$("#folder-path").value = r.path' in snippet


def test_browse_handler_suggests_leaf_name(index_html: str):
    """If the user hasn't typed a folder name yet, the browse
    handler should default it to the last path segment so the
    Add flow is one click instead of two fields of typing."""
    idx = index_html.find('"#btn-browse-folder"')
    snippet = index_html[idx:idx + 1500]
    assert "split(/[\\\\/]/)" in snippet
    assert "leaf" in snippet


# ───────── refresh icon button ──────────────────────────────────────

def test_refresh_button_is_now_icon(index_html: str):
    """The button must carry the icon glyph + a tooltip + the new
    class so it doesn't render full-width like the old text button."""
    idx = index_html.find('id="btn-refresh-folders"')
    assert idx > 0
    snippet = index_html[idx:idx + 300]
    assert "↻" in snippet
    assert 'class="folder-refresh-btn"' in snippet
    assert 'title="Refresh folder list"' in snippet
    assert 'aria-label="Refresh folder list"' in snippet


def test_refresh_button_spins_while_loading(index_html: str):
    """The .spinning class drives a CSS keyframe animation; the
    click handler must add it then strip it."""
    assert "@keyframes folder-refresh-spin" in index_html
    assert ".folder-refresh-btn.spinning {" in index_html
    idx = index_html.find('"#btn-refresh-folders"')
    snippet = index_html[idx:idx + 600]
    assert 'classList.add("spinning")' in snippet
    assert 'classList.remove("spinning")' in snippet


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_bumped(index_html: str):
    from one_link import __version__
    assert __version__ == "0.10.6"
    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
