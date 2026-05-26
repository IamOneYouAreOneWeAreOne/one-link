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
    # Belt-and-suspenders: the native picker dispatcher honors this
    # env var as a kill switch — guarantees no test run can EVER pop
    # a real OS folder dialog, even if a future test forgets to
    # patch _native_folder_picker.
    monkeypatch.setenv("ONE_LINK_DISABLE_NATIVE_PICKER", "1")
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
    assert 'aria-label="Show nearby devices"' in snippet
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


def test_tile_online_opens_nearby_panel(index_html: str):
    idx = index_html.find("function _handleMeshTile(")
    snippet = index_html[idx:idx + 1500]
    online_idx = snippet.find('kind === "online"')
    assert online_idx > 0
    branch = snippet[online_idx:online_idx + 400]
    assert "_openActivityNearbyFromTile()" in branch
    assert '[data-pane="convo"]' not in branch


def test_nearby_rows_are_clickable_and_keyboard_accessible(index_html: str):
    idx = index_html.find("function nearbyRow(")
    assert idx > 0, "nearbyRow not present"
    snippet = index_html[idx:idx + 1400]
    assert 'row.setAttribute("role", "button")' in snippet
    assert "row.tabIndex = 0" in snippet
    assert "row.onkeydown" in snippet
    assert 'ev.key !== "Enter" && ev.key !== " "' in snippet


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
    with patch("one_link.server._native_folder_picker", return_value=None):
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
    with patch("one_link.server._native_folder_picker", return_value=chosen):
        resp = await client.post("/api/fs/pick-folder", headers=_h(token), json={})
    assert resp.status == 200
    j = await resp.json()
    assert j["path"] == chosen
    assert j["cancelled"] is False


@pytest.mark.asyncio
async def test_pick_folder_cancellation_returns_null_path(http):
    """When the user cancels OR no picker is available, the helper
    returns None — endpoint must surface that as cancelled=True."""
    client, _, _, token = http
    with patch("one_link.server._native_folder_picker", return_value=None):
        resp = await client.post("/api/fs/pick-folder", headers=_h(token), json={})
    assert resp.status == 200
    j = await resp.json()
    assert j["path"] is None
    assert j["cancelled"] is True


# ───────── native picker dispatch ──────────────────────────────────

def test_native_picker_uses_powershell_on_windows(monkeypatch):
    """When the modern IFileOpenDialog can't initialize, the
    dispatcher falls through to PowerShell + WinForms, NOT
    straight to tkinter (which looks blurry on hi-DPI displays
    and shows the feather icon instead of native chrome)."""
    from one_link import server
    # These dispatch-routing tests need the kill switch off so we
    # can actually exercise the platform branches.
    monkeypatch.delenv("ONE_LINK_DISABLE_NATIVE_PICKER", raising=False)
    monkeypatch.setattr(server.sys, "platform", "win32")
    called = {}
    # Modern picker unavailable so we exercise the PS branch.
    monkeypatch.setattr(
        server, "_pick_win_ifiledialog", lambda t: server._PICKER_UNAVAILABLE,
    )
    def fake_ps(title):
        called["ps"] = title
        return "C:/Picked"
    def fake_tk(title):
        called["tk"] = title
        return "C:/SHOULD_NOT_BE_USED"
    monkeypatch.setattr(server, "_pick_win_powershell", fake_ps)
    monkeypatch.setattr(server, "_pick_tkinter_fallback", fake_tk)
    result = server._native_folder_picker("hi")
    assert result == "C:/Picked"
    assert "ps" in called
    assert "tk" not in called


def test_native_picker_falls_back_to_tk_when_powershell_missing(monkeypatch):
    """If PowerShell is missing/locked-down, the dispatcher must fall
    through to the tk fallback rather than fail silently — that
    keeps the Browse button working on locked-down Windows boxes."""
    from one_link import server
    monkeypatch.delenv("ONE_LINK_DISABLE_NATIVE_PICKER", raising=False)
    monkeypatch.setattr(server.sys, "platform", "win32")
    # Modern picker unavailable so the dispatcher reaches PS.
    monkeypatch.setattr(
        server, "_pick_win_ifiledialog", lambda t: server._PICKER_UNAVAILABLE,
    )
    monkeypatch.setattr(server, "_pick_win_powershell", lambda t: None)
    monkeypatch.setattr(server, "_pick_tkinter_fallback", lambda t: "C:/Tk")
    assert server._native_folder_picker("hi") == "C:/Tk"


def test_native_picker_uses_osascript_on_mac(monkeypatch):
    from one_link import server
    monkeypatch.delenv("ONE_LINK_DISABLE_NATIVE_PICKER", raising=False)
    monkeypatch.setattr(server.sys, "platform", "darwin")
    monkeypatch.setattr(server, "_pick_mac_osascript", lambda t: "/Users/me/Pick")
    assert server._native_folder_picker("hi") == "/Users/me/Pick"


def test_native_picker_uses_linux_dispatch(monkeypatch):
    from one_link import server
    monkeypatch.delenv("ONE_LINK_DISABLE_NATIVE_PICKER", raising=False)
    monkeypatch.setattr(server.sys, "platform", "linux")
    monkeypatch.setattr(server, "_pick_linux", lambda t: "/home/me/Pick")
    assert server._native_folder_picker("hi") == "/home/me/Pick"


def test_kill_switch_returns_none_when_env_var_set(monkeypatch):
    """Verify the kill switch itself: when ONE_LINK_DISABLE_NATIVE_PICKER
    is set, the dispatcher must return None without invoking ANY
    platform branch. Belt-and-suspenders so a future test that forgets
    to patch can never pop a real folder dialog."""
    from one_link import server
    monkeypatch.setenv("ONE_LINK_DISABLE_NATIVE_PICKER", "1")
    # If any platform helper is reached, blow up loudly so the test
    # tells us the switch failed.
    def _boom(t):
        raise AssertionError("kill switch failed: platform helper invoked")
    monkeypatch.setattr(server, "_pick_win_ifiledialog", _boom)
    monkeypatch.setattr(server, "_pick_win_powershell", _boom)
    monkeypatch.setattr(server, "_pick_mac_osascript", _boom)
    monkeypatch.setattr(server, "_pick_linux", _boom)
    monkeypatch.setattr(server, "_pick_tkinter_fallback", _boom)
    assert server._native_folder_picker("hi") is None


def test_windows_dispatcher_tries_modern_picker_first(monkeypatch):
    """v0.21.x: the modern IFileOpenDialog is PRIMARY on Windows
    again — users found the legacy WinForms picker visually awful
    ('its aweful'). If modern returns a real path, legacy MUST NOT
    also pop."""
    from one_link import server
    monkeypatch.delenv("ONE_LINK_DISABLE_NATIVE_PICKER", raising=False)
    monkeypatch.setattr(server.sys, "platform", "win32")
    call_order: list[str] = []

    def fake_modern(t):
        call_order.append("modern")
        return "C:/From/Modern"

    def fake_ps(t):
        call_order.append("powershell")
        return "C:/From/PowerShell"

    monkeypatch.setattr(server, "_pick_win_ifiledialog", fake_modern)
    monkeypatch.setattr(server, "_pick_win_powershell", fake_ps)
    out = server._native_folder_picker("hi")
    assert out == "C:/From/Modern"
    assert call_order == ["modern"], (
        "legacy picker must NOT run when modern returns a path"
    )


def test_windows_dispatcher_falls_through_to_powershell_when_modern_unavailable(monkeypatch):
    """If IFileOpenDialog can't initialize (REGDB_E_CLASSNOTREG
    on stripped Windows, COM blocked), fall through to PowerShell.
    The _PICKER_UNAVAILABLE sentinel signals 'try the fallback';
    None signals 'user cancelled' (no fallback)."""
    from one_link import server
    monkeypatch.delenv("ONE_LINK_DISABLE_NATIVE_PICKER", raising=False)
    monkeypatch.setattr(server.sys, "platform", "win32")
    monkeypatch.setattr(
        server, "_pick_win_ifiledialog", lambda t: server._PICKER_UNAVAILABLE,
    )
    monkeypatch.setattr(
        server, "_pick_win_powershell", lambda t: "C:/From/PowerShell/Fallback",
    )
    assert server._native_folder_picker("hi") == "C:/From/PowerShell/Fallback"


def test_windows_dispatcher_modern_cancel_does_not_fall_through(monkeypatch):
    """When the modern picker returns None (user cancelled), we
    MUST NOT pop a second PowerShell dialog. The user just
    dismissed a dialog; another one would be confusing."""
    from one_link import server
    monkeypatch.delenv("ONE_LINK_DISABLE_NATIVE_PICKER", raising=False)
    monkeypatch.setattr(server.sys, "platform", "win32")
    monkeypatch.setattr(server, "_pick_win_ifiledialog", lambda t: None)

    def _boom(t):
        raise AssertionError(
            "PowerShell picker invoked after modern returned None "
            "(cancellation) — this would pop TWO dialogs in a row"
        )
    monkeypatch.setattr(server, "_pick_win_powershell", _boom)
    monkeypatch.setattr(server, "_pick_tkinter_fallback", _boom)
    assert server._native_folder_picker("hi") is None


def test_windows_dispatcher_final_fallback_is_tk(monkeypatch):
    """Both modern + PowerShell unavailable → tkinter final
    fallback. Guarantees SOMETHING pops even on locked-down
    Windows boxes where both COM init AND PowerShell fail."""
    from one_link import server
    monkeypatch.delenv("ONE_LINK_DISABLE_NATIVE_PICKER", raising=False)
    monkeypatch.setattr(server.sys, "platform", "win32")
    monkeypatch.setattr(
        server, "_pick_win_ifiledialog", lambda t: server._PICKER_UNAVAILABLE,
    )
    monkeypatch.setattr(server, "_pick_win_powershell", lambda t: None)
    monkeypatch.setattr(server, "_pick_tkinter_fallback", lambda t: "C:/Tk")
    assert server._native_folder_picker("hi") == "C:/Tk"


def test_modern_picker_uses_fos_pickfolders_options():
    """Source-text gate: the modern picker MUST set
    FOS_PICKFOLDERS (0x20) + FOS_FORCEFILESYSTEM (0x40) on the
    IFileDialog. Without FOS_PICKFOLDERS we'd get a file picker
    instead of a folder picker; without FOS_FORCEFILESYSTEM the
    dialog would let users pick virtual items like 'This PC'
    that don't have a real filesystem path."""
    from pathlib import Path as _Path
    src = (_Path(__file__).resolve().parents[1] / "src" / "one_link" / "server.py").read_text(encoding="utf-8")
    idx = src.find("def _pick_win_ifiledialog(")
    assert idx > 0, "_pick_win_ifiledialog handler not found"
    end = src.find("\ndef _pick_win_powershell(", idx)
    body = src[idx:end if end > 0 else idx + 6000]
    assert "FOS_PICKFOLDERS = 0x20" in body
    assert "FOS_FORCEFILESYSTEM = 0x40" in body
    assert "FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM" in body, (
        "SetOptions must pass both flags - folder-picker mode AND "
        "filesystem-only enforcement"
    )
    assert "CLSID_FileOpenDialog" in body
    assert "IID_IFileOpenDialog" in body
    # The CANCELLED HRESULT (0x800704C7) is the common case - user
    # closed the dialog. Must be handled distinctly from real
    # failures so cancellation returns None silently.
    assert "CANCELLED_HR" in body or "0x800704C7" in body


def test_modern_picker_short_circuits_on_non_windows():
    """A Linux/macOS caller of _pick_win_ifiledialog must return
    _PICKER_UNAVAILABLE without raising. Defense in depth: the
    dispatcher already only calls it on win32, but a future
    refactor that calls the helper directly shouldn't blow up."""
    from one_link import server
    import unittest.mock as _mock
    with _mock.patch.object(server.sys, "platform", "linux"):
        assert server._pick_win_ifiledialog("hi") is server._PICKER_UNAVAILABLE
    with _mock.patch.object(server.sys, "platform", "darwin"):
        assert server._pick_win_ifiledialog("hi") is server._PICKER_UNAVAILABLE


def test_modern_picker_tries_broker_clsid_on_stripped_windows():
    """Some Windows 11 builds register ONLY the BrokerFileOpenDialog
    CLSID (3217B1B1-...), not the classic FileOpenDialog CLSID
    (DC1C5A9C-...). The picker MUST try both - source-text gate
    pins both CLSIDs are present + the broker is the explicit
    REGDB_E_CLASSNOTREG fallback."""
    from pathlib import Path as _Path
    src = (_Path(__file__).resolve().parents[1] / "src" / "one_link" / "server.py").read_text(encoding="utf-8")
    idx = src.find("def _pick_win_ifiledialog(")
    end = src.find("\ndef _pick_win_powershell(", idx)
    body = src[idx:end]
    assert "DC1C5A9C-E88A-4ADE-A5A1-60F82A20AEF7" in body, (
        "classic FileOpenDialog CLSID must be tried first"
    )
    assert "3217B1B1-5DC3-4590-9C62-EF9E2DF1C25D" in body, (
        "BrokerFileOpenDialog CLSID must be the fallback for "
        "Win11 installs that don't register the classic one"
    )
    # REGDB_E_CLASSNOTREG = 0x80040154 = -2147221164. The retry
    # path must explicitly key on this error code.
    assert "-2147221164" in body or "0x80040154" in body


def test_modern_picker_creates_owner_window_for_zorder():
    """v0.21.x: Show(hwnd=None) drops the dialog behind the user's
    foreground window because there's no Z-order anchor. The first
    fix tried GetForegroundWindow (the BROWSER's HWND) as parent;
    that didn't reliably work because cross-process owners don't
    force Z-order. Second fix (current): create a tiny invisible
    TopMost owner window IN THE DAEMON'S process via CreateWindowExW,
    use that as the IFileOpenDialog's owner. Same pattern PowerShell
    uses with its hidden TopMost owner form. Pin the structure so
    a refactor can't revert to Show(None) or back to the cross-
    process foreground HWND approach."""
    from pathlib import Path as _Path
    src = (_Path(__file__).resolve().parents[1] / "src" / "one_link" / "server.py").read_text(encoding="utf-8")
    idx = src.find("def _pick_win_ifiledialog(")
    end = src.find("\ndef _pick_win_powershell(", idx)
    body = src[idx:end]
    # Must call AllowSetForegroundWindow so Windows lets the daemon
    # process's owner window come to front (foreground-lock policy
    # would otherwise suppress focus-steal from a background app).
    assert "AllowSetForegroundWindow" in body, (
        "missing AllowSetForegroundWindow — the owner window can't "
        "take front-of-Z-order without it, dialog stays behind"
    )
    # Must create an in-process owner window.
    assert "CreateWindowExW" in body, (
        "missing CreateWindowExW — without an in-process owner, "
        "Show() has no Z-order anchor and the dialog opens behind"
    )
    # Must make the owner WS_VISIBLE so Windows treats it as a real
    # Z-order anchor (invisible owners get skipped silently).
    assert "WS_VISIBLE" in body, (
        "owner window must be WS_VISIBLE — Windows treats invisible "
        "owners as non-anchors and Show() returns CANCELLED_HR even "
        "on successful pick"
    )
    # Must be TopMost so the modal definitely lands above the browser.
    assert "WS_EX_TOPMOST" in body
    # And must be cleaned up.
    assert "DestroyWindow" in body, (
        "owner window must be destroyed after Show() returns — "
        "otherwise we leak a window handle per Browse click"
    )
    # And the dialog must actually use it.
    assert "Show(ppv, owner_hwnd)" in body, (
        "Show must be called with the resolved owner_hwnd"
    )


def test_pick_folder_endpoint_uses_dedicated_thread():
    """v0.21.x: asyncio.to_thread reuses threads from a shared
    pool. Windows IFileOpenDialog requires the calling thread to
    be in STA (single-threaded apartment) mode; if any prior call
    on that thread initialized COM as MTA, our STA init returns
    RPC_E_CHANGED_MODE and the dialog ends up in a broken state
    (visible-but-unresponsive, or hidden entirely). Pin that
    api_pick_folder spawns a fresh threading.Thread per call so
    COM state can never leak across requests."""
    from pathlib import Path as _Path
    src = (_Path(__file__).resolve().parents[1] / "src" / "one_link" / "server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_pick_folder(")
    assert idx > 0
    end = src.find("\n    async def ", idx + 1)
    body = src[idx:end if end > 0 else idx + 4000]
    # Must use a fresh threading.Thread, NOT asyncio.to_thread
    # directly on _native_folder_picker.
    assert "threading.Thread" in body, (
        "api_pick_folder must spawn a dedicated thread for the "
        "picker — asyncio.to_thread reuses a shared pool which "
        "leaks COM state and silently breaks the dialog"
    )
    # Must NOT directly to_thread the picker itself (the .join is
    # OK; the picker call is the part that needs the fresh thread).
    assert "asyncio.to_thread(_native_folder_picker" not in body, (
        "api_pick_folder is back to asyncio.to_thread on the picker "
        "itself — this is exactly the bug that broke the Browse "
        "button: shared pool threads come with leaked COM state"
    )
    # And must actually start + join the thread.
    assert ".start()" in body
    assert ".join" in body


def test_powershell_picker_passes_dialog_title(monkeypatch):
    """The title we configure must reach the WinForms dialog so
    the user sees 'Choose a folder to share with One Link' rather
    than a default 'Browse for Folder' label."""
    from one_link import server
    captured = {}
    def fake_run(args, **kw):
        captured["args"] = args
        class _R:
            returncode = 0
            stdout = "C:/Picked"
            stderr = ""
        return _R()
    monkeypatch.setattr(server.subprocess, "run", fake_run)
    out = server._pick_win_powershell("Choose a folder to share with One Link")
    assert out == "C:/Picked"
    # The PS script string lives in args[-1] for `-Command <script>`.
    script = captured["args"][-1]
    assert "Choose a folder to share with One Link" in script
    assert "FolderBrowserDialog" in script
    # v0.21.x: the script must NOT use UseDescriptionForTitle or
    # AutoUpgradeEnabled - those properties don't exist on Windows
    # PowerShell 5.1's bundled FolderBrowserDialog and setting them
    # threw 'property cannot be found' errors that broke the picker.
    assert "UseDescriptionForTitle" not in script, (
        "PS 5.1 (default on Win10/11) doesn't have this property; "
        "setting it crashes the script and the dialog never appears"
    )
    assert "AutoUpgradeEnabled" not in script, (
        "PS 5.1 doesn't have this property either"
    )
    # The TopMost owner window pattern must be present so the
    # picker comes up in FRONT of the browser, not behind it.
    assert "TopMost" in script
    assert "$d.ShowDialog($owner)" in script, (
        "ShowDialog must be called with the hidden owner so the "
        "picker is z-ordered correctly"
    )


def test_powershell_picker_returns_none_on_empty_path(monkeypatch):
    """Cancel via the PS dialog leaves SelectedPath empty — must
    surface as None, not as ''."""
    from one_link import server
    def fake_run(args, **kw):
        class _R:
            returncode = 0
            stdout = ""
            stderr = ""
        return _R()
    monkeypatch.setattr(server.subprocess, "run", fake_run)
    assert server._pick_win_powershell("hi") is None


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
    snippet = index_html[idx:idx + 400]
    assert "↻" in snippet
    assert 'class="folder-refresh-btn"' in snippet
    # Title text was tightened in v0.21.x but must still be present
    # so hover discovers what the icon does.
    assert 'title="' in snippet, (
        "refresh icon button needs a hover tooltip — without one "
        "the ↻ glyph is undiscoverable"
    )
    assert 'aria-label="Refresh folder list"' in snippet


def test_folder_row_action_buttons_have_tooltips(index_html: str):
    """v0.21.x: Share / Sync / Remove buttons on each folder row
    must carry .title text so hovering reveals what they do. The
    labels alone ('Share', 'Sync', 'Remove') don't tell a new user
    that Share is one-time peer-grant vs Sync being a manual push
    vs Remove only severing the One Link link (not deleting files)."""
    # JS sets these via element.title = "..."
    idx = index_html.find("for (const f of state.folders)")
    assert idx > 0
    # v0.21.x added an Open button + click-to-open name/path before
    # the Share/Sync/Remove block, so the slice has to be wider to
    # cover all four tooltips.
    body = index_html[idx:idx + 6000]
    # Share tooltip must mention the selected-peer requirement.
    assert "share.title" in body, (
        "Share button missing hover tooltip"
    )
    assert "sync.title" in body, (
        "Sync button missing hover tooltip"
    )
    assert "remove.title" in body, (
        "Remove button missing hover tooltip"
    )
    # Remove tooltip MUST tell the user it doesn't delete files on
    # disk — that's the load-bearing reassurance for the action.
    assert "NOT" in body and "deleted" in body, (
        "Remove tooltip must explicitly say files on disk are NOT "
        "deleted — without that reassurance users will fear clicking it"
    )


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
    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
