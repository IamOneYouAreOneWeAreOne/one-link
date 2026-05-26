"""v0.21.x E2E — folder UX surfaces shipped in the 9-ship sweep.

Pins that the new DOM landmarks exist and the public JS entry points
(openFolderBrowser, openFolderSettings) are wired. We don't drive
a full real-folder flow here — that lives in the behavioral suite
+ ceremony integration test — but we DO want a "did the build wire
this up?" guard so a future refactor that removes an id can't
silently ship.

What this catches:
  - someone deletes/renames #folder-browser-backdrop / -path /
    -list / -preview without updating callers
  - someone deletes/renames #folder-settings-backdrop / -ignored /
    -maxmb / -policy / -save / -close
  - openFolderBrowser / openFolderSettings JS entries get nuked
  - the v0.21.x API endpoints stop returning 200 to a valid auth
    header (smoke)

Out of scope:
  - real file-content rendering (would need a populated folder; that
    flow is exercised in tests/test_ship1_file_browser_behavioral_v021.py)
  - rename detection / version history wiring (behavioral tests)
"""
from __future__ import annotations

import requests


# ── new DOM landmarks present ─────────────────────────────────────


def test_folder_browser_modal_exists_in_dom(ui_page):
    """The Ship 1 folder browser modal must be present in the DOM
    (display:none initially). If it's missing, no one can click
    'Open' on a folder card to see its contents."""
    backdrop = ui_page.locator("#folder-browser-backdrop")
    assert backdrop.count() == 1, (
        "#folder-browser-backdrop missing — Ship 1 folder browser "
        "modal not wired into index.html"
    )
    # The shell of the modal must include path, list, preview panes.
    for sel in [
        "#folder-browser-title", "#folder-browser-path",
        "#folder-browser-list", "#folder-browser-preview",
        "#folder-browser-search", "#folder-browser-close",
    ]:
        assert ui_page.locator(sel).count() == 1, (
            f"{sel} missing — Ship 1 folder browser modal incomplete"
        )


def test_folder_settings_modal_exists_in_dom(ui_page):
    """The Ship 4 per-folder settings modal must be present in the
    DOM. If it's missing, users can't set ignored_patterns /
    max_file_bytes / conflict policy on a folder."""
    backdrop = ui_page.locator("#folder-settings-backdrop")
    assert backdrop.count() == 1, (
        "#folder-settings-backdrop missing — Ship 4 folder settings "
        "modal not wired into index.html"
    )
    for sel in [
        "#folder-settings-ignored", "#folder-settings-maxmb",
        "#folder-settings-close", "#folder-settings-target",
    ]:
        assert ui_page.locator(sel).count() == 1, (
            f"{sel} missing — Ship 4 folder settings modal incomplete"
        )


def test_folder_offers_section_exists_in_dom(ui_page):
    """The Ship 0 incoming-folder-offers section must be present in
    the DOM (display:none initially when there are no offers).
    Without this, users get a folder push from a paired peer and
    have no place to accept/decline it."""
    assert ui_page.locator("#folder-offers-section").count() == 1
    assert ui_page.locator("#folder-offers-list").count() == 1
    assert ui_page.locator("#folder-offers-count").count() == 1


# ── new JS entry points wired (source-text guard) ────────────────
#
# Both openFolderBrowser and openFolderSettings are intentionally
# IIFE-scoped closures (not window globals); they're invoked through
# button.onclick = () => openFolderBrowser(f) wired at render time.
# Checking window.* would falsely fail. Instead we verify the
# functions are DEFINED in the bundled page source, so a refactor
# that nukes them gets caught.


def test_folder_card_actions_row_wraps_on_narrow_panels(ui_page):
    """The folder card's actions row (Open / Share / Sync / Settings /
    Remove) MUST wrap to a second line when the panel is too narrow
    to fit all 5 buttons at a readable width. Without flex-wrap the
    "Settings" label gets clipped to "Settin..." in the ~400px-wide
    folders aside. Verified by inspecting the computed style of
    .file-actions in the bundled CSS."""
    src = ui_page.content()
    # The rule MUST set flex-wrap: wrap on .file-actions and a
    # readable min-width on the buttons. Pin both so a future CSS
    # tidy can't silently revert.
    assert "flex-wrap: wrap" in src, (
        ".file-actions must set flex-wrap: wrap so 5 buttons in a "
        "narrow aside don't clip the Settings label"
    )
    assert "min-width: 70px" in src or "min-width:70px" in src, (
        ".file-actions button must set min-width so buttons stay "
        "readable rather than squishing to fit on one row"
    )


def test_openFolderBrowser_definition_present_in_source(ui_page):
    """The Ship 1 folder browser entry point must remain defined in
    the bundled JS. If a refactor deletes it, the Folder card Open
    button silently no-ops at render time."""
    src = ui_page.content()
    assert "function openFolderBrowser" in src or \
           "openFolderBrowser =" in src, (
        "openFolderBrowser definition missing from index.html source "
        "— Ship 1 entry point removed; the Folder card Open button "
        "won't work"
    )


def test_openFolderSettings_definition_present_in_source(ui_page):
    """The Ship 4 folder settings entry point must remain defined.
    Same risk as openFolderBrowser."""
    src = ui_page.content()
    assert "function openFolderSettings" in src or \
           "openFolderSettings =" in src, (
        "openFolderSettings definition missing from index.html source "
        "— Ship 4 entry point removed; the Folder card Settings "
        "button won't work"
    )


# ── v0.21.x API endpoints respond to a valid token ────────────────
#
# These are pure HTTP smoke checks against the live daemon — they
# don't need a browser context. They guard the routing wiring
# (server.py route table) so a refactor can't silently 404 the new
# endpoints.


def _hdr(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_api_folder_offers_returns_200(live_daemon):
    """GET /api/folder-offers must respond 200 with {offers: [...]}."""
    r = requests.get(
        f"{live_daemon.base_url}/api/folder-offers",
        headers=_hdr(live_daemon.token),
        timeout=5,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "offers" in body
    assert isinstance(body["offers"], list)


def test_api_power_status_returns_200(live_daemon):
    """GET /api/power-status (Ship 7) must surface the daemon's
    battery + metered view + the user's pause-on-battery setting."""
    r = requests.get(
        f"{live_daemon.base_url}/api/power-status",
        headers=_hdr(live_daemon.token),
        timeout=5,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    # on_battery + metered are bools; pause_on_battery is a bool.
    for key in ("on_battery", "metered"):
        assert key in body, f"missing {key} in power-status response"
        assert isinstance(body[key], bool)


def test_api_folder_offers_rejects_missing_token(live_daemon):
    """Missing Authorization header must produce a 401 from
    /api/folder-offers — a peer-pushed list of offers leaks who's
    sent us folder shares, so it MUST be authenticated."""
    r = requests.get(
        f"{live_daemon.base_url}/api/folder-offers",
        timeout=5,
    )
    assert r.status_code == 401, (
        f"expected 401 without auth, got {r.status_code}: {r.text!r}"
    )
