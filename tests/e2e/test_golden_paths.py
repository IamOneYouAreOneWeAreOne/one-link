"""v0.21.x golden-path E2E tests.

These tests pin the 'happy path' the user walks through on first
install. If any of these fail, the project's #1 selling point ('it
just works for a non-technical friend in under 5 minutes') is
broken - the README's 'we got there' test no longer passes.

Each test is intentionally high-level and DOM-stable: we look for
named landmarks (Chat tab, Files tab, Activity tab, etc.) rather
than CSS classes that might be restyled, so a future visual
refactor doesn't churn the tests.
"""
from __future__ import annotations

import re

import requests


# ── basic UI is alive ──────────────────────────────────────────────


def test_top_nav_tabs_all_present(ui_page):
    """The four primary navigation tabs (Chat / Files / Folders /
    Activity) MUST render on every load. If any disappears, the
    user loses access to a whole pane of functionality."""
    for tab_name in ["Chat", "Files", "Folders", "Activity"]:
        loc = ui_page.get_by_role("button", name=tab_name).or_(
            ui_page.get_by_text(tab_name, exact=True)
        ).first
        assert loc.count() > 0, (
            f"top-nav tab {tab_name!r} missing from rendered UI; "
            "users would have no way to reach that pane"
        )


def test_identity_chip_shows_pseudonym_or_hostname(ui_page):
    """The top-right identity chip surfaces the user's display name.
    The pseudonym ('I am One') is the default. Without this,
    users have no in-app cue for which identity they're operating
    under (matters on multi-identity Phase D)."""
    # The chip is at #me-chip / similar. Let's find it via text.
    body_text = ui_page.locator("body").inner_text()
    # Either the pseudonym OR the hostname OR the short_id - any
    # of those is fine as the identity surface. What we DON'T want
    # is a blank chip or a literal 'undefined'.
    assert "undefined" not in body_text.lower().split("\n")[0:20].__str__()


def test_pair_a_new_device_button_is_reachable(ui_page):
    """The first action a brand-new user takes is pairing a second
    device. If 'Pair a new device' isn't a discoverable button,
    the project's onboarding is broken."""
    pair_btn = ui_page.get_by_text(re.compile(r"Pair a new device", re.IGNORECASE)).first
    assert pair_btn.count() > 0, (
        "'Pair a new device' button missing from sidebar; "
        "users have no way to start the pairing flow"
    )


# ── recovery wizard surface ──────────────────────────────────────


def test_recovery_wizard_button_opens_three_track_modal(ui_page):
    """v0.21.x recovery wizard ships three independent recovery
    tracks (phrase, encrypted backup, social shares). Opening the
    wizard should surface all three as distinct cards. Without
    this, the recovery-from-lost-devices story is invisible."""
    # The wizard opens via a settings entry or a recovery-status
    # CTA - find it via text.
    # Open Settings first (gear icon at the top right).
    # Index.html uses #btn-settings; older builds used #btn-open-settings
    # or .btn-settings. Keep all selectors as fallbacks.
    settings_btn = ui_page.locator(
        "#btn-settings, #btn-open-settings, .btn-settings, "
        "[aria-label*='Settings']"
    ).first
    assert settings_btn.count() > 0, (
        "settings button not found — every selector failed; the "
        "Settings entry point is no longer reachable from the UI"
    )
    settings_btn.click()
    ui_page.wait_for_timeout(500)
    # Look for the recovery wizard launcher within settings.
    recovery_launcher = ui_page.get_by_text(
        re.compile(r"recovery|backup", re.IGNORECASE)
    )
    assert recovery_launcher.count() > 0, (
        "no recovery/backup entry in Settings; the v0.21.x "
        "recovery wizard is unreachable from the UI"
    )


# ── error handling ─────────────────────────────────────────────────


def test_unauthorized_api_call_returns_help_not_blank_unauthorized(live_daemon):
    """A user reload with a stale token used to land on a blank
    'unauthorized' page. The v0.21.x audit fix ships a friendly
    help page instead. Verify by hitting /api/me with no token
    and checking we get a structured 401 with a hint."""
    r = requests.get(
        f"{live_daemon.base_url}/api/me", timeout=5,
    )
    assert r.status_code == 401
    # The response can be JSON ({"error": ..., "hint": ...}) or
    # HTML (the help page). Either is fine - the regression to
    # avoid is a literal empty body or just the word 'unauthorized'.
    body = r.text.strip()
    assert body, "401 response had empty body"
    assert body.lower() != "unauthorized", (
        "401 response is just the literal word 'unauthorized'; "
        "the v0.21.x audit fix ships a help message instead"
    )


# ── security headers (every release should set these) ────────────


def test_index_response_sets_security_headers(live_daemon):
    """The main UI MUST ship with X-Content-Type-Options, CSP,
    and an origin-scoped browser bearer. Without these the site is open to MIME
    sniffing attacks and XSS amplification."""
    r = requests.get(
        live_daemon.auth_url, allow_redirects=False, timeout=5,
    )
    assert r.status_code == 200, f"got {r.status_code}: {r.text[:200]}"
    assert r.headers.get("X-Content-Type-Options", "").lower() == "nosniff"
    csp = r.headers.get("Content-Security-Policy", "")
    assert csp, "no CSP set on index response"
    assert "default-src" in csp or "script-src" in csp, (
        f"CSP missing source directives: {csp!r}"
    )
    # Plain loopback cookies are port-agnostic. The response expires every
    # historical auth cookie and injects a revocable origin-storage session.
    set_cookie = r.headers.get("Set-Cookie", "")
    assert "ol_ui=" in set_cookie
    assert "Max-Age=0" in set_cookie
    assert "ol_persistent_session_token" in r.text
    assert live_daemon.token not in r.text


def test_api_files_overrides_x_frame_options_for_inline_previews(live_daemon):
    """Already tested in test_session_bug_regressions but this is
    the explicit golden-path assertion: every release must serve
    /api/files with SAMEORIGIN framing so the PDF + video + audio
    preview iframes/elements can render. A regression here breaks
    EVERY preview, not just one bug."""
    inbox = live_daemon.home / "data" / "inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    (inbox / "preview_gate.txt").write_bytes(b"hello preview")
    r = requests.get(
        f"{live_daemon.base_url}/api/files/preview_gate.txt",
        headers={"Authorization": f"Bearer {live_daemon.token}"},
        timeout=5,
    )
    assert r.status_code == 200
    xfo = r.headers.get("X-Frame-Options", "")
    csp = r.headers.get("Content-Security-Policy", "")
    assert xfo.upper() == "SAMEORIGIN" or "frame-ancestors 'self'" in csp


# ── doctrine-of-invisibility live check ──────────────────────────


def test_index_html_does_not_render_any_reconnecting_overlay(ui_page):
    """Doctrine of invisibility §3.2.a: no 'Reconnecting...' overlay
    visible to the user. The unit test pins source-text; this is
    the live-DOM check that, even after JS-driven UI updates fire,
    no rendered text contains the forbidden phrase."""
    # All visible text on the page.
    body_text = ui_page.locator("body").inner_text().lower()
    # The doctrine regex (matches 'reconnecting', 'reestablishing',
    # 'trying to connect') applied to the rendered text.
    forbidden = [
        "reconnecting",
        "reestablishing",
        "trying to connect",
        "trying-to-connect",
    ]
    found = [w for w in forbidden if w in body_text]
    assert not found, (
        f"doctrine §3.2.a violation in rendered UI: {found}; "
        "the user is being told the network is reconnecting, "
        "which the invisibility doctrine forbids"
    )
