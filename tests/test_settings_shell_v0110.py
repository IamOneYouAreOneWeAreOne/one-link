"""v0.11.0 — Settings shell.

Phase 1 of the Settings overhaul: replace the single long-scroll
settings modal with a navigable left-rail + pane layout, matching
the convention every major app converges on (Discord, Slack,
Signal, Telegram, WhatsApp).

Goals for THIS phase:
  - Categories: Profile / Privacy / Notifications / Appearance /
    Chats / Network / Storage / Devices / Shortcuts / Advanced /
    About.
  - Existing setting IDs are preserved so all the saved-settings
    JS keeps working unchanged.
  - About surfaces version + protocol + schema dynamically.
  - Profile surfaces fingerprint dynamically (read-only).
  - Open settings always lands on Profile (predictable).
  - Phase 2+ slots in features into existing categories without
    further restructuring.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── shell + nav ────────────────────────────────────────────────

def test_settings_modal_uses_shell_layout(index_html: str):
    """The shell class drives the nav-rail + pane grid. Without it
    the modal falls back to the old long-scroll body."""
    assert 'class="modal settings-shell"' in index_html


def test_settings_has_header_with_close(index_html: str):
    """A persistent header with an × close anchor — same convention
    Discord/Slack/Telegram all use. The Save button stays in the
    footer."""
    idx = index_html.find('id="settings-backdrop"')
    assert idx > 0
    scope = index_html[idx:idx + 4000]
    assert 'class="settings-header"' in scope
    assert 'class="settings-close"' in scope
    assert 'id="settings-cancel"' in scope


def test_nav_rail_present(index_html: str):
    assert 'class="settings-nav"' in index_html
    assert 'id="settings-nav"' in index_html


@pytest.mark.parametrize("name,glyph", [
    ("profile", "👤"),
    ("privacy", "🛡"),
    ("notifications", "🔔"),
    ("appearance", "🎨"),
    ("chats", "💬"),
    ("network", "🌐"),
    ("storage", "💾"),
    ("devices", "🖥"),
    ("shortcuts", "⌨"),
    ("advanced", "⚙"),
    ("about", "ⓘ"),
])
def test_each_section_has_nav_button(index_html: str, name: str, glyph: str):
    """Pin every section so a future refactor can't quietly remove
    one. Both the nav button AND the matching pane must exist."""
    assert f'data-settings-pane="{name}"' in index_html
    # The glyph appears in the nav button — useful affordance and
    # also a regression guard for ordering / labeling.
    assert glyph in index_html


def test_each_section_has_pane(index_html: str):
    """Counts must match: 11 nav items, 11 panes. v0.14.4 added
    `.desktop-only` to network/shortcuts/advanced nav buttons; the
    structural pin must survive arbitrary additional classes —
    match on `data-settings-pane="<name>"` plus the role class
    individually instead of pinning a fixed class string."""
    import re

    expected = [
        "profile", "privacy", "notifications", "appearance",
        "chats", "network", "storage", "devices",
        "shortcuts", "advanced", "about",
    ]
    for name in expected:
        nav_pattern = re.compile(
            r'<button\s+class="[^"]*settings-nav-item[^"]*"[^>]*'
            rf'data-settings-pane="{name}"'
        )
        pane_pattern = re.compile(
            r'<section\s+class="[^"]*settings-pane[^"]*"[^>]*'
            rf'data-settings-pane="{name}"'
        )
        assert nav_pattern.search(index_html), f"nav button missing for {name!r}"
        assert pane_pattern.search(index_html), f"pane section missing for {name!r}"


# ───────── existing input IDs preserved ──────────────────────────────

@pytest.mark.parametrize("input_id", [
    "set-name",                 # Profile
    "set-pair-allow-all",       # Privacy
    "set-passphrase",           # Privacy
    "set-notif",                # Notifications
    "set-sound",                # Notifications
    "set-sound-test",           # Notifications
    "set-dnd-enabled",          # Notifications
    "set-dnd-start",            # Notifications
    "set-dnd-end",              # Notifications
    "set-theme",                # Appearance
    "set-autoaccept",           # Chats
    "set-rendezvous",           # Network
    "set-download-folder",      # Storage
    "set-log-level",            # Advanced
    "settings-open-diagnostics", # Advanced
])
def test_existing_setting_id_preserved(index_html: str, input_id: str):
    """All the inputs the existing JS reads/writes must still exist.
    Renaming any of these would silently break load/save flows."""
    assert f'id="{input_id}"' in index_html, (
        f"setting input id={input_id!r} missing — JS that reads/writes "
        f"it would silently no-op"
    )


# ───────── JS dispatch + dynamic fields ──────────────────────────────

def test_pane_switcher_function_present(index_html: str):
    assert "function switchSettingsPane(name)" in index_html


def test_nav_item_click_wires_pane_switch(index_html: str):
    idx = index_html.find('document.querySelectorAll(".settings-nav-item")')
    assert idx > 0
    snippet = index_html[idx:idx + 400]
    assert "switchSettingsPane(" in snippet


def test_open_resets_to_profile(index_html: str):
    """Each open of settings should land on Profile so the user has
    a predictable entry point. Without this, the last clicked pane
    would persist across sessions, which feels random when a friend
    asks 'where do I change my display name?'"""
    idx = index_html.find('$("#btn-settings").onclick')
    assert idx > 0, "settings open handler not found"
    snippet = index_html[idx:idx + 9000]
    assert 'switchSettingsPane("profile")' in snippet


def test_about_pane_fills_dynamically(index_html: str):
    """Version / protocol / schema must be filled from /api/me, not
    hardcoded — otherwise a refactor's version bump goes stale."""
    assert "function refreshSettingsAbout()" in index_html
    idx = index_html.find("function refreshSettingsAbout()")
    snippet = index_html[idx:idx + 1000]
    assert '#settings-about-version' in snippet
    assert '#settings-about-protocol' in snippet
    assert '#settings-about-schema' in snippet
    assert '#settings-identity-fp' in snippet


def test_about_pane_links_to_source(index_html: str):
    """The About pane must link out to the source repo — table-stakes
    transparency for a privacy-positioned product. Search the whole
    pane body (until `</section>`) so legitimate growth — install
    affordance, connect-another-device QR — doesn't false-fail this
    pin on a fixed character window."""
    idx = index_html.find('data-settings-pane="about"')
    # Find the second occurrence (the pane, not the nav).
    pane_idx = index_html.find('data-settings-pane="about"', idx + 1)
    pane_end = index_html.find("</section>", pane_idx)
    assert pane_end > pane_idx
    scope = index_html[pane_idx:pane_end]
    assert "github.com/IamOneYouAreOneWeAreOne/one-link" in scope


# ───────── version pin ───────────────────────────────────────────────

def test_page_version_bumped(index_html: str):
    """The page-version string must match __version__. We don't pin
    a specific version here so future ships in the 0.11.x line don't
    have to update this file."""
    from one_link import __version__
    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
