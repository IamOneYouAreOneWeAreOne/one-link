"""v0.14.4 — Phone tier: cut power-user settings rows.

Ship-spec from `docs/PHONE_TIER.md`:

  Reach:  removal-only — phones drop entire settings panes
          (Network, Shortcuts, Advanced) and per-row tunings
          (download folder, bandwidth granularity, auto-accept
          extensions, env-var passphrase, lock-screen preview,
          reaction notifications) that don't translate to the
          phone form-factor.
  Hide:   pane-level cuts use `.desktop-only` (unconditional).
          Per-row tunings use `data-tier="advanced"` so a phone
          power-user can opt in via show-advanced.
  Async:  none.
  Depth:  the Settings nav button + the matching pane section
          carry the SAME tag, so flipping advanced reveals both
          the entry point and the destination.

Tests pin every nav button + pane section + per-row tag.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


def _find_tag_for_settings_pane(html: str, name: str, role: str) -> str:
    """Locate the open tag for a `[data-settings-pane="<name>"]`
    element matching `role` ("settings-nav-item" or "settings-pane")."""
    needle = f'data-settings-pane="{name}"'
    cursor = 0
    while True:
        idx = html.find(needle, cursor)
        if idx < 0:
            return ""
        open_start = html.rfind("<", 0, idx)
        open_end = html.find(">", idx)
        tag = html[open_start:open_end + 1]
        if role in tag:
            return tag
        cursor = idx + 1


# ───────── pane-level cuts: Network / Shortcuts / Advanced ──────────

def test_network_nav_is_desktop_only(index_html: str):
    """Rendezvous URL config is operator-grade. Cut on phone."""
    tag = _find_tag_for_settings_pane(index_html, "network", "settings-nav-item")
    assert tag, "network nav-item not found"
    assert "desktop-only" in tag


def test_network_pane_is_desktop_only(index_html: str):
    """Defense-in-depth: nav button hidden + section hidden so even
    programmatic switchSettingsPane('network') doesn't land here."""
    tag = _find_tag_for_settings_pane(index_html, "network", "settings-pane")
    assert tag, "network pane section not found"
    assert "desktop-only" in tag


def test_shortcuts_nav_is_desktop_only(index_html: str):
    """Touch users have no keyboard shortcuts to look up."""
    tag = _find_tag_for_settings_pane(index_html, "shortcuts", "settings-nav-item")
    assert "desktop-only" in tag


def test_shortcuts_pane_is_desktop_only(index_html: str):
    tag = _find_tag_for_settings_pane(index_html, "shortcuts", "settings-pane")
    assert "desktop-only" in tag


def test_advanced_nav_is_desktop_only(index_html: str):
    """Diagnostics / debug overlay / DB vacuum are operator-tier."""
    tag = _find_tag_for_settings_pane(index_html, "advanced", "settings-nav-item")
    assert "desktop-only" in tag


def test_advanced_pane_is_desktop_only(index_html: str):
    tag = _find_tag_for_settings_pane(index_html, "advanced", "settings-pane")
    assert "desktop-only" in tag


# ───────── panes that MUST stay visible on phone ────────────────────

def test_profile_pane_unchanged(index_html: str):
    tag = _find_tag_for_settings_pane(index_html, "profile", "settings-nav-item")
    assert "desktop-only" not in tag
    assert 'data-tier="advanced"' not in tag


def test_privacy_pane_unchanged(index_html: str):
    tag = _find_tag_for_settings_pane(index_html, "privacy", "settings-nav-item")
    assert "desktop-only" not in tag


def test_notifications_pane_unchanged(index_html: str):
    tag = _find_tag_for_settings_pane(index_html, "notifications", "settings-nav-item")
    assert "desktop-only" not in tag


def test_appearance_pane_unchanged(index_html: str):
    tag = _find_tag_for_settings_pane(index_html, "appearance", "settings-nav-item")
    assert "desktop-only" not in tag


def test_chats_pane_unchanged(index_html: str):
    tag = _find_tag_for_settings_pane(index_html, "chats", "settings-nav-item")
    assert "desktop-only" not in tag


def test_storage_pane_unchanged(index_html: str):
    """Storage pane stays visible — phone users care about per-chat
    usage and the size cap. Granular tunings inside it are tagged
    individually."""
    tag = _find_tag_for_settings_pane(index_html, "storage", "settings-nav-item")
    assert "desktop-only" not in tag


def test_devices_pane_unchanged(index_html: str):
    tag = _find_tag_for_settings_pane(index_html, "devices", "settings-nav-item")
    assert "desktop-only" not in tag


def test_about_pane_unchanged(index_html: str):
    """About is the v0.14.8 long-press escape hatch host. It MUST
    remain visible on phone."""
    tag = _find_tag_for_settings_pane(index_html, "about", "settings-nav-item")
    assert "desktop-only" not in tag


# ───────── per-row advanced tags inside Storage ─────────────────────

def test_download_folder_section_is_advanced(index_html: str):
    """iOS + Android sandboxes don't expose a writable absolute path
    the user picks; built-in inbox is the only sensible default on
    phone. Tag the SECTION (header + input + help all hide together)."""
    idx = index_html.find("set-download-folder")
    assert idx > 0
    section_start = index_html.rfind('<div class="settings-section"', 0, idx)
    open_end = index_html.find(">", section_start)
    tag = index_html[section_start:open_end + 1]
    assert 'data-tier="advanced"' in tag


def test_bandwidth_section_is_advanced(index_html: str):
    """Granular per-MB/s throttling is operator-grade. Phones rely
    on the OS data-saver."""
    idx = index_html.find("set-bandwidth-cap")
    assert idx > 0
    section_start = index_html.rfind('<div class="settings-section"', 0, idx)
    open_end = index_html.find(">", section_start)
    tag = index_html[section_start:open_end + 1]
    assert 'data-tier="advanced"' in tag


def test_auto_accept_size_cap_stays_visible(index_html: str):
    """The size cap row MUST remain visible on phone — this is the
    defang-by-budget primitive. Don't tag the row as advanced."""
    idx = index_html.find("set-auto-accept-size")
    assert idx > 0
    row_start = index_html.rfind('<div class="settings-row', 0, idx)
    open_end = index_html.find(">", row_start)
    tag = index_html[row_start:open_end + 1]
    assert 'data-tier="advanced"' not in tag


def test_auto_accept_extensions_row_is_advanced(index_html: str):
    """Per-extension allowlists are advanced; size cap covers the
    common case."""
    idx = index_html.find("set-auto-accept-exts")
    assert idx > 0
    row_start = index_html.rfind('<div class="settings-row', 0, idx)
    open_end = index_html.find(">", row_start)
    tag = index_html[row_start:open_end + 1]
    assert 'data-tier="advanced"' in tag


# ───────── per-row advanced tags inside Privacy ─────────────────────

def test_passphrase_row_is_advanced(index_html: str):
    """Setting an env var before launch is not a phone-installable
    workflow. Phone relies on OS Secure Enclave for at-rest."""
    idx = index_html.find("set-passphrase")
    assert idx > 0
    row_start = index_html.rfind('<div class="settings-row', 0, idx)
    open_end = index_html.find(">", row_start)
    tag = index_html[row_start:open_end + 1]
    assert 'data-tier="advanced"' in tag


def test_pair_allow_all_row_unchanged(index_html: str):
    """The trust-new-pairings toggle stays default-visible — it's a
    direct behavior switch users might toggle daily, not power-user
    configuration."""
    idx = index_html.find("set-pair-allow-all")
    assert idx > 0
    row_start = index_html.rfind('<div class="settings-row', 0, idx)
    open_end = index_html.find(">", row_start)
    tag = index_html[row_start:open_end + 1]
    assert 'data-tier="advanced"' not in tag
    assert "desktop-only" not in tag


# ───────── per-row advanced tags inside Notifications ───────────────

def test_what_to_notify_section_is_advanced(index_html: str):
    """Lock-screen preview + reaction-ping are tuning, not core.
    Phone users control these via the OS notification settings."""
    idx = index_html.find("set-notif-preview")
    assert idx > 0
    section_start = index_html.rfind('<div class="settings-section"', 0, idx)
    open_end = index_html.find(">", section_start)
    tag = index_html[section_start:open_end + 1]
    assert 'data-tier="advanced"' in tag


def test_dnd_section_unchanged(index_html: str):
    """Quiet hours is a daily-use feature on phone — keep visible."""
    idx = index_html.find("set-dnd-enabled")
    assert idx > 0
    section_start = index_html.rfind('<div class="settings-section"', 0, idx)
    open_end = index_html.find(">", section_start)
    tag = index_html[section_start:open_end + 1]
    assert 'data-tier="advanced"' not in tag
    assert "desktop-only" not in tag


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_matches_package(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
