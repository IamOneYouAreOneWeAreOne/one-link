"""v0.14.5 — Phone tier: trim per-device drawer.

Ship-spec from `docs/PHONE_TIER.md`:

  Reach:  removal-only — phone users opening a device drawer see
          only the daily-use surfaces (alias, mute, allow-all,
          identity SAS, disappearing messages, chat tools, trust
          actions). Operator-tier surfaces — connection regime,
          latency, NAT class, granular per-capability toggles,
          and the trust timeline — collapse to the show-advanced
          tier.
  Hide:   `data-tier="advanced"` on the Reachability section, the
          per-capability cap-toggle row, and the trust history
          section. The "Allow all" master toggle above the cap row
          stays default-visible so phone users can flip permissions
          off entirely without going advanced.
  Async:  none.
  Depth:  identity surfaces (Short ID, Fingerprint, SAS, SAS art
          toggle) stay default-visible because in-person verification
          is THE primitive that defends the channel; we don't gate
          it behind an opt-in.

Tests pin the section tags + verify the daily-use surfaces remain
default-visible.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


def _section_tag_for_id(html: str, sid: str) -> str:
    """Return the open tag for `<div ... id="{sid}">` (or empty)."""
    needle = f'id="{sid}"'
    idx = html.find(needle)
    if idx < 0:
        return ""
    open_start = html.rfind("<", 0, idx)
    open_end = html.find(">", idx)
    return html[open_start:open_end + 1]


def _section_tag_containing_label(html: str, label: str) -> str:
    """Find the nearest `<div class="settings-section ..."` ancestor of
    a section header that says `<span>{label}</span>`."""
    needle = f"<span>{label}</span>"
    idx = html.find(needle)
    if idx < 0:
        return ""
    # Walk back to the enclosing parent settings-section (with closing
    # quote on `class="settings-section"` to avoid matching the inner
    # `settings-section-h` header div).
    section_start = html.rfind('<div class="settings-section"', 0, idx)
    if section_start < 0:
        return ""
    open_end = html.find(">", section_start)
    return html[section_start:open_end + 1]


# ───────── advanced-tier sections ───────────────────────────────────

def test_reachability_section_is_advanced(index_html: str):
    """Connection regime, latency, address are operator-grade."""
    tag = _section_tag_containing_label(index_html, "Reachability")
    assert tag, "Reachability section header not found"
    assert 'data-tier="advanced"' in tag


def test_cap_toggle_row_is_advanced(index_html: str):
    """Granular per-capability toggles are advanced; "Allow all"
    above is the daily-use surface."""
    tag = _section_tag_for_id(index_html, "dev-cap-row")
    assert tag, "#dev-cap-row not found"
    assert 'data-tier="advanced"' in tag


def test_trust_history_section_is_advanced(index_html: str):
    """Trust timeline is forensic; daily-use users see SAS instead."""
    tag = _section_tag_for_id(index_html, "dev-trust-history-section")
    assert tag, "#dev-trust-history-section not found"
    assert 'data-tier="advanced"' in tag


# ───────── default-visible (must stay) ──────────────────────────────

def test_display_section_unchanged(index_html: str):
    """Custom name + mute + mute-duration are daily-use; phone users
    must see them."""
    tag = _section_tag_containing_label(index_html, "Display")
    assert tag
    assert 'data-tier="advanced"' not in tag


def test_permissions_section_unchanged(index_html: str):
    """The Permissions section ITSELF stays visible; only the
    granular cap-toggle row inside it is advanced."""
    tag = _section_tag_containing_label(index_html, "Permissions")
    assert tag
    assert 'data-tier="advanced"' not in tag


def test_identity_section_unchanged(index_html: str):
    """Short ID + fingerprint + SAS + SAS art toggle MUST stay
    default-visible. In-person verification is THE primitive that
    defends the channel; we don't gate it behind an opt-in."""
    # Header uses the HTML entity for the ampersand.
    tag = _section_tag_containing_label(index_html, "Identity &amp; trust")
    assert tag
    assert 'data-tier="advanced"' not in tag


def test_disappearing_messages_unchanged(index_html: str):
    tag = _section_tag_containing_label(index_html, "Disappearing messages")
    assert tag
    assert 'data-tier="advanced"' not in tag


def test_verified_in_person_unchanged(index_html: str):
    tag = _section_tag_for_id(index_html, "dev-verify-section")
    assert tag
    assert 'data-tier="advanced"' not in tag


def test_chat_tools_unchanged(index_html: str):
    """Media gallery + export + clear-history are daily-ish; keep
    visible on phone (phone users still want export / clear)."""
    tag = _section_tag_containing_label(index_html, "Chat tools")
    assert tag
    assert 'data-tier="advanced"' not in tag


def test_trust_actions_unchanged(index_html: str):
    """Unpair + Block stay default-visible — those are the bedrock
    safety affordances."""
    tag = _section_tag_containing_label(index_html, "Trust actions")
    assert tag
    assert 'data-tier="advanced"' not in tag


# ───────── allow-all toggle is the daily-use surface ────────────────

def test_dev_allow_all_row_unchanged(index_html: str):
    """The Allow-all master toggle row inside Permissions must stay
    visible — it's the user's coarse on/off for capabilities."""
    idx = index_html.find("dev-allow-all")
    assert idx > 0
    row_start = index_html.rfind('<div class="settings-row', 0, idx)
    open_end = index_html.find(">", row_start)
    tag = index_html[row_start:open_end + 1]
    assert 'data-tier="advanced"' not in tag


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_matches_package(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
