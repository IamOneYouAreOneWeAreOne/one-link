"""v0.14.6 — Phone tier: composer + drag-drop trim.

Ship-spec from `docs/PHONE_TIER.md`:

  Reach:  iOS users with a home indicator stop having the send
          button half-covered by the system swipe target.
  Hide:   the screenshot-from-clipboard button (`#btn-screenshot`)
          and the drag-drop overlay (`#drop-overlay`) gain
          `.desktop-only` — phones don't have the host UX
          for either (no system "paste from clipboard" for
          screenshots, no drag from the home screen).
  Async:  none.
  Depth:  the composer pads its bottom edge using
          `max(8px, env(safe-area-inset-bottom))` so non-notched
          devices keep their 8px breathing room while iPhones
          with the home indicator get the OS-recommended inset.

Tests pin the markup tags + the CSS rule.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── desktop-only tags ────────────────────────────────────────

def test_screenshot_button_is_desktop_only(index_html: str):
    """Phones use the OS share sheet, not in-app clipboard paste."""
    idx = index_html.find('id="btn-screenshot"')
    assert idx > 0
    open_start = index_html.rfind("<button", 0, idx)
    open_end = index_html.find(">", idx)
    tag = index_html[open_start:open_end + 1]
    assert "desktop-only" in tag


def test_drop_overlay_is_desktop_only(index_html: str):
    """Phones have no drag-from-home-screen affordance; the overlay
    is dead weight on touch."""
    idx = index_html.find('id="drop-overlay"')
    assert idx > 0
    open_start = index_html.rfind("<div", 0, idx)
    open_end = index_html.find(">", idx)
    tag = index_html[open_start:open_end + 1]
    assert "desktop-only" in tag


# ───────── essentials must remain on phone ──────────────────────────

def test_attach_button_unchanged(index_html: str):
    """The attach button (📎) is the phone path for sending files —
    must NEVER carry desktop-only."""
    idx = index_html.find('id="btn-attach2"')
    assert idx > 0
    open_start = index_html.rfind("<button", 0, idx)
    open_end = index_html.find(">", idx)
    tag = index_html[open_start:open_end + 1]
    assert "desktop-only" not in tag


def test_voice_button_unchanged(index_html: str):
    """Voice messages are a first-class phone surface; keep visible."""
    idx = index_html.find('id="btn-voice"')
    assert idx > 0
    open_start = index_html.rfind("<button", 0, idx)
    open_end = index_html.find(">", idx)
    tag = index_html[open_start:open_end + 1]
    assert "desktop-only" not in tag


def test_send_button_unchanged(index_html: str):
    idx = index_html.find('id="btn-send"')
    assert idx > 0
    open_start = index_html.rfind("<button", 0, idx)
    open_end = index_html.find(">", idx)
    tag = index_html[open_start:open_end + 1]
    assert "desktop-only" not in tag


# ───────── safe-area-inset for iOS home indicator ───────────────────

def test_composer_uses_safe_area_inset_bottom(index_html: str):
    """The composer's bottom padding MUST clamp to
    `max(8px, env(safe-area-inset-bottom))` so the send button
    isn't covered by the home-indicator swipe target on iPhones."""
    assert "env(safe-area-inset-bottom)" in index_html
    # The rule lives inside the mobile media query — pin both in
    # one go via a substring match.
    assert "padding-bottom: max(8px, env(safe-area-inset-bottom))" in index_html


def test_safe_area_rule_lives_inside_mobile_media_query(index_html: str):
    """The rule must NOT apply on desktop, where browsers without
    env() support could choke. Verify it sits inside the existing
    @media (max-width: 720px) block."""
    media_idx = index_html.find("@media (max-width: 720px)")
    media_idx2 = index_html.find("@media (max-width: 720px)", media_idx + 1)
    assert media_idx2 > 0
    rule_idx = index_html.find("padding-bottom: max(8px, env(safe-area-inset-bottom))")
    assert rule_idx > media_idx2, "safe-area-inset rule must live INSIDE the mobile media query"


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_matches_package(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
