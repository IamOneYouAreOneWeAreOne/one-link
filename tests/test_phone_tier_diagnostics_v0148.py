"""v0.14.8 — Phone diagnostics escape hatch.

Ship-spec from `docs/PHONE_TIER.md`:

  Reach:  phone users can still reach the diagnostics overlay
          even though Ctrl+Shift+D doesn't exist on touch and
          the Advanced settings pane (which has the desktop
          Diagnostics button) is `desktop-only` post-v0.14.4.
  Hide:   the long-press handler is gated to phone form-factor
          so desktop users keep their existing keyboard +
          Advanced-pane paths and don't surprise themselves
          by lingering on the version string.
  Async:  none — long-press is a 800ms debounce.
  Depth:  the version string in About carries
          `data-long-press-diagnostics="1"` so future ships can
          locate the affordance for deep-linking / accessibility
          work, and the phone-only hint paragraph
          `#phone-diag-hint` is shown via a CSS rule with
          `display: block !important` overriding the inline
          `display:none`.

Tests pin the markup, the long-press wiring, and the form-factor
gate.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── markup ───────────────────────────────────────────────────

def test_about_version_string_carries_long_press_marker(index_html: str):
    """The version readout MUST carry `data-long-press-diagnostics="1"`
    so future tooling can locate it without grepping for the id."""
    idx = index_html.find('id="settings-about-version"')
    assert idx > 0
    open_start = index_html.rfind("<", 0, idx)
    open_end = index_html.find(">", idx)
    tag = index_html[open_start:open_end + 1]
    assert 'data-long-press-diagnostics="1"' in tag


def test_phone_diag_hint_paragraph_present(index_html: str):
    """The phone-only hint paragraph exists and starts hidden via
    inline style — the CSS rule below promotes it to visible on phone."""
    assert 'id="phone-diag-hint"' in index_html
    idx = index_html.find('id="phone-diag-hint"')
    open_start = index_html.rfind("<", 0, idx)
    open_end = index_html.find(">", idx)
    tag = index_html[open_start:open_end + 1]
    assert "display:none" in tag
    # Confirm the human-readable copy is there.
    body_start = open_end + 1
    body_end = index_html.find("</p>", body_start)
    body = index_html[body_start:body_end]
    assert "Long-press" in body
    assert "diagnostics" in body.lower()


def test_phone_form_factor_reveals_diag_hint(index_html: str):
    """The CSS rule that promotes #phone-diag-hint to visible on phone
    MUST use `!important` so it beats the inline `display:none`."""
    needle = (
        'html[data-form-factor="phone"] #phone-diag-hint '
        "{ display: block !important; }"
    )
    assert needle in index_html


# ───────── long-press wiring ────────────────────────────────────────

def test_long_press_handler_present(index_html: str):
    """The IIFE that wires touchstart/end + mousedown/up MUST exist."""
    assert "_wirePhoneDiagnosticsLongPress" in index_html


def test_long_press_threshold_is_800ms(index_html: str):
    """800ms matches platform conventions (iOS context-menu trigger)."""
    idx = index_html.find("_wirePhoneDiagnosticsLongPress")
    snippet = index_html[idx:idx + 3000]
    assert "setTimeout(" in snippet
    assert "800" in snippet


def test_long_press_targets_about_version(index_html: str):
    idx = index_html.find("_wirePhoneDiagnosticsLongPress")
    snippet = index_html[idx:idx + 3000]
    assert '$("#settings-about-version")' in snippet


def test_long_press_skipped_off_phone(index_html: str):
    """Desktop has Ctrl+Shift+D + the Advanced pane button. The
    handler MUST early-return on non-phone form-factors so a desktop
    user lingering on the version string doesn't get surprised."""
    idx = index_html.find("_wirePhoneDiagnosticsLongPress")
    snippet = index_html[idx:idx + 3000]
    assert 'data-form-factor' in snippet
    assert '!== "phone"' in snippet


def test_long_press_opens_debug_overlay(index_html: str):
    idx = index_html.find("_wirePhoneDiagnosticsLongPress")
    snippet = index_html[idx:idx + 3000]
    assert "openDebugOverlay()" in snippet


def test_long_press_closes_settings_first(index_html: str):
    """When the diagnostics overlay opens, close the settings modal
    so two backdrops aren't stacked on top of each other."""
    idx = index_html.find("_wirePhoneDiagnosticsLongPress")
    snippet = index_html[idx:idx + 3000]
    assert '#settings-backdrop' in snippet
    assert 'classList.remove("show")' in snippet


def test_long_press_cancels_on_move(index_html: str):
    """Touchmove cancels the timer — a user scrolling the about pane
    must not accidentally open diagnostics."""
    idx = index_html.find("_wirePhoneDiagnosticsLongPress")
    snippet = index_html[idx:idx + 3000]
    assert 'touchmove' in snippet
    assert "clearTimeout" in snippet


def test_long_press_handles_mouse_too(index_html: str):
    """Hybrid form-factors (Surface, Chromebook touch) often classify
    as tablet but use mouse — wire mousedown/up as a fallback."""
    idx = index_html.find("_wirePhoneDiagnosticsLongPress")
    snippet = index_html[idx:idx + 3000]
    assert 'mousedown' in snippet
    assert 'mouseup' in snippet


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_matches_package(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
