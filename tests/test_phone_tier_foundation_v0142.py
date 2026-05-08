"""v0.14.2 — Phone tier foundation.

Ship-spec gated by `docs/PHONE_TIER.md`:

  Reach:  the page knows whether it's loaded on a phone, tablet,
          or desktop and tags <html> with `data-form-factor` so
          subsequent ships can hide power-user surfaces by tagging
          elements `.desktop-only` or `[data-tier="advanced"]`.
  Hide:   the show-advanced toggle in Profile flips a class on
          <html> that reveals `[data-tier="advanced"]` regardless
          of form-factor; persistence is desktop-only so a phone
          user who briefly enables advanced doesn't get stuck in
          it on the next launch.
  Async:  re-evaluation of form-factor on resize is debounced so a
          phone rotation doesn't flicker the whole UI.
  Depth:  this ship is mechanism-only. v0.14.3 → v0.14.8 tag the
          actual elements. Pin the mechanism here so a future
          refactor of the toggle / detector can't silently break
          every subsequent phone-tier ship.

Tests pin the markup, the CSS reveal rules, and the JS helpers.
No daemon plumbing — purely a static-page contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── form-factor detector + applier ───────────────────────────

def test_detect_form_factor_helper_present(index_html: str):
    """`_detectFormFactor` is the single source of truth for which
    tier the page is in. Renaming or removing it breaks every
    subsequent v0.14.x ship that hides things on phone."""
    assert "function _detectFormFactor()" in index_html


def test_detect_uses_min_dimension_not_width(index_html: str):
    """Use min(innerWidth, innerHeight) so a phone in landscape
    doesn't suddenly look like a desktop."""
    idx = index_html.find("function _detectFormFactor()")
    snippet = index_html[idx:idx + 800]
    assert "Math.min(window.innerWidth, window.innerHeight)" in snippet


def test_detect_phone_threshold_pinned(index_html: str):
    """The 480px phone breakpoint is the contract. Don't let it
    drift without an explicit ship + redocumented PHONE_TIER.md."""
    idx = index_html.find("function _detectFormFactor()")
    snippet = index_html[idx:idx + 800]
    assert "<= 480" in snippet
    assert 'return "phone"' in snippet


def test_detect_tablet_threshold_pinned(index_html: str):
    """Tablet-tier sits between 481-900 + touch. Tablet currently
    behaves as desktop for hiding rules, but the bucket exists for
    future divergence."""
    idx = index_html.find("function _detectFormFactor()")
    snippet = index_html[idx:idx + 800]
    assert "<= 900" in snippet
    assert 'return "tablet"' in snippet


def test_detect_falls_through_to_desktop(index_html: str):
    idx = index_html.find("function _detectFormFactor()")
    snippet = index_html[idx:idx + 800]
    assert 'return "desktop"' in snippet


def test_detect_uses_useragent_mobile_signal(index_html: str):
    """A small desktop window must not mis-classify as a phone, but
    a phone reporting an unusually wide viewport (zoom / split-view)
    still classifies as phone via UA. Pin both signals."""
    idx = index_html.find("function _detectFormFactor()")
    snippet = index_html[idx:idx + 800]
    assert "navigator.userAgent" in snippet
    assert "iphone" in snippet
    assert "android" in snippet


def test_apply_form_factor_writes_html_attribute(index_html: str):
    """`<html data-form-factor="...">` is the wire CSS reads. Don't
    let a refactor target body/main instead — the CSS rules below
    require it specifically on the documentElement."""
    idx = index_html.find("function _applyFormFactor()")
    snippet = index_html[idx:idx + 400]
    assert 'document.documentElement.setAttribute("data-form-factor"' in snippet


def test_apply_runs_at_script_open_before_paint(index_html: str):
    """We MUST set the attribute before any CSS that depends on it
    is evaluated. Easiest way: call `_applyFormFactor()` immediately
    after the function defs, inside the IIFE, before init()."""
    apply_def = index_html.find("function _applyFormFactor()")
    init_def = index_html.find("async function init()")
    invoke = index_html.find("_applyFormFactor();", apply_def)
    assert apply_def > 0
    assert init_def > 0
    assert apply_def < invoke < init_def


def test_resize_listener_is_debounced(index_html: str):
    """A phone rotating between portrait + landscape must not
    flicker the form-factor; the 250ms debounce is the contract."""
    apply_def = index_html.find("function _applyFormFactor()")
    snippet = index_html[apply_def:apply_def + 2000]
    assert 'window.addEventListener("resize"' in snippet
    assert "setTimeout(_applyFormFactor, 250)" in snippet


# ───────── CSS reveal rules ─────────────────────────────────────────

def test_phone_hides_desktop_only(index_html: str):
    """Rule 1: every element tagged `.desktop-only` MUST disappear
    on phone form-factor. v0.14.3+ relies on this."""
    assert (
        'html[data-form-factor="phone"] .desktop-only { display: none !important; }'
        in index_html
    )


def test_phone_hides_advanced_tier_by_default(index_html: str):
    """Rule 2: `[data-tier="advanced"]` is hidden on phone unless
    the user has explicitly opted into advanced mode."""
    assert (
        'html[data-form-factor="phone"] [data-tier="advanced"] { display: none; }'
        in index_html
    )


def test_show_advanced_class_reveals_globally(index_html: str):
    """Rule 3: `html.show-advanced` un-hides advanced surfaces
    regardless of form-factor. Use `display: revert` so the
    element returns to its natural display, not forced block."""
    assert (
        "html.show-advanced [data-tier=\"advanced\"] { display: revert !important; }"
        in index_html
    )


def test_advanced_hint_style_present(index_html: str):
    """The per-pane "N advanced controls hidden" hint has a styled
    class so it doesn't look like dropped junk text."""
    assert ".advanced-hint" in index_html
    idx = index_html.find(".advanced-hint {")
    snippet = index_html[idx:idx + 400]
    assert "font-style: italic" in snippet


# ───────── show-advanced toggle markup ──────────────────────────────

def test_show_advanced_toggle_input_present(index_html: str):
    """The toggle's id is the join point for the JS handler. Don't
    rename without updating _setShowAdvanced + the wiring below."""
    assert 'id="set-show-advanced"' in index_html


def test_toggle_lives_in_profile_pane(index_html: str):
    """It must sit in Profile / settings (not in a one-off menu) so
    the user finds it where they're already adjusting visibility +
    notification + privacy controls."""
    profile_idx = index_html.find('id="set-show-advanced"')
    label_window = index_html[max(0, profile_idx - 600):profile_idx]
    assert "Advanced controls" in label_window or "advanced" in label_window.lower()


# ───────── state.tier + helpers ─────────────────────────────────────

def test_state_tier_initialized_default(index_html: str):
    """`state.tier` is the runtime mirror of html.show-advanced;
    JS branches on it to skip rendering advanced-only widgets."""
    assert 'state.tier = "default"' in index_html


def test_init_tier_reads_form_factor(index_html: str):
    """Initialization branches on form-factor — desktop reads
    persisted preference, phone always starts in default tier."""
    idx = index_html.find("function _initTier()")
    assert idx > 0
    snippet = index_html[idx:idx + 1500]
    assert "data-form-factor" in snippet
    assert 'localStorage.getItem("one_link.show_advanced")' in snippet


def test_init_tier_invoked_at_boot(index_html: str):
    """`_initTier()` MUST run during the IIFE so the toggle reflects
    the saved preference before the user can interact."""
    init_def = index_html.find("function _initTier()")
    set_def = index_html.find("function _setShowAdvanced(on, persist)")
    invoke = index_html.find("_initTier();", init_def)
    assert init_def > 0
    assert set_def > 0
    assert invoke > set_def


def test_set_show_advanced_toggles_html_class(index_html: str):
    """The class flip is what triggers Rule 3 above. Don't let a
    refactor switch this to a body class or class on .app — Rule 3
    is pinned on `html`."""
    idx = index_html.find("function _setShowAdvanced(on, persist)")
    snippet = index_html[idx:idx + 800]
    assert 'document.documentElement.classList.toggle("show-advanced", on)' in snippet


def test_set_show_advanced_updates_state(index_html: str):
    idx = index_html.find("function _setShowAdvanced(on, persist)")
    snippet = index_html[idx:idx + 800]
    assert 'state.tier = on ? "advanced" : "default"' in snippet


def test_set_show_advanced_persists_only_when_asked(index_html: str):
    """Persistence is opt-in via the `persist` argument so phone
    sessions reset and don't leak advanced-tier state across
    restarts."""
    idx = index_html.find("function _setShowAdvanced(on, persist)")
    snippet = index_html[idx:idx + 800]
    assert "if (persist)" in snippet
    assert 'localStorage.setItem("one_link.show_advanced"' in snippet


def test_toggle_change_handler_persists_only_on_desktop(index_html: str):
    """The handler reads form-factor again at change-time so a
    phone user who triggers it (e.g. via the [Show] hint) doesn't
    accidentally persist."""
    idx = index_html.find('$("#set-show-advanced")?.addEventListener')
    assert idx > 0
    snippet = index_html[idx:idx + 600]
    assert "data-form-factor" in snippet
    assert 'ff === "desktop"' in snippet
    assert "_setShowAdvanced(" in snippet


# ───────── per-pane hint helper ─────────────────────────────────────

def test_attach_advanced_hint_helper_present(index_html: str):
    """v0.14.3+ wires this on each pane that has hidden advanced
    rows. Pin the API now so subsequent ships can rely on the
    name + signature."""
    assert "function _attachAdvancedHint(hostSelector)" in index_html


def test_advanced_hint_short_circuits_when_already_attached(index_html: str):
    """Re-running on the same host must not double-append. Pin the
    `:scope > .advanced-hint` guard."""
    idx = index_html.find("function _attachAdvancedHint(hostSelector)")
    snippet = index_html[idx:idx + 1500]
    assert ":scope > .advanced-hint" in snippet


def test_advanced_hint_skipped_when_no_hidden_descendants(index_html: str):
    """If a pane has zero `[data-tier="advanced"]` children, no
    hint is added — otherwise we'd dangle dead helper text."""
    idx = index_html.find("function _attachAdvancedHint(hostSelector)")
    snippet = index_html[idx:idx + 1500]
    assert "advanced.length === 0" in snippet


def test_advanced_hint_show_link_flips_global(index_html: str):
    """The [Show] link inside the hint flips the global toggle, not
    just hides the hint locally."""
    idx = index_html.find("function _attachAdvancedHint(hostSelector)")
    snippet = index_html[idx:idx + 1500]
    assert "_setShowAdvanced(true, false)" in snippet


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_matches_package(index_html: str):
    """The PAGE_BUILT_FOR constant must match the package version
    so the daemon-page version-mismatch banner doesn't fire on a
    fresh install. Forward-compatible: this test stays green across
    later version bumps."""
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
