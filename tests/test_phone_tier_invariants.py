"""Phone-tier cross-cutting invariants.

These pins guard properties that span multiple v0.14.x ships and
would otherwise be easy to break by accident in a future ship.

If any of these fail it indicates a tier-semantics regression — not
a single-ship bug. Read carefully before "fixing" by relaxing the
assertion.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── tag mutual-exclusion ─────────────────────────────────────

def test_no_element_carries_both_tier_tags(index_html: str):
    """`.desktop-only` and `data-tier="advanced"` are mutually
    exclusive semantics:
      - desktop-only = unreachable on phone at any tier
      - data-tier="advanced" = reachable on phone via show-advanced

    An element with both is incoherent — phone-advanced users get
    `[data-tier]` revealed, but `.desktop-only`'s !important wins,
    leaving them with a tag that says "advanced" but never appears.
    Find any tag that lists both classes/attributes and fail."""
    # Match opening tags that contain both "desktop-only" and
    # data-tier="advanced" anywhere in the same tag.
    open_tag = re.compile(r'<[a-z][^>]*>', re.IGNORECASE)
    offenders = []
    for match in open_tag.finditer(index_html):
        tag = match.group(0)
        if "desktop-only" in tag and 'data-tier="advanced"' in tag:
            # Allow inside CSS comments / docblocks (rare but possible).
            offenders.append(tag[:200])
    assert not offenders, (
        "Elements MUST NOT be tagged both desktop-only AND advanced: "
        f"{offenders}"
    )


# ───────── CSS rule cascade ─────────────────────────────────────────

def test_css_rule_order_reveal_after_hide(index_html: str):
    """The show-advanced reveal rule MUST appear AFTER the phone-hide
    rules in the source. CSS resolves equal-specificity conflicts by
    declaration order; if the reveal came first, the hide would win
    and `[data-tier="advanced"]` would never become visible on phone
    when show-advanced is on."""
    hide_idx = index_html.find('html[data-form-factor="phone"] [data-tier="advanced"] { display: none; }')
    reveal_idx = index_html.find('html.show-advanced [data-tier="advanced"] { display: revert !important; }')
    assert hide_idx > 0
    assert reveal_idx > 0
    assert reveal_idx > hide_idx, "show-advanced reveal MUST come after the phone-hide rule"


def test_desktop_only_uses_important(index_html: str):
    """`.desktop-only` MUST use `!important` so the show-advanced
    reveal rule (which targets `[data-tier="advanced"]` only) can't
    accidentally surface a desktop-only element. They're separate
    semantic tiers."""
    rule = 'html[data-form-factor="phone"] .desktop-only { display: none !important; }'
    assert rule in index_html


def test_show_advanced_reveal_does_not_target_desktop_only(index_html: str):
    """The show-advanced reveal rule MUST NOT match
    `.desktop-only` — that's the deeper "cut" tier and is meant to
    stay cut at any phone setting."""
    # Search for any rule that combines show-advanced with desktop-only.
    illegal = re.compile(r"html\.show-advanced[^{]*\.desktop-only")
    assert not illegal.search(index_html), (
        "show-advanced rule must not target .desktop-only — those tiers are independent"
    )


# ───────── _phoneCannotShow guard coverage ─────────────────────────

def test_every_programmatic_files_pane_click_is_guarded(index_html: str):
    """Every programmatic `document.querySelector('[data-pane="files"]')`
    click MUST be preceded (within the same handler) by
    `_phoneCannotShow(filesBtn)`. Otherwise the handler fires
    state.filesMode + refreshFiles against an inert pane on phone."""
    # Find every occurrence of querySelector('[data-pane="files"]')
    cursor = 0
    while True:
        idx = index_html.find("document.querySelector('[data-pane=\"files\"]')", cursor)
        if idx < 0:
            break
        cursor = idx + 1
        # Look ahead 600 chars for the guard. If the same handler
        # eventually calls .click() before the guard appears, it's a
        # bug. Conservative pin: guard appears within 400 chars.
        window = index_html[idx:idx + 600]
        click_idx = window.find(".click()")
        guard_idx = window.find("_phoneCannotShow(filesBtn)")
        # Either the handler doesn't click (defensive null-check) or
        # the guard comes before the click.
        if click_idx > 0:
            assert guard_idx > 0 and guard_idx < click_idx, (
                f"unguarded files-pane click at offset {idx}: {window[:300]!r}"
            )


# ───────── version-pin consistency ──────────────────────────────────

def test_version_string_consistent_across_artifacts(index_html: str):
    """`__version__` (Python), `version =` in pyproject.toml, and
    PAGE_BUILT_FOR (HTML) MUST all agree. A drift between any two
    surfaces the daemon-page mismatch banner or breaks pip
    installation. This is a release-discipline guardrail."""
    from one_link import __version__
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    pyproject_match = re.search(r'^\s*version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    assert pyproject_match, "pyproject.toml is missing a version field"
    assert pyproject_match.group(1) == __version__, (
        f"pyproject.toml version {pyproject_match.group(1)!r} != "
        f"one_link.__version__ {__version__!r}"
    )
    page_match = re.search(r'PAGE_BUILT_FOR\s*=\s*"([^"]+)"', index_html)
    assert page_match
    assert page_match.group(1) == __version__, (
        f"PAGE_BUILT_FOR {page_match.group(1)!r} != "
        f"one_link.__version__ {__version__!r}"
    )


# ───────── form-factor detector robustness ─────────────────────────

def test_detector_branches_on_three_form_factors(index_html: str):
    """The detector MUST return one of three values: phone, tablet,
    desktop. A new value would silently fall through both CSS rules
    and JS branches, leaving the layout in an unspecified state."""
    idx = index_html.find("function _detectFormFactor()")
    # Stop at the next top-level function so we don't bleed into the
    # adjacent _applyFormFactor or unrelated code.
    end = index_html.find("\n  function ", idx + 1)
    snippet = index_html[idx:end]
    for value in ('"phone"', '"tablet"', '"desktop"'):
        assert value in snippet, f"detector missing return value {value}"
    # No fourth return value snuck in.
    extras = re.findall(r'return\s+"([^"]+)"', snippet)
    assert set(extras) <= {"phone", "tablet", "desktop"}, (
        f"unexpected return values from detector: {extras}"
    )


def test_detector_handles_missing_useragent(index_html: str):
    """Servers / scrapers / very old browsers may set navigator.userAgent
    to undefined or null. The detector MUST coerce to a string before
    matching to avoid a TypeError that crashes script init."""
    idx = index_html.find("function _detectFormFactor()")
    snippet = index_html[idx:idx + 1500]
    assert 'navigator.userAgent || ""' in snippet, (
        "detector must default-coerce navigator.userAgent to a string"
    )


def test_detector_lowercases_useragent_before_match(index_html: str):
    """User-Agent strings vary in case (`iPhone` vs `iphone`). The
    detector MUST .toLowerCase() before regex-matching to avoid
    classifying iPhones as desktop."""
    idx = index_html.find("function _detectFormFactor()")
    snippet = index_html[idx:idx + 1500]
    assert ".toLowerCase()" in snippet


# ───────── show-advanced state-tier consistency ─────────────────────

def test_state_tier_only_assigned_two_values(index_html: str):
    """`state.tier` MUST only ever be "default" or "advanced". A
    third value would desync against html.show-advanced presence.
    Catches both literal assignments and ternary branches."""
    # Literal assignments: state.tier = "X"
    literals = set(re.findall(r'state\.tier\s*=\s*"([^"]+)"', index_html))
    # Ternary branches inside _setShowAdvanced: on ? "advanced" : "default"
    # Capture both branches via a paired regex.
    ternary = re.search(
        r'state\.tier\s*=\s*[^?;]+\?\s*"([^"]+)"\s*:\s*"([^"]+)"',
        index_html,
    )
    if ternary:
        literals.update({ternary.group(1), ternary.group(2)})
    assert literals == {"default", "advanced"}, (
        f"unexpected state.tier values: {literals}"
    )


def test_show_advanced_persistence_key_pinned(index_html: str):
    """The localStorage key MUST be the namespaced `one_link.show_advanced`,
    NOT a bare key that could collide with other apps in a shared
    localStorage namespace (e.g. inside a PWA host)."""
    assert 'localStorage.getItem("one_link.show_advanced")' in index_html
    assert 'localStorage.setItem("one_link.show_advanced"' in index_html


# ───────── orphan-coverage canary ───────────────────────────────────

def test_every_phone_tier_test_file_present(index_html: str):
    """Sanity guard: each of the v0.14.2 → v0.14.8 ships has a
    matching test file. A missing one means the ship's pins were
    deleted or never written."""
    test_dir = Path("tests")
    expected = [
        "test_phone_tier_foundation_v0142.py",
        "test_phone_tier_cuts_v0143.py",
        "test_phone_tier_settings_v0144.py",
        "test_phone_tier_drawer_v0145.py",
        "test_phone_tier_composer_v0146.py",
        "test_phone_tier_pair_v0147.py",
        "test_phone_tier_diagnostics_v0148.py",
    ]
    for name in expected:
        assert (test_dir / name).exists(), f"missing test file: {name}"
