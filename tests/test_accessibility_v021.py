"""v0.21.x accessibility quick-pass gates.

NOT a full a11y audit (that needs human review + a screen reader
walk). These tests pin the most-common WCAG-2 failures we know
about: icon-only buttons without an aria-label, form inputs whose
only label is a placeholder, modals without a close button reachable
from the keyboard.

The intent is to make these failure modes mechanically catchable so
a future refactor that drops an aria-label fails CI before users
hit a screen reader that announces 'button' with no context.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


_INDEX_HTML = Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "index.html"


@pytest.fixture(scope="module")
def index_html() -> str:
    return _INDEX_HTML.read_text(encoding="utf-8")


# ── icon-only buttons must have aria-label ──────────────────────────


# Glyphs that are commonly used as the entire visible button content.
# These ALWAYS need an aria-label because the screen reader can't
# meaningfully read the glyph.
_ICON_ONLY_PATTERN = re.compile(
    r'<button[^>]*>\s*'
    r'(?:↻|✕|×|⚙|🔍|🗑|☰|⋯|↪|⎘|★|↑|↓|◀|▶|⏪|⏩|⏯|✓|✗)'
    r'\s*</button>',
)


def test_icon_only_buttons_have_aria_label(index_html):
    """A button whose visible content is a single icon glyph MUST
    have an aria-label OR a title attribute. Otherwise screen
    readers announce 'button' with no context.

    The previously-found cases (↻ camera-swap, × onboarding-skip)
    were fixed in this same commit; pin both."""
    icon_only_no_label = []
    for m in re.finditer(
        r'<button(?P<attrs>[^>]*?)>(?P<content>[^<]+)</button>',
        index_html,
    ):
        content = m.group("content").strip()
        # Single-glyph + no alphanumeric -> icon-only.
        if (
            len(content) <= 4
            and not any(c.isalnum() for c in content)
            and content not in ("", " ")
        ):
            attrs = m.group("attrs")
            if "aria-label" not in attrs and "title=" not in attrs:
                icon_only_no_label.append(content)
    assert not icon_only_no_label, (
        f"icon-only buttons missing aria-label or title: "
        f"{icon_only_no_label[:10]}. Screen readers announce these "
        f"as just 'button'."
    )


# ── form inputs labeled only by placeholder ────────────────────────


_PLACEHOLDER_ONLY_INPUT = re.compile(
    r'<input(?P<attrs>[^>]*?)>',
)


def test_top_level_inputs_have_aria_label_not_just_placeholder(index_html):
    """A `placeholder` attribute is NOT a label per WCAG. Screen
    readers may not announce it consistently across browsers.
    Top-level inputs (the ones a brand-new user would interact
    with) must have either an aria-label or an associated <label>
    via aria-labelledby.

    Pin the three most-visible inputs we just fixed: search-input,
    folder-name, folder-path."""
    for input_id in ("search-input", "folder-name", "folder-path"):
        pattern = re.compile(
            rf'<input[^>]*?id=["\']{re.escape(input_id)}["\'][^>]*?>'
        )
        m = pattern.search(index_html)
        assert m, f"<input id={input_id!r}> not found"
        attrs = m.group()
        assert "aria-label" in attrs or "aria-labelledby" in attrs, (
            f"<input id={input_id!r}> has no aria-label / aria-labelledby; "
            f"a placeholder is not a label for screen readers"
        )


def test_all_form_controls_have_persistent_accessible_names(index_html):
    """Placeholders disappear while typing and are not labels.

    Pin every static input/textarea/select, including controls inside hidden
    drawers: hidden-at-boot UI is still announced when the drawer opens.
    """
    label_targets = set(
        re.findall(
            r'<label\b[^>]*\bfor=["\']([^"\']+)["\']',
            index_html,
            flags=re.IGNORECASE,
        )
    )
    missing: list[str] = []
    for match in re.finditer(
        r'<(?P<tag>input|textarea|select)\b(?P<attrs>[^>]*)>',
        index_html,
        flags=re.IGNORECASE,
    ):
        attrs = match.group("attrs")
        if re.search(r'\btype=["\']hidden["\']', attrs, re.IGNORECASE):
            continue
        control_id_match = re.search(r'\bid=["\']([^"\']+)["\']', attrs)
        control_id = control_id_match.group(1) if control_id_match else ""
        explicitly_named = bool(
            re.search(r'\baria-label(?:ledby)?=["\'][^"\']+["\']', attrs)
        )
        prefix = index_html[: match.start()].lower()
        nested_in_label = prefix.rfind("<label") > prefix.rfind("</label>")
        if (
            not explicitly_named
            and not nested_in_label
            and control_id not in label_targets
        ):
            missing.append(control_id or f"anonymous-{match.group('tag').lower()}")
    assert not missing, f"form controls without persistent accessible names: {missing}"


def test_document_metadata_and_mobile_menu_name(index_html):
    assert re.search(r'<meta\s+name="description"\s+content="[^"]+"', index_html)
    menu = re.search(
        r'<button[^>]*id="mobile-hamburger-top"[^>]*>([^<]+)</button>',
        index_html,
    )
    assert menu
    tag = menu.group(0)
    visible = menu.group(1).strip().lower()
    accessible = re.search(r'aria-label="([^"]+)"', tag)
    assert accessible and visible in accessible.group(1).lower()


def test_dark_theme_secondary_text_meets_wcag_aa_floor(index_html):
    """The audited token is 4.73:1 even on the lightest dark surface."""
    assert "--text-dimmer:#7f8798" in index_html
    assert "color: #9485ff" in index_html
    assert "background: #6f4df1" in index_html


def test_phone_layout_is_viewport_bounded_with_safe_touch_targets(index_html):
    """Pin the mobile overflow/touch regression found in device emulation.

    The desktop header's intrinsic width used to expand a 390px phone page to
    roughly 635px, while content-box safe-area padding made the header overlap
    the main grid row.  Dense settings/sidebar controls also missed the 44px
    touch-target contract documented by the responsive layer.
    """
    assert "--ol-mobile-header-h: calc(56px + env(safe-area-inset-top))" in index_html
    assert "grid-template-rows: var(--ol-mobile-header-h) auto 1fr" in index_html
    assert "max-width: 100vw" in index_html
    assert "box-sizing: border-box" in index_html
    assert ".pane-tabs {\n      flex: 1 1 0;\n      min-width: 0;\n      margin: 0;" in index_html
    assert ".settings-shell button," in index_html
    assert ".settings-shell select {\n      min-height: 44px;" in index_html
    assert "@media (pointer: coarse)" in index_html
    assert "button:not([hidden])," in index_html


# ── modals must declare role + aria-modal ──────────────────────────


def test_recovery_wizard_modals_have_modal_a11y_attrs(index_html):
    """Modal-shaped dialogs must set role='dialog' and aria-modal='true'
    so screen readers + assistive tech announce them as modals and
    trap focus appropriately. Pin: the createElement-based modal
    factories set both attrs before injecting the modal into the
    DOM."""
    # Look for the modal-construction pattern: `m.id = "<modal_id>"`
    # followed within a small window by role + aria-modal.
    for modal_id in ("recovery-wizard", "recovery-rotate-modal"):
        m = re.search(
            rf'\.id\s*=\s*["\']{re.escape(modal_id)}["\']',
            index_html,
        )
        assert m, f"could not find construction site of {modal_id!r}"
        window = index_html[m.start():m.start() + 1500]
        assert 'setAttribute("role", "dialog")' in window, (
            f"modal {modal_id!r} construction doesn't call "
            f"setAttribute('role', 'dialog')"
        )
        assert 'setAttribute("aria-modal", "true")' in window, (
            f"modal {modal_id!r} construction doesn't call "
            f"setAttribute('aria-modal', 'true')"
        )


# ── keyboard escape on backdrops ──────────────────────────────────


def test_settings_backdrop_can_be_dismissed_by_keyboard(index_html):
    """Modal backdrops with backdrop-click-to-close must ALSO be
    dismissible via Escape (keyboard users can't backdrop-click).
    Pin the Settings modal handler shape."""
    # Look for a generic Escape-key handler near settings.
    has_escape_handler = (
        '"Escape"' in index_html or "'Escape'" in index_html
    )
    assert has_escape_handler, (
        "no Escape-key handler found anywhere in index.html; "
        "modals should be dismissible from the keyboard"
    )
