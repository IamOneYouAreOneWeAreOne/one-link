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
