"""Tests for the Reality dot UI surface.

Mirrors the pattern in ``test_voice_messages_v092.py``: substring
assertions over the HTML source pin the wire contracts and DOM
structure. The actual rendering is exercised in a browser; these
tests catch unintended regressions to the component shape.

The Reality dot is the calm provenance indicator on each verified
media bubble. Per the Doctrine of Invisibility §4.c, it is REQUIRED
on the call surface; per §3.5.c it is visible (never surreptitious);
per §3.9.a it never exposes raw fingerprint hex.
"""

from __future__ import annotations

from pathlib import Path

import pytest


WEB_DIR = Path(__file__).resolve().parent.parent / "src" / "one_link" / "web"
INDEX_HTML_PATH = WEB_DIR / "index.html"


@pytest.fixture(scope="module")
def index_html() -> str:
    return INDEX_HTML_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# CSS surface
# ---------------------------------------------------------------------------

def test_reality_dot_css_class_defined(index_html: str) -> None:
    assert ".reality-dot {" in index_html


def test_reality_dot_verified_state_styled(index_html: str) -> None:
    """The verified state must have its own colour rule. Without
    this the dot is colour-flat and verified/unverified become
    indistinguishable."""
    assert ".reality-dot.verified" in index_html


def test_reality_dot_unverified_state_styled(index_html: str) -> None:
    assert ".reality-dot.unverified" in index_html


def test_reality_detail_pane_styled(index_html: str) -> None:
    """The detail pane (tap-to-reveal) has its own styling block."""
    assert ".reality-detail {" in index_html
    assert ".reality-detail.show" in index_html


def test_reality_dot_hover_affordance(index_html: str) -> None:
    """A subtle hover transform conveys the dot is interactive."""
    assert ".reality-dot:hover" in index_html


# ---------------------------------------------------------------------------
# State integration
# ---------------------------------------------------------------------------

def test_state_provenance_by_blob_field_present(index_html: str) -> None:
    """state.provenanceByBlob is the load-bearing map keying
    provenance UI state by blob hash."""
    assert "provenanceByBlob: new Map()" in index_html


# ---------------------------------------------------------------------------
# Renderer function
# ---------------------------------------------------------------------------

def test_render_reality_dot_function_defined(index_html: str) -> None:
    assert "function renderRealityDot(" in index_html


def test_render_reality_dot_returns_dot_and_detail(index_html: str) -> None:
    """The renderer returns a {dot, detail} pair so the caller can
    insert both into the bubble. A null return means no provenance
    is known — calm hidden state per Doctrine §3.5.c."""
    idx = index_html.find("function renderRealityDot(")
    snippet = index_html[idx:idx + 3500]
    assert "return { dot, detail }" in snippet
    assert "return null" in snippet


def test_render_reality_dot_uses_plain_language_only(index_html: str) -> None:
    """The renderer surface must use plain-language labels from
    frame_provenance.to_ui_dict and never expose hex / network
    technology jargon. Doctrine §3.9.a, §3.6.c."""
    idx = index_html.find("function renderRealityDot(")
    snippet = index_html[idx:idx + 3500]
    # The renderer reads plain-language fields only.
    for plain in ("state_.kind", "state_.path", "state_.recording"):
        assert plain in snippet
    # Forbidden tokens — no raw hex, no Wi-Fi / 5G surface in the
    # renderer body.
    for forbidden in ("toHex", "fingerprint", "wi-fi", "5g", "lte"):
        assert forbidden.lower() not in snippet.lower(), (
            f"renderer leaks forbidden token: {forbidden}"
        )


def test_reality_dot_tap_to_reveal_detail(index_html: str) -> None:
    """Tap on the dot toggles the detail pane. Click handler attached
    via addEventListener; keyboard also supported (Enter / Space)."""
    idx = index_html.find("function renderRealityDot(")
    snippet = index_html[idx:idx + 3500]
    assert 'addEventListener("click"' in snippet
    assert 'addEventListener("keydown"' in snippet
    assert "tabindex" in snippet


def test_reality_dot_aria_label_for_screen_readers(index_html: str) -> None:
    """Doctrine §5.b — screen-reader navigability. The dot must
    carry an aria-label so blind users hear what it conveys."""
    idx = index_html.find("function renderRealityDot(")
    snippet = index_html[idx:idx + 3500]
    assert 'setAttribute("aria-label"' in snippet


# ---------------------------------------------------------------------------
# Integration with the file bubble
# ---------------------------------------------------------------------------

def test_file_bubble_calls_render_reality_dot(index_html: str) -> None:
    """The audio bubble path in renderFileBubble must call
    renderRealityDot(msg.blob) and append both dot + detail
    elements when a state exists."""
    # Find the inline-audio block:
    idx = index_html.find("inline audio player for any received audio")
    assert idx > 0, "missing inline-audio comment anchor"
    snippet = index_html[idx:idx + 2500]
    assert "renderRealityDot(msg.blob)" in snippet
    assert "wrap.appendChild(reality.dot)" in snippet
    assert "wrap.appendChild(reality.detail)" in snippet


# ---------------------------------------------------------------------------
# WebSocket event handler
# ---------------------------------------------------------------------------

def test_ws_handler_processes_frame_provenance_event(index_html: str) -> None:
    """ws.onmessage must dispatch the 'frame_provenance' event type
    and populate state.provenanceByBlob."""
    idx = index_html.find('m.type === "frame_provenance"')
    assert idx > 0, "missing frame_provenance WS event handler"
    snippet = index_html[idx:idx + 1500]
    assert "state.provenanceByBlob.set(m.blob" in snippet
    assert "verified" in snippet


def test_ws_handler_rerenders_messages_on_provenance_arrival(index_html: str) -> None:
    """Newly-arrived provenance must trigger a re-render of visible
    messages so the dot appears on already-rendered bubbles."""
    idx = index_html.find('m.type === "frame_provenance"')
    snippet = index_html[idx:idx + 1500]
    assert "renderMessages" in snippet


# ---------------------------------------------------------------------------
# Doctrine compliance of the surface itself
# ---------------------------------------------------------------------------

def test_no_raw_hex_in_reality_dot_renderer(index_html: str) -> None:
    """A safety net for Doctrine §3.9.a: the renderer's body must
    never .hex() or .toString(16) anywhere."""
    idx = index_html.find("function renderRealityDot(")
    end_idx = index_html.find("function ", idx + 30)  # next function defines the boundary
    snippet = index_html[idx:end_idx if end_idx > 0 else idx + 3500]
    assert ".toString(16)" not in snippet
    assert ".hex()" not in snippet


def test_no_settings_toggle_for_reality_dot(index_html: str) -> None:
    """Per Doctrine §3.1.a, there is no 'Show provenance' or
    'Advanced trust mode' toggle. The Reality dot is on by default,
    always."""
    # Search the whole file — no settings entry for provenance.
    forbidden_phrases = [
        "Show Reality dot",
        "show reality dot",
        "Advanced trust",
        "Enable provenance",
        "provenance toggle",
    ]
    for phrase in forbidden_phrases:
        assert phrase not in index_html, (
            f"Reality dot must not be user-toggleable: found {phrase!r}"
        )
