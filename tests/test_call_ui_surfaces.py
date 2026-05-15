"""Tests for the browser call UI surfaces.

Mirrors the test_voice_messages_v092 + test_reality_dot_ui pattern:
substring assertions over index.html pin the DOM + JS hooks the
call UI relies on. The actual rendering is exercised in a browser;
these tests catch unintended regressions to the contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest


INDEX_HTML_PATH = (
    Path(__file__).resolve().parent.parent
    / "src" / "one_link" / "web" / "index.html"
)


@pytest.fixture(scope="module")
def index_html() -> str:
    return INDEX_HTML_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# CSS — overlay + active-call surfaces present
# ---------------------------------------------------------------------------

def test_call_overlay_class_styled(index_html: str) -> None:
    assert ".call-overlay" in index_html
    assert ".call-overlay.show" in index_html


def test_call_active_class_styled(index_html: str) -> None:
    assert ".call-active" in index_html
    assert ".call-active.show" in index_html


def test_recording_badge_styled(index_html: str) -> None:
    assert ".call-recording-badge" in index_html
    assert ".call-recording-badge.show" in index_html


def test_sas_pane_styled(index_html: str) -> None:
    assert ".sas-pane" in index_html
    assert ".sas-pane.show" in index_html


# ---------------------------------------------------------------------------
# DOM — overlay divs exist
# ---------------------------------------------------------------------------

def test_outgoing_overlay_div(index_html: str) -> None:
    assert 'id="call-outgoing-overlay"' in index_html
    assert 'id="call-outgoing-peer"' in index_html


def test_incoming_overlay_div(index_html: str) -> None:
    assert 'id="call-incoming-overlay"' in index_html
    assert 'id="call-incoming-peer"' in index_html
    # Accept + Decline buttons
    assert 'id="btn-call-accept"' in index_html
    assert 'id="btn-call-decline"' in index_html


def test_active_call_surface_div(index_html: str) -> None:
    assert 'id="call-active-surface"' in index_html
    assert 'id="call-active-name"' in index_html
    assert 'id="btn-call-hangup"' in index_html
    assert 'id="btn-call-record"' in index_html


def test_recording_badge_dom(index_html: str) -> None:
    assert 'id="call-recording-badge"' in index_html
    # Doctrine §7.2: visible recording indicator with plain language
    # — must include "Recording" and "both sides agreed" so the
    # user never wonders whether silent recording is happening.
    assert "Recording (both sides agreed)" in index_html


def test_sas_pane_dom(index_html: str) -> None:
    assert 'id="call-sas-pane"' in index_html
    assert 'id="call-sas-words"' in index_html
    assert 'id="btn-sas-yes"' in index_html
    assert 'id="btn-sas-no"' in index_html


# ---------------------------------------------------------------------------
# Accessibility — every overlay has role=dialog + aria-label
# ---------------------------------------------------------------------------

def test_overlays_have_dialog_role_and_aria_label(index_html: str) -> None:
    # The three call overlays must be screen-reader navigable.
    snippets = [
        index_html.find('id="call-outgoing-overlay"'),
        index_html.find('id="call-incoming-overlay"'),
        index_html.find('id="call-active-surface"'),
    ]
    assert all(idx > 0 for idx in snippets)
    for idx in snippets:
        block = index_html[max(0, idx - 60):idx + 200]
        assert 'role="dialog"' in block
        assert "aria-label=" in block


def test_buttons_have_aria_labels(index_html: str) -> None:
    for btn_id, expected_label_word in [
        ("btn-call-cancel", "End"),
        ("btn-call-accept", "Accept"),
        ("btn-call-decline", "Decline"),
        ("btn-call-hangup", "End"),
        ("btn-call-record", "Save"),
    ]:
        idx = index_html.find(f'id="{btn_id}"')
        assert idx > 0, f"missing button id {btn_id}"
        snippet = index_html[idx:idx + 200]
        assert 'aria-label=' in snippet


# ---------------------------------------------------------------------------
# JS — public entry points + WS handler hook
# ---------------------------------------------------------------------------

def test_start_call_function_exposed(index_html: str) -> None:
    """`window.startLivingPresenceCall(peerVk, peerLabel)` is the
    function a 'Call Mom' button calls. Pin its presence + signature."""
    assert "window.startLivingPresenceCall = async function" in index_html


def test_call_event_handler_exposed(index_html: str) -> None:
    """The driver exposes a forwarder for the WebSocket dispatcher."""
    assert "window.handleLivingPresenceCallEvent = function" in index_html


def test_ws_dispatch_forwards_call_event(index_html: str) -> None:
    """The existing ws.onmessage chain has a branch that forwards
    `call_event` to the driver."""
    idx = index_html.find('m.type === "call_event"')
    assert idx > 0
    snippet = index_html[idx:idx + 500]
    assert "handleLivingPresenceCallEvent(m)" in snippet


# ---------------------------------------------------------------------------
# All four overlay states the driver handles
# ---------------------------------------------------------------------------

def test_driver_handles_show_ring(index_html: str) -> None:
    idx = index_html.find("window.handleLivingPresenceCallEvent = function")
    snippet = index_html[idx:idx + 4000]
    assert '"show_ring"' in snippet


def test_driver_handles_phase_changed(index_html: str) -> None:
    idx = index_html.find("window.handleLivingPresenceCallEvent = function")
    snippet = index_html[idx:idx + 4000]
    assert '"phase_changed"' in snippet
    assert '"active"' in snippet
    assert '"ended"' in snippet


def test_driver_handles_recording_state_changed(index_html: str) -> None:
    idx = index_html.find("window.handleLivingPresenceCallEvent = function")
    snippet = index_html[idx:idx + 4000]
    assert '"recording_state_changed"' in snippet


def test_driver_handles_resume_offer(index_html: str) -> None:
    idx = index_html.find("window.handleLivingPresenceCallEvent = function")
    snippet = index_html[idx:idx + 4000]
    assert '"resume_offer_available"' in snippet


# ---------------------------------------------------------------------------
# Doctrine — no forbidden surfaces in the call UI
# ---------------------------------------------------------------------------

def test_no_forbidden_call_strings_in_driver_block(index_html: str) -> None:
    """The call-UI driver block must not contain any
    doctrine-forbidden user-facing strings. The doctrine lint also
    checks the whole file; here we pin the local guarantee."""
    idx = index_html.find("Living Presence Tier α-pre — call UI driver")
    end = index_html.find("</script>", idx)
    block = index_html[idx:end]
    forbidden = [
        "reconnecting",
        "call failed",
        "please try again",
        "your connection is unstable",
    ]
    low = block.lower()
    for tok in forbidden:
        assert tok not in low, f"call UI driver leaks forbidden token: {tok}"
