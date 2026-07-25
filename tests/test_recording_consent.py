"""Tests for the recording consent FSM."""

from __future__ import annotations


from one_link.frame_provenance import RecordingState
from one_link.recording_consent import (
    RECORDING_DECLINE,
    RECORDING_GRANT,
    RECORDING_REQUEST,
    RECORDING_STOP,
    ConsentEvent,
    ConsentEventKind,
    ConsentPhase,
    ConsentState,
    RecordingConsent,
    consent_label,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _new() -> ConsentState:
    return RecordingConsent.initial_state(call_id="call-x")


def _event(kind: ConsentEventKind, ts: int = 0) -> ConsentEvent:
    return ConsentEvent(kind=kind, occurred_at_ms=ts)


# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------

def test_initial_state_is_not_recording() -> None:
    s = _new()
    assert s.phase == ConsentPhase.NONE
    assert s.requestor is None


# ---------------------------------------------------------------------------
# Outbound flow (we initiate)
# ---------------------------------------------------------------------------

def test_local_request_emits_recording_request() -> None:
    fsm = RecordingConsent()
    out = fsm.handle(_new(), _event(ConsentEventKind.LOCAL_REQUEST_START, ts=100))
    assert out.state.phase == ConsentPhase.AWAITING_REMOTE_RESPONSE
    assert out.state.requestor == "local"
    assert len(out.outbound) == 1
    assert out.outbound[0].type == RECORDING_REQUEST
    # Provenance still says NOT_RECORDING — recording starts only on grant.
    assert out.recording_state_for_provenance == RecordingState.NOT_RECORDING


def test_remote_grant_transitions_to_recording() -> None:
    fsm = RecordingConsent()
    s = fsm.handle(_new(), _event(ConsentEventKind.LOCAL_REQUEST_START, ts=100)).state
    out = fsm.handle(s, _event(ConsentEventKind.REMOTE_GRANT, ts=200))
    assert out.state.phase == ConsentPhase.RECORDING
    assert out.state.started_at_ms == 200
    # Provenance now flips — every frame from here is tagged RECORDING_MUTUAL.
    assert out.recording_state_for_provenance == RecordingState.RECORDING_MUTUAL


def test_remote_decline_returns_to_none_no_outbound() -> None:
    fsm = RecordingConsent()
    s = fsm.handle(_new(), _event(ConsentEventKind.LOCAL_REQUEST_START, ts=100)).state
    out = fsm.handle(s, _event(ConsentEventKind.REMOTE_DECLINE, ts=200))
    assert out.state.phase == ConsentPhase.NONE
    assert out.outbound == ()
    assert out.recording_state_for_provenance == RecordingState.NOT_RECORDING


def test_user_withdraws_pending_request() -> None:
    """User taps stop before peer responds — withdraw cleanly."""
    fsm = RecordingConsent()
    s = fsm.handle(_new(), _event(ConsentEventKind.LOCAL_REQUEST_START, ts=100)).state
    out = fsm.handle(s, _event(ConsentEventKind.LOCAL_STOP, ts=150))
    assert out.state.phase == ConsentPhase.NONE
    # Notify peer we withdrew.
    assert out.outbound[0].type == RECORDING_STOP
    assert out.outbound[0].payload["reason"] == "withdrawn"


# ---------------------------------------------------------------------------
# Inbound flow (peer initiates)
# ---------------------------------------------------------------------------

def test_remote_request_surfaces_local_response() -> None:
    fsm = RecordingConsent()
    out = fsm.handle(_new(), _event(ConsentEventKind.REMOTE_REQUEST_START, ts=100))
    assert out.state.phase == ConsentPhase.AWAITING_LOCAL_RESPONSE
    assert out.state.requestor == "remote"
    # No outbound yet — we're waiting on local user.
    assert out.outbound == ()


def test_local_approve_emits_grant() -> None:
    fsm = RecordingConsent()
    s = fsm.handle(_new(), _event(ConsentEventKind.REMOTE_REQUEST_START, ts=100)).state
    out = fsm.handle(s, _event(ConsentEventKind.LOCAL_APPROVE_REQUEST, ts=200))
    assert out.state.phase == ConsentPhase.RECORDING
    assert out.outbound[0].type == RECORDING_GRANT
    assert out.recording_state_for_provenance == RecordingState.RECORDING_MUTUAL


def test_local_decline_emits_decline_message() -> None:
    fsm = RecordingConsent()
    s = fsm.handle(_new(), _event(ConsentEventKind.REMOTE_REQUEST_START, ts=100)).state
    out = fsm.handle(s, _event(ConsentEventKind.LOCAL_DECLINE_REQUEST, ts=200))
    assert out.state.phase == ConsentPhase.NONE
    assert out.outbound[0].type == RECORDING_DECLINE


def test_remote_withdraws_their_request() -> None:
    fsm = RecordingConsent()
    s = fsm.handle(_new(), _event(ConsentEventKind.REMOTE_REQUEST_START, ts=100)).state
    out = fsm.handle(s, _event(ConsentEventKind.REMOTE_STOP, ts=150))
    assert out.state.phase == ConsentPhase.NONE
    # No outbound — peer withdrew, we just acknowledge.
    assert out.outbound == ()


# ---------------------------------------------------------------------------
# Stop semantics — either side ends recording immediately
# ---------------------------------------------------------------------------

def test_local_stop_during_recording_ends_and_notifies() -> None:
    fsm = RecordingConsent()
    s = fsm.handle(_new(), _event(ConsentEventKind.LOCAL_REQUEST_START, ts=100)).state
    s = fsm.handle(s, _event(ConsentEventKind.REMOTE_GRANT, ts=200)).state
    out = fsm.handle(s, _event(ConsentEventKind.LOCAL_STOP, ts=10_000))
    assert out.state.phase == ConsentPhase.NONE
    assert out.outbound[0].type == RECORDING_STOP
    assert out.recording_state_for_provenance == RecordingState.NOT_RECORDING


def test_remote_stop_during_recording_ends_silently_locally() -> None:
    """Peer stopped — our state mirrors theirs (doctrine: recording
    requires both sides AGREEING THROUGHOUT)."""
    fsm = RecordingConsent()
    s = fsm.handle(_new(), _event(ConsentEventKind.LOCAL_REQUEST_START, ts=100)).state
    s = fsm.handle(s, _event(ConsentEventKind.REMOTE_GRANT, ts=200)).state
    out = fsm.handle(s, _event(ConsentEventKind.REMOTE_STOP, ts=10_000))
    assert out.state.phase == ConsentPhase.NONE
    # We don't need to notify; peer initiated.
    assert out.outbound == ()


def test_local_revoke_treated_as_stop() -> None:
    """User revokes the RECORD capability post-hoc — same as Stop."""
    fsm = RecordingConsent()
    s = fsm.handle(_new(), _event(ConsentEventKind.LOCAL_REQUEST_START, ts=100)).state
    s = fsm.handle(s, _event(ConsentEventKind.REMOTE_GRANT, ts=200)).state
    out = fsm.handle(s, _event(ConsentEventKind.LOCAL_REVOKE, ts=300))
    assert out.state.phase == ConsentPhase.NONE
    assert out.outbound[0].type == RECORDING_STOP


# ---------------------------------------------------------------------------
# Illegal / stale events: never crash
# ---------------------------------------------------------------------------

def test_unrelated_event_in_none_is_noop() -> None:
    fsm = RecordingConsent()
    # Stale REMOTE_STOP arrives when we weren't recording.
    out = fsm.handle(_new(), _event(ConsentEventKind.REMOTE_STOP, ts=100))
    assert out.state.phase == ConsentPhase.NONE
    assert out.outbound == ()


def test_local_approve_when_no_remote_request_is_noop() -> None:
    fsm = RecordingConsent()
    out = fsm.handle(_new(), _event(ConsentEventKind.LOCAL_APPROVE_REQUEST, ts=100))
    assert out.state.phase == ConsentPhase.NONE


def test_grant_during_recording_is_noop() -> None:
    """We're already recording; a late grant is meaningless."""
    fsm = RecordingConsent()
    s = fsm.handle(_new(), _event(ConsentEventKind.LOCAL_REQUEST_START, ts=100)).state
    s = fsm.handle(s, _event(ConsentEventKind.REMOTE_GRANT, ts=200)).state
    # Another grant arrives somehow.
    out = fsm.handle(s, _event(ConsentEventKind.REMOTE_GRANT, ts=300))
    # State unchanged.
    assert out.state == s


# ---------------------------------------------------------------------------
# Doctrine compliance of plain-language labels
# ---------------------------------------------------------------------------

_FORBIDDEN_UI_TOKENS = (
    "may be recorded",
    "quality assurance",
    "for training",
    "your data",
)


def test_consent_labels_plain_language() -> None:
    for phase in ConsentPhase:
        label = consent_label(phase).lower()
        for tok in _FORBIDDEN_UI_TOKENS:
            assert tok not in label, (
                f"consent_label({phase.name}) leaks {tok!r}: {label!r}"
            )


# ---------------------------------------------------------------------------
# End-to-end happy path
# ---------------------------------------------------------------------------

def test_full_recording_lifecycle_happy_path() -> None:
    fsm = RecordingConsent()

    # Alice taps "Save this call"
    s = _new()
    out1 = fsm.handle(s, _event(ConsentEventKind.LOCAL_REQUEST_START, ts=1_000))
    s = out1.state
    assert out1.outbound[0].type == RECORDING_REQUEST
    assert s.phase == ConsentPhase.AWAITING_REMOTE_RESPONSE

    # Bob taps Allow → his RECORDING_GRANT arrives at Alice
    out2 = fsm.handle(s, _event(ConsentEventKind.REMOTE_GRANT, ts=3_500))
    s = out2.state
    assert s.phase == ConsentPhase.RECORDING
    # From this moment on, every FrameProvenance.recording_state =
    # RECORDING_MUTUAL on Alice's outbound media.
    assert out2.recording_state_for_provenance == RecordingState.RECORDING_MUTUAL

    # Recording runs for a while… no events to FSM.

    # Bob taps Stop on his side
    out3 = fsm.handle(s, _event(ConsentEventKind.REMOTE_STOP, ts=300_000))
    s = out3.state
    assert s.phase == ConsentPhase.NONE
    # Alice's UI shows "no longer recording"; her media tags flip.
    assert out3.recording_state_for_provenance == RecordingState.NOT_RECORDING
