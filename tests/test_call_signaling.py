"""Tests for the call lifecycle FSM.

Covers every transition + every illegal-event no-op + the full
happy-path flow + the headline-demo "WiFi-unplugged becomes capsule"
in FSM form.
"""

from __future__ import annotations

import pytest

from one_link.call_signaling import (
    CALL_ACCEPT,
    CALL_DECLINE,
    CALL_END,
    CALL_INVITE,
    DEFAULT_INVITE_TIMEOUT_MS,
    DEFAULT_RESUME_WINDOW_MS,
    RESUME_OFFER,
    CallLifecycle,
    CallPhase,
    CallState,
    EndCause,
    EventKind,
    LifecycleEvent,
    LocalAction,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _new_originator(call_id: str = "call-x") -> CallState:
    return CallLifecycle.initial_state(
        call_id=call_id,
        peer_master_vk_hex="peer-fp",
        local_role="originator",
        started_at_ms=1_000,
    )


def _new_recipient(call_id: str = "call-x") -> CallState:
    return CallLifecycle.initial_state(
        call_id=call_id,
        peer_master_vk_hex="peer-fp",
        local_role="recipient",
        started_at_ms=1_000,
    )


def _event(kind: EventKind, ts: int = 0, **data) -> LifecycleEvent:
    return LifecycleEvent(kind=kind, occurred_at_ms=ts, data=data)


# ---------------------------------------------------------------------------
# initial_state validation
# ---------------------------------------------------------------------------

def test_initial_state_originator() -> None:
    s = _new_originator()
    assert s.phase == CallPhase.INVITING
    assert s.local_role == "originator"
    assert s.invite_timeout_ms == DEFAULT_INVITE_TIMEOUT_MS
    assert s.end_cause == EndCause.UNSET


def test_initial_state_recipient() -> None:
    s = _new_recipient()
    assert s.phase == CallPhase.INVITING
    assert s.local_role == "recipient"


def test_initial_state_rejects_unknown_role() -> None:
    with pytest.raises(ValueError, match="local_role"):
        CallLifecycle.initial_state(
            call_id="x", peer_master_vk_hex="y",
            local_role="bystander", started_at_ms=0,
        )


# ---------------------------------------------------------------------------
# Originator happy path: INVITE → ACCEPT → ACTIVE → HANGUP
# ---------------------------------------------------------------------------

def test_originator_sends_invite_on_user_initiate() -> None:
    fsm = CallLifecycle()
    s0 = _new_originator()
    out = fsm.handle(s0, _event(EventKind.USER_INITIATE_CALL, ts=2_000))
    assert out.state.invite_sent_at_ms == 2_000
    assert len(out.outbound) == 1
    assert out.outbound[0].type == CALL_INVITE
    assert out.outbound[0].target_peer_fp == "peer-fp"
    assert out.outbound[0].payload["call_id"] == "call-x"
    assert LocalAction.START_INVITE_TIMER in out.local_actions


def test_originator_on_accept_transitions_to_active() -> None:
    fsm = CallLifecycle()
    s = _new_originator()
    s = fsm.handle(s, _event(EventKind.USER_INITIATE_CALL, ts=2_000)).state
    out = fsm.handle(s, _event(EventKind.WIRE_ACCEPT, ts=3_000))
    assert out.state.phase == CallPhase.ACTIVE
    assert out.state.accepted_at_ms == 3_000
    assert LocalAction.STOP_INVITE_TIMER in out.local_actions
    assert LocalAction.START_MEDIA in out.local_actions


def test_originator_active_user_hangup_ends_clean() -> None:
    fsm = CallLifecycle()
    s = _new_originator()
    s = fsm.handle(s, _event(EventKind.USER_INITIATE_CALL, ts=1)).state
    s = fsm.handle(s, _event(EventKind.WIRE_ACCEPT, ts=2)).state
    out = fsm.handle(s, _event(EventKind.USER_HANGUP, ts=10_000))
    assert out.state.phase == CallPhase.ENDED
    assert out.state.end_cause == EndCause.USER_HANGUP_LOCAL
    assert out.outbound[0].type == CALL_END
    assert LocalAction.STOP_MEDIA in out.local_actions


# ---------------------------------------------------------------------------
# Originator declined-by-peer path: converts to ASYNC, not failure
# ---------------------------------------------------------------------------

def test_originator_on_decline_converts_to_async_not_failure() -> None:
    """Doctrine §3.2.e — declined calls become voice-note captures
    rather than surfacing 'Call failed.'"""
    fsm = CallLifecycle()
    s = _new_originator()
    s = fsm.handle(s, _event(EventKind.USER_INITIATE_CALL, ts=1)).state
    out = fsm.handle(s, _event(EventKind.WIRE_DECLINE, ts=2))
    assert out.state.phase == CallPhase.ASYNC_CAPTURE
    assert out.state.end_cause == EndCause.PEER_DECLINED
    assert LocalAction.CAPTURE_TO_CAPSULE in out.local_actions


def test_originator_invite_timeout_converts_to_async() -> None:
    fsm = CallLifecycle()
    s = _new_originator()
    s = fsm.handle(s, _event(EventKind.USER_INITIATE_CALL, ts=1)).state
    out = fsm.handle(s, _event(EventKind.INVITE_TIMER_EXPIRED, ts=31_000))
    assert out.state.phase == CallPhase.ASYNC_CAPTURE
    assert out.state.end_cause == EndCause.INVITE_TIMEOUT
    assert LocalAction.CAPTURE_TO_CAPSULE in out.local_actions


def test_originator_can_cancel_before_acceptance() -> None:
    fsm = CallLifecycle()
    s = _new_originator()
    s = fsm.handle(s, _event(EventKind.USER_INITIATE_CALL, ts=1)).state
    out = fsm.handle(s, _event(EventKind.USER_HANGUP, ts=500))
    assert out.state.phase == CallPhase.ENDED
    assert out.state.end_cause == EndCause.USER_HANGUP_LOCAL
    assert out.outbound[0].type == CALL_END


# ---------------------------------------------------------------------------
# Recipient happy path: INVITE → RING → ACCEPT → ACTIVE
# ---------------------------------------------------------------------------

def test_recipient_invite_shows_ring() -> None:
    fsm = CallLifecycle()
    s = _new_recipient()
    out = fsm.handle(s, _event(EventKind.WIRE_INVITE, ts=1))
    assert out.state.phase == CallPhase.RINGING
    assert LocalAction.SHOW_RING in out.local_actions


def test_recipient_accept_emits_accept_and_starts_media() -> None:
    fsm = CallLifecycle()
    s = _new_recipient()
    s = fsm.handle(s, _event(EventKind.WIRE_INVITE, ts=1)).state
    out = fsm.handle(s, _event(EventKind.USER_ACCEPT, ts=2))
    assert out.state.phase == CallPhase.ACTIVE
    assert out.outbound[0].type == CALL_ACCEPT
    assert LocalAction.HIDE_RING in out.local_actions
    assert LocalAction.START_MEDIA in out.local_actions


def test_recipient_decline_emits_decline_message() -> None:
    fsm = CallLifecycle()
    s = _new_recipient()
    s = fsm.handle(s, _event(EventKind.WIRE_INVITE, ts=1)).state
    out = fsm.handle(s, _event(EventKind.USER_DECLINE, ts=2))
    assert out.state.phase == CallPhase.ENDED
    assert out.outbound[0].type == CALL_DECLINE
    assert LocalAction.HIDE_RING in out.local_actions


def test_recipient_caller_hangs_up_before_pickup() -> None:
    """Caller cancels invite while it's still ringing on our side.
    We end cleanly without emitting any message."""
    fsm = CallLifecycle()
    s = _new_recipient()
    s = fsm.handle(s, _event(EventKind.WIRE_INVITE, ts=1)).state
    out = fsm.handle(s, _event(EventKind.WIRE_END, ts=2))
    assert out.state.phase == CallPhase.ENDED
    assert out.state.end_cause == EndCause.USER_HANGUP_REMOTE
    assert LocalAction.HIDE_RING in out.local_actions


# ---------------------------------------------------------------------------
# Active phase remote hangup
# ---------------------------------------------------------------------------

def test_active_remote_hangup_ends_call() -> None:
    fsm = CallLifecycle()
    s = _new_recipient()
    s = fsm.handle(s, _event(EventKind.WIRE_INVITE, ts=1)).state
    s = fsm.handle(s, _event(EventKind.USER_ACCEPT, ts=2)).state
    out = fsm.handle(s, _event(EventKind.WIRE_END, ts=100))
    assert out.state.phase == CallPhase.ENDED
    assert out.state.end_cause == EndCause.USER_HANGUP_REMOTE
    assert LocalAction.STOP_MEDIA in out.local_actions


# ---------------------------------------------------------------------------
# Async conversion: Immune System triggers, lifecycle reflects
# ---------------------------------------------------------------------------

def test_active_to_async_on_immune_conversion() -> None:
    """When the Immune System emits CONVERT_TO_ASYNC, the lifecycle
    transitions to ASYNC_CAPTURE so the daemon persists the
    in-flight buffer as a voice note."""
    fsm = CallLifecycle()
    s = _new_originator()
    s = fsm.handle(s, _event(EventKind.USER_INITIATE_CALL, ts=1)).state
    s = fsm.handle(s, _event(EventKind.WIRE_ACCEPT, ts=2)).state
    out = fsm.handle(s, _event(EventKind.IMMUNE_CONVERT_TO_ASYNC, ts=500))
    assert out.state.phase == CallPhase.ASYNC_CAPTURE
    assert out.state.end_cause == EndCause.NETWORK_ASYNC_CONVERSION
    assert LocalAction.STOP_MEDIA in out.local_actions
    assert LocalAction.CAPTURE_TO_CAPSULE in out.local_actions


def test_async_capture_to_resumable_opens_window() -> None:
    fsm = CallLifecycle()
    s = _new_originator()
    s = fsm.handle(s, _event(EventKind.USER_INITIATE_CALL, ts=1)).state
    s = fsm.handle(s, _event(EventKind.WIRE_ACCEPT, ts=2)).state
    s = fsm.handle(s, _event(EventKind.IMMUNE_CONVERT_TO_ASYNC, ts=500)).state
    out = fsm.handle(s, _event(EventKind.ASYNC_CAPSULE_FINALIZED, ts=600))
    assert out.state.phase == CallPhase.RESUMABLE
    assert out.state.resume_window_close_at_ms == 600 + DEFAULT_RESUME_WINDOW_MS
    assert LocalAction.OPEN_RESUME_WINDOW in out.local_actions


# ---------------------------------------------------------------------------
# Resume window
# ---------------------------------------------------------------------------

def test_resumable_user_resume_emits_resume_offer() -> None:
    fsm = CallLifecycle()
    s = CallState(
        call_id="call-x", peer_master_vk_hex="peer-fp",
        local_role="originator",
        phase=CallPhase.RESUMABLE,
        started_at_ms=1, resume_window_close_at_ms=600_000,
    )
    out = fsm.handle(s, _event(EventKind.USER_RESUME, ts=500))
    assert out.state.phase == CallPhase.ENDED
    assert out.outbound[0].type == RESUME_OFFER
    assert out.outbound[0].payload["prior_call_id"] == "call-x"


def test_resumable_remote_resume_closes_window() -> None:
    fsm = CallLifecycle()
    s = CallState(
        call_id="call-x", peer_master_vk_hex="peer-fp",
        local_role="originator",
        phase=CallPhase.RESUMABLE,
        started_at_ms=1, resume_window_close_at_ms=600_000,
    )
    out = fsm.handle(s, _event(EventKind.WIRE_RESUME_OFFER, ts=500))
    assert out.state.phase == CallPhase.ENDED
    assert LocalAction.CLOSE_RESUME_WINDOW in out.local_actions


def test_resumable_window_expires_cleanly() -> None:
    fsm = CallLifecycle()
    s = CallState(
        call_id="call-x", peer_master_vk_hex="peer-fp",
        local_role="originator",
        phase=CallPhase.RESUMABLE,
        started_at_ms=1, resume_window_close_at_ms=600_000,
    )
    out = fsm.handle(s, _event(EventKind.RESUME_WINDOW_EXPIRED, ts=600_001))
    assert out.state.phase == CallPhase.ENDED
    assert LocalAction.CLOSE_RESUME_WINDOW in out.local_actions


# ---------------------------------------------------------------------------
# Illegal / late events are no-ops
# ---------------------------------------------------------------------------

def test_late_accept_after_decline_is_noop() -> None:
    """The peer's ACCEPT arrives AFTER we've already declined. The
    FSM no-ops rather than partially transitioning."""
    fsm = CallLifecycle()
    s = _new_recipient()
    s = fsm.handle(s, _event(EventKind.WIRE_INVITE, ts=1)).state
    s = fsm.handle(s, _event(EventKind.USER_DECLINE, ts=2)).state
    # We're ENDED. A late ACCEPT message arrives. FSM no-ops.
    out = fsm.handle(s, _event(EventKind.WIRE_ACCEPT, ts=3))
    assert out.state == s
    assert out.outbound == ()


def test_invite_during_active_is_noop() -> None:
    fsm = CallLifecycle()
    s = _new_recipient()
    s = fsm.handle(s, _event(EventKind.WIRE_INVITE, ts=1)).state
    s = fsm.handle(s, _event(EventKind.USER_ACCEPT, ts=2)).state
    # A second INVITE arrives mid-call. No-op (idempotent).
    out = fsm.handle(s, _event(EventKind.WIRE_INVITE, ts=3))
    assert out.state == s


def test_unknown_event_in_phase_is_noop() -> None:
    """Belt-and-suspenders for any event/phase combo we didn't
    explicitly handle. FSM must never crash."""
    fsm = CallLifecycle()
    s = _new_originator()
    out = fsm.handle(s, _event(EventKind.RESUME_WINDOW_EXPIRED, ts=1))
    assert out.state == s
    assert out.outbound == ()


# ---------------------------------------------------------------------------
# Full happy-path scenario
# ---------------------------------------------------------------------------

def test_full_originator_happy_path() -> None:
    fsm = CallLifecycle()
    s = _new_originator(call_id="happy")

    # 1. User taps "Call Mom"
    out = fsm.handle(s, _event(EventKind.USER_INITIATE_CALL, ts=1_000))
    s = out.state
    assert s.phase == CallPhase.INVITING
    assert s.invite_sent_at_ms == 1_000

    # 2. Mom accepts (a few seconds later)
    out = fsm.handle(s, _event(EventKind.WIRE_ACCEPT, ts=3_500))
    s = out.state
    assert s.phase == CallPhase.ACTIVE
    assert s.accepted_at_ms == 3_500

    # 3. Conversation runs… (no events to the FSM)
    # 4. Alice hangs up
    out = fsm.handle(s, _event(EventKind.USER_HANGUP, ts=120_000))
    s = out.state
    assert s.phase == CallPhase.ENDED
    assert s.end_cause == EndCause.USER_HANGUP_LOCAL
    assert s.ended_at_ms == 120_000


def test_full_async_capsule_resume_scenario() -> None:
    """The headline demo as an FSM trace: call → async → resumable
    → resumed (within window) → new call begins."""
    fsm = CallLifecycle()
    s = _new_originator(call_id="resume-demo")

    # User calls Mom
    s = fsm.handle(s, _event(EventKind.USER_INITIATE_CALL, ts=1_000)).state
    # Mom accepts
    s = fsm.handle(s, _event(EventKind.WIRE_ACCEPT, ts=2_000)).state
    assert s.phase == CallPhase.ACTIVE

    # WiFi drops mid-call; Immune System converts to async
    s = fsm.handle(s, _event(EventKind.IMMUNE_CONVERT_TO_ASYNC, ts=8_000)).state
    assert s.phase == CallPhase.ASYNC_CAPTURE
    assert s.end_cause == EndCause.NETWORK_ASYNC_CONVERSION

    # Capsule is captured; resume window opens
    s = fsm.handle(s, _event(EventKind.ASYNC_CAPSULE_FINALIZED, ts=10_000)).state
    assert s.phase == CallPhase.RESUMABLE
    assert s.resume_window_close_at_ms == 10_000 + DEFAULT_RESUME_WINDOW_MS

    # WiFi comes back; user taps Resume
    out = fsm.handle(s, _event(EventKind.USER_RESUME, ts=300_000))
    assert out.state.phase == CallPhase.ENDED   # this lifecycle is done
    assert out.outbound[0].type == RESUME_OFFER  # daemon now starts a NEW call
