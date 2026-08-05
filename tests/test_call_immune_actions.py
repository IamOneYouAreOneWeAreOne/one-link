"""Tests for the Immune action plan translator.

The plan_for_decision function is pure: same ImmuneDecision in →
same ActionPlan out. The execute_plan helper is the side-effecting
wrapper; tests for it use a mock broadcast_tail + a real
CallManager.
"""

from __future__ import annotations



from one_link.call_immune import (
    GraduationMode,
    ImmuneAction,
    ImmuneDecision,
    ImmuneSystem,
)
from one_link.call_immune_actions import (
    BrowserAction,
    execute_plan,
    plan_for_decision,
)
from one_link.call_manager import (
    CallManager,
    ManagerEvent,
    ManagerEventKind,
)
from one_link.call_session import Rung
from one_link.call_signaling import CallPhase


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decision(
    action: ImmuneAction,
    *,
    emitted: bool = True,
    reason: str = "test",
) -> ImmuneDecision:
    return ImmuneDecision(
        action=action,
        reason_code=reason,
        triggered_by="test",
        confidence=0.9,
        tick=0,
        vitals_hash="0" * 32,
        emitted=emitted,
    )


# ---------------------------------------------------------------------------
# plan_for_decision — by action
# ---------------------------------------------------------------------------

def test_non_emitted_decision_yields_empty_plan() -> None:
    plan = plan_for_decision(
        decision=_decision(ImmuneAction.CONVERT_TO_ASYNC, emitted=False),
        call_id="c1", now_ms=0,
    )
    assert plan.browser_actions == ()
    assert plan.manager_events == ()


def test_request_lower_fidelity_emits_browser_action() -> None:
    plan = plan_for_decision(
        decision=_decision(ImmuneAction.REQUEST_LOWER_FIDELITY),
        call_id="c1", now_ms=0,
    )
    assert len(plan.browser_actions) == 1
    a = plan.browser_actions[0]
    assert a.tail_kind == "immune_lower_fidelity"
    assert a.call_id == "c1"
    assert a.payload["target_video_bitrate_kbps"] == 200
    # No FSM event — the call doesn't change phase for fidelity drops.
    assert plan.manager_events == ()


def test_request_voice_only_emits_calm_user_message() -> None:
    plan = plan_for_decision(
        decision=_decision(ImmuneAction.REQUEST_VOICE_ONLY),
        call_id="c1", now_ms=0,
    )
    a = plan.browser_actions[0]
    assert a.user_message  # non-empty
    # Doctrine — no jargon.
    assert "error" not in a.user_message.lower()
    assert "codec" not in a.user_message.lower()


def test_convert_to_async_emits_manager_event_and_capsule_message() -> None:
    plan = plan_for_decision(
        decision=_decision(ImmuneAction.CONVERT_TO_ASYNC),
        call_id="c1", now_ms=100,
    )
    # Browser is told to start MediaRecorder for capsule capture.
    assert any(
        a.tail_kind == "immune_convert_to_async"
        for a in plan.browser_actions
    )
    # FSM is told to convert to async.
    assert len(plan.manager_events) == 1
    ev = plan.manager_events[0]
    assert ev.kind == ManagerEventKind.IMMUNE_CONVERT_TO_ASYNC
    assert ev.occurred_at_ms == 100


def test_prewarm_route_emits_browser_action_no_fsm_event() -> None:
    plan = plan_for_decision(
        decision=_decision(ImmuneAction.PREWARM_BACKUP_ROUTE),
        call_id="c1", now_ms=0,
    )
    assert plan.browser_actions[0].tail_kind == "immune_prewarm_route"
    assert plan.manager_events == ()


def test_suggest_handoff_emits_user_facing_prompt() -> None:
    plan = plan_for_decision(
        decision=_decision(ImmuneAction.SUGGEST_DEVICE_HANDOFF),
        call_id="c1", now_ms=0,
    )
    a = plan.browser_actions[0]
    assert a.tail_kind == "immune_suggest_handoff"
    assert "mic" in a.user_message.lower() or "phone" in a.user_message.lower()


def test_emergency_rekey_emits_calm_user_message() -> None:
    plan = plan_for_decision(
        decision=_decision(ImmuneAction.EMERGENCY_REKEY),
        call_id="c1", now_ms=0,
    )
    a = plan.browser_actions[0]
    assert a.tail_kind == "immune_rekey"
    assert a.user_message


def test_hold_yields_empty_plan() -> None:
    plan = plan_for_decision(
        decision=_decision(ImmuneAction.HOLD),
        call_id="c1", now_ms=0,
    )
    assert plan.browser_actions == ()
    assert plan.manager_events == ()


# ---------------------------------------------------------------------------
# BrowserAction wire encoding
# ---------------------------------------------------------------------------

def test_browser_action_to_wire_envelope() -> None:
    a = BrowserAction(
        tail_kind="immune_voice_only",
        call_id="c1",
        user_message="Voice is holding strong.",
        payload={"compiler_rung_hint": int(Rung.AUDIO_ONLY)},
    )
    wire = a.to_wire()
    assert wire["type"] == "call_event"
    assert wire["tail_kind"] == "immune_voice_only"
    assert wire["call_id"] == "c1"
    assert wire["user_message"] == "Voice is holding strong."
    assert wire["compiler_rung_hint"] == int(Rung.AUDIO_ONLY)


# ---------------------------------------------------------------------------
# execute_plan
# ---------------------------------------------------------------------------

def test_execute_plan_broadcasts_browser_actions() -> None:
    sent: list[dict] = []
    plan = plan_for_decision(
        decision=_decision(ImmuneAction.REQUEST_VOICE_ONLY),
        call_id="c1", now_ms=0,
    )
    execute_plan(plan=plan, manager=None, broadcast_tail=sent.append)
    assert len(sent) == 1
    assert sent[0]["tail_kind"] == "immune_voice_only"


def test_execute_plan_feeds_manager_event_into_callmanager() -> None:
    mgr = CallManager(
        call_id="c1",
        peer_master_vk_hex="peer",
        local_role="originator",
        local_master_vk_hex="me",
        started_at_ms=1_000,
    )
    # Bring the call to ACTIVE so IMMUNE_CONVERT_TO_ASYNC is valid.
    mgr.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    mgr.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2_000))
    assert mgr.phase == CallPhase.ACTIVE

    sent: list[dict] = []
    plan = plan_for_decision(
        decision=_decision(ImmuneAction.CONVERT_TO_ASYNC),
        call_id="c1", now_ms=3_000,
    )
    execute_plan(plan=plan, manager=mgr, broadcast_tail=sent.append)
    # Phase advanced — Tier δ headline behavior.
    assert mgr.phase == CallPhase.ASYNC_CAPTURE


def test_execute_plan_handles_broadcast_failure_gracefully() -> None:
    seen = []

    def boom(_ev):
        seen.append(_ev)
        raise RuntimeError("ws closed")

    plan = plan_for_decision(
        decision=_decision(ImmuneAction.REQUEST_VOICE_ONLY),
        call_id="c1", now_ms=0,
    )

    execute_plan(plan=plan, manager=None, broadcast_tail=boom)

    # The broadcast must have been ATTEMPTED for its failure to be what is
    # handled. An executor that never broadcasts also never raises, and would
    # pass this while the UI silently stopped being told anything.
    assert seen, "no broadcast was attempted, so no failure was handled"


def test_execute_plan_returns_manager_outputs() -> None:
    mgr = CallManager(
        call_id="c2",
        peer_master_vk_hex="peer",
        local_role="originator",
        local_master_vk_hex="me",
        started_at_ms=1_000,
    )
    mgr.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    mgr.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2_000))

    plan = plan_for_decision(
        decision=_decision(ImmuneAction.CONVERT_TO_ASYNC),
        call_id="c2", now_ms=3_000,
    )
    outputs = execute_plan(plan=plan, manager=mgr, broadcast_tail=lambda _: None)
    assert len(outputs) == 1


# ---------------------------------------------------------------------------
# Integration: ImmuneSystem.tick → plan_for_decision
# ---------------------------------------------------------------------------

def test_immune_decision_to_plan_pipeline() -> None:
    """A decision flowing out of ImmuneSystem.tick is consumable
    by plan_for_decision without massaging."""
    from one_link.call_vitals import (
        CallVitals, CapabilitySnapshot, DeviceRole, ThermalState,
    )
    from one_link.frame_provenance import PathClass

    bad_vitals = CallVitals(
        call_id="c1",
        peer_fp="peer",
        tick=10,
        rtt_ewma_ms=600.0,  # very bad
        loss_rate_ewma=0.2,  # 20% loss
        jitter_ms=50.0,
        bandwidth_estimate_kbps=20.0,  # below voice-only threshold
        reliability=0.3,
        last_alive_ms=1_700_000_000_000,
        path_class=PathClass.RELAY,
        path_fragility_score=0.9,
        backup_routes_warm=0,
        own_device_role=DeviceRole.INACTIVE,
        own_battery_pct=80.0,
        own_thermal_state=ThermalState.NOMINAL,
        peer_device_present=True,
        audio_frames_received=0,
        audio_frames_dropped=0,
        video_frames_received=0,
        video_frames_predicted=0,
        confirm_ratio_voice=0.5,
        confirm_ratio_video=0.5,
        path_attested=False,
        capability_state=CapabilitySnapshot.empty(),
    )
    immune = ImmuneSystem(mode=GraduationMode.AUTOPILOT)
    decision = immune.tick(bad_vitals)
    plan = plan_for_decision(decision=decision, call_id="c1", now_ms=0)
    # Bad vitals → SOMETHING happens (not just HOLD).
    assert plan.browser_actions or plan.manager_events
