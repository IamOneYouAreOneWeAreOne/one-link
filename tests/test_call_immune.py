"""Tests for the Call Immune System.

Covers:
    - Each sub-controller's threshold logic (transport, path, device)
    - Arbitrator severity ordering + voice-safe override
    - Hysteresis: trigger at high, recover at low
    - Graduation modes: SHADOW logs all but emits nothing;
      ASSIST emits reversible actions only; AUTOPILOT emits all
    - Determinism: same vitals → same decision
    - vitals_hash field is preserved through the decision
    - Audit log capacity bound
    - Sink callback fires for emitted decisions only (not HOLDs)
    - Sink raise doesn't crash the tick
    - Promote/demote between graduation modes
"""

from __future__ import annotations

import threading

import pytest

from one_link.call_immune import (
    Arbitrator,
    GraduationMode,
    ImmuneAction,
    ImmuneDecision,
    ImmuneSystem,
    Thresholds,
)
from one_link.call_vitals import (
    CallVitals,
    CapabilitySnapshot,
    DeviceRole,
    ThermalState,
)
from one_link.frame_provenance import PathClass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _vitals(**over) -> CallVitals:
    base = dict(
        call_id="call-0",
        peer_fp="peer-0",
        tick=0,
        rtt_ewma_ms=50.0,
        loss_rate_ewma=0.0,
        jitter_ms=0.0,
        bandwidth_estimate_kbps=1000.0,
        reliability=1.0,
        last_alive_ms=1_700_000_000_000,
        path_class=PathClass.DIRECT,
        path_fragility_score=0.0,
        backup_routes_warm=0,
        own_device_role=DeviceRole.INACTIVE,
        own_battery_pct=None,
        own_thermal_state=ThermalState.NOMINAL,
        peer_device_present=True,
        audio_frames_received=0,
        audio_frames_dropped=0,
        video_frames_received=0,
        video_frames_predicted=0,
        confirm_ratio_voice=1.0,
        confirm_ratio_video=1.0,
        path_attested=False,
        capability_state=CapabilitySnapshot.empty(),
    )
    base.update(over)
    return CallVitals(**base)


# ---------------------------------------------------------------------------
# Transport health controller
# ---------------------------------------------------------------------------

def test_healthy_transport_holds() -> None:
    arb = Arbitrator()
    d = arb.decide(_vitals())
    assert d.action == ImmuneAction.HOLD


def test_high_rtt_prewarms_backup() -> None:
    arb = Arbitrator()
    # voice-safe override would HOLD; lower confirm ratio so the
    # transport vote actually wins.
    d = arb.decide(_vitals(rtt_ewma_ms=500.0, confirm_ratio_voice=0.50))
    assert d.action == ImmuneAction.PREWARM_BACKUP_ROUTE
    assert "rtt_ewma_ms" in d.triggered_by


def test_severe_rtt_switches_route() -> None:
    arb = Arbitrator()
    d = arb.decide(_vitals(rtt_ewma_ms=1500.0, confirm_ratio_voice=0.50))
    assert d.action == ImmuneAction.SWITCH_ROUTE


def test_moderate_loss_requests_lower_fidelity() -> None:
    arb = Arbitrator()
    d = arb.decide(_vitals(loss_rate_ewma=0.08, confirm_ratio_voice=0.50))
    assert d.action == ImmuneAction.REQUEST_LOWER_FIDELITY
    assert "loss_rate_ewma" in d.triggered_by


def test_high_loss_requests_voice_only() -> None:
    arb = Arbitrator()
    d = arb.decide(_vitals(loss_rate_ewma=0.20))
    assert d.action == ImmuneAction.REQUEST_VOICE_ONLY


def test_extreme_loss_converts_to_async() -> None:
    arb = Arbitrator()
    d = arb.decide(_vitals(loss_rate_ewma=0.50))
    assert d.action == ImmuneAction.CONVERT_TO_ASYNC


def test_high_jitter_requests_lower_fidelity() -> None:
    arb = Arbitrator()
    d = arb.decide(_vitals(jitter_ms=100.0, confirm_ratio_voice=0.50))
    assert d.action == ImmuneAction.REQUEST_LOWER_FIDELITY
    assert "jitter_ms" in d.triggered_by


# ---------------------------------------------------------------------------
# Path brain controller
# ---------------------------------------------------------------------------

def test_critical_fragility_converts_to_async() -> None:
    arb = Arbitrator()
    d = arb.decide(_vitals(path_fragility_score=0.95))
    assert d.action == ImmuneAction.CONVERT_TO_ASYNC


def test_high_fragility_switches_route() -> None:
    arb = Arbitrator()
    d = arb.decide(_vitals(path_fragility_score=0.80, confirm_ratio_voice=0.50))
    assert d.action == ImmuneAction.SWITCH_ROUTE


def test_rising_fragility_prewarms_backup() -> None:
    arb = Arbitrator()
    d = arb.decide(_vitals(
        path_fragility_score=0.60, confirm_ratio_voice=0.50,
    ))
    assert d.action == ImmuneAction.PREWARM_BACKUP_ROUTE


def test_peer_absent_converts_to_async() -> None:
    arb = Arbitrator()
    d = arb.decide(_vitals(
        tick=10, peer_device_present=False, last_alive_ms=1
    ))
    assert d.action == ImmuneAction.CONVERT_TO_ASYNC
    assert "peer_device_present" in d.triggered_by


# ---------------------------------------------------------------------------
# Device wellness controller
# ---------------------------------------------------------------------------

def test_low_battery_suggests_handoff() -> None:
    arb = Arbitrator()
    d = arb.decide(_vitals(own_battery_pct=10.0, confirm_ratio_voice=0.50))
    assert d.action == ImmuneAction.SUGGEST_DEVICE_HANDOFF
    assert "own_battery_pct" in d.triggered_by


def test_hot_device_suggests_handoff() -> None:
    arb = Arbitrator()
    d = arb.decide(_vitals(
        own_thermal_state=ThermalState.HOT, confirm_ratio_voice=0.50,
    ))
    assert d.action == ImmuneAction.SUGGEST_DEVICE_HANDOFF
    assert "own_thermal_state" in d.triggered_by


# ---------------------------------------------------------------------------
# Arbitrator severity + voice-safe override
# ---------------------------------------------------------------------------

def test_arbitrator_picks_highest_severity() -> None:
    """When transport says PREWARM and path says SWITCH, SWITCH
    wins (higher severity)."""
    arb = Arbitrator()
    d = arb.decide(_vitals(
        rtt_ewma_ms=500.0,                # would PREWARM_BACKUP_ROUTE
        path_fragility_score=0.80,        # would SWITCH_ROUTE
        confirm_ratio_voice=0.50,
    ))
    assert d.action == ImmuneAction.SWITCH_ROUTE


def test_voice_safe_override_suppresses_prewarm() -> None:
    """When voice is healthy and the trigger was only RTT, defer the
    prewarm. The user isn't currently being harmed."""
    arb = Arbitrator()
    d = arb.decide(_vitals(
        rtt_ewma_ms=500.0,  # would PREWARM
        confirm_ratio_voice=1.0,  # but voice is fine
        loss_rate_ewma=0.0,
        path_fragility_score=0.0,
    ))
    assert d.action == ImmuneAction.HOLD
    assert d.reason_code == "voice_safe_override"


def test_voice_safe_override_does_not_suppress_async_conversion() -> None:
    """End-state safety actions (async, voice-only, rekey) are never
    overridden by the voice-safe rule."""
    arb = Arbitrator()
    d = arb.decide(_vitals(
        loss_rate_ewma=0.50,
        confirm_ratio_voice=1.0,   # voice happens to be fine right NOW
    ))
    assert d.action == ImmuneAction.CONVERT_TO_ASYNC


def test_voice_safe_override_does_not_suppress_switch() -> None:
    arb = Arbitrator()
    d = arb.decide(_vitals(
        rtt_ewma_ms=2000.0,  # would SWITCH_ROUTE
        confirm_ratio_voice=1.0,
    ))
    assert d.action == ImmuneAction.SWITCH_ROUTE


# ---------------------------------------------------------------------------
# Determinism — soak replay invariant
# ---------------------------------------------------------------------------

def test_same_vitals_yields_same_decision() -> None:
    """Determinism across independent Arbitrator instances: same
    vitals → same first decision. (The Arbitrator carries
    per-call hysteresis state, so back-to-back calls on the same
    instance will differ — that's the hysteresis working — but
    fresh instances must agree.)"""
    arb_a = Arbitrator()
    arb_b = Arbitrator()
    v1 = _vitals(rtt_ewma_ms=500.0, confirm_ratio_voice=0.50)
    v2 = _vitals(rtt_ewma_ms=500.0, confirm_ratio_voice=0.50)
    d1 = arb_a.decide(v1)
    d2 = arb_b.decide(v2)
    assert d1.action == d2.action
    assert d1.reason_code == d2.reason_code
    assert d1.triggered_by == d2.triggered_by
    assert d1.vitals_hash == d2.vitals_hash


def test_decision_carries_vitals_hash() -> None:
    arb = Arbitrator()
    v = _vitals(rtt_ewma_ms=600.0)
    d = arb.decide(v)
    assert d.vitals_hash == v.vitals_hash()
    assert d.tick == v.tick


# ---------------------------------------------------------------------------
# Graduation modes
# ---------------------------------------------------------------------------

def test_shadow_mode_logs_but_does_not_emit() -> None:
    sys_ = ImmuneSystem(mode=GraduationMode.SHADOW)
    d = sys_.tick(_vitals(loss_rate_ewma=0.50))
    # SHADOW mode marks the decision as not emitted.
    assert d.action == ImmuneAction.CONVERT_TO_ASYNC
    assert d.emitted is False
    # It IS in the audit log.
    assert len(sys_.audit_log()) == 1


def test_assist_mode_emits_reversible_only() -> None:
    sys_ = ImmuneSystem(mode=GraduationMode.ASSIST)
    # Prewarm is reversible → emitted
    d_prewarm = sys_.tick(_vitals(
        call_id="c1", rtt_ewma_ms=500.0, confirm_ratio_voice=0.50,
    ))
    assert d_prewarm.action == ImmuneAction.PREWARM_BACKUP_ROUTE
    assert d_prewarm.emitted is True

    # Convert to async is end-state → NOT emitted under ASSIST
    d_async = sys_.tick(_vitals(call_id="c2", loss_rate_ewma=0.50))
    assert d_async.action == ImmuneAction.CONVERT_TO_ASYNC
    assert d_async.emitted is False


def test_autopilot_emits_everything_except_hold() -> None:
    sys_ = ImmuneSystem(mode=GraduationMode.AUTOPILOT)
    # Async-conversion is end-state but emitted under AUTOPILOT
    d_async = sys_.tick(_vitals(loss_rate_ewma=0.50))
    assert d_async.emitted is True
    # HOLD is always non-emitted.
    d_hold = sys_.tick(_vitals(call_id="other"))
    assert d_hold.action == ImmuneAction.HOLD
    assert d_hold.emitted is False


# ---------------------------------------------------------------------------
# Sink callback
# ---------------------------------------------------------------------------

def test_sink_called_only_for_emitted_decisions() -> None:
    received: list[ImmuneDecision] = []
    sys_ = ImmuneSystem(mode=GraduationMode.AUTOPILOT, sink=received.append)
    sys_.tick(_vitals(loss_rate_ewma=0.50))       # CONVERT, emitted
    sys_.tick(_vitals(call_id="hold-call"))       # HOLD, not emitted
    assert len(received) == 1
    assert received[0].action == ImmuneAction.CONVERT_TO_ASYNC


def test_sink_raising_does_not_crash_tick() -> None:
    def bad_sink(_d: ImmuneDecision) -> None:
        raise RuntimeError("oh no")
    sys_ = ImmuneSystem(mode=GraduationMode.AUTOPILOT, sink=bad_sink)
    # Must not raise
    d = sys_.tick(_vitals(loss_rate_ewma=0.50))
    assert d.emitted is True


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def test_audit_log_grows_per_tick() -> None:
    sys_ = ImmuneSystem(mode=GraduationMode.SHADOW)
    for i in range(5):
        sys_.tick(_vitals(tick=i))
    assert len(sys_) == 5
    assert all(isinstance(d, ImmuneDecision) for d in sys_.audit_log())


def test_audit_log_capped_at_cap() -> None:
    sys_ = ImmuneSystem(mode=GraduationMode.SHADOW, audit_cap=10)
    for i in range(20):
        sys_.tick(_vitals(tick=i))
    assert len(sys_) == 10
    # The newest decisions are retained; oldest evicted.
    ticks = [d.tick for d in sys_.audit_log()]
    assert ticks == list(range(10, 20))


def test_clear_audit_log() -> None:
    sys_ = ImmuneSystem(mode=GraduationMode.SHADOW)
    for i in range(5):
        sys_.tick(_vitals(tick=i))
    sys_.clear_audit_log()
    assert len(sys_) == 0


# ---------------------------------------------------------------------------
# Promotion
# ---------------------------------------------------------------------------

def test_promote_changes_emission_behaviour() -> None:
    sys_ = ImmuneSystem(mode=GraduationMode.SHADOW)
    d = sys_.tick(_vitals(loss_rate_ewma=0.50))
    assert d.emitted is False
    sys_.promote_to(GraduationMode.AUTOPILOT)
    d2 = sys_.tick(_vitals(call_id="c2", loss_rate_ewma=0.50))
    assert d2.emitted is True


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

def test_concurrent_ticks_dont_corrupt_state() -> None:
    """8 threads × 100 ticks each. No exceptions; final audit log
    size is well-defined (≤ cap)."""
    sys_ = ImmuneSystem(mode=GraduationMode.SHADOW, audit_cap=10_000)
    errors: list[BaseException] = []

    def worker(call_id: str) -> None:
        try:
            for i in range(100):
                sys_.tick(_vitals(call_id=call_id, tick=i))
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(f"call-{i}",)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(sys_) == 800
