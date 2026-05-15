"""Tests for the Route Brain.

Covers:
    - score_path: each component (rtt, loss, fragility, tau_c,
      attestation, warmth) moves the score in the right direction
    - PREWARM_BACKUP_ROUTE picks the best cold path
    - Re-prewarming with same candidates is idempotent
    - SWITCH_ROUTE prefers warm backups over cold paths
    - SWITCH refuses to flap on small margins
    - SWITCH commits when margin is met
    - HOLD when no alternatives exist
    - HOLD when candidates list is empty
    - HOLD when Immune-System action is not prewarm/switch
    - Deterministic tiebreak on equal scores
    - on_active_path_lost clears the active state
    - Pure: same inputs always produce same outputs
"""

from __future__ import annotations

import pytest

from one_link.call_immune import ImmuneAction, ImmuneDecision
from one_link.frame_provenance import PathClass
from one_link.route_brain import (
    RouteBrain,
    RouteCandidate,
    RouteCommand,
    RouteCommandKind,
    RouteState,
    score_path,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decision(action: ImmuneAction, tick: int = 0) -> ImmuneDecision:
    return ImmuneDecision(
        action=action,
        reason_code="test",
        triggered_by=(),
        confidence=1.0,
        tick=tick,
        vitals_hash="hash",
    )


def _path(
    pid: str,
    *,
    rtt: float = 50.0,
    loss: float = 0.0,
    fragility: float = 0.0,
    tau_c: float = 0.5,
    attested: bool = False,
    warm: bool = False,
    path_class: PathClass = PathClass.LAN,
) -> RouteCandidate:
    return RouteCandidate(
        path_id=pid,
        path_class=path_class,
        rtt_ewma_ms=rtt,
        loss_rate_ewma=loss,
        bandwidth_kbps=1000.0,
        fragility_score=fragility,
        tau_c_score=tau_c,
        attested=attested,
        warm=warm,
    )


# ---------------------------------------------------------------------------
# Scoring primitives
# ---------------------------------------------------------------------------

def test_score_path_good_path_high() -> None:
    s = score_path(_path("good", rtt=20.0, loss=0.0, fragility=0.0, attested=True, warm=True))
    assert s > 0.85


def test_score_path_bad_path_low() -> None:
    s = score_path(_path("bad", rtt=2000.0, loss=0.30, fragility=0.95, attested=False, warm=False))
    assert s < 0.30


def test_lower_rtt_scores_higher() -> None:
    fast = _path("fast", rtt=30.0)
    slow = _path("slow", rtt=500.0)
    assert score_path(fast) > score_path(slow)


def test_lower_loss_scores_higher() -> None:
    clean = _path("clean", loss=0.0)
    lossy = _path("lossy", loss=0.10)
    assert score_path(clean) > score_path(lossy)


def test_lower_fragility_scores_higher() -> None:
    robust = _path("robust", fragility=0.0)
    fragile = _path("fragile", fragility=0.80)
    assert score_path(robust) > score_path(fragile)


def test_attested_scores_higher() -> None:
    attested = _path("att", attested=True)
    not_attested = _path("not", attested=False)
    assert score_path(attested) > score_path(not_attested)


def test_warm_scores_higher() -> None:
    warm = _path("warm", warm=True)
    cold = _path("cold", warm=False)
    assert score_path(warm) > score_path(cold)


# ---------------------------------------------------------------------------
# PREWARM
# ---------------------------------------------------------------------------

def test_prewarm_picks_best_cold_path() -> None:
    rb = RouteBrain()
    candidates = [
        _path("active", warm=True),
        _path("bad-backup", rtt=900.0, loss=0.18),
        _path("good-backup", rtt=60.0, loss=0.01),
    ]
    state, cmd = rb.step(
        decision=_decision(ImmuneAction.PREWARM_BACKUP_ROUTE),
        candidates=candidates,
        state=RouteState(active_path_id="active"),
    )
    assert cmd.kind == RouteCommandKind.PREWARM_PATH
    assert cmd.target_path_id == "good-backup"
    assert "good-backup" in state.warm_backups


def test_prewarm_idempotent_when_already_warm() -> None:
    """Once we've prewarmed path X, requesting prewarm again with
    the same candidate list should NOT re-prewarm X (it's already
    in warm_backups)."""
    rb = RouteBrain()
    candidates = [
        _path("active", warm=True),
        _path("backup-A"),
    ]
    state = RouteState(
        active_path_id="active",
        warm_backups=frozenset({"backup-A"}),
    )
    new_state, cmd = rb.step(
        decision=_decision(ImmuneAction.PREWARM_BACKUP_ROUTE),
        candidates=candidates,
        state=state,
    )
    # No cold alternatives left; HOLD.
    assert cmd.kind == RouteCommandKind.HOLD
    assert cmd.reason_code == "no_cold_alternative"


def test_prewarm_handles_zero_candidates() -> None:
    rb = RouteBrain()
    state, cmd = rb.step(
        decision=_decision(ImmuneAction.PREWARM_BACKUP_ROUTE),
        candidates=[],
        state=RouteState(active_path_id="x"),
    )
    assert cmd.kind == RouteCommandKind.HOLD


# ---------------------------------------------------------------------------
# SWITCH
# ---------------------------------------------------------------------------

def test_switch_prefers_warm_backup() -> None:
    rb = RouteBrain()
    candidates = [
        _path("active", rtt=900.0, loss=0.20),       # active, but terrible
        _path("warm-backup", rtt=80.0, warm=True),   # warm
        _path("excellent-cold", rtt=30.0, attested=True),  # cold but excellent
    ]
    state = RouteState(active_path_id="active")
    new_state, cmd = rb.step(
        decision=_decision(ImmuneAction.SWITCH_ROUTE),
        candidates=candidates,
        state=state,
    )
    assert cmd.kind == RouteCommandKind.SWITCH_TO_PATH
    # Warm pool wins, even though the cold path's raw score is high.
    assert cmd.target_path_id == "warm-backup"
    assert new_state.active_path_id == "warm-backup"


def test_switch_uses_cold_path_when_no_warm_options() -> None:
    rb = RouteBrain()
    candidates = [
        _path("active", rtt=900.0, loss=0.20),
        _path("cold-A", rtt=50.0),
    ]
    state = RouteState(active_path_id="active")
    new_state, cmd = rb.step(
        decision=_decision(ImmuneAction.SWITCH_ROUTE),
        candidates=candidates,
        state=state,
    )
    assert cmd.kind == RouteCommandKind.SWITCH_TO_PATH
    assert cmd.target_path_id == "cold-A"
    assert cmd.reason_code == "switch_to_cold"


def test_switch_refuses_when_margin_not_met() -> None:
    """Switch must beat the active path by at least the switch
    margin. Otherwise we'd flap between near-equal paths."""
    rb = RouteBrain(switch_margin=0.10)
    # Active is fine; alternative is slightly better but well below
    # the margin. Should HOLD.
    candidates = [
        _path("active", rtt=50.0, warm=True),
        _path("backup", rtt=45.0, warm=True),
    ]
    state = RouteState(active_path_id="active")
    new_state, cmd = rb.step(
        decision=_decision(ImmuneAction.SWITCH_ROUTE),
        candidates=candidates,
        state=state,
    )
    assert cmd.kind == RouteCommandKind.HOLD
    assert cmd.reason_code == "margin_not_met"
    assert new_state.active_path_id == "active"


def test_switch_commits_when_margin_met() -> None:
    rb = RouteBrain(switch_margin=0.10)
    candidates = [
        _path("active", rtt=900.0, loss=0.15),       # terrible
        _path("backup", rtt=30.0, attested=True, warm=True),  # great
    ]
    state = RouteState(active_path_id="active")
    new_state, cmd = rb.step(
        decision=_decision(ImmuneAction.SWITCH_ROUTE),
        candidates=candidates,
        state=state,
    )
    assert cmd.kind == RouteCommandKind.SWITCH_TO_PATH
    assert cmd.target_path_id == "backup"


def test_switch_drops_target_from_warm_backups_after_switch() -> None:
    """Once a path becomes active, it's no longer a 'backup.'
    The Route Brain removes it from warm_backups so subsequent
    prewarms can re-fill the slot."""
    rb = RouteBrain(switch_margin=0.0)
    candidates = [
        _path("active", rtt=500.0, loss=0.10),
        _path("backup", rtt=40.0, warm=True),
    ]
    state = RouteState(
        active_path_id="active",
        warm_backups=frozenset({"backup"}),
    )
    new_state, cmd = rb.step(
        decision=_decision(ImmuneAction.SWITCH_ROUTE),
        candidates=candidates,
        state=state,
    )
    assert new_state.active_path_id == "backup"
    assert "backup" not in new_state.warm_backups


def test_switch_with_zero_candidates_holds() -> None:
    rb = RouteBrain()
    state, cmd = rb.step(
        decision=_decision(ImmuneAction.SWITCH_ROUTE),
        candidates=[],
        state=RouteState(active_path_id="x"),
    )
    assert cmd.kind == RouteCommandKind.HOLD
    assert cmd.reason_code == "no_candidates"


def test_switch_with_no_alternatives_holds() -> None:
    """Only the active path exists in the candidate list."""
    rb = RouteBrain()
    state, cmd = rb.step(
        decision=_decision(ImmuneAction.SWITCH_ROUTE),
        candidates=[_path("active")],
        state=RouteState(active_path_id="active"),
    )
    assert cmd.kind == RouteCommandKind.HOLD
    assert cmd.reason_code == "no_alternative_path"


# ---------------------------------------------------------------------------
# Other actions are pass-throughs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("action", [
    ImmuneAction.HOLD,
    ImmuneAction.REQUEST_LOWER_FIDELITY,
    ImmuneAction.REQUEST_VOICE_ONLY,
    ImmuneAction.SUGGEST_DEVICE_HANDOFF,
    ImmuneAction.CONVERT_TO_ASYNC,
    ImmuneAction.EMERGENCY_REKEY,
])
def test_non_route_actions_hold(action: ImmuneAction) -> None:
    rb = RouteBrain()
    state = RouteState(active_path_id="x")
    new_state, cmd = rb.step(
        decision=_decision(action),
        candidates=[_path("x"), _path("y")],
        state=state,
    )
    assert cmd.kind == RouteCommandKind.HOLD
    assert new_state == state


# ---------------------------------------------------------------------------
# Determinism + tiebreak
# ---------------------------------------------------------------------------

def test_tiebreak_lex_min_path_id() -> None:
    """Two paths with identical scores: tiebreak picks lex-min."""
    rb = RouteBrain()
    candidates = [
        _path("zzzz", rtt=50.0),
        _path("aaaa", rtt=50.0),
    ]
    state, cmd = rb.step(
        decision=_decision(ImmuneAction.PREWARM_BACKUP_ROUTE),
        candidates=candidates,
        state=RouteState(),
    )
    assert cmd.target_path_id == "aaaa"


def test_same_inputs_yield_same_outputs() -> None:
    rb_a = RouteBrain()
    rb_b = RouteBrain()
    candidates = [
        _path("active", rtt=900.0, loss=0.20),
        _path("backup", rtt=50.0, warm=True),
    ]
    state = RouteState(active_path_id="active")
    decision = _decision(ImmuneAction.SWITCH_ROUTE)
    a_state, a_cmd = rb_a.step(decision=decision, candidates=candidates, state=state)
    b_state, b_cmd = rb_b.step(decision=decision, candidates=candidates, state=state)
    assert a_state == b_state
    assert a_cmd == b_cmd


# ---------------------------------------------------------------------------
# Path loss recovery
# ---------------------------------------------------------------------------

def test_on_active_path_lost_clears_state() -> None:
    rb = RouteBrain()
    state = RouteState(
        active_path_id="active",
        warm_backups=frozenset({"backup-A"}),
    )
    new_state = rb.on_active_path_lost(state)
    assert new_state.active_path_id is None
    # warm_backups stays intact so the next SWITCH can pick them up.
    assert "backup-A" in new_state.warm_backups
