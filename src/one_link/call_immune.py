"""Call Immune System — the 100 ms-tick controller.

Reads :class:`CallVitals` each tick. Emits an :class:`ImmuneDecision`.
Three sub-controllers run in parallel; an Arbitrator picks the
highest-severity action.

The architectural firewall is non-negotiable: this module NEVER
touches media or transport directly. It emits *requests* to the
Presence Compiler, Route Brain, and Multi-Device Body. Each
downstream engine has refusal authority. This is how cascade
failures are prevented.

The Arbitrator is pure: given the same CallVitals it returns the
same ImmuneDecision. The decision's ``vitals_hash`` ties to
:meth:`CallVitals.vitals_hash` so soak-replay can verify
determinism.

Graduation modes:

  SHADOW   — controller runs, decisions are logged, no actions emitted
             (Tier γ — collecting the dataset to tune thresholds)
  ASSIST   — actions REQUEST_LOWER_FIDELITY / PREWARM_BACKUP_ROUTE
             are emitted; SWITCH_ROUTE / CONVERT_TO_ASYNC require
             user-equivalent confirmation
  AUTOPILOT — all actions enabled (Tier η+)

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.1
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Callable, Optional

from one_link.call_vitals import (
    CallVitals,
    ThermalState,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

class ImmuneAction(IntEnum):
    """The only outputs the Immune System can emit. Severity ordering
    is by integer value (HIGHER = more severe).

    Severity ordering (highest → lowest):
        EMERGENCY_REKEY > CONVERT_TO_ASYNC > SWITCH_ROUTE
        > REQUEST_VOICE_ONLY > REQUEST_LOWER_FIDELITY
        > SUGGEST_DEVICE_HANDOFF > PREWARM_BACKUP_ROUTE > HOLD
    """

    HOLD                   = 0
    PREWARM_BACKUP_ROUTE   = 1
    SUGGEST_DEVICE_HANDOFF = 2
    REQUEST_LOWER_FIDELITY = 3
    REQUEST_VOICE_ONLY     = 4
    SWITCH_ROUTE           = 5
    CONVERT_TO_ASYNC       = 6
    EMERGENCY_REKEY        = 7


class GraduationMode(Enum):
    """Current mode of the Immune System. See module docstring."""

    SHADOW    = "shadow"
    ASSIST    = "assist"
    AUTOPILOT = "autopilot"


@dataclass(frozen=True)
class ImmuneDecision:
    """A single decision emitted on a tick. Pure function of the
    vitals + previous decision (if any).

    ``vitals_hash`` echoes the hash from
    :meth:`CallVitals.vitals_hash`. Soak-replay verifies that
    given the same vitals_hash the same decision is emitted.
    """

    action: ImmuneAction
    reason_code: str            # e.g. "loss_above_async_threshold"
    triggered_by: tuple[str, ...]   # names of fields that crossed thresholds
    confidence: float           # 0..1 for SHADOW-mode learning
    tick: int
    vitals_hash: str
    # Was this decision actually emitted to downstream engines, or
    # only logged? In SHADOW mode all decisions are recorded but
    # only ``HOLD``-equivalents leave the audit log.
    emitted: bool = True


# ---------------------------------------------------------------------------
# Thresholds + hysteresis
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Thresholds:
    """Trigger + recover thresholds with explicit hysteresis. The
    Immune System never flips back into a green state until the
    relevant signal has dropped well below the trigger — this
    eliminates oscillation at the boundary, which the user would
    feel as flicker.

    Recover values are typically ½ of trigger values (per the
    architecture doc). Override via constructor for tuning sessions.
    """

    rtt_prewarm_trigger_ms: float = 400.0
    rtt_prewarm_recover_ms: float = 180.0
    rtt_switch_trigger_ms: float = 800.0
    rtt_switch_recover_ms: float = 350.0

    loss_degrade_trigger: float = 0.05
    loss_degrade_recover: float = 0.02
    loss_voice_only_trigger: float = 0.15
    loss_voice_only_recover: float = 0.05
    loss_async_trigger: float = 0.35
    loss_async_recover: float = 0.10

    jitter_degrade_ms: float = 80.0

    fragility_async_threshold: float = 0.90
    fragility_switch_threshold: float = 0.75
    fragility_prewarm_threshold: float = 0.55

    # If the peer's last_alive_ms is more than this many ms behind
    # the wall clock, the call is presumed dead → async conversion.
    peer_silence_async_ms: int = 12_000

    # Battery + thermal handoff thresholds.
    battery_handoff_pct: float = 18.0   # below this → suggest move to another device
    thermal_handoff_state: ThermalState = ThermalState.HOT

    # Confidence floor: voice/video frames decoded confidently.
    voice_confirm_safe_threshold: float = 0.85


# ---------------------------------------------------------------------------
# Sub-controllers
# ---------------------------------------------------------------------------

@dataclass
class _ControllerOutput:
    """One sub-controller's vote per tick."""

    action: ImmuneAction
    reason_code: str
    triggered_by: tuple[str, ...]
    confidence: float


class TransportHealthController:
    """Watches RTT + loss + jitter, with explicit hysteresis.

    Hysteresis: once a degraded state is entered, the controller
    stays in it until the relevant signal drops below the
    *recover* threshold (typically half the trigger). This kills
    oscillation at boundaries that would otherwise translate to
    user-visible flicker.
    """

    def __init__(self, thresholds: Thresholds) -> None:
        self._t = thresholds

    def decide(
        self,
        v: CallVitals,
        last: Optional[ImmuneDecision],
        state: _HysteresisState,
    ) -> _ControllerOutput:
        # ── Hard-trigger end states (no hysteresis — terminal) ───
        if v.loss_rate_ewma >= self._t.loss_async_trigger:
            return _ControllerOutput(
                action=ImmuneAction.CONVERT_TO_ASYNC,
                reason_code="loss_above_async_threshold",
                triggered_by=("loss_rate_ewma",),
                confidence=_confidence_from_overshoot(
                    v.loss_rate_ewma, self._t.loss_async_trigger
                ),
            )

        if v.rtt_ewma_ms >= self._t.rtt_switch_trigger_ms:
            return _ControllerOutput(
                action=ImmuneAction.SWITCH_ROUTE,
                reason_code="rtt_above_switch_threshold",
                triggered_by=("rtt_ewma_ms",),
                confidence=_confidence_from_overshoot(
                    v.rtt_ewma_ms, self._t.rtt_switch_trigger_ms
                ),
            )

        # ── Voice-only state, with hysteresis ────────────────────
        if state.in_voice_only:
            if v.loss_rate_ewma >= self._t.loss_voice_only_recover:
                # Stay voice-only — but re-emitting is HOLD (idempotent
                # state, not a new action). The Compiler is already
                # in voice-only mode.
                return _ControllerOutput(
                    action=ImmuneAction.HOLD,
                    reason_code="staying_voice_only",
                    triggered_by=("loss_rate_ewma",),
                    confidence=0.85,
                )
            # Recovered below threshold — let go.
            state.in_voice_only = False
        elif v.loss_rate_ewma >= self._t.loss_voice_only_trigger:
            state.in_voice_only = True
            return _ControllerOutput(
                action=ImmuneAction.REQUEST_VOICE_ONLY,
                reason_code="loss_above_voice_only_threshold",
                triggered_by=("loss_rate_ewma",),
                confidence=_confidence_from_overshoot(
                    v.loss_rate_ewma, self._t.loss_voice_only_trigger
                ),
            )

        # ── Degraded-video state, with hysteresis ────────────────
        currently_above_degrade = (
            v.loss_rate_ewma >= self._t.loss_degrade_trigger
            or v.jitter_ms >= self._t.jitter_degrade_ms
        )
        currently_below_recover = (
            v.loss_rate_ewma < self._t.loss_degrade_recover
            and v.jitter_ms < self._t.jitter_degrade_ms * 0.5
        )

        if state.in_degraded_video:
            if currently_below_recover:
                state.in_degraded_video = False
                # Fall through to prewarm / hold check.
            else:
                # Stay degraded — emit HOLD (idempotent).
                return _ControllerOutput(
                    action=ImmuneAction.HOLD,
                    reason_code="staying_degraded_video",
                    triggered_by=("loss_rate_ewma", "jitter_ms"),
                    confidence=0.85,
                )
        elif currently_above_degrade:
            state.in_degraded_video = True
            triggered: list[str] = []
            if v.loss_rate_ewma >= self._t.loss_degrade_trigger:
                triggered.append("loss_rate_ewma")
            if v.jitter_ms >= self._t.jitter_degrade_ms:
                triggered.append("jitter_ms")
            return _ControllerOutput(
                action=ImmuneAction.REQUEST_LOWER_FIDELITY,
                reason_code="loss_or_jitter_above_degrade",
                triggered_by=tuple(triggered),
                confidence=0.70,
            )

        # ── Prewarm state, with hysteresis ───────────────────────
        if state.in_prewarm:
            if v.rtt_ewma_ms < self._t.rtt_prewarm_recover_ms:
                state.in_prewarm = False
            else:
                # Stay prewarmed — backup is already established;
                # re-emitting is HOLD (idempotent).
                return _ControllerOutput(
                    action=ImmuneAction.HOLD,
                    reason_code="staying_prewarmed",
                    triggered_by=("rtt_ewma_ms",),
                    confidence=0.85,
                )
        elif v.rtt_ewma_ms >= self._t.rtt_prewarm_trigger_ms:
            state.in_prewarm = True
            return _ControllerOutput(
                action=ImmuneAction.PREWARM_BACKUP_ROUTE,
                reason_code="rtt_above_prewarm_threshold",
                triggered_by=("rtt_ewma_ms",),
                confidence=_confidence_from_overshoot(
                    v.rtt_ewma_ms, self._t.rtt_prewarm_trigger_ms
                ),
            )

        return _ControllerOutput(
            action=ImmuneAction.HOLD,
            reason_code="transport_healthy",
            triggered_by=(),
            confidence=1.0,
        )


class PathBrainController:
    """Watches path-topology fragility + peer presence."""

    def __init__(self, thresholds: Thresholds) -> None:
        self._t = thresholds

    def decide(
        self,
        v: CallVitals,
        last: Optional[ImmuneDecision],
        state: _HysteresisState,
    ) -> _ControllerOutput:
        # Peer has gone quiet — the call has effectively ended.
        if (
            v.last_alive_ms > 0
            and v.tick > 0
            and v.peer_device_present is False
        ):
            return _ControllerOutput(
                action=ImmuneAction.CONVERT_TO_ASYNC,
                reason_code="peer_device_absent",
                triggered_by=("peer_device_present",),
                confidence=1.0,
            )

        if v.path_fragility_score >= self._t.fragility_async_threshold:
            return _ControllerOutput(
                action=ImmuneAction.CONVERT_TO_ASYNC,
                reason_code="fragility_critical",
                triggered_by=("path_fragility_score",),
                confidence=_confidence_from_overshoot(
                    v.path_fragility_score, self._t.fragility_async_threshold
                ),
            )

        # Path-switch hysteresis: once we've switched routes, stay
        # switched until fragility drops well below the trigger.
        # Re-firing SWITCH on tick-to-tick noise is the worst case.
        if state.path_switched:
            if v.path_fragility_score < self._t.fragility_switch_threshold * 0.5:
                state.path_switched = False
                # Fall through to lower-tier checks.
            else:
                return _ControllerOutput(
                    action=ImmuneAction.HOLD,
                    reason_code="already_switched",
                    triggered_by=("path_fragility_score",),
                    confidence=0.85,
                )
        elif v.path_fragility_score >= self._t.fragility_switch_threshold:
            state.path_switched = True
            # Once we issue SWITCH the prewarm slot is consumed; clear it
            # so a subsequent fragility dip into prewarm range doesn't
            # also re-emit a prewarm.
            state.in_prewarm = True
            return _ControllerOutput(
                action=ImmuneAction.SWITCH_ROUTE,
                reason_code="fragility_high",
                triggered_by=("path_fragility_score",),
                confidence=_confidence_from_overshoot(
                    v.path_fragility_score, self._t.fragility_switch_threshold
                ),
            )

        # Prewarm hysteresis: share the same _HysteresisState.in_prewarm
        # flag as TransportHealthController. Once a prewarm has been
        # issued (by either signal), don't re-issue.
        if state.in_prewarm:
            if v.path_fragility_score < self._t.fragility_prewarm_threshold * 0.5:
                # Both transport AND path say recovered. The transport
                # controller manages its own recovery; we just don't
                # re-fire on path signal alone.
                pass
            return _ControllerOutput(
                action=ImmuneAction.HOLD,
                reason_code="already_prewarmed",
                triggered_by=("path_fragility_score",),
                confidence=0.85,
            )

        if v.path_fragility_score >= self._t.fragility_prewarm_threshold:
            state.in_prewarm = True
            return _ControllerOutput(
                action=ImmuneAction.PREWARM_BACKUP_ROUTE,
                reason_code="fragility_rising",
                triggered_by=("path_fragility_score",),
                confidence=_confidence_from_overshoot(
                    v.path_fragility_score, self._t.fragility_prewarm_threshold
                ),
            )

        return _ControllerOutput(
            action=ImmuneAction.HOLD,
            reason_code="path_stable",
            triggered_by=(),
            confidence=1.0,
        )


class DeviceWellnessController:
    """Watches own device's battery + thermal state.

    Suggestion is idempotent — once a handoff is suggested for a
    call, don't re-suggest until the underlying state clears.
    """

    def __init__(self, thresholds: Thresholds) -> None:
        self._t = thresholds

    def decide(
        self,
        v: CallVitals,
        last: Optional[ImmuneDecision],
        state: _HysteresisState,
    ) -> _ControllerOutput:
        triggered: list[str] = []

        if (
            v.own_battery_pct is not None
            and v.own_battery_pct <= self._t.battery_handoff_pct
        ):
            triggered.append("own_battery_pct")

        if v.own_thermal_state >= self._t.thermal_handoff_state:
            triggered.append("own_thermal_state")

        if triggered:
            if state.handoff_suggested:
                # Idempotent — already suggested, don't spam.
                return _ControllerOutput(
                    action=ImmuneAction.HOLD,
                    reason_code="handoff_already_suggested",
                    triggered_by=tuple(triggered),
                    confidence=0.85,
                )
            state.handoff_suggested = True
            return _ControllerOutput(
                action=ImmuneAction.SUGGEST_DEVICE_HANDOFF,
                reason_code="device_wellness_low",
                triggered_by=tuple(triggered),
                confidence=0.80,
            )

        # Conditions cleared — reset so a future excursion re-fires.
        state.handoff_suggested = False
        return _ControllerOutput(
            action=ImmuneAction.HOLD,
            reason_code="device_wellness_ok",
            triggered_by=(),
            confidence=1.0,
        )


# ---------------------------------------------------------------------------
# Per-call hysteresis state
# ---------------------------------------------------------------------------

@dataclass
class _HysteresisState:
    """Tracks which degraded modes a call is currently in. The
    Arbitrator uses this to enforce trigger/recover hysteresis:
    transitions UP cross the trigger; transitions DOWN cross the
    recover threshold. Between the two, the system stays in
    whatever state it's already in. This eliminates the boundary
    flapping the user would feel as flicker."""

    in_prewarm: bool = False           # ever crossed prewarm trigger this call
    in_degraded_video: bool = False    # REQUEST_LOWER_FIDELITY active
    in_voice_only: bool = False        # REQUEST_VOICE_ONLY active
    handoff_suggested: bool = False    # SUGGEST_DEVICE_HANDOFF idempotent
    # Path-brain hysteresis. Once we've issued a switch on a
    # rising fragility excursion, don't immediately step back down
    # to PREWARM when fragility momentarily dips. Switch is a
    # cost-bearing action (warm new route, attestation, key
    # exchange) so re-firing it back-to-back is the worst-case
    # behavior.
    path_switched: bool = False        # SWITCH_ROUTE emitted; recover below threshold/2

    def reset(self) -> None:
        self.in_prewarm = False
        self.in_degraded_video = False
        self.in_voice_only = False
        self.handoff_suggested = False
        self.path_switched = False


# ---------------------------------------------------------------------------
# Confidence helper
# ---------------------------------------------------------------------------

def _confidence_from_overshoot(value: float, trigger: float) -> float:
    """Soft confidence: 0.6 at the trigger, asymptoting toward 1.0
    as value exceeds it. Provides a gentle ramp for SHADOW-mode
    learning without coupling to a specific shape."""
    if trigger <= 0:
        return 1.0
    overshoot = max(0.0, (value - trigger) / trigger)
    return min(1.0, 0.6 + 0.4 * (overshoot / (1.0 + overshoot)))


# ---------------------------------------------------------------------------
# The Arbitrator
# ---------------------------------------------------------------------------

class Arbitrator:
    """Pure aggregator: picks the highest-severity vote across
    controllers, with hysteresis on raise paths.

    The "voice safe" override: when the user is currently being
    served well by voice (confirm ratio high, loss low), HOLD even
    if a single signal crossed a threshold. The threshold is
    necessary but not sufficient — the Immune System reasons about
    whether the user is *currently* being harmed.

    Hysteresis is per-call. The Arbitrator caches a
    :class:`_HysteresisState` per ``call_id`` and threads it through
    each controller. Determinism is preserved because the state is
    a pure function of the sequence of vitals seen so far — same
    sequence → same state → same decisions.
    """

    def __init__(self, thresholds: Optional[Thresholds] = None) -> None:
        self._t = thresholds or Thresholds()
        self._transport = TransportHealthController(self._t)
        self._path = PathBrainController(self._t)
        self._device = DeviceWellnessController(self._t)
        self._hysteresis: dict[str, _HysteresisState] = {}

    def reset_call(self, call_id: str) -> None:
        """Clear the hysteresis state for a specific call. Used by
        the soak harness between iterations so each scenario starts
        clean."""
        self._hysteresis.pop(call_id, None)

    def reset_all(self) -> None:
        self._hysteresis.clear()

    def decide(
        self,
        v: CallVitals,
        last: Optional[ImmuneDecision] = None,
    ) -> ImmuneDecision:
        state = self._hysteresis.setdefault(v.call_id, _HysteresisState())
        votes = [
            self._transport.decide(v, last, state),
            self._path.decide(v, last, state),
            self._device.decide(v, last, state),
        ]
        # Highest severity wins. Ties go to the first vote in
        # transport / path / device order (deterministic).
        votes.sort(key=lambda o: int(o.action), reverse=True)
        chosen = votes[0]

        # Voice-safe override. When voice is healthy AND the signal
        # that crossed is something the user isn't feeling yet
        # (RTT but no loss, fragility but no degraded media), we
        # defer the prewarm. Async conversion + voice-only + emergency
        # rekey are NEVER overridden — those are end-state safety
        # actions.
        if (
            chosen.action in (
                ImmuneAction.PREWARM_BACKUP_ROUTE,
                ImmuneAction.SUGGEST_DEVICE_HANDOFF,
            )
            and v.confirm_ratio_voice >= self._t.voice_confirm_safe_threshold
            and v.loss_rate_ewma < self._t.loss_degrade_recover
            and v.path_fragility_score < self._t.fragility_prewarm_threshold
        ):
            return ImmuneDecision(
                action=ImmuneAction.HOLD,
                reason_code="voice_safe_override",
                triggered_by=chosen.triggered_by,
                confidence=0.95,
                tick=v.tick,
                vitals_hash=v.vitals_hash(),
            )

        return ImmuneDecision(
            action=chosen.action,
            reason_code=chosen.reason_code,
            triggered_by=chosen.triggered_by,
            confidence=chosen.confidence,
            tick=v.tick,
            vitals_hash=v.vitals_hash(),
        )


# ---------------------------------------------------------------------------
# The runtime — graduation gate + audit log
# ---------------------------------------------------------------------------

# Type of the consumer that downstream engines plug in. Receives
# every emitted decision in real-time.
DecisionSink = Callable[[ImmuneDecision], None]


class ImmuneSystem:
    """Top-level runtime. Owns the Arbitrator + per-call last-
    decision cache + the in-memory audit log.

    Tick rate is the caller's responsibility (the daemon's tick
    loop drives this). The Immune System itself is purely
    synchronous: ``tick(vitals)`` is a pure function over
    (vitals, last_decision_for_this_call).

    Thread-safe: a single internal lock guards last_decisions +
    the audit log. The audit log is bounded so a long-running
    daemon can't OOM by accumulating decisions forever.
    """

    DEFAULT_AUDIT_CAP = 4096

    def __init__(
        self,
        *,
        mode: GraduationMode = GraduationMode.SHADOW,
        thresholds: Optional[Thresholds] = None,
        audit_cap: int = DEFAULT_AUDIT_CAP,
        sink: Optional[DecisionSink] = None,
    ) -> None:
        self.mode = mode
        self._arb = Arbitrator(thresholds)
        self._last: dict[str, ImmuneDecision] = {}
        self._audit_log: list[ImmuneDecision] = []
        self._audit_cap = int(audit_cap)
        self._lock = threading.Lock()
        self._sink = sink

    # -- core API --

    def tick(self, vitals: CallVitals) -> ImmuneDecision:
        """Emit (and log) one decision for one tick of one call."""
        with self._lock:
            last = self._last.get(vitals.call_id)
            decision = self._arb.decide(vitals, last)
            # Gate emission by graduation mode.
            emitted = self._should_emit(decision.action)
            if not emitted:
                # Replace the field while preserving everything else.
                from dataclasses import replace
                decision = replace(decision, emitted=False)
            self._last[vitals.call_id] = decision
            self._audit_log.append(decision)
            self._evict_overflow()

        # Sink runs outside the lock so a slow consumer doesn't
        # back-pressure tick latency.
        if decision.emitted and self._sink is not None:
            try:
                self._sink(decision)
            except Exception as exc:
                log.warning("immune-system sink raised: %s", exc)

        return decision

    def _should_emit(self, action: ImmuneAction) -> bool:
        if action == ImmuneAction.HOLD:
            return False  # HOLDs are logged but not acted on
        if self.mode == GraduationMode.SHADOW:
            return False  # SHADOW: log everything, emit nothing
        if self.mode == GraduationMode.ASSIST:
            # ASSIST: only emit reversible / low-cost actions.
            # SWITCH / CONVERT_TO_ASYNC / EMERGENCY_REKEY need
            # AUTOPILOT (or user-equivalent confirmation, which
            # the daemon may layer on later).
            return action in (
                ImmuneAction.PREWARM_BACKUP_ROUTE,
                ImmuneAction.REQUEST_LOWER_FIDELITY,
                ImmuneAction.SUGGEST_DEVICE_HANDOFF,
            )
        # AUTOPILOT: emit anything except HOLD.
        return True

    def _evict_overflow(self) -> None:
        # Bounded ring: drop oldest when over cap. Pop-from-head
        # is O(n); we accept it because tick rate is 10 Hz and
        # cap is 4096 — net cost is negligible.
        while len(self._audit_log) > self._audit_cap:
            self._audit_log.pop(0)

    # -- introspection --

    def last_decision_for(self, call_id: str) -> Optional[ImmuneDecision]:
        with self._lock:
            return self._last.get(call_id)

    def audit_log(self) -> list[ImmuneDecision]:
        with self._lock:
            return list(self._audit_log)

    def clear_audit_log(self) -> None:
        with self._lock:
            self._audit_log.clear()
            self._last.clear()
            self._arb.reset_all()

    # -- graduation --

    def promote_to(self, mode: GraduationMode) -> None:
        """Move to a more permissive mode. Demotions are allowed too
        (for emergency rollback during incidents)."""
        with self._lock:
            self.mode = mode

    def __len__(self) -> int:
        with self._lock:
            return len(self._audit_log)
