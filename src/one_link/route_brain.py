"""Route Brain — path-prewarm + path-switch controller.

Reads the current set of available paths to a peer, scores each on a
composite cost function, and emits :class:`RouteCommand` events when
the Immune System asks for a prewarm or switch.

Pure controller: holds no I/O. The signaling layer (MEDIA_REDIRECT
wire messages, native handshake-to-prewarm a relay, the 200 ms
crossfade on media tracks during a switch) lives downstream.

Composite cost score (per LIVING_PRESENCE_ARCHITECTURE.md §4.4):

    cost = 0.25 * rtt_score
         + 0.30 * loss_score
         + 0.20 * (1 - fragility_score)
         + 0.10 * tau_c_score
         + 0.10 * attestation_score
         + 0.05 * warmth_score

All sub-scores are normalised to [0.0, 1.0]; higher = better. The
Route Brain picks the path with the highest score.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Optional

from one_link.call_immune import ImmuneAction, ImmuneDecision
from one_link.frame_provenance import PathClass

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Path candidate
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RouteCandidate:
    """One available path. Daemon's ``_relay_metrics`` +
    ``ol_routing`` candidates feed this in. The Route Brain doesn't
    distinguish between freshly-discovered cold paths and known
    warm ones except via the ``warm`` flag — warmth saves the
    handshake cost on switch."""

    path_id: str
    path_class: PathClass
    rtt_ewma_ms: float
    loss_rate_ewma: float           # 0.0..1.0
    bandwidth_kbps: float
    fragility_score: float = 0.0    # 0=robust 1=critical (ol_homology)
    tau_c_score: float = 0.5        # ol_routing tau_c-weighted score
    attested: bool = False          # confidential-tier verified
    warm: bool = False              # session already established
    last_used_ms: int = 0


# ---------------------------------------------------------------------------
# Output commands
# ---------------------------------------------------------------------------

class RouteCommandKind(IntEnum):
    HOLD            = 0
    PREWARM_PATH    = 1   # establish handshake but stay on current
    SWITCH_TO_PATH  = 2   # move media to this path now


@dataclass(frozen=True)
class RouteCommand:
    """Emitted when the Route Brain wants the signaling layer to
    act. ``HOLD`` means the brain explicitly considered and chose
    not to change anything."""

    kind: RouteCommandKind
    target_path_id: Optional[str]
    crossfade_ms: int = 200
    reason_code: str = "score_better"
    decided_at_ms: int = 0


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScoringWeights:
    """Composite cost weights. All sub-scores normalised [0,1];
    higher score = better path. Defaults from the architecture doc."""

    rtt: float = 0.25
    loss: float = 0.30
    fragility: float = 0.20
    tau_c: float = 0.10
    attestation: float = 0.10
    warmth: float = 0.05


# RTT score: 1.0 at <=50ms, decaying linearly to 0.0 at 1000ms.
_RTT_GOOD_MS = 50.0
_RTT_BAD_MS = 1000.0


def _rtt_score(rtt_ms: float) -> float:
    if rtt_ms <= _RTT_GOOD_MS:
        return 1.0
    if rtt_ms >= _RTT_BAD_MS:
        return 0.0
    return 1.0 - (rtt_ms - _RTT_GOOD_MS) / (_RTT_BAD_MS - _RTT_GOOD_MS)


def _loss_score(loss: float) -> float:
    # 1.0 at 0% loss, 0.0 at >=20% loss.
    if loss <= 0.0:
        return 1.0
    if loss >= 0.20:
        return 0.0
    return 1.0 - (loss / 0.20)


def _attestation_score(attested: bool) -> float:
    return 1.0 if attested else 0.4


def _warmth_score(warm: bool) -> float:
    # Warm paths save a full handshake on switch — worth a small bonus.
    return 1.0 if warm else 0.5


def score_path(
    cand: RouteCandidate,
    *,
    weights: Optional[ScoringWeights] = None,
) -> float:
    """Composite path score in [0.0, 1.0]. Higher = better. Pure
    function — same inputs always yield same output."""
    w = weights or ScoringWeights()
    return (
        w.rtt         * _rtt_score(cand.rtt_ewma_ms)
        + w.loss        * _loss_score(cand.loss_rate_ewma)
        + w.fragility   * (1.0 - max(0.0, min(1.0, cand.fragility_score)))
        + w.tau_c       * max(0.0, min(1.0, cand.tau_c_score))
        + w.attestation * _attestation_score(cand.attested)
        + w.warmth      * _warmth_score(cand.warm)
    )


# ---------------------------------------------------------------------------
# Route state (per call)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RouteState:
    """The Route Brain's mutable per-call state. Frozen so each
    decision returns a new state — keeps the controller pure."""

    active_path_id: Optional[str] = None
    warm_backups: frozenset[str] = field(default_factory=frozenset)


# ---------------------------------------------------------------------------
# Route Brain
# ---------------------------------------------------------------------------

class RouteBrain:
    """Per-call route controller. Receives Immune-System decisions
    and the current set of candidates; returns ``RouteCommand``s.

    The brain doesn't synchronously dial a relay or migrate a media
    stream — it emits *intentions* the signaling layer turns into
    real network actions. Same separation as the
    :class:`PresenceCompiler` / media-pipeline split.
    """

    def __init__(
        self,
        *,
        weights: Optional[ScoringWeights] = None,
        # Minimum margin a challenger must beat the active path by
        # before we switch. Prevents flicker between similar paths.
        switch_margin: float = 0.10,
    ) -> None:
        self._weights = weights or ScoringWeights()
        self._switch_margin = float(switch_margin)

    # ── decision ────────────────────────────────────────────────

    def step(
        self,
        *,
        decision: ImmuneDecision,
        candidates: list[RouteCandidate],
        state: RouteState,
    ) -> tuple[RouteState, RouteCommand]:
        """Process one Immune-System decision. Returns the new
        :class:`RouteState` and the :class:`RouteCommand` to emit.

        Idempotent for repeat requests: prewarming an already-warm
        path is a no-op (HOLD); switching to the active path is a
        no-op.
        """
        action = decision.action
        if action == ImmuneAction.PREWARM_BACKUP_ROUTE:
            return self._handle_prewarm(decision, candidates, state)
        if action == ImmuneAction.SWITCH_ROUTE:
            return self._handle_switch(decision, candidates, state)
        # Any other action (including HOLD) → no route change.
        return state, RouteCommand(
            kind=RouteCommandKind.HOLD,
            target_path_id=state.active_path_id,
            reason_code="no_request",
            decided_at_ms=decision.tick,
        )

    # ── prewarm ────────────────────────────────────────────────

    def _handle_prewarm(
        self,
        decision: ImmuneDecision,
        candidates: list[RouteCandidate],
        state: RouteState,
    ) -> tuple[RouteState, RouteCommand]:
        # Best cold path that isn't the active one. If a viable cold
        # alternative exists, mark it warm and emit PREWARM_PATH.
        cold = [
            c for c in candidates
            if c.path_id != state.active_path_id
            and c.path_id not in state.warm_backups
            and not c.warm
        ]
        if not cold:
            return state, RouteCommand(
                kind=RouteCommandKind.HOLD,
                target_path_id=state.active_path_id,
                reason_code="no_cold_alternative",
                decided_at_ms=decision.tick,
            )
        best = self._best_of(cold)
        new_state = replace(
            state,
            warm_backups=state.warm_backups | frozenset({best.path_id}),
        )
        return new_state, RouteCommand(
            kind=RouteCommandKind.PREWARM_PATH,
            target_path_id=best.path_id,
            reason_code="prewarm_best_cold",
            decided_at_ms=decision.tick,
        )

    # ── switch ─────────────────────────────────────────────────

    def _handle_switch(
        self,
        decision: ImmuneDecision,
        candidates: list[RouteCandidate],
        state: RouteState,
    ) -> tuple[RouteState, RouteCommand]:
        if not candidates:
            return state, RouteCommand(
                kind=RouteCommandKind.HOLD,
                target_path_id=state.active_path_id,
                reason_code="no_candidates",
                decided_at_ms=decision.tick,
            )
        # Prefer warm backups when switching (no handshake cost).
        warm_options = [
            c for c in candidates
            if c.path_id != state.active_path_id
            and (c.warm or c.path_id in state.warm_backups)
        ]
        cold_options = [
            c for c in candidates
            if c.path_id != state.active_path_id
            and not c.warm
            and c.path_id not in state.warm_backups
        ]
        choice_pool = warm_options or cold_options
        if not choice_pool:
            return state, RouteCommand(
                kind=RouteCommandKind.HOLD,
                target_path_id=state.active_path_id,
                reason_code="no_alternative_path",
                decided_at_ms=decision.tick,
            )
        best = self._best_of(choice_pool)

        # If there IS an active path, require margin before switching.
        if state.active_path_id is not None:
            active = next(
                (c for c in candidates if c.path_id == state.active_path_id),
                None,
            )
            if active is not None:
                margin = score_path(best, weights=self._weights) - score_path(
                    active, weights=self._weights,
                )
                if margin < self._switch_margin:
                    return state, RouteCommand(
                        kind=RouteCommandKind.HOLD,
                        target_path_id=state.active_path_id,
                        reason_code="margin_not_met",
                        decided_at_ms=decision.tick,
                    )

        new_state = replace(
            state,
            active_path_id=best.path_id,
            # Once we switch onto a path it's the active one — drop
            # it from warm_backups (it's no longer a backup).
            warm_backups=state.warm_backups - frozenset({best.path_id}),
        )
        return new_state, RouteCommand(
            kind=RouteCommandKind.SWITCH_TO_PATH,
            target_path_id=best.path_id,
            reason_code=(
                "switch_to_warm_backup" if warm_options else "switch_to_cold"
            ),
            decided_at_ms=decision.tick,
        )

    # ── helpers ────────────────────────────────────────────────

    def _best_of(self, pool: list[RouteCandidate]) -> RouteCandidate:
        """Highest-scored path. Tiebreak on lex-min path_id."""
        return max(
            pool, key=lambda c: (score_path(c, weights=self._weights), -ord(c.path_id[0]) if c.path_id else 0),
        ) if False else sorted(
            pool,
            key=lambda c: (-score_path(c, weights=self._weights), c.path_id),
        )[0]

    # ── path-loss recovery ─────────────────────────────────────

    def on_active_path_lost(self, state: RouteState) -> RouteState:
        """Called by the signaling layer when the active path is
        confirmed dead (e.g., the relay returned a 410). Clears
        the active path so the next switch picks fresh."""
        return replace(state, active_path_id=None)
