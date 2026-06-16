"""Presence Compiler — picks the active representation rung.

Listens for :class:`ImmuneDecision` requests + capability changes,
emits :class:`RungTransition` events that downstream media
machinery turns into real codec / track changes.

The Compiler is internal mechanism. The user never sees it. Per the
Doctrine of Invisibility §3.8.a, rung changes do not surface as
toasts or banners — they are smooth crossfades in the media
pipeline.

Two load-bearing invariants:

  1. Monotone descent / slow ascent.

     Drops happen instantly: any request to descend is honored on
     the next tick. Rises require a stability window (default 10
     seconds at 100 ms tick = 100 ticks). This eliminates flicker
     when the network is on a knife's edge between two rungs.

  2. Capability mask is enforced first.

     A rung is unreachable unless every capability it requires is in
     the peer-intersection set. If the peer doesn't advertise
     ``SEMANTIC_MEDIA_V1`` and a model-pack hash that matches ours,
     the semantic rungs are silently masked off the ladder — the
     Compiler will never request them.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.2
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from one_link.call_immune import ImmuneAction, ImmuneDecision
from one_link.call_session import Rung

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Rung spec: required capabilities + audio/video codec
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RungSpec:
    """Static definition of one rung on the representation ladder."""

    rung: Rung
    name: str                       # plain-language ("audio only")
    min_kbps: float                 # below this, rung not viable
    min_confirm_ratio: Optional[float]  # None = not needed
    requires_caps: tuple[str, ...]  # capabilities both peers must advertise
    audio_codec: Optional[str]
    video_codec: Optional[str]
    is_semantic: bool               # uses model-pack reconstruction


# The full 9-rung ladder (matches LIVING_PRESENCE_ARCHITECTURE §4.2).
# Higher index = lower fidelity = lower bandwidth.
LADDER: tuple[RungSpec, ...] = (
    RungSpec(Rung.RAW_AV,            "raw_av",            1000.0, None, ("webrtc_av_v1",),     "opus", "vp9",  False),
    RungSpec(Rung.OPUS_VIDEO,        "opus_video",         300.0, None, ("webrtc_av_v1",),     "opus", "vp9",  False),
    RungSpec(Rung.SEMANTIC_DELTA_AV, "semantic_delta_av",   30.0, 0.95, ("semantic_media_v1",), None,   None,  True),
    RungSpec(Rung.FACE_STILL_MOTION, "face_still_motion",   10.0, 0.90, ("semantic_media_v1",), "opus", None,  True),
    RungSpec(Rung.AUDIO_ONLY,        "audio_only",          16.0, None, ("webrtc_av_v1",),     "opus", None,  False),
    RungSpec(Rung.PUSH_TO_TALK,      "push_to_talk",         3.0, None, ("webrtc_av_v1",),     "opus", None,  False),
    RungSpec(Rung.CONCEPT_TEXT,      "concept_text",         0.1, None, ("semantic_media_v1",), None,   None,  True),
    RungSpec(Rung.ASYNC_CAPSULE,     "async_capsule",        0.0, None, (),                     None,   None,  False),
    RungSpec(Rung.AMBIENT_PRESENCE,  "ambient_presence",     0.0, None, (),                     None,   None,  False),
)

_RUNG_BY_VALUE: dict[Rung, RungSpec] = {r.rung: r for r in LADDER}


# ---------------------------------------------------------------------------
# Transition output
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RungTransition:
    """The Compiler's output. Downstream media machinery is the
    consumer; for the user, the transition is invisible (smooth
    crossfade + softening, never a toast)."""

    from_rung: Rung
    to_rung: Rung
    reason_code: str
    tick: int


# ---------------------------------------------------------------------------
# Compiler
# ---------------------------------------------------------------------------

class PresenceCompiler:
    """Per-call rung selector. Hold one instance per active call.

    Reads:
      - The most recent ``ImmuneDecision`` (drives downward transitions)
      - The peer's negotiated capability set (caps mask)
      - The current bandwidth estimate (rung's min_kbps gate)
      - Confirm ratio (some rungs need a confidence floor)

    Writes:
      - :class:`RungTransition` events when the active rung changes.
        Same-rung re-evaluations emit None.
    """

    # Stability window for ascending — number of ticks of "could be
    # higher" conditions required before we actually raise.
    DEFAULT_ASCENT_HYSTERESIS_TICKS = 100   # 10s at 100ms tick

    def __init__(
        self,
        *,
        peer_capabilities: frozenset[str],
        model_pack_match: bool = False,
        initial_rung: Rung = Rung.RAW_AV,
        ascent_hysteresis_ticks: int = DEFAULT_ASCENT_HYSTERESIS_TICKS,
    ) -> None:
        self._peer_caps = peer_capabilities
        self._model_match = model_pack_match
        self._ascent_hysteresis = int(ascent_hysteresis_ticks)
        self._current = initial_rung
        # The tick at which we last *descended* (so we know when to
        # consider rising again).
        self._last_descent_tick = 0
        # The tick at which conditions first looked "good enough" to
        # rise; resets every time conditions degrade.
        self._stable_since_tick: Optional[int] = None

    # ── viability ───────────────────────────────────────────────

    def viable_rungs(
        self,
        *,
        bandwidth_kbps: float,
        confirm_ratio_voice: float,
    ) -> tuple[RungSpec, ...]:
        """Subset of the ladder reachable RIGHT NOW given peer caps,
        model match, bandwidth, and confirm ratio."""
        out: list[RungSpec] = []
        for spec in LADDER:
            if not all(c in self._peer_caps for c in spec.requires_caps):
                continue
            if spec.is_semantic and not self._model_match:
                continue
            if bandwidth_kbps < spec.min_kbps:
                continue
            if (
                spec.min_confirm_ratio is not None
                and confirm_ratio_voice < spec.min_confirm_ratio
            ):
                continue
            out.append(spec)
        return tuple(out)

    # ── action → target rung ────────────────────────────────────

    @staticmethod
    def _target_for_action(action: ImmuneAction, current: Rung) -> Rung:
        """Map an Immune-System action to the target rung the
        Compiler should descend toward. Returns the current rung
        for actions that don't drive a rung change (PREWARM,
        SUGGEST_DEVICE_HANDOFF, etc.)."""
        if action == ImmuneAction.CONVERT_TO_ASYNC:
            return Rung.ASYNC_CAPSULE
        if action == ImmuneAction.REQUEST_VOICE_ONLY:
            return Rung.AUDIO_ONLY
        if action == ImmuneAction.REQUEST_LOWER_FIDELITY:
            # One rung down from current. If we're at the bottom of
            # the non-async ladder, this is a no-op.
            next_rung_value = min(int(current) + 1, int(Rung.PUSH_TO_TALK))
            return Rung(next_rung_value)
        # All other actions don't drive a rung change.
        return current

    # ── tick (the core driver) ──────────────────────────────────

    # Ascent requires loss below this floor. Mirrors the
    # Immune System's loss_degrade_recover threshold so the two
    # engines agree on what "recovered" means.
    ASCENT_LOSS_FLOOR = 0.02

    def request(
        self,
        decision: ImmuneDecision,
        *,
        bandwidth_kbps: float,
        confirm_ratio_voice: float,
        loss_rate_ewma: float = 0.0,
    ) -> Optional[RungTransition]:
        """Process one Immune-System decision. Returns a
        :class:`RungTransition` if the active rung changed; None
        if it stayed the same.

        ``loss_rate_ewma`` gates ascent. The Immune System keeps a
        call in degraded state for as long as loss is above its
        recover threshold (default 0.02); the Compiler mirrors
        that by refusing to ascend until loss matches. Without this
        mirror, the Compiler climbs back to RAW_AV the moment HOLD
        is emitted — even though HOLD means "stay in current
        degraded state," not "everything is fine."
        """
        target = self._target_for_action(decision.action, self._current)

        if int(target) > int(self._current):
            # Descend (lower fidelity = higher index). Always allowed,
            # even if the target isn't strictly viable — async-capsule
            # has no min bandwidth and is always reachable.
            return self._descend_to(target, decision.reason_code, decision.tick)

        # Otherwise: consider ascending. Ascend only after stability
        # window AND only if a higher rung is viable AND conditions
        # are genuinely good (not just sustainable).
        return self._maybe_ascend(
            tick=decision.tick,
            bandwidth_kbps=bandwidth_kbps,
            confirm_ratio_voice=confirm_ratio_voice,
            loss_rate_ewma=loss_rate_ewma,
        )

    def _descend_to(
        self, target: Rung, reason_code: str, tick: int,
    ) -> Optional[RungTransition]:
        if target == self._current:
            return None
        prev = self._current
        self._current = target
        self._last_descent_tick = tick
        self._stable_since_tick = None
        log.info(
            "presence-compiler descent %s -> %s (%s)",
            prev.name, target.name, reason_code,
        )
        return RungTransition(
            from_rung=prev,
            to_rung=target,
            reason_code=reason_code,
            tick=tick,
        )

    def _maybe_ascend(
        self,
        *,
        tick: int,
        bandwidth_kbps: float,
        confirm_ratio_voice: float,
        loss_rate_ewma: float = 0.0,
    ) -> Optional[RungTransition]:
        # ASYNC_CAPSULE is terminal: never ascend out of it without
        # an explicit resume call.
        if self._current == Rung.ASYNC_CAPSULE:
            return None

        # Loss-rate floor for ascent. While loss is above this floor
        # the call is still in a degraded operating regime (per the
        # Immune System's hysteresis). The Compiler must not race
        # ahead of the Immune System.
        if loss_rate_ewma > self.ASCENT_LOSS_FLOOR:
            self._stable_since_tick = None
            return None

        viable = self.viable_rungs(
            bandwidth_kbps=bandwidth_kbps,
            confirm_ratio_voice=confirm_ratio_voice,
        )
        # Find the highest-fidelity viable rung.
        if not viable:
            return None
        best = min(viable, key=lambda s: int(s.rung))

        if int(best.rung) >= int(self._current):
            # Already at or below the best viable rung — nothing to do.
            self._stable_since_tick = None
            return None

        # Conditions support a higher rung. Has the window elapsed?
        if self._stable_since_tick is None:
            self._stable_since_tick = tick
            return None

        if tick - self._stable_since_tick < self._ascent_hysteresis:
            # Need more stable ticks before rising.
            return None

        # Rise.
        prev = self._current
        self._current = best.rung
        self._stable_since_tick = None
        log.info(
            "presence-compiler ascent %s -> %s (conditions stable)",
            prev.name, best.rung.name,
        )
        return RungTransition(
            from_rung=prev,
            to_rung=best.rung,
            reason_code="ascent_after_stability",
            tick=tick,
        )

    # ── introspection ──────────────────────────────────────────

    @property
    def current_rung(self) -> Rung:
        return self._current

    @property
    def current_rung_spec(self) -> RungSpec:
        return _RUNG_BY_VALUE[self._current]

    def force_rung(self, rung: Rung) -> None:
        """Test-only: force the current rung without going through
        the descent/ascent gates. Production code should never call
        this — Immune System's request() is the only mutator."""
        self._current = rung
        self._stable_since_tick = None
