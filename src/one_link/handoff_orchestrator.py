"""Handoff orchestrator — drives route + device transitions.

Two consumers — Route Brain (path swaps) and Body Engine (device
swaps) — share the same primitive: a 200ms equal-power crossfade
that overlaps two media streams while the listener experiences
constant perceived volume.

This module owns the orchestration:
  - :class:`HandoffOrchestrator` accepts handoff requests.
  - Tracks active handoffs (call_id → :class:`ActiveHandoff`).
  - Emits per-tick gain pairs the caller applies to its actual
    audio buffers (or forwards as JSON to the browser, which
    applies them via Web Audio API gain nodes).
  - Logs each handoff for the audit log.

Pure module: no I/O, no daemon imports. Threading: a single lock
guards the active-handoff map. The orchestrator is tick-driven —
the daemon's existing periodic loop advances it.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.3 + §4.4
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Optional

from one_link.crossfade import (
    DEFAULT_DURATION_MS,
    CrossfadeKind,
    CrossfadePlan,
    CrossfadeSample,
    make_device_handoff,
    make_route_handoff,
)


class HandoffPhase(IntEnum):
    """Lifecycle of one in-flight handoff."""

    REQUESTED = 0   # plan minted; primary still serves audio
    PREWARMING = 1  # secondary stream established; not yet mixing
    MIXING    = 2   # crossfade in progress
    COMPLETE  = 3   # secondary is sole producer; primary may tear down


@dataclass(frozen=True)
class HandoffRequest:
    """Caller's description of the handoff intent."""

    call_id: str
    kind: CrossfadeKind
    # Opaque IDs the caller uses to identify primary + secondary
    # transports. The orchestrator never inspects them; they're
    # passed back via tail events so the browser / Route Brain knows
    # which streams the gains apply to.
    primary_id: str
    secondary_id: str
    duration_ms: int = DEFAULT_DURATION_MS
    # Description for the audit log + user-facing toast (if any).
    reason: str = ""


@dataclass
class ActiveHandoff:
    """Mutable state for an in-flight handoff."""

    request: HandoffRequest
    plan: CrossfadePlan
    phase: HandoffPhase = HandoffPhase.REQUESTED
    elapsed_ms: float = 0.0


@dataclass(frozen=True)
class HandoffTick:
    """One tick output — what the caller should do this tick."""

    call_id: str
    phase: HandoffPhase
    sample: Optional[CrossfadeSample]
    primary_id: str
    secondary_id: str
    completed: bool = False


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class HandoffOrchestrator:
    """One per daemon. Holds all in-flight handoffs across all
    active calls. Thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: dict[str, ActiveHandoff] = {}

    def start_handoff(
        self,
        *,
        request: HandoffRequest,
        now_ms: int,
    ) -> HandoffTick:
        """Begin a handoff. Idempotent: if a handoff is already in
        flight for ``request.call_id``, returns its current tick
        without disrupting it."""
        with self._lock:
            existing = self._active.get(request.call_id)
            if existing is not None:
                return self._tick_locked(existing, now_ms)
            if request.kind == CrossfadeKind.ROUTE_HANDOFF:
                plan = make_route_handoff(
                    started_at_ms=now_ms,
                    duration_ms=request.duration_ms,
                )
            elif request.kind == CrossfadeKind.DEVICE_HANDOFF:
                plan = make_device_handoff(
                    started_at_ms=now_ms,
                    duration_ms=request.duration_ms,
                )
            else:
                raise ValueError(
                    f"unsupported crossfade kind: {request.kind}",
                )
            active = ActiveHandoff(
                request=request,
                plan=plan,
                phase=HandoffPhase.REQUESTED,
            )
            self._active[request.call_id] = active
            return self._tick_locked(active, now_ms)

    def mark_prewarmed(self, call_id: str) -> None:
        """The caller (Route Brain / Body Engine) signals that the
        secondary transport is ready. The orchestrator advances to
        MIXING on the next tick."""
        with self._lock:
            active = self._active.get(call_id)
            if active is None:
                return
            if active.phase == HandoffPhase.REQUESTED:
                self._active[call_id] = replace(
                    active, phase=HandoffPhase.PREWARMING,
                )

    def tick(self, call_id: str, now_ms: int) -> Optional[HandoffTick]:
        """Advance one tick for one call. Returns None if no handoff
        is in flight for this call."""
        with self._lock:
            active = self._active.get(call_id)
            if active is None:
                return None
            return self._tick_locked(active, now_ms)

    def abort(self, call_id: str) -> None:
        """Cancel an in-flight handoff. Caller should roll back the
        secondary transport. The primary stream continues; the
        listener heard nothing unusual."""
        with self._lock:
            self._active.pop(call_id, None)

    def has_active(self, call_id: str) -> bool:
        with self._lock:
            return call_id in self._active

    def active_count(self) -> int:
        with self._lock:
            return len(self._active)

    def _tick_locked(
        self, active: ActiveHandoff, now_ms: int,
    ) -> HandoffTick:
        elapsed = now_ms - active.plan.started_at_ms
        # Phase transitions:
        if active.phase == HandoffPhase.PREWARMING:
            # Begin mixing from now — re-anchor the plan's clock.
            mixing_plan = replace(active.plan, started_at_ms=now_ms)
            active = replace(active, plan=mixing_plan, phase=HandoffPhase.MIXING)
            self._active[active.request.call_id] = active
            elapsed = 0
        if active.phase == HandoffPhase.REQUESTED:
            # Still waiting for prewarm. Primary serves everything.
            return HandoffTick(
                call_id=active.request.call_id,
                phase=active.phase,
                sample=CrossfadeSample(0.0, 1.0, 0.0),
                primary_id=active.request.primary_id,
                secondary_id=active.request.secondary_id,
                completed=False,
            )
        if active.phase == HandoffPhase.MIXING:
            sample = active.plan.gain_at(elapsed)
            if elapsed >= active.plan.duration_ms:
                completed = True
                self._active.pop(active.request.call_id, None)
            else:
                completed = False
            return HandoffTick(
                call_id=active.request.call_id,
                phase=HandoffPhase.COMPLETE if completed else HandoffPhase.MIXING,
                sample=sample,
                primary_id=active.request.primary_id,
                secondary_id=active.request.secondary_id,
                completed=completed,
            )
        # COMPLETE — shouldn't be in the active map; defensive.
        return HandoffTick(
            call_id=active.request.call_id,
            phase=HandoffPhase.COMPLETE,
            sample=CrossfadeSample(float(active.plan.duration_ms), 0.0, 1.0),
            primary_id=active.request.primary_id,
            secondary_id=active.request.secondary_id,
            completed=True,
        )
