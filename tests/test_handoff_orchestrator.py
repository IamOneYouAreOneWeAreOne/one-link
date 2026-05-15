"""Tests for the handoff orchestrator — Route + Body Engine glue.

Verifies the lifecycle: REQUESTED → PREWARMING → MIXING → COMPLETE.
The 200ms acceptance bound (Tier ε) is enforced — at end-of-fade
the secondary is sole producer.
"""

from __future__ import annotations

import pytest

from one_link.crossfade import CrossfadeKind
from one_link.handoff_orchestrator import (
    ActiveHandoff,
    HandoffOrchestrator,
    HandoffPhase,
    HandoffRequest,
    HandoffTick,
)


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def test_start_handoff_emits_requested_tick() -> None:
    orch = HandoffOrchestrator()
    req = HandoffRequest(
        call_id="c1", kind=CrossfadeKind.ROUTE_HANDOFF,
        primary_id="lan-1", secondary_id="relay-2",
    )
    tick = orch.start_handoff(request=req, now_ms=1_000)
    assert tick.phase == HandoffPhase.REQUESTED
    assert tick.sample.gain_old == 1.0
    assert tick.sample.gain_new == 0.0
    assert orch.has_active("c1")


def test_mark_prewarmed_then_tick_advances_to_mixing() -> None:
    orch = HandoffOrchestrator()
    req = HandoffRequest(
        call_id="c1", kind=CrossfadeKind.ROUTE_HANDOFF,
        primary_id="lan-1", secondary_id="relay-2",
    )
    orch.start_handoff(request=req, now_ms=1_000)
    orch.mark_prewarmed("c1")
    # First tick after prewarm — re-anchored at this time → mixing
    # starts with gain_old≈1, gain_new≈0.
    tick = orch.tick("c1", now_ms=1_000)
    assert tick.phase == HandoffPhase.MIXING
    assert tick.sample.gain_old == pytest.approx(1.0, abs=1e-9)


def test_full_handoff_completes_after_duration() -> None:
    orch = HandoffOrchestrator()
    req = HandoffRequest(
        call_id="c1", kind=CrossfadeKind.ROUTE_HANDOFF,
        primary_id="lan-1", secondary_id="relay-2",
        duration_ms=200,
    )
    orch.start_handoff(request=req, now_ms=1_000)
    orch.mark_prewarmed("c1")
    orch.tick("c1", now_ms=1_000)  # anchor
    # Halfway through.
    mid = orch.tick("c1", now_ms=1_100)
    assert mid.phase == HandoffPhase.MIXING
    assert mid.completed is False
    # At-end.
    end = orch.tick("c1", now_ms=1_200)
    assert end.completed is True
    assert end.sample.gain_old == 0.0
    assert end.sample.gain_new == 1.0
    # Orchestrator auto-cleans on completion.
    assert not orch.has_active("c1")


def test_handoff_meets_200ms_acceptance_target() -> None:
    """Tier ε: 'all converge without media gap > 250 ms.' The
    default 200ms duration must be the elapsed time from
    start-of-mixing to fully-new audio."""
    orch = HandoffOrchestrator()
    req = HandoffRequest(
        call_id="c1", kind=CrossfadeKind.ROUTE_HANDOFF,
        primary_id="lan-1", secondary_id="relay-2",
    )
    orch.start_handoff(request=req, now_ms=0)
    orch.mark_prewarmed("c1")
    orch.tick("c1", now_ms=0)
    # At 200ms exactly, the fade is complete.
    final = orch.tick("c1", now_ms=200)
    assert final.completed is True
    assert final.sample.gain_new == 1.0


def test_abort_removes_active_handoff() -> None:
    orch = HandoffOrchestrator()
    req = HandoffRequest(
        call_id="c1", kind=CrossfadeKind.ROUTE_HANDOFF,
        primary_id="lan-1", secondary_id="relay-2",
    )
    orch.start_handoff(request=req, now_ms=0)
    orch.abort("c1")
    assert not orch.has_active("c1")


def test_tick_for_unknown_call_returns_none() -> None:
    orch = HandoffOrchestrator()
    assert orch.tick("ghost", now_ms=0) is None


def test_idempotent_start_returns_existing_tick() -> None:
    """A second start_handoff for the same call_id while one is
    already in flight must not disrupt it."""
    orch = HandoffOrchestrator()
    req1 = HandoffRequest(
        call_id="c1", kind=CrossfadeKind.ROUTE_HANDOFF,
        primary_id="lan-1", secondary_id="relay-2",
    )
    req2 = HandoffRequest(
        call_id="c1", kind=CrossfadeKind.ROUTE_HANDOFF,
        primary_id="lan-1", secondary_id="relay-3",  # different secondary
    )
    orch.start_handoff(request=req1, now_ms=0)
    tick = orch.start_handoff(request=req2, now_ms=0)
    # Still pointing at relay-2 (the first request).
    assert tick.secondary_id == "relay-2"


def test_active_count_tracks_concurrent_handoffs() -> None:
    orch = HandoffOrchestrator()
    for i in range(3):
        req = HandoffRequest(
            call_id=f"c{i}", kind=CrossfadeKind.ROUTE_HANDOFF,
            primary_id="p", secondary_id="s",
        )
        orch.start_handoff(request=req, now_ms=0)
    assert orch.active_count() == 3


# ---------------------------------------------------------------------------
# Device handoff
# ---------------------------------------------------------------------------

def test_device_handoff_uses_device_kind() -> None:
    orch = HandoffOrchestrator()
    req = HandoffRequest(
        call_id="c1", kind=CrossfadeKind.DEVICE_HANDOFF,
        primary_id="laptop", secondary_id="phone",
    )
    orch.start_handoff(request=req, now_ms=0)
    orch.mark_prewarmed("c1")
    tick = orch.tick("c1", now_ms=0)
    assert tick.phase == HandoffPhase.MIXING
    # primary/secondary IDs propagate.
    assert tick.primary_id == "laptop"
    assert tick.secondary_id == "phone"


# ---------------------------------------------------------------------------
# Unknown kind refusal
# ---------------------------------------------------------------------------

def test_unsupported_kind_raises() -> None:
    orch = HandoffOrchestrator()
    # Use an int outside the enum range — IntEnum allows construction
    # via int() but the orchestrator checks specific kinds.
    bogus_kind = 999

    class _FakeRequest:
        call_id = "c1"
        kind = bogus_kind
        primary_id = "p"
        secondary_id = "s"
        duration_ms = 200
        reason = ""
    with pytest.raises(ValueError):
        orch.start_handoff(request=_FakeRequest(), now_ms=0)
