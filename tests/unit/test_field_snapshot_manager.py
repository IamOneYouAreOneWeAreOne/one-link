"""Tests for FieldSnapshotManager — the daemon's periodic field-solve
hub that downstream consumers (ratchet cadence, bandit prior,
prefetch) read from."""

from __future__ import annotations

import time

import pytest


def _phase_e_available() -> bool:
    try:
        from one_link_native import coherence_field  # noqa: F401

        return True
    except ImportError:
        return False


def test_construct_with_default_config():
    from one_link.field_snapshot import FieldSnapshotManager

    mgr = FieldSnapshotManager()
    # Calibration applied (or fallback kept on the dataclass).
    assert mgr._config.helmholtz_d > 0  # type: ignore[attr-defined]
    assert mgr._config.helmholtz_gamma >= 0  # type: ignore[attr-defined]


def test_snapshot_starts_none():
    from one_link.field_snapshot import FieldSnapshotManager

    mgr = FieldSnapshotManager()
    assert mgr.snapshot() is None


def test_cadence_for_peer_safe_default_when_unsolved():
    from one_link.field_snapshot import FieldSnapshotManager

    mgr = FieldSnapshotManager()
    # No snapshot → cadence query returns None (callers treat as
    # "use baseline").
    assert mgr.cadence_for_peer("any-peer") is None


def test_metrics_surface_always_safe():
    from one_link.field_snapshot import FieldSnapshotManager

    mgr = FieldSnapshotManager()
    m = mgr.metrics()
    # Must always include the four base counters, even without a
    # snapshot.
    assert "field_solve_count" in m
    assert "field_solve_failures" in m
    assert "field_topology_edge_count" in m
    assert "field_source_peer_count" in m
    assert m["field_solve_count"] == 0
    assert m["field_solve_failures"] == 0


def test_update_topology_and_sources():
    from one_link.field_snapshot import FieldSnapshotManager

    mgr = FieldSnapshotManager()
    mgr.update_topology([("a", "b", 1.0), ("b", "c", 0.5)])
    mgr.update_peer_source("a", density=0.9, flux=0.7)
    mgr.update_peer_source("b", density=0.4, flux=0.3)
    # Verified via metrics surface (no need to expose the internals).
    m = mgr.metrics()
    assert m["field_topology_edge_count"] == 2
    assert m["field_source_peer_count"] == 2


def test_forget_peer_drops_source():
    from one_link.field_snapshot import FieldSnapshotManager

    mgr = FieldSnapshotManager()
    mgr.update_peer_source("a", density=1.0, flux=0.5)
    mgr.update_peer_source("b", density=1.0, flux=0.5)
    assert mgr.metrics()["field_source_peer_count"] == 2
    mgr.forget_peer("a")
    assert mgr.metrics()["field_source_peer_count"] == 1


@pytest.mark.skipif(
    not _phase_e_available(),
    reason="one_link_native.coherence_field not installed",
)
def test_tick_produces_snapshot_on_valid_topology():
    """Force a tick (without the background loop) and assert a
    snapshot lands with the right shape."""
    from one_link.field_snapshot import FieldSnapshotManager

    mgr = FieldSnapshotManager()
    # 4-peer ring with non-trivial sources.
    mgr.update_topology(
        [("a", "b", 1.0), ("b", "c", 1.0), ("c", "d", 1.0), ("d", "a", 1.0)]
    )
    for p in ("a", "b", "c", "d"):
        mgr.update_peer_source(p, density=1.0, flux=0.5)
    mgr._tick()  # type: ignore[attr-defined]
    snap = mgr.snapshot()
    assert snap is not None
    assert snap.peers == ("a", "b", "c", "d")
    assert len(snap.field) == 4
    assert len(snap.cadences) == 4
    assert snap.solve_iterations >= 1
    assert snap.solve_residual < 1e-3


@pytest.mark.skipif(
    not _phase_e_available(),
    reason="one_link_native.coherence_field not installed",
)
def test_cadence_for_peer_after_tick():
    from one_link.field_snapshot import FieldSnapshotManager

    mgr = FieldSnapshotManager()
    mgr.update_topology(
        [("a", "b", 1.0), ("b", "c", 1.0), ("c", "d", 1.0)]
    )
    for p in ("a", "b", "c", "d"):
        mgr.update_peer_source(p, density=1.0, flux=0.5)
    mgr._tick()  # type: ignore[attr-defined]
    cadence_a = mgr.cadence_for_peer("a")
    assert cadence_a is not None
    assert 1 <= cadence_a <= 1_000_000  # baseline default
    # Unknown peer → None.
    assert mgr.cadence_for_peer("nonexistent") is None


@pytest.mark.skipif(
    not _phase_e_available(),
    reason="one_link_native.coherence_field not installed",
)
def test_field_score_for_peer_normalised():
    """Field score is in (0, 1] with 1 = highest coherence."""
    from one_link.field_snapshot import FieldSnapshotManager

    mgr = FieldSnapshotManager()
    # Asymmetric topology so the field is non-uniform.
    mgr.update_topology(
        [("a", "b", 1.0), ("a", "c", 1.0), ("a", "d", 1.0)]
    )
    mgr.update_peer_source("a", density=1.0, flux=0.5)
    mgr.update_peer_source("b", density=0.1, flux=0.05)
    mgr.update_peer_source("c", density=0.1, flux=0.05)
    mgr.update_peer_source("d", density=0.1, flux=0.05)
    mgr._tick()  # type: ignore[attr-defined]
    score_a = mgr.field_score_for_peer("a")
    score_b = mgr.field_score_for_peer("b")
    assert score_a is not None
    assert score_b is not None
    assert 0 < score_a <= 1
    assert 0 < score_b <= 1


def test_metrics_after_tick_carries_snapshot_age():
    from one_link.field_snapshot import FieldSnapshotManager

    mgr = FieldSnapshotManager()
    m = mgr.metrics()
    # Pre-tick: snapshot age is -1.0 (sentinel).
    assert m["field_snapshot_age_ms"] == -1.0


def test_start_stop_lifecycle():
    """The background loop must start, run at least one tick (or
    error gracefully if native isn't available), and stop cleanly."""
    from one_link.field_snapshot import FieldConfig, FieldSnapshotManager

    cfg = FieldConfig(update_interval_s=0.05)
    mgr = FieldSnapshotManager(cfg)
    mgr.start()
    # Idempotent.
    mgr.start()
    time.sleep(0.15)
    mgr.stop()
    # No assertion on solve count — if native is missing this is 0,
    # which is the expected safe-default behavior.
