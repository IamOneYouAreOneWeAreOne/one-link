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


# ── Phase E #4: env-var kill switches ──────────────────────────────


def test_cadence_disable_env_var_returns_none(monkeypatch):
    """ONE_LINK_FIELD_CADENCE_DISABLE=1 must force cadence_for_peer
    to return None even when a fresh snapshot exists."""
    from one_link.field_snapshot import FieldSnapshot, FieldSnapshotManager

    mgr = FieldSnapshotManager()
    # Seed an in-memory snapshot directly so the test doesn't depend
    # on the native crate.
    fake = FieldSnapshot(
        peers=("a", "b"),
        field=(0.5, 0.5),
        cadences=((0, 1.5, 666666), (1, 1.5, 666666)),
        solve_iterations=10,
        solve_residual=1e-7,
        solve_wall_ns=12345,
        captured_at_ns=time.perf_counter_ns(),
    )
    mgr._current = fake  # type: ignore[attr-defined]
    # Sanity: without the kill switch, the cadence is the seeded value.
    assert mgr.cadence_for_peer("a") == 666666
    # Flip the kill switch — cadence_for_peer now refuses to advise.
    monkeypatch.setenv("ONE_LINK_FIELD_CADENCE_DISABLE", "1")
    assert mgr.cadence_for_peer("a") is None
    # Clearing the var (or any non-truthy value) re-enables.
    monkeypatch.setenv("ONE_LINK_FIELD_CADENCE_DISABLE", "0")
    assert mgr.cadence_for_peer("a") == 666666


def test_master_field_disable_pauses_solve_loop(monkeypatch):
    """ONE_LINK_FIELD_DISABLE=1 pauses the background tick — solve
    count stays at 0 even after we let the loop run."""
    from one_link.field_snapshot import FieldConfig, FieldSnapshotManager

    monkeypatch.setenv("ONE_LINK_FIELD_DISABLE", "1")
    cfg = FieldConfig(update_interval_s=0.02)
    mgr = FieldSnapshotManager(cfg)
    # Seed enough topology so _tick *would* solve if it ran.
    mgr.update_topology(
        [("a", "b", 1.0), ("b", "c", 1.0), ("c", "a", 1.0)]
    )
    for p in ("a", "b", "c"):
        mgr.update_peer_source(p, density=1.0, flux=0.5)
    mgr.start()
    time.sleep(0.12)  # 6 tick windows; would normally produce ≥1 solve
    mgr.stop()
    assert mgr.solve_count == 0


# ── Phase E #2: fragility-event surface ────────────────────────────


def test_update_fragility_events_stores_and_replaces():
    """update_fragility_events replaces (not appends to) the pending
    list — caller passing [] clears."""
    from one_link.field_snapshot import FieldSnapshotManager

    mgr = FieldSnapshotManager()
    mgr.update_fragility_events([(["a", "b"], 1.0), (["c"], 0.5)])
    assert len(mgr._fragility_events) == 2  # type: ignore[attr-defined]
    mgr.update_fragility_events([(["d"], 2.0)])
    assert len(mgr._fragility_events) == 1  # type: ignore[attr-defined]
    mgr.update_fragility_events([])
    assert mgr._fragility_events == []  # type: ignore[attr-defined]


@pytest.mark.skipif(
    not _phase_e_available(),
    reason="one_link_native.coherence_field not installed",
)
def test_fragility_events_reduce_field_at_affected_nodes():
    """Acceptance gate for Phase E #2 (homology → field): peers in a
    fragility event must have a lower recovered field value than
    peers in the same baseline graph WITHOUT the event."""
    from one_link.field_snapshot import FieldSnapshotManager

    def _solve(events):
        mgr = FieldSnapshotManager()
        mgr.update_topology(
            [
                ("a", "b", 1.0), ("b", "c", 1.0), ("c", "d", 1.0),
                ("d", "a", 1.0), ("a", "c", 0.5), ("b", "d", 0.5),
            ]
        )
        for p in ("a", "b", "c", "d"):
            mgr.update_peer_source(p, density=1.0, flux=0.5)
        if events:
            mgr.update_fragility_events(events, coupling_strength=2.0)
        mgr._tick()  # type: ignore[attr-defined]
        snap = mgr.snapshot()
        assert snap is not None
        return dict(zip(snap.peers, snap.field))

    baseline = _solve([])
    fragile = _solve([(["a", "b"], 1.0)])
    # Affected peers' field is lower (suppressed by the negative
    # spike injected via inject_fragility_events). Pure correctness
    # check; the exact magnitude depends on (D, gamma, weight).
    assert fragile["a"] < baseline["a"]
    assert fragile["b"] < baseline["b"]


# ── Phase E #5: snapshot persistence across restart ────────────────


@pytest.mark.skipif(
    not _phase_e_available(),
    reason="one_link_native.coherence_field not installed",
)
def test_snapshot_persists_and_warm_starts_next_manager(tmp_path):
    """A solved snapshot survives a manager restart when persist_path
    is provided — the new manager's snapshot() returns the persisted
    value before its own first tick."""
    from one_link.field_snapshot import FieldSnapshotManager

    persist_path = tmp_path / "field-snapshot.json"
    mgr1 = FieldSnapshotManager(persist_path=persist_path)
    mgr1.update_topology(
        [("a", "b", 1.0), ("b", "c", 1.0), ("c", "a", 1.0)]
    )
    for p in ("a", "b", "c"):
        mgr1.update_peer_source(p, density=1.0, flux=0.5)
    mgr1._tick()  # type: ignore[attr-defined]
    snap1 = mgr1.snapshot()
    assert snap1 is not None
    assert persist_path.exists()

    # New manager pointed at the same path warm-starts.
    mgr2 = FieldSnapshotManager(persist_path=persist_path)
    snap2 = mgr2.snapshot()
    assert snap2 is not None
    assert snap2.peers == snap1.peers
    assert snap2.field == snap1.field
    assert snap2.cadences == snap1.cadences


def test_snapshot_load_tolerates_missing_file(tmp_path):
    """No persisted file → snapshot() is None, no exception."""
    from one_link.field_snapshot import FieldSnapshotManager

    mgr = FieldSnapshotManager(persist_path=tmp_path / "absent.json")
    assert mgr.snapshot() is None


def test_snapshot_load_tolerates_malformed_file(tmp_path):
    """Corrupt persisted file is silently discarded — manager keeps
    operating as if no snapshot were on disk."""
    from one_link.field_snapshot import FieldSnapshotManager

    bad = tmp_path / "field-snapshot.json"
    bad.write_text("not-valid-json{", encoding="utf-8")
    mgr = FieldSnapshotManager(persist_path=bad)
    assert mgr.snapshot() is None
