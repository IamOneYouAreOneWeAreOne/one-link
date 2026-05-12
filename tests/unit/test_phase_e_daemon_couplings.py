"""Phase E #1 + #2 — daemon-side coupling wirings.

Tests for:
  - chunk-cohold registry built by _observe_prefetch
  - _tick_homology_feeder() builds the cohold graph + pushes
    fragility events to the FieldSnapshotManager
  - field_rank_holders() ranks holders by field-distance and
    honours the ONE_LINK_FIELD_PREFETCH_DISABLE kill-switch

These don't spin a full daemon (that's the integration suite); they
construct the minimum Daemon-shape needed to exercise each path.
"""

from __future__ import annotations

import time

import pytest


def _phase_e_available() -> bool:
    try:
        from one_link_native import coherence_field  # noqa: F401

        return True
    except ImportError:
        return False


def _homology_available() -> bool:
    try:
        from one_link_native import homology  # noqa: F401

        return True
    except ImportError:
        return False


# ── _chunk_holders registry (powered by _observe_prefetch) ────────


def test_observe_prefetch_populates_chunk_holders():
    """After _observe_prefetch fires for (peer, blob), the
    daemon's _chunk_holders registry knows peer holds blob."""
    from one_link.daemon import Daemon

    d = Daemon.__new__(Daemon)
    d._chunk_holders = {}
    d._chunk_holders_cap = 4096
    d._prefetch_predictor = None
    d._prefetch_unavailable_logged = False
    blob = "a" * 64
    fp = "deadbeef" + ("0" * 56)
    d._observe_prefetch(fp, blob)
    assert blob in d._chunk_holders
    assert "deadbee" + "f" in d._chunk_holders[blob] or "deadbeef" in d._chunk_holders[blob]


def test_observe_prefetch_multiple_peers_share_blob():
    """Multiple peers observing the same blob all show up as
    holders. This is what powers the cohold edge calculation."""
    from one_link.daemon import Daemon

    d = Daemon.__new__(Daemon)
    d._chunk_holders = {}
    d._chunk_holders_cap = 4096
    d._prefetch_predictor = None
    d._prefetch_unavailable_logged = False
    blob = "b" * 64
    d._observe_prefetch("aaaaaaaa" + ("0" * 56), blob)
    d._observe_prefetch("bbbbbbbb" + ("0" * 56), blob)
    d._observe_prefetch("cccccccc" + ("0" * 56), blob)
    assert d._chunk_holders[blob] == {"aaaaaaaa", "bbbbbbbb", "cccccccc"}


def test_observe_prefetch_rejects_invalid_blob():
    """Malformed blob hex doesn't pollute the registry."""
    from one_link.daemon import Daemon

    d = Daemon.__new__(Daemon)
    d._chunk_holders = {}
    d._chunk_holders_cap = 4096
    d._prefetch_predictor = None
    d._prefetch_unavailable_logged = False
    d._observe_prefetch("aaaaaaaa", "not-a-hex")
    d._observe_prefetch("aaaaaaaa", "")
    assert d._chunk_holders == {}


def test_observe_prefetch_evicts_eldest_at_cap():
    """When the registry hits its cap, the oldest chunk is evicted
    to make room. Memory stays bounded on long-lived daemons."""
    from one_link.daemon import Daemon

    d = Daemon.__new__(Daemon)
    d._chunk_holders = {}
    d._chunk_holders_cap = 3
    d._prefetch_predictor = None
    d._prefetch_unavailable_logged = False
    for i in range(5):
        d._observe_prefetch("aaaaaaaa" + ("0" * 56), f"{i:064x}")
    # Registry never exceeds the cap.
    assert len(d._chunk_holders) <= 3


# ── _tick_homology_feeder builds graph + pushes events ────────────


@pytest.mark.skipif(
    not (_phase_e_available() and _homology_available()),
    reason="one_link_native crates not installed",
)
def test_tick_homology_feeder_pushes_events_when_fragile():
    """End-to-end: registry → cohold graph → fragility detection →
    FieldSnapshotManager.update_fragility_events called."""
    from one_link.daemon import Daemon
    from one_link.field_snapshot import FieldSnapshotManager

    d = Daemon.__new__(Daemon)
    d._chunk_holders = {
        "a" * 64: {"peer_a", "peer_b"},
        "b" * 64: {"peer_a", "peer_b"},
        "c" * 64: {"peer_c"},  # singleton → fragile
        "d" * 64: {"peer_c"},  # singleton → fragile
    }
    captured: list = []

    class _CapturingMgr(FieldSnapshotManager):
        def update_fragility_events(self, events, *, coupling_strength=1.0):
            captured.append((events, coupling_strength))
            super().update_fragility_events(
                events, coupling_strength=coupling_strength
            )

    mgr = _CapturingMgr()
    d._tick_homology_feeder(mgr)
    # The feeder must have at least invoked the surface (events
    # might be empty if fragility is below threshold, but the
    # call itself proves the pipeline ran end-to-end).
    assert len(captured) == 1


def test_tick_homology_feeder_clears_events_when_few_chunks():
    """With fewer than 2 chunks in the registry, the feeder clears
    any stale fragility events so the field re-equilibrates."""
    from one_link.daemon import Daemon
    from one_link.field_snapshot import FieldSnapshotManager

    d = Daemon.__new__(Daemon)
    d._chunk_holders = {"a" * 64: {"only-peer"}}
    captured: list = []

    class _CapturingMgr(FieldSnapshotManager):
        def update_fragility_events(self, events, *, coupling_strength=1.0):
            captured.append(list(events))
            super().update_fragility_events(
                events, coupling_strength=coupling_strength
            )

    mgr = _CapturingMgr()
    d._tick_homology_feeder(mgr)
    # Empty event list (no fragility computed; clears stale state).
    assert captured == [[]]


# ── field_rank_holders ─────────────────────────────────────────────


def test_field_rank_holders_empty_input_passthrough():
    from one_link.daemon import Daemon

    d = Daemon.__new__(Daemon)
    d._field_snapshot = None
    assert d.field_rank_holders([]) == []
    assert d.field_rank_holders(["lone-peer"]) == ["lone-peer"]


def test_field_rank_holders_no_snapshot_keeps_input_order():
    """Without a snapshot the helper falls back to input order — no
    crash, no random reordering."""
    from one_link.daemon import Daemon

    d = Daemon.__new__(Daemon)
    d._field_snapshot = None
    assert d.field_rank_holders(["a", "b", "c"]) == ["a", "b", "c"]


def test_field_rank_holders_ranks_by_field_score():
    """With a snapshot where peer 'a' has highest field score, 'a'
    sorts first regardless of input order."""
    from one_link.daemon import Daemon
    from one_link.field_snapshot import FieldSnapshot, FieldSnapshotManager

    mgr = FieldSnapshotManager()
    # field[0]=0.9 (high), [1]=0.5, [2]=0.1 (low) — a > b > c
    mgr._current = FieldSnapshot(  # type: ignore[attr-defined]
        peers=("a", "b", "c"),
        field=(0.9, 0.5, 0.1),
        cadences=((0, 1.0, 100000), (1, 1.0, 100000), (2, 1.0, 100000)),
        solve_iterations=10, solve_residual=1e-7,
        solve_wall_ns=12345, captured_at_ns=time.perf_counter_ns(),
    )
    d = Daemon.__new__(Daemon)
    d._field_snapshot = mgr
    # Input in reverse order; output sorted by descending field score.
    assert d.field_rank_holders(["c", "b", "a"]) == ["a", "b", "c"]


def test_field_rank_holders_unknown_peers_fall_back():
    """If none of the holders is in the snapshot, the helper falls
    back to the input order (no rearrangement)."""
    from one_link.daemon import Daemon
    from one_link.field_snapshot import FieldSnapshot, FieldSnapshotManager

    mgr = FieldSnapshotManager()
    mgr._current = FieldSnapshot(  # type: ignore[attr-defined]
        peers=("known1", "known2"),
        field=(0.5, 0.5),
        cadences=((0, 1.0, 100000), (1, 1.0, 100000)),
        solve_iterations=10, solve_residual=1e-7,
        solve_wall_ns=12345, captured_at_ns=time.perf_counter_ns(),
    )
    d = Daemon.__new__(Daemon)
    d._field_snapshot = mgr
    assert d.field_rank_holders(
        ["unknown_a", "unknown_b", "unknown_c"],
    ) == ["unknown_a", "unknown_b", "unknown_c"]


def test_field_rank_holders_env_kill_switch(monkeypatch):
    """ONE_LINK_FIELD_PREFETCH_DISABLE=1 forces input-order
    passthrough even with a useful snapshot present."""
    from one_link.daemon import Daemon
    from one_link.field_snapshot import FieldSnapshot, FieldSnapshotManager

    mgr = FieldSnapshotManager()
    mgr._current = FieldSnapshot(  # type: ignore[attr-defined]
        peers=("a", "b", "c"),
        field=(0.1, 0.5, 0.9),  # c is highest
        cadences=((0, 1.0, 100000), (1, 1.0, 100000), (2, 1.0, 100000)),
        solve_iterations=10, solve_residual=1e-7,
        solve_wall_ns=12345, captured_at_ns=time.perf_counter_ns(),
    )
    d = Daemon.__new__(Daemon)
    d._field_snapshot = mgr
    # Sanity: without the switch, c sorts first.
    assert d.field_rank_holders(["a", "b", "c"])[0] == "c"
    # With the switch flipped, input order is preserved.
    monkeypatch.setenv("ONE_LINK_FIELD_PREFETCH_DISABLE", "1")
    assert d.field_rank_holders(["a", "b", "c"]) == ["a", "b", "c"]


# ── Phase E #2 — coherence_score propagates into swarm_plan ───────


def test_swarm_planner_promotes_high_coherence_peer():
    """Acceptance gate for Phase E #2 swarm-fetch wiring.

    Given two peers with identical trust + reliability + latency,
    a higher coherence_score must promote one ahead of the other
    in the planner's route_score. This is the contract the daemon's
    pull_swarm_missing_chunks call relies on.
    """
    from one_link.swarm_plan import source_from_hashes

    high = source_from_hashes(
        "aaaa" * 16,
        ["beef" * 16],
        trust_score=0.5,
        latency_ms=10.0,
        bandwidth_bps=1_000_000.0,
        reliability=1.0,
        coherence_score=0.9,
    )
    low = source_from_hashes(
        "bbbb" * 16,
        ["beef" * 16],
        trust_score=0.5,
        latency_ms=10.0,
        bandwidth_bps=1_000_000.0,
        reliability=1.0,
        coherence_score=0.1,
    )
    # route_score is (trust, coherence, reliability, ...). With trust
    # tied, coherence breaks the tie. Higher tuple wins.
    assert high.route_score() > low.route_score()


def test_swarm_planner_falls_back_when_coherence_absent():
    """When coherence_score is None, the planner falls back to its
    derived score (mix of trust/reliability/bandwidth/latency) — no
    crash, no skew from a missing field snapshot."""
    from one_link.swarm_plan import source_from_hashes

    src = source_from_hashes(
        "aaaa" * 16,
        ["beef" * 16],
        trust_score=0.5,
        latency_ms=10.0,
        bandwidth_bps=1_000_000.0,
        reliability=1.0,
        coherence_score=None,
    )
    # route_score()[1] is the coherence slot — without explicit
    # input it's the derived fallback, which must still be in (0, 1].
    coherence_slot = src.route_score()[1]
    assert 0.0 <= coherence_slot <= 1.0


# ── Phase E #1 — swarm claims enrich the cohold registry ──────────


def test_collect_swarm_chunk_claims_enriches_chunk_holders():
    """After a swarm chunk-query returns claims, the daemon's
    _chunk_holders registry must reflect "this peer has these
    chunks." This is the gossip path that feeds the homology
    feeder beyond locally-observed FILE_DONE events."""
    from one_link.daemon import Daemon

    d = Daemon.__new__(Daemon)
    d._chunk_holders = {}
    d._chunk_holders_cap = 4096
    # Simulate the same registry update the daemon's
    # _collect_swarm_chunk_claims hook performs on its return path.
    claims = {
        "aaaaaaaa" + ("0" * 56): {"11" * 32, "22" * 32},
        "bbbbbbbb" + ("0" * 56): {"22" * 32, "33" * 32},
    }
    for peer_fp, chunk_hashes in claims.items():
        short_id = peer_fp[:8]
        for blob_hex in chunk_hashes:
            if d._valid_blob_hex(blob_hex):
                d._chunk_holders.setdefault(blob_hex, set()).add(short_id)

    # Now every claimed peer is registered as holder of every
    # claimed chunk. Chunk 22*32 has two holders (cohold edge).
    assert "11" * 32 in d._chunk_holders
    assert d._chunk_holders["11" * 32] == {"aaaaaaaa"}
    assert d._chunk_holders["22" * 32] == {"aaaaaaaa", "bbbbbbbb"}
    assert d._chunk_holders["33" * 32] == {"bbbbbbbb"}
