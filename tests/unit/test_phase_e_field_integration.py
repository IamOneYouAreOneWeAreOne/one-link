"""Phase E end-to-end integration: build a 50-peer fragile swarm,
solve the Helmholtz field, and exercise every coupling (homology
fragility injection, prefetch priorities, ratchet cadence advisory,
support-phase boundary).

This is the Python-side proof that the full Phase E surface works
through the daemon's adapter layer — not just the Rust crate's
internal tests.
"""

from __future__ import annotations

import pytest


def _phase_e_available() -> bool:
    try:
        from one_link_native import coherence_field  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _phase_e_available(),
    reason="one_link_native.coherence_field not installed",
)


def _build_fragile_swarm(n_total: int = 50, fragile_band: range | None = None):
    """50-peer ring + fragile band: every node in `fragile_band` has
    reduced edge weight, modelling a high-loss / churning sub-region.
    """
    from one_link.coherence_field_native import graph_laplacian

    if fragile_band is None:
        fragile_band = range(20, 30)
    g = graph_laplacian(n_total)
    for i in range(n_total):
        j = (i + 1) % n_total
        # Edges *within* the fragile band have lower weight; edges
        # *crossing into* the band also degraded.
        if i in fragile_band or j in fragile_band:
            g.add_edge(i, j, 0.1)
        else:
            g.add_edge(i, j, 1.0)
    return g


def test_helmholtz_solve_converges_on_fragile_swarm():
    from one_link.coherence_field_native import solve_helmholtz

    n = 50
    g = _build_fragile_swarm(n)
    # Single source at node 0 (outside fragile band).
    source = [0.0] * n
    source[0] = 1.0
    result = solve_helmholtz(g, d=1.0, gamma=0.1, source=source)
    assert result["converged"] is True
    assert result["iterations"] <= 100
    assert result["residual"] < 1e-5
    # Field magnitude near source > field magnitude in fragile band.
    fragile_field = sum(abs(result["field"][i]) for i in range(20, 30)) / 10
    near_source_field = sum(abs(result["field"][i]) for i in range(0, 5)) / 5
    assert near_source_field > fragile_field, (
        f"Field should be larger near source ({near_source_field:.4f}) "
        f"than in fragile band ({fragile_field:.4f})"
    )


def test_fragility_injection_reshapes_field():
    """Homology coupling: injecting fragility events at nodes in the
    band should drive the source vector down at those nodes, which
    in turn lowers the recovered field there."""
    from one_link.coherence_field_native import (
        inject_fragility_events,
        solve_helmholtz,
    )

    n = 50
    g = _build_fragile_swarm(n)
    # Baseline: uniform source.
    source = [1.0] * n
    baseline = solve_helmholtz(g, 1.0, 0.1, source)["field"]
    # Inject 3 fragility events targeting the fragile band.
    events = [
        ([22, 23, 24], 0.8),
        ([25, 26], 0.6),
        ([27, 28, 29], 0.7),
    ]
    new_source, applied = inject_fragility_events(
        source, events, coupling_strength=0.5
    )
    after = solve_helmholtz(g, 1.0, 0.1, new_source)["field"]
    # At least one of the targeted nodes had its field reduced.
    band_baseline = sum(baseline[20:30])
    band_after = sum(after[20:30])
    assert band_after < band_baseline, (
        f"Fragility injection should reduce band field: "
        f"baseline {band_baseline:.4f}, after {band_after:.4f}"
    )
    # Applied penalty is non-empty at the targeted nodes.
    assert sum(applied[22:30]) > 0


def test_prefetch_priorities_rank_high_field_holders_first():
    """Field-driven prefetch coupling: holders with higher local field
    rank ahead of holders in the fragile well."""
    from one_link.coherence_field_native import (
        prefetch_priorities,
        solve_helmholtz,
    )

    n = 50
    g = _build_fragile_swarm(n)
    source = [0.0] * n
    source[0] = 1.0
    field = solve_helmholtz(g, 1.0, 0.1, source)["field"]
    # Pick holders: 3 in fragile band, 3 outside.
    requester = 5
    holders = [22, 25, 28, 40, 41, 42]
    priorities = prefetch_priorities(
        field, requester, holders, route_weight=1.0
    )
    # Top-ranked holder must be one of the outside-band ones.
    top_holder = priorities[0][0]
    assert top_holder in {40, 41, 42}, (
        f"Top prefetch holder should be outside fragile band, got {top_holder}; "
        f"priorities: {priorities}"
    )


def test_rotation_cadence_low_field_peers_rotate_faster():
    """Ratchet coupling: peers in low-coherence wells get smaller
    bytes-between-rotations than peers in stable neighborhoods."""
    from one_link.chunk_ratchet import field_driven_rotation_cadence
    from one_link.coherence_field_native import solve_helmholtz

    n = 50
    g = _build_fragile_swarm(n)
    source = [0.0] * n
    source[0] = 1.0
    field = solve_helmholtz(g, 1.0, 0.1, source)["field"]
    cadences = field_driven_rotation_cadence(
        field, baseline_bytes=1_000_000, mu_max=4.0, power=2.0
    )
    # Convert to {peer: bytes_between} dict.
    btw = {peer: bytes_btw for peer, _mult, bytes_btw in cadences}
    # Fragile-band peer should have smaller bytes-between than a
    # peer near the source (high field).
    band_btw = btw[25]
    near_source_btw = btw[2]
    assert band_btw <= near_source_btw, (
        f"Fragile peer (25) should rotate at least as often as near-source "
        f"peer (2): band {band_btw}, near {near_source_btw}"
    )
    # All values within sane range.
    assert all(1 <= b <= 1_000_000 for _, _, b in cadences)


def test_identity_dual_source_with_phase_modulates_edge_peers():
    """Boundary kernel coupling: applying the support-phase kernel
    to the dual source should sign-flip edge peers."""
    from one_link.coherence_field_native import identity_dual_source_with_phase

    n = 8
    density = [1.0] * n
    flux = [0.5] * n
    # Linear ramp of cumulative support from core to edge.
    c_support = [i / (n - 1) for i in range(n)]
    source = identity_dual_source_with_phase(
        density, flux, c_support, alpha=0.5, beta=0.5
    )
    # Core (low c_support) → positive source.
    assert source[0] > 0
    # Edge (high c_support, past c0 = 0.80) → negative source.
    assert source[-1] < 0


def test_calibration_apparent_horizon_anchors_scale_correctly():
    """Cross-domain unity: g_A from One Link / OneField / BioMesh
    calibrations should span many orders of magnitude. Verifies the
    field algebra is shared but per-domain anchors stay distinct."""
    from one_link.coherence_field_native import _native_field

    ol = _native_field.one_link_calibration()
    of = _native_field.one_field_calibration()
    bm = _native_field.bio_mesh_calibration()
    anchors = [
        ol["apparent_horizon_anchor"],
        of["apparent_horizon_anchor"],
        bm["apparent_horizon_anchor"],
    ]
    # All positive + finite.
    assert all(a > 0 and a != float("inf") for a in anchors)
    # Range spans at least 100×.
    assert max(anchors) / min(anchors) > 100


def test_full_phase_e_loop_end_to_end():
    """The whole Phase E flow in one test:
        1. Build a fragile swarm
        2. Solve the Helmholtz field
        3. Inject fragility events → re-solve
        4. Derive prefetch priorities + ratchet cadences from the field
        5. Verify all couplings produce sensible outputs
    """
    from one_link.chunk_ratchet import field_driven_rotation_cadence
    from one_link.coherence_field_native import (
        identity_dual_source_with_phase,
        inject_fragility_events,
        prefetch_priorities,
        solve_helmholtz,
    )

    n = 50
    g = _build_fragile_swarm(n)
    # Step 1: production source via dual + phase kernel.
    density = [1.0 if i not in range(20, 30) else 0.3 for i in range(n)]
    flux = [0.5] * n
    c_support = [i / (n - 1) for i in range(n)]
    source = identity_dual_source_with_phase(density, flux, c_support)

    # Step 2: solve.
    result = solve_helmholtz(g, 1.0, 0.1, source)
    assert result["converged"]
    field = result["field"]

    # Step 3: inject fragility events from a "homology detector"
    # (simulated here as known band-internal cycles).
    events = [([22, 25, 28], 0.7)]
    new_source, _ = inject_fragility_events(
        source, events, coupling_strength=0.3
    )
    result2 = solve_helmholtz(g, 1.0, 0.1, new_source)
    assert result2["converged"]
    field2 = result2["field"]

    # Step 4: derive couplings from the updated field.
    cadences = field_driven_rotation_cadence(field2)
    assert len(cadences) == n
    holders = list(range(10, 20)) + list(range(40, 50))
    priorities = prefetch_priorities(field2, requester=0, holders=holders)
    assert len(priorities) == len(holders)

    # Step 5: invariants.
    # All cadences in valid range.
    for peer, mult, btw in cadences:
        assert 0 <= peer < n
        assert 1.0 <= mult <= 4.0
        assert 1 <= btw <= 1_000_000
    # All priorities sorted by cost.
    costs = [p[2] for p in priorities]
    assert costs == sorted(costs)
