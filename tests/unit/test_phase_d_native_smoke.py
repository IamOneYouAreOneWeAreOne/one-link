"""Phase D native binding smoke tests.

Exercises the pyo3 bindings for ``ol_routing``, ``ol_prefetch``, and
``ol_homology`` to confirm the Python surface round-trips with the
Rust crates. End-to-end semantics are covered by the Rust unit + property
tests; this file just proves the FFI boundary works.
"""

from __future__ import annotations

import pytest


def _native_available() -> bool:
    try:
        from one_link_native import routing, prefetch, homology  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native Phase D submodules not installed (build via maturin)",
)


# ── ol_routing ────────────────────────────────────────────────────────


def test_routing_edge_cost_smaller_for_higher_tau_c():
    from one_link_native import routing

    short = routing.edge_cost(0.001, 100.0, 0.0)
    long = routing.edge_cost(0.010, 100.0, 0.0)
    assert long < short


def test_routing_loss_penalty_four_at_half_loss():
    from one_link_native import routing

    assert abs(routing.loss_penalty(0.5) - 4.0) < 1e-9


def test_routing_shortest_path_picks_low_loss_route():
    from one_link_native import routing

    g = routing.AdjacencyGraph()
    # Direct A→C with high loss (cost 100).
    g.add_edge("A", "C", routing.edge_cost(0.001, 100.0, 0.95))
    # Indirect A→B→C with low loss (cost 2 × 1).
    g.add_edge("A", "B", routing.edge_cost(0.001, 100.0, 0.0))
    g.add_edge("B", "C", routing.edge_cost(0.001, 100.0, 0.0))
    path, total = g.shortest_path("A", "C")
    assert path == ["A", "B", "C"]
    assert total > 0


def test_routing_byzantine_bounds():
    from one_link_native import routing

    assert routing.max_byzantine_count(4) == 1
    assert routing.max_byzantine_count(100) == 33
    assert routing.quorum_safe(10, 3) is True
    assert routing.quorum_safe(10, 4) is False


def test_routing_tau_corroboration_rejects_lying_peer():
    from one_link_native import routing

    # Peer claims τ_c=1s (very stable) but only 5% success observed.
    assert (
        routing.tau_claim_corroborated(1.0, 0.05, 0.5) is False
    )
    assert (
        routing.tau_claim_corroborated(1.0, 0.95, 0.5) is True
    )


# ── ol_prefetch ───────────────────────────────────────────────────────


def test_prefetch_observe_then_predict():
    from one_link_native import prefetch

    p = prefetch.Predictor()
    peer = b"\x01" * 32
    file_a = b"\xAA" * 32
    file_b = b"\xBB" * 32
    file_c = b"\xCC" * 32

    # Build A→B as the dominant pattern.
    for i in range(20):
        p.observe(peer, file_a, i * 100)
        p.observe(peer, file_b, i * 100 + 10)
        p.observe(peer, file_c, i * 100 + 20)
    # Anchor at A and predict.
    p.observe(peer, file_a, 9999)
    preds = p.predict_top_n(peer, 3)
    assert len(preds) > 0
    fid, conf = preds[0]
    assert fid == file_b
    assert 0.0 < conf <= 1.0


def test_prefetch_cohort_prior_transfer():
    from one_link_native import prefetch

    p = prefetch.Predictor()
    alice = b"\x01" * 32
    bob = b"\x02" * 32
    file_a = b"\xAA" * 32
    file_b = b"\xBB" * 32

    # Alice has a strong A→B pattern.
    for i in range(50):
        p.observe(alice, file_a, i * 100)
        p.observe(alice, file_b, i * 100 + 10)
    # Bob is brand new — transfer Alice's prior at full weight.
    p.transfer_prior_from(alice, bob, 1.0)
    p.observe(bob, file_a, 99999)
    preds = p.predict_top_n(bob, 1)
    assert len(preds) == 1
    assert preds[0][0] == file_b


def test_prefetch_rejects_invalid_decay_factor():
    from one_link_native import prefetch

    with pytest.raises(ValueError):
        prefetch.Predictor(60_000, 1.5)


# ── ol_homology ───────────────────────────────────────────────────────


def test_homology_components_of_single_chunk():
    from one_link_native import homology

    r = homology.components_of(["a"], [])
    assert r.n_components == 1
    assert r.sizes == [1]
    assert r.singletons == ["a"]


def test_homology_components_of_chain():
    from one_link_native import homology

    r = homology.components_of(
        ["a", "b", "c", "d"], [("a", "b"), ("b", "c"), ("c", "d")]
    )
    assert r.n_components == 1
    assert r.sizes == [4]


def test_homology_fragility_score_detects_bridge():
    from one_link_native import homology

    # a — b — c: b is a bridge.
    holders = {"a": 5, "b": 5, "c": 5}
    scores, priority = homology.fragility_score(
        ["a", "b", "c"], [("a", "b"), ("b", "c")], holders
    )
    b_score = next(s for s in scores if s.chunk_id == "b")
    a_score = next(s for s in scores if s.chunk_id == "a")
    assert b_score.is_bridge
    assert not a_score.is_bridge
    assert b_score.score > a_score.score
    assert "b" in priority


def test_homology_fragility_singleton_is_high():
    from one_link_native import homology

    # Single chunk held by 1 peer: maximally fragile.
    holders = {"a": 1}
    scores, priority = homology.fragility_score(["a"], [], holders)
    assert len(scores) == 1
    assert scores[0].score > 0.6
    assert "a" in priority
