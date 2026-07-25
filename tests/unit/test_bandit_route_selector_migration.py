"""Phase C-3 daemon migration: transfer_brain.BanditRouteSelector.

Verifies the bandit-backed route selector replacing EMA ranking on the
route-choice axis. Acceptance: bandit converges on a known-best route
within ~200 interactions (consistent with the Phase C acceptance gate
for ol_bandit).
"""

from __future__ import annotations

import pytest


def _native_available() -> bool:
    try:
        from one_link import bandit_native

        return bandit_native.HAS_NATIVE
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.bandit not installed (build via maturin)",
)


def test_bandit_selector_distinct_arms():
    from one_link.transfer_brain import BanditRouteSelector

    sel = BanditRouteSelector(("lan", "wan", "relay"), seed=42)
    assert sel.routes == ("lan", "wan", "relay")
    pick = sel.select_route()
    assert pick in sel.routes


def test_bandit_selector_records_and_updates_arms():
    from one_link.transfer_brain import BanditRouteSelector

    sel = BanditRouteSelector(("lan", "wan"), seed=1)
    sel.record_outcome("lan", bandwidth_bps=500_000_000, success=True)
    sel.record_outcome("wan", bandwidth_bps=10_000_000, success=False)
    stats = dict((r, (a, b)) for r, a, b in sel.arm_stats())
    # lan got a reward, wan got a failure → distinct posterior shapes.
    assert stats["lan"][0] > stats["wan"][0]


def test_bandit_selector_converges_to_known_best_route():
    """Plan acceptance gate for ol_bandit: convergence within ~200
    interactions. Seed three routes with known reward distributions
    (lan=fast, wan=slow, relay=mid); after 200 simulated transfers
    the best-arm method must return 'lan'."""
    from one_link.transfer_brain import BanditRouteSelector

    sel = BanditRouteSelector(("lan", "wan", "relay"), seed=0xCAFE)
    # Pretend the true mean throughputs are:
    #   lan   = 800 Mbps (reward ~0.8)
    #   wan   = 100 Mbps (reward ~0.1)
    #   relay = 400 Mbps (reward ~0.4)
    truth_bps = {
        "lan": 800_000_000,
        "wan": 100_000_000,
        "relay": 400_000_000,
    }
    for _ in range(200):
        route = sel.select_route()
        sel.record_outcome(route, bandwidth_bps=truth_bps[route], success=True)
    assert sel.best_route() == "lan", (
        f"bandit failed to converge — picked {sel.best_route()}; stats={sel.arm_stats()}"
    )


def test_bandit_selector_rejects_unknown_route():
    from one_link.transfer_brain import BanditRouteSelector

    sel = BanditRouteSelector(("lan",), seed=1)
    with pytest.raises(KeyError):
        sel.record_outcome("ghost", bandwidth_bps=1_000_000, success=True)


def test_bandit_selector_requires_nonempty_routes():
    from one_link.transfer_brain import BanditRouteSelector

    with pytest.raises(ValueError):
        BanditRouteSelector((), seed=0)


# ── Phase C-3 (ADR-0027): bandit cutover into AdaptiveTransferBrain.decide() ──


def test_decide_uses_bandit_route_when_initialized():
    """Once the brain has observed traffic and built its bandit, decide()
    must restrict candidate_routes to the bandit's Thompson-sampled
    pick (per stress-test #3: bandit replaces EMA route ranking)."""
    import os

    from one_link.transfer_brain import (
        AdaptiveTransferBrain,
        TransferRouteObservation,
    )

    saved = os.environ.pop("ONE_LINK_BANDIT_ROUTE_PICKER", None)
    try:
        brain = AdaptiveTransferBrain()
        # Seed both arms with biased observations so the bandit
        # converges on "lan".
        for _ in range(200):
            brain.observe(
                TransferRouteObservation(route="lan", ok=True, bandwidth_bps=8e8)
            )
            brain.observe(
                TransferRouteObservation(route="wan", ok=True, bandwidth_bps=1e7)
            )
        assert brain.best_route_bandit() == "lan"
        # Call decide() across many trials — over enough Thompson
        # samples the bandit overwhelmingly picks "lan". Confirm the
        # decision's selected route is among the candidate set.
        picks = []
        for _ in range(50):
            d = brain.decide(
                size_bytes=10 * 1024 * 1024,
                supports_cdc=True,
                routes=("lan", "wan"),
            )
            picks.append(d.selected.route)
        # With 200 strongly-biased observations toward lan, the
        # bandit's Thompson sample should pick lan most of the time.
        # We accept a small fraction of wan picks (exploration).
        lan_share = picks.count("lan") / len(picks)
        assert lan_share >= 0.8, f"bandit pick lan share: {lan_share}"
    finally:
        if saved is not None:
            os.environ["ONE_LINK_BANDIT_ROUTE_PICKER"] = saved


def test_decide_falls_back_to_pareto_when_bandit_disabled():
    """ONE_LINK_BANDIT_ROUTE_PICKER=0 rolls back to legacy multi-route
    Pareto search — used during production incidents."""
    import os

    from one_link.transfer_brain import (
        AdaptiveTransferBrain,
        TransferRouteObservation,
    )

    saved = os.environ.get("ONE_LINK_BANDIT_ROUTE_PICKER")
    try:
        os.environ["ONE_LINK_BANDIT_ROUTE_PICKER"] = "0"
        brain = AdaptiveTransferBrain()
        # Same biased observations — but the env flag disables
        # bandit-driven route selection.
        for _ in range(200):
            brain.observe(
                TransferRouteObservation(route="lan", ok=True, bandwidth_bps=8e8)
            )
            brain.observe(
                TransferRouteObservation(route="wan", ok=True, bandwidth_bps=1e7)
            )
        # decide() should now consider BOTH routes via the EMA-driven
        # Pareto path — we can't predict which it picks without
        # replicating cost math, so we just assert it picks SOME route
        # from the candidate set + the call doesn't blow up.
        d = brain.decide(
            size_bytes=10 * 1024 * 1024,
            supports_cdc=True,
            routes=("lan", "wan"),
        )
        assert d.selected.route in {"lan", "wan"}
    finally:
        if saved is None:
            os.environ.pop("ONE_LINK_BANDIT_ROUTE_PICKER", None)
        else:
            os.environ["ONE_LINK_BANDIT_ROUTE_PICKER"] = saved


def test_decide_handles_single_route_with_bandit():
    """With only one candidate route, the bandit narrowing is a no-op
    (no choice to make). Single-route case must still produce a
    decision."""
    from one_link.transfer_brain import (
        AdaptiveTransferBrain,
        TransferRouteObservation,
    )

    brain = AdaptiveTransferBrain()
    brain.observe(
        TransferRouteObservation(route="lan", ok=True, bandwidth_bps=1e9)
    )
    d = brain.decide(
        size_bytes=1 * 1024 * 1024,
        supports_cdc=False,
        routes=("lan",),
    )
    assert d.selected.route == "lan"


def test_decide_without_bandit_observations_uses_pareto():
    """A fresh brain (no observe() calls) has no bandit yet. decide()
    must work + pick from the candidate routes via the existing
    multi-route Pareto path."""
    from one_link.transfer_brain import AdaptiveTransferBrain

    brain = AdaptiveTransferBrain()
    # Bandit isn't initialized until observe() is called.
    assert brain.best_route_bandit() is None
    d = brain.decide(
        size_bytes=512 * 1024,
        supports_cdc=False,
        routes=("lan", "wan"),
    )
    assert d.selected.route in {"lan", "wan"}
