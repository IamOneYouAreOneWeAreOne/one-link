"""Phase C-3 daemon migration: transfer_brain.BanditRouteSelector.

Verifies the bandit-backed route selector replacing the EMA route
memory subsystem. Acceptance: bandit converges on a known-best route
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
