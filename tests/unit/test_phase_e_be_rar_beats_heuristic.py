"""Phase E relay-routing physical-correctness tests.

This is the in-process "multi-daemon simulation" version of the Phase
E acceptance gate. It builds 5+ simulated relay candidates with
controlled RTT + loss distributions and verifies that the BE-RAR
scorer (driving `_pick_best_relay` when ``ol_coherence_field`` is
available) makes physically sensible picks.

The BE-RAR shape ``nu(y) = 1/(1 − exp(−√y))`` is the same function
that drives galaxy rotation-curve fitting in the S_One canonical
theorem stack. Mapped onto network loss via ``y = (1 − loss)/loss``,
it produces a *smoother* penalty than the heuristic ``1/(1 − loss)²``:
moderate loss is not crushed, but extreme loss still diverges. That
softer asymptote is the design choice — it lets BE-RAR rank near-tie
cases by RTT (the only remaining axis) instead of being dominated by
a runaway loss term.
"""

from __future__ import annotations

import random
from collections import Counter

import pytest


def _phase_e_available() -> bool:
    try:
        from one_link_native import coherence_field, routing  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _phase_e_available(),
    reason="Phase E native crates not installed",
)


class _Relay:
    """Mock relay with a stable rendezvous URL for the picker to key on."""

    def __init__(self, url: str) -> None:
        self._rendezvous_url = url

    def __repr__(self) -> str:
        return f"_Relay({self._rendezvous_url})"


class _DaemonStub:
    """Minimal daemon shape that satisfies _pick_best_relay's
    expectations: a `_relay_metrics` dict and `_relay_metrics_for`
    method."""

    def __init__(self) -> None:
        self._relay_metrics: dict = {}

    def _relay_metrics_for(self, url: str):
        return self._relay_metrics.get(url)


def _populate(stub: _DaemonStub, url: str, *, rtt_ms: float, loss: float) -> None:
    """Direct-injection: set steady-state metrics without going through
    record_relay_observation's EWMA. The EWMA converges in ~20
    observations; for a controlled experiment we want the post-convergence
    state immediately."""
    stub._relay_metrics[url] = {
        "rtt_ms": rtt_ms,
        "loss_rate": loss,
        "n_attempts": 100,
        "n_successes": int(100 * (1 - loss)),
        "last_observed_ms": 0,
    }


def _expected_best_be_rar(metrics_per_url: dict[str, dict]) -> str:
    """The ground-truth best relay UNDER BE-RAR's own cost function.
    Computes ``rtt × nu(y_quality)`` where ``y_quality = (1-loss)/loss``,
    independently from the daemon's picker, and returns the url that
    minimizes it. Tests assert the picker agrees with this."""
    import math

    def nu(y: float) -> float:
        if y <= 0:
            return float("inf")
        return 1.0 / (1.0 - math.exp(-math.sqrt(y)))

    best_url = None
    best_cost = float("inf")
    for url, m in metrics_per_url.items():
        loss = min(max(m["loss_rate"], 1e-6), 1.0 - 1e-6)
        y_quality = (1.0 - loss) / loss
        cost = m["rtt_ms"] * nu(y_quality)
        if cost < best_cost:
            best_url = url
            best_cost = cost
    assert best_url is not None
    return best_url


def _adversarial_topology(seed: int, n_relays: int = 5) -> dict[str, dict]:
    """Build a loss-matrix where one relay is clearly best (lowest
    cost), several others are close-second, and one is a clear loser.
    The "close-second" relays are where BE-RAR's softer asymptote
    matters: heuristic 1/(1-loss)^2 can over-penalise small loss
    differences."""
    rng = random.Random(seed)
    out = {}
    # One clearly-best relay (low RTT + low loss).
    out[f"r{seed}_best"] = {
        "rtt_ms": 20.0 + rng.random() * 10,
        "loss_rate": rng.uniform(0.0, 0.05),
    }
    # Close-second relays (RTT slightly higher, loss similar).
    for k in range(n_relays - 2):
        out[f"r{seed}_close_{k}"] = {
            "rtt_ms": 30.0 + rng.random() * 20,
            "loss_rate": rng.uniform(0.02, 0.10),
        }
    # One clear loser (high RTT + high loss).
    out[f"r{seed}_bad"] = {
        "rtt_ms": 200.0 + rng.random() * 100,
        "loss_rate": rng.uniform(0.30, 0.60),
    }
    return out


def _run_pick(topology: dict[str, dict]):
    """Run _pick_best_relay against a synthetic topology, returning
    the chosen relay's url. The daemon module unconditionally tries to
    import coherence_field_native at the top of _pick_best_relay, so
    BE-RAR mode is auto-enabled when the crate is installed."""
    from one_link.daemon import Daemon

    stub = _DaemonStub()
    for url, m in topology.items():
        _populate(stub, url, rtt_ms=m["rtt_ms"], loss=m["loss_rate"])
    relays = [_Relay(url) for url in topology]
    ordered = Daemon._pick_best_relay(stub, relays)  # type: ignore[arg-type]
    return ordered[0]._rendezvous_url


def test_be_rar_picks_best_relay_on_clear_winner():
    """Easy case: one relay is clearly best by BE-RAR's cost.
    The picker must agree with the independent BE-RAR ground truth."""
    topology = {
        "good": {"rtt_ms": 20.0, "loss_rate": 0.01},
        "ok": {"rtt_ms": 100.0, "loss_rate": 0.10},
        "bad": {"rtt_ms": 500.0, "loss_rate": 0.50},
    }
    expected = _expected_best_be_rar(topology)
    chosen = _run_pick(topology)
    assert chosen == expected


def test_be_rar_picks_best_relay_under_close_ties():
    """Across 100 adversarial topologies the daemon's picker must
    match the independent BE-RAR ground-truth scorer 100% — both run
    the same math, so any disagreement is an implementation bug."""
    n_trials = 100
    agreements = 0
    for seed in range(n_trials):
        topology = _adversarial_topology(seed)
        expected = _expected_best_be_rar(topology)
        chosen = _run_pick(topology)
        if chosen == expected:
            agreements += 1
    assert agreements == n_trials, (
        f"daemon picker disagreed with BE-RAR ground truth on "
        f"{n_trials - agreements}/{n_trials} topologies (expected 0)"
    )


def test_be_rar_avoids_lossy_when_rtt_disadvantage_is_unfavourable():
    """BE-RAR must reject a lossy relay when its RTT is no better
    than (or worse than) a clean alternative. The harder case —
    "lossy with much lower RTT beats clean with high RTT" — IS
    allowed; that's the design choice of the softer BE-RAR asymptote.
    """
    rng = random.Random(0)
    picks_lossy = 0
    for _ in range(200):
        # Lossy is at least as slow as safe — no RTT advantage to
        # outweigh the loss penalty.
        safe_rtt = rng.uniform(30, 50)
        lossy_rtt = rng.uniform(safe_rtt, safe_rtt + 50)
        topology = {
            "safe": {"rtt_ms": safe_rtt, "loss_rate": rng.uniform(0.0, 0.05)},
            "lossy": {"rtt_ms": lossy_rtt, "loss_rate": rng.uniform(0.50, 0.80)},
        }
        chosen = _run_pick(topology)
        if chosen == "lossy":
            picks_lossy += 1
    assert picks_lossy == 0, (
        f"BE-RAR picked lossy {picks_lossy}/200 times when lossy had no "
        "RTT advantage — must always prefer safe in this regime"
    )


def test_be_rar_picks_low_rtt_when_loss_is_equal():
    """When two relays have identical loss but different RTT, the
    BE-RAR scorer must pick the lower-RTT one (the only remaining
    distinguishing axis)."""
    for trial in range(50):
        rng = random.Random(trial)
        loss = rng.uniform(0.0, 0.10)
        rtt_a = 20.0
        rtt_b = 100.0
        topology = {
            "fast": {"rtt_ms": rtt_a, "loss_rate": loss},
            "slow": {"rtt_ms": rtt_b, "loss_rate": loss},
        }
        chosen = _run_pick(topology)
        assert chosen == "fast", (
            f"trial {trial}: expected 'fast', got {chosen!r} "
            f"(loss={loss:.3f}, rtt_fast={rtt_a}, rtt_slow={rtt_b})"
        )


def test_be_rar_invariant_pure_passthrough_when_metrics_missing():
    """With no metrics recorded, _pick_best_relay must preserve input
    order (every relay gets the default 1.0 cost — stable sort)."""
    from one_link.daemon import Daemon

    class _NoMetrics:
        def _relay_metrics_for(self, _url):
            return None

    urls = ["a", "b", "c", "d", "e"]
    relays = [_Relay(u) for u in urls]
    out = Daemon._pick_best_relay(_NoMetrics(), relays)  # type: ignore[arg-type]
    assert [r._rendezvous_url for r in out] == urls


def test_be_rar_statistical_agreement_with_ground_truth_at_scale():
    """Run 1000 random topologies. The daemon's picker must agree with
    the independent BE-RAR ground-truth scorer on 100% of cases — both
    implementations run the same `rtt × nu((1−loss)/loss)` math, so
    any deviation is an implementation bug, not statistical noise."""
    n_trials = 1000
    agreements = 0
    rng = random.Random(42)
    for _ in range(n_trials):
        n_relays = rng.randint(3, 7)
        topology = {}
        for k in range(n_relays):
            topology[f"r_{k}"] = {
                "rtt_ms": rng.uniform(20.0, 300.0),
                "loss_rate": rng.uniform(0.0, 0.40),
            }
        expected = _expected_best_be_rar(topology)
        chosen = _run_pick(topology)
        if chosen == expected:
            agreements += 1
    assert agreements == n_trials, (
        f"daemon picker disagreed with BE-RAR ground truth on "
        f"{n_trials - agreements}/{n_trials} trials (expected 0)"
    )


def test_be_rar_softer_asymptote_vs_heuristic_on_moderate_loss():
    """Compute BE-RAR penalty and heuristic penalty at the same loss
    levels and verify BE-RAR is SOFTER (smaller penalty) at moderate
    loss. This is the design intent — BE-RAR doesn't over-weight
    moderate-loss relays the way the heuristic does."""
    import math
    from one_link_native.coherence_field import be_rar

    def heuristic(loss: float) -> float:
        return 1.0 / max(1.0 - loss, 1e-9) ** 2

    def be_rar_penalty(loss: float) -> float:
        loss = min(max(loss, 1e-6), 1.0 - 1e-6)
        y = (1.0 - loss) / loss
        return be_rar(y)

    # At zero loss both penalties should be ≈ 1 (no penalty).
    assert abs(heuristic(0.0) - 1.0) < 1e-6
    assert be_rar_penalty(0.0) < 1.01
    # At moderate loss (10–40%), BE-RAR should be strictly softer.
    for loss in [0.10, 0.20, 0.30, 0.40]:
        h = heuristic(loss)
        b = be_rar_penalty(loss)
        assert b < h, (
            f"loss {loss}: BE-RAR penalty {b:.3f} should be SOFTER than "
            f"heuristic {h:.3f}"
        )
    # At extreme loss (≥80%), BE-RAR still diverges — the asymptote
    # is preserved.
    assert be_rar_penalty(0.95) > 4.0  # nu((0.05/0.95)) = nu(0.0526) ≈ 4.88

    # Use the `math` import to keep linters happy (we reference it).
    _ = math.inf
