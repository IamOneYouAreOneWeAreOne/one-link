"""Tests for Phase I — OnlineLearner Python surface."""

from __future__ import annotations

import math

import pytest

from one_link import selector_native


pytestmark = pytest.mark.skipif(
    not selector_native.HAS_NATIVE,
    reason="one_link_native.selector not installed",
)


def _stranger_ctx_kwargs() -> dict:
    """Context that has a meaningful privacy gradient — stranger
    peer, 1-hop, no-cover means alignment_gap > 0 so the learner's
    privacy_weight gradient is non-zero."""
    return dict(
        kind="TEXT",
        size=1024,
        peer="rejected",  # stranger
        urgency="foreground",
        radio_state="active",
        network="wifi",
        user_mode="normal",
        observed_loss=0.0,
        pattern_strength=0.0,
    )


def _weak_privacy_decision() -> dict:
    return {
        "transport": "quic_stream",
        "path": "classical",
        "onion_hops": 1,
        "cover_traffic": False,
        "batch_decision": "emit_now",
        "anchor_lay": False,
        "predictor_warm": False,
    }


def test_construction_defaults_present() -> None:
    learner = selector_native.online_learner()
    assert learner.name() == "OnlineLearner"
    w = learner.weights()
    d = learner.defaults()
    assert set(w.keys()) == set(d.keys())
    # Fresh learner: weights == defaults.
    for k in w:
        assert w[k] == d[k]


def test_decide_passthrough() -> None:
    """Fresh learner.decide() returns the same Decision as a fresh
    UnifiedMin would."""
    learner = selector_native.online_learner()
    um = selector_native.unified_min()
    kwargs = dict(
        kind="TEXT", size=1024, peer="pinned",
        user_mode="normal",
    )
    assert learner.decide(**kwargs) == um.decide(**kwargs)


def test_observe_advances_stats() -> None:
    learner = selector_native.online_learner()
    d = _weak_privacy_decision()
    ctx = _stranger_ctx_kwargs()
    learner.observe(5.0, d, **ctx)
    s = learner.stats()
    assert s["n_observations"] == 1
    assert s["mean_abs_regret"] > 0


def test_observe_nonfinite_regret_dropped() -> None:
    learner = selector_native.online_learner()
    d = _weak_privacy_decision()
    ctx = _stranger_ctx_kwargs()
    learner.observe(math.nan, d, **ctx)
    learner.observe(math.inf, d, **ctx)
    learner.observe(-math.inf, d, **ctx)
    assert learner.stats()["n_observations"] == 0


def test_observe_shifts_weights() -> None:
    learner = selector_native.online_learner(
        learning_rate=0.01,  # crank up so the change is visible quickly
    )
    d = _weak_privacy_decision()
    ctx = _stranger_ctx_kwargs()
    before = learner.weights()["privacy_weight"]
    for _ in range(100):
        learner.observe(10.0, d, **ctx)
    after = learner.weights()["privacy_weight"]
    assert after > before, f"expected privacy_weight to grow: {before} -> {after}"


def test_regularization_pulls_back_to_defaults() -> None:
    """After displacement from positive regret, zero-regret observations
    with strong regularization should pull the weight back toward its
    factory default."""
    learner = selector_native.online_learner(
        learning_rate=0.01,
        regularization=0.5,
    )
    d = _weak_privacy_decision()
    ctx = _stranger_ctx_kwargs()
    # Push up.
    for _ in range(100):
        learner.observe(10.0, d, **ctx)
    displaced = learner.weights()["privacy_weight"]
    default_pw = learner.defaults()["privacy_weight"]
    assert displaced > default_pw
    # Pull back.
    for _ in range(200):
        learner.observe(0.0, d, **ctx)
    pulled = learner.weights()["privacy_weight"]
    assert pulled < displaced


def test_weights_bounded_under_saturated_regret() -> None:
    """Phase I gate: with regret = 100 saturated, weights stay
    within (0, 10× default) — no oscillation, no blow-up."""
    learner = selector_native.online_learner(
        learning_rate=0.05,  # aggressive
        weight_bound_multiplier=10.0,
    )
    d = _weak_privacy_decision()
    ctx = _stranger_ctx_kwargs()
    for _ in range(2000):
        learner.observe(100.0, d, **ctx)
    w = learner.weights()
    defaults = learner.defaults()
    # A learner returning no weights would satisfy every bound below while
    # having learned nothing -- "weights stay bounded" must be a statement
    # about actual weights.
    assert w, "the learner exposed no weights after 2000 observations"
    assert set(w) == set(defaults), (
        f"weights and defaults disagree on keys: {sorted(set(w) ^ set(defaults))}"
    )
    for k, v in w.items():
        d_v = defaults[k]
        assert 0.0 <= v, f"{k} went negative: {v}"
        assert v <= d_v * 10.0 + 1e-3, f"{k} exceeded 10× default: {v} vs {d_v}"


def test_decisions_remain_contract_compliant_after_learning() -> None:
    """Property: even after 1000 observations, every mode's decisions
    still respect their contract."""
    learner = selector_native.online_learner(
        learning_rate=0.02,
    )
    d = _weak_privacy_decision()
    ctx = _stranger_ctx_kwargs()
    for _ in range(500):
        learner.observe(7.0, d, **ctx)
    # Now test every mode.
    for mode in ("normal", "paranoid", "battery_save", "latency_strict"):
        dec = learner.decide(
            kind="TEXT", size=1024, peer="pinned",
            user_mode=mode,
        )
        violations = selector_native.verify_contract(dec, mode)
        assert violations == [], (
            f"after learning, mode={mode} produced violations {violations}; "
            f"decision={dec}"
        )


def test_invalid_decision_dict_rejected() -> None:
    learner = selector_native.online_learner()
    ctx = _stranger_ctx_kwargs()
    # Missing required field.
    with pytest.raises(ValueError, match="decision missing"):
        learner.observe(1.0, {"transport": "quic_stream"}, **ctx)
    # Unknown transport label.
    bad = {**_weak_privacy_decision(), "transport": "supercritical"}
    with pytest.raises(ValueError, match="unknown transport"):
        learner.observe(1.0, bad, **ctx)


def test_stats_track_clamp_events() -> None:
    """Property: clamp events are non-negative + monotone over the
    learner's lifetime."""
    learner = selector_native.online_learner(
        learning_rate=1.0,  # maximum
        weight_bound_multiplier=2.0,  # tight bound -> more clamps
    )
    d = _weak_privacy_decision()
    ctx = _stranger_ctx_kwargs()
    prev_clamps = 0
    for _ in range(100):
        learner.observe(100.0, d, **ctx)
        s = learner.stats()
        assert s["clamp_events"] >= prev_clamps
        prev_clamps = s["clamp_events"]
    # Under saturated regret + tight bound, some clamps should fire.
    assert learner.stats()["clamp_events"] > 0


def test_repr_includes_stats() -> None:
    learner = selector_native.online_learner()
    r = repr(learner)
    assert "OnlineLearner" in r
    assert "n_obs=" in r
