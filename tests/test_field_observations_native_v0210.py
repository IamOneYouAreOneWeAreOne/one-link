"""Tests for ``one_link.field_observations_native`` — D23 + D24.

Exercises the trust-weighted EWMA + gradient surface for the daemon's
field-observation pipeline.
"""

from __future__ import annotations

import pytest

from one_link import field_observations_native as fo


pytestmark = pytest.mark.skipif(
    not fo.HAS_NATIVE,
    reason="one_link_native.coherence_field.FieldObservations not available; "
    "run `cd native && maturin develop --release`",
)


# ---------- Construction ----------


def test_module_metadata() -> None:
    assert fo.NATIVE_VERSION is not None


def test_default_constructor() -> None:
    o = fo.field_observations()
    assert o.is_empty is True
    assert o.len == 0
    assert abs(o.alpha - 0.05) < 1e-6


def test_custom_alpha_and_initial() -> None:
    o = fo.field_observations(alpha=0.1, initial_value=0.8)
    assert abs(o.alpha - 0.1) < 1e-6
    # initial_value only takes effect on first observation.
    o.update("p", 0.9, 1.0)
    # new = (1 − 0.1) · 0.8 + 0.1 · 0.9 = 0.72 + 0.09 = 0.81
    v = o.tau_at("p")
    assert v is not None
    assert abs(v - 0.81) < 1e-5


def test_zero_alpha_rejected() -> None:
    with pytest.raises(ValueError):
        fo.field_observations(alpha=0.0)


def test_oversize_alpha_rejected() -> None:
    with pytest.raises(ValueError):
        fo.field_observations(alpha=1.5)


# ---------- Update + read ----------


def test_update_and_read_back() -> None:
    o = fo.field_observations(alpha=0.1)
    o.update("p1", 0.9, 1.0)
    v = o.tau_at("p1")
    assert v is not None
    # new = 0.9 · 0.5 + 0.1 · 0.9 = 0.54
    assert abs(v - 0.54) < 1e-5


def test_tau_at_unknown_peer_is_none() -> None:
    o = fo.field_observations()
    assert o.tau_at("ghost") is None


def test_ewma_converges_to_observed() -> None:
    o = fo.field_observations(alpha=0.1)
    for _ in range(200):
        o.update("p", 0.9, 1.0)
    v = o.tau_at("p")
    assert v is not None and abs(v - 0.9) < 0.01


def test_trust_zero_is_no_op() -> None:
    o = fo.field_observations()
    o.update("p", 0.95, 1.0)
    before = o.tau_at("p")
    o.update("p", 0.0, 0.0)
    after = o.tau_at("p")
    assert before == after


# ---------- Validation ----------


def test_rejects_oob_observation() -> None:
    o = fo.field_observations()
    with pytest.raises(ValueError):
        o.update("p", 1.5, 1.0)
    with pytest.raises(ValueError):
        o.update("p", -0.1, 1.0)


def test_rejects_oob_trust() -> None:
    o = fo.field_observations()
    with pytest.raises(ValueError):
        o.update("p", 0.5, 1.5)
    with pytest.raises(ValueError):
        o.update("p", 0.5, -0.1)


# ---------- Gradient ----------


def test_gradient_none_without_neighbors() -> None:
    o = fo.field_observations()
    o.update("p", 0.5, 1.0)
    assert o.gradient_at("p") is None


def test_gradient_near_zero_when_neighbors_match() -> None:
    o = fo.field_observations(alpha=0.5)
    for _ in range(50):
        for peer in ("self", "a", "b", "c"):
            o.update(peer, 0.8, 1.0)
    o.set_neighbors("self", ["a", "b", "c"])
    g = o.gradient_at("self")
    assert g is not None
    assert g < 0.001


def test_gradient_positive_when_neighbors_diverge() -> None:
    o = fo.field_observations(alpha=0.5)
    for _ in range(50):
        o.update("self", 0.5, 1.0)
        o.update("a", 0.9, 1.0)
        o.update("b", 0.1, 1.0)
    o.set_neighbors("self", ["a", "b"])
    g = o.gradient_at("self")
    assert g is not None
    assert g > 0.1


def test_gradient_clearable_with_empty_list() -> None:
    o = fo.field_observations()
    o.update("p", 0.5, 1.0)
    o.set_neighbors("p", ["a"])
    o.set_neighbors("p", [])
    assert o.gradient_at("p") is None


# ---------- Poisoning defense (Gap 4 invariant) ----------


def test_trust_weighted_resists_poisoning() -> None:
    """Mirrors the Rust test: at 15% attacker fraction with trust=0.1,
    the field stays within 0.1 of the honest baseline."""
    o = fo.field_observations(alpha=0.05)
    # 85 honest observations from trusted peers.
    for _ in range(85):
        o.update("p", 0.8, 1.0)
    honest = o.tau_at("p")
    # 15 adversarial pulls from low-trust peers.
    for _ in range(15):
        o.update("p", 0.0, 0.1)
    after = o.tau_at("p")
    assert honest is not None and after is not None
    assert abs(honest - after) < 0.1


# ---------- Lifecycle ----------


def test_len_tracks_unique_peers() -> None:
    o = fo.field_observations()
    o.update("p1", 0.5, 1.0)
    o.update("p2", 0.5, 1.0)
    o.update("p1", 0.6, 1.0)
    assert o.len == 2


def test_repr_includes_state() -> None:
    o = fo.field_observations()
    o.update("p", 0.5, 1.0)
    r = repr(o)
    assert "FieldObservations" in r
    assert "len=1" in r
