"""Tests for ``one_link.align_native`` — D02 alignment trust function.

Mirrors the Rust unit tests + property tests but on the pyo3 boundary.
Also exercises the pure-Python fallback so the suite is meaningful even
when the native crate is not built.
"""

from __future__ import annotations

import math

import pytest

from one_link import align_native


# ---------- Native-path tests (skipped if not built) ----------

native_only = pytest.mark.skipif(
    not align_native.HAS_NATIVE,
    reason="one_link_native.align not installed; run `cd native && maturin develop --release`",
)


@native_only
def test_module_metadata() -> None:
    assert align_native.NATIVE_VERSION is not None


@native_only
def test_perfect_alignment_at_zero() -> None:
    for l in (align_native.l_paired(), align_native.l_known(), align_native.l_stranger()):
        t = align_native.trust_score(0.0, 0.0, l)
        assert abs(t - 1.0) < 1e-6


@native_only
def test_default_l_session_constants() -> None:
    # Map matches the integration map: 100 / 30 / 5 days.
    assert align_native.l_paired() == 100.0
    assert align_native.l_known() == 30.0
    assert align_native.l_stranger() == 5.0


@native_only
def test_paired_decays_slower_than_stranger() -> None:
    # See align.rs::tests::paired_decays_slower_than_stranger for the math.
    # 5 days silence: paired ~0.77 (trusted), stranger ~0.0055 (gone).
    five_days = 5.0 * 86_400.0
    paired = align_native.trust_score(1.0, five_days, align_native.l_paired())
    stranger = align_native.trust_score(1.0, five_days, align_native.l_stranger())
    assert paired > 0.5
    assert stranger < 0.01
    assert paired > stranger


@native_only
def test_hop_distance_monotone() -> None:
    s = 86_400.0  # 1 day
    t1 = align_native.trust_score(1.0, s, align_native.l_known())
    t3 = align_native.trust_score(3.0, s, align_native.l_known())
    t5 = align_native.trust_score(5.0, s, align_native.l_known())
    assert t1 > t3 > t5


@native_only
def test_staleness_monotone() -> None:
    hop = 1.0
    l = align_native.l_paired()
    t_fresh = align_native.trust_score(hop, 0.0, l)
    t_day = align_native.trust_score(hop, 86_400.0, l)
    t_month = align_native.trust_score(hop, 30.0 * 86_400.0, l)
    assert t_fresh > t_day > t_month


@native_only
def test_trust_for_relationship_alias_mapping() -> None:
    # Both "paired" and the daemon's "pinned" alias resolve identically.
    t_paired = align_native.trust_for("paired", 1.0, 86_400.0)
    t_pinned = align_native.trust_for("pinned", 1.0, 86_400.0)
    assert t_paired == t_pinned

    t_known = align_native.trust_for("known", 1.0, 86_400.0)
    t_pending = align_native.trust_for("pending", 1.0, 86_400.0)
    assert t_known == t_pending

    t_stranger = align_native.trust_for("stranger", 1.0, 86_400.0)
    t_rejected = align_native.trust_for("rejected", 1.0, 86_400.0)
    assert t_stranger == t_rejected


@native_only
def test_trust_for_case_insensitive() -> None:
    t1 = align_native.trust_for("PAIRED", 1.0, 86_400.0)
    t2 = align_native.trust_for("paired", 1.0, 86_400.0)
    assert t1 == t2


@native_only
def test_trust_for_unknown_relationship_rejects() -> None:
    with pytest.raises(ValueError):
        align_native.trust_for("invalid_tier", 1.0, 86_400.0)


@native_only
def test_rejects_negative_hop() -> None:
    with pytest.raises(ValueError):
        align_native.trust_score(-1.0, 0.0, align_native.l_paired())


@native_only
def test_rejects_negative_staleness() -> None:
    with pytest.raises(ValueError):
        align_native.trust_score(1.0, -1.0, align_native.l_paired())


@native_only
def test_rejects_zero_l_session() -> None:
    with pytest.raises(ValueError):
        align_native.trust_score(1.0, 0.0, 0.0)


@native_only
def test_rejects_negative_l_session() -> None:
    with pytest.raises(ValueError):
        align_native.trust_score(1.0, 0.0, -10.0)


@native_only
def test_rejects_nonfinite_inputs() -> None:
    with pytest.raises(ValueError):
        align_native.trust_score(float("nan"), 0.0, align_native.l_paired())
    with pytest.raises(ValueError):
        align_native.trust_score(1.0, float("inf"), align_native.l_paired())


@native_only
def test_native_and_python_agree() -> None:
    # The pure-Python fallback should match the native within fp tolerance.
    cases = [
        (0.0, 0.0, 100.0),
        (1.0, 0.0, 100.0),
        (3.0, 86_400.0, 30.0),
        (5.0, 10.0 * 86_400.0, 5.0),
        (2.5, 7.0 * 86_400.0, 50.0),
    ]
    for hop, staleness, l in cases:
        native = align_native.trust_score(hop, staleness, l)
        py = align_native.trust_score_python(hop, staleness, l)
        assert abs(native - py) < 1e-5, (
            f"native={native} vs python={py} for hop={hop} staleness={staleness} l={l}"
        )


# ---------- Pure-Python-fallback tests (always run, no native required) ----------


def test_python_fallback_perfect_alignment() -> None:
    t = align_native.trust_score_python(0.0, 0.0, 100.0)
    assert abs(t - 1.0) < 1e-6


def test_python_fallback_monotone_hops() -> None:
    s = 86_400.0
    t1 = align_native.trust_score_python(1.0, s, 30.0)
    t3 = align_native.trust_score_python(3.0, s, 30.0)
    assert t1 > t3


def test_python_fallback_rejects_invalid() -> None:
    with pytest.raises(ValueError):
        align_native.trust_score_python(-1.0, 0.0, 100.0)
    with pytest.raises(ValueError):
        align_native.trust_score_python(1.0, -1.0, 100.0)
    with pytest.raises(ValueError):
        align_native.trust_score_python(1.0, 0.0, 0.0)
    with pytest.raises(ValueError):
        align_native.trust_score_python(math.nan, 0.0, 100.0)


def test_python_fallback_in_unit_interval() -> None:
    # Any valid input -> trust in [0, 1]. At extreme decay, exp underflows
    # to 0.0; that's the semantically correct "trust exhausted" value.
    import random
    rng = random.Random(0xA11)
    for _ in range(100):
        hop = rng.uniform(0.0, 20.0)
        staleness = rng.uniform(0.0, 365.0 * 86_400.0)
        l = rng.uniform(0.5, 500.0)
        t = align_native.trust_score_python(hop, staleness, l)
        assert 0.0 <= t <= 1.0
