"""ADR-0019 algebraic-correctness tests for ``one_link.bandit_native``."""

from __future__ import annotations

import pytest

from one_link import bandit_native

pytestmark = pytest.mark.skipif(
    not bandit_native.HAS_NATIVE,
    reason="one_link_native not installed; run `cd native && maturin develop --release`",
)


def test_module_metadata() -> None:
    assert bandit_native.NATIVE_VERSION is not None


def test_basic_select_update() -> None:
    b = bandit_native.bandit(5, seed=42)
    assert b.n_arms == 5
    arm = b.select()
    assert 0 <= arm < 5
    b.update(arm, 1.0)


def test_converges_on_optimal_arm() -> None:
    b = bandit_native.bandit(5, seed=0xCAFE)
    # Train: arm 4 always rewarded, others never.
    for _ in range(100):
        for arm in range(5):
            reward = 1.0 if arm == 4 else 0.0
            b.update(arm, reward)
    assert b.best_arm() == 4

    # Sample-based check: 100 selects, most should pick arm 4.
    hits = sum(1 for _ in range(100) if b.select() == 4)
    assert hits >= 80


def test_rejects_invalid_reward() -> None:
    b = bandit_native.bandit(3)
    with pytest.raises(Exception):
        b.update(0, -0.1)
    with pytest.raises(Exception):
        b.update(0, 1.5)


def test_rejects_arm_out_of_range() -> None:
    b = bandit_native.bandit(3)
    with pytest.raises(Exception):
        b.update(10, 0.5)


def test_rejects_zero_arms() -> None:
    with pytest.raises(Exception):
        bandit_native.bandit(0)


def test_arms_diagnostic() -> None:
    b = bandit_native.bandit(3, seed=1)
    arms = b.arms()
    assert len(arms) == 3
    # Fresh: every (alpha, beta) = (1.0, 1.0).
    for alpha, beta in arms:
        assert alpha == 1.0
        assert beta == 1.0
    # After one positive update, arm 0's alpha = 2.0.
    b.update(0, 1.0)
    arms = b.arms()
    assert arms[0][0] == 2.0
    assert arms[0][1] == 1.0


def test_repr_includes_state() -> None:
    b = bandit_native.bandit(5)
    repr_str = repr(b)
    assert "n_arms=5" in repr_str
