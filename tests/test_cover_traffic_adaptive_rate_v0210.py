"""Tests for the adaptive cover-traffic rate wiring.

Exercises:
  - CoverTrafficDaemon.set_rate_multiplier clamps to [0.0, 1.0]
  - rate_multiplier property reports the current value
  - stats() includes rate_multiplier, effective_rate_hz, skipped
  - Bernoulli-skip in _run actually skips when multiplier<1 (counted
    via skipped property)
  - Daemon.update_cover_traffic_rate_from_selector reads cover_ratio
    and maps to multiplier
  - Paranoid mode forces multiplier=1.0 regardless of ratio
  - Baseline floor (0.3) prevents fully-quiet emitter
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from one_link import cover_traffic as ct
from one_link import daemon as daemon_module


def _bare_daemon():
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d._user_mode_value = "normal"
    d._cover_traffic = None
    d._cover_traffic_env_gate = False
    d._selector_decision_counters = {
        "total": 0,
        "transport": {},
        "path": {},
        "onion_hops": {},
        "cover_traffic_on": 0,
        "cover_traffic_off": 0,
        "batch_decision": {},
        "anchor_lay_on": 0,
        "anchor_lay_off": 0,
        "predictor_warm_on": 0,
        "predictor_warm_off": 0,
        "f4_violations": 0,
    }
    return d


# ---------- set_rate_multiplier ----------


pytestmark_native = pytest.mark.skipif(
    not ct.HAS_NATIVE,
    reason="one_link_native.sphinx not installed",
)


@pytestmark_native
def test_default_multiplier_is_one() -> None:
    d = ct.CoverTrafficDaemon(rate_hz=10.0)
    assert d.rate_multiplier == 1.0


@pytestmark_native
def test_set_rate_multiplier_in_range() -> None:
    d = ct.CoverTrafficDaemon(rate_hz=10.0)
    d.set_rate_multiplier(0.5)
    assert d.rate_multiplier == 0.5
    d.set_rate_multiplier(0.0)
    assert d.rate_multiplier == 0.0
    d.set_rate_multiplier(1.0)
    assert d.rate_multiplier == 1.0


@pytestmark_native
def test_set_rate_multiplier_clamps_negative_to_zero() -> None:
    d = ct.CoverTrafficDaemon(rate_hz=10.0)
    d.set_rate_multiplier(-0.5)
    assert d.rate_multiplier == 0.0


@pytestmark_native
def test_set_rate_multiplier_clamps_above_one() -> None:
    d = ct.CoverTrafficDaemon(rate_hz=10.0)
    d.set_rate_multiplier(2.5)
    assert d.rate_multiplier == 1.0


@pytestmark_native
def test_stats_includes_multiplier_fields() -> None:
    d = ct.CoverTrafficDaemon(rate_hz=10.0)
    d.set_rate_multiplier(0.5)
    stats = d.stats()
    assert stats["rate_multiplier"] == 0.5
    assert stats["effective_rate_hz"] == 5.0
    assert stats["skipped"] == 0


# ---------- Bernoulli skip actually skips ----------


@pytestmark_native
def test_bernoulli_skip_zero_multiplier_skips_everything() -> None:
    """multiplier=0 means every emit is skipped. With a fast scheduler
    we should accumulate several skipped ticks in a short window."""
    # Use a high-frequency scheduler so we get many ticks quickly.
    d = ct.CoverTrafficDaemon(rate_hz=50.0, emit_cover=None)
    d.set_user_mode("paranoid")  # bypass mode-contract refusal
    d.set_rate_multiplier(0.0)
    d.start()
    time.sleep(0.5)
    d.stop(join_timeout=1.0)
    # At least some scheduler ticks fired in 500ms at 50Hz; all should
    # have been skipped.
    assert d.skipped > 0
    assert d._emitted == 0


@pytestmark_native
def test_bernoulli_skip_full_multiplier_emits_everything() -> None:
    """multiplier=1 means every emit fires."""
    d = ct.CoverTrafficDaemon(rate_hz=50.0, emit_cover=None)
    d.set_user_mode("paranoid")
    d.set_rate_multiplier(1.0)
    d.start()
    time.sleep(0.5)
    d.stop(join_timeout=1.0)
    assert d.skipped == 0
    assert d._emitted > 0


# ---------- daemon-level adaptive wiring ----------


def test_update_rate_no_emitter_returns_none() -> None:
    d = _bare_daemon()
    assert d.update_cover_traffic_rate_from_selector() is None


def test_update_rate_paranoid_forces_one() -> None:
    d = _bare_daemon()
    d._user_mode_value = "paranoid"
    emitter = MagicMock()
    d._cover_traffic = emitter
    # Even with cover_ratio=0, paranoid forces multiplier=1.0.
    result = d.update_cover_traffic_rate_from_selector()
    assert result == 1.0
    emitter.set_rate_multiplier.assert_called_once_with(1.0)


def test_update_rate_uses_cover_ratio_from_stats() -> None:
    d = _bare_daemon()
    emitter = MagicMock()
    d._cover_traffic = emitter
    # 7 of 10 decisions recommended cover; ratio = 0.7.
    d._selector_decision_counters["total"] = 10
    d._selector_decision_counters["cover_traffic_on"] = 7
    d._selector_decision_counters["cover_traffic_off"] = 3
    result = d.update_cover_traffic_rate_from_selector()
    assert result == 0.7
    emitter.set_rate_multiplier.assert_called_once_with(0.7)


def test_update_rate_baseline_floor_at_0_3() -> None:
    """When cover_ratio is below the baseline (0.3), the floor wins so
    the emitter never goes fully silent (which would itself be a
    signal)."""
    d = _bare_daemon()
    emitter = MagicMock()
    d._cover_traffic = emitter
    # 1 of 10 decisions = 10% — below the floor.
    d._selector_decision_counters["total"] = 10
    d._selector_decision_counters["cover_traffic_on"] = 1
    d._selector_decision_counters["cover_traffic_off"] = 9
    result = d.update_cover_traffic_rate_from_selector()
    assert result == 0.3
    emitter.set_rate_multiplier.assert_called_once_with(0.3)


def test_update_rate_caps_at_one() -> None:
    """cover_ratio can theoretically exceed 1.0 only via bad data;
    multiplier should still cap at 1.0."""
    d = _bare_daemon()
    emitter = MagicMock()
    d._cover_traffic = emitter
    d._selector_decision_counters["total"] = 10
    d._selector_decision_counters["cover_traffic_on"] = 999  # impossible
    result = d.update_cover_traffic_rate_from_selector()
    assert result == 1.0


def test_update_rate_survives_emitter_exception() -> None:
    d = _bare_daemon()
    emitter = MagicMock()
    emitter.set_rate_multiplier.side_effect = RuntimeError("simulated")
    d._cover_traffic = emitter
    d._selector_decision_counters["total"] = 10
    d._selector_decision_counters["cover_traffic_on"] = 5
    # Must not raise.
    result = d.update_cover_traffic_rate_from_selector()
    assert result is None


def test_update_rate_battery_save_still_adaptive() -> None:
    """battery_save forbids cover entirely (handled by mode contract);
    adaptive rate doesn't fight that. The mode-contract reconciler
    keeps the emitter stopped; the rate update just sets the
    multiplier for when/if it does run."""
    d = _bare_daemon()
    d._user_mode_value = "battery_save"
    emitter = MagicMock()
    d._cover_traffic = emitter
    d._selector_decision_counters["total"] = 10
    d._selector_decision_counters["cover_traffic_on"] = 8
    # Mode forbids cover, but adaptive rate isn't the gate. cover_ratio
    # = 0.8 -> multiplier = 0.8. The mode-contract reconciler keeps the
    # emitter stopped, so this multiplier is dormant; if the user
    # switches out of battery_save later, the next reconcile kicks
    # the emitter on AT the most-recent multiplier.
    result = d.update_cover_traffic_rate_from_selector()
    # Not paranoid, so no forced 1.0. cover_ratio applied.
    assert result == 0.8
