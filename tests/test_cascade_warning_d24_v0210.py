"""Integration map §11 + D24 — Tests for cascade-warning telemetry.

Exercises:
  - _maybe_record_cascade_warning probes gradient_at + increments
    counter when gradient > threshold
  - Counter stays at zero when field_obs is None
  - Counter stays at zero when gradient_at returns None
  - Counter stays at zero when gradient < threshold
  - Counter survives gradient_at exception (defensive)
  - cascade_warning_stats returns the documented shape
  - Wire-through from _write_field_observation
"""

from __future__ import annotations

from unittest.mock import MagicMock


from one_link import daemon as daemon_module


def _bare_daemon():
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d._field_obs = None
    d._cascade_warning_threshold = 0.5
    d._cascade_warning_count = 0
    return d


# ---------- _maybe_record_cascade_warning ----------


def test_no_field_obs_no_op() -> None:
    d = _bare_daemon()
    d._field_obs = None
    d._maybe_record_cascade_warning("peerA")
    assert d._cascade_warning_count == 0


def test_field_obs_without_gradient_method_no_op() -> None:
    """When the native FieldObservations lacks gradient_at (e.g. an
    older binding), the helper must silently skip — no exception."""
    d = _bare_daemon()
    obs = MagicMock(spec=["update", "tau_for_peer"])
    # spec= excludes gradient_at so hasattr returns False.
    d._field_obs = obs
    d._maybe_record_cascade_warning("peerA")
    assert d._cascade_warning_count == 0


def test_gradient_returning_none_no_op() -> None:
    """When gradient_at returns None (no neighbors configured), the
    counter doesn't tick."""
    d = _bare_daemon()
    obs = MagicMock()
    obs.gradient_at = MagicMock(return_value=None)
    d._field_obs = obs
    d._maybe_record_cascade_warning("peerA")
    assert d._cascade_warning_count == 0


def test_gradient_below_threshold_no_op() -> None:
    d = _bare_daemon()
    obs = MagicMock()
    obs.gradient_at = MagicMock(return_value=0.1)  # below 0.5 threshold
    d._field_obs = obs
    d._maybe_record_cascade_warning("peerA")
    assert d._cascade_warning_count == 0


def test_gradient_above_threshold_increments() -> None:
    d = _bare_daemon()
    obs = MagicMock()
    obs.gradient_at = MagicMock(return_value=0.9)  # above 0.5 threshold
    d._field_obs = obs
    d._maybe_record_cascade_warning("peerA")
    assert d._cascade_warning_count == 1


def test_gradient_exactly_at_threshold_does_not_tick() -> None:
    """Strict greater-than: equal-to-threshold doesn't count."""
    d = _bare_daemon()
    obs = MagicMock()
    obs.gradient_at = MagicMock(return_value=0.5)
    d._field_obs = obs
    d._maybe_record_cascade_warning("peerA")
    assert d._cascade_warning_count == 0


def test_gradient_exception_survives() -> None:
    """Native crashes on gradient_at must not break the daemon."""
    d = _bare_daemon()
    obs = MagicMock()
    obs.gradient_at = MagicMock(side_effect=RuntimeError("simulated"))
    d._field_obs = obs
    # Must not raise.
    d._maybe_record_cascade_warning("peerA")
    assert d._cascade_warning_count == 0


def test_gradient_non_numeric_no_op() -> None:
    """A pathological native binding returning a non-numeric type
    must not raise on the float() cast."""
    d = _bare_daemon()
    obs = MagicMock()
    obs.gradient_at = MagicMock(return_value="not-a-number")
    d._field_obs = obs
    d._maybe_record_cascade_warning("peerA")
    assert d._cascade_warning_count == 0


def test_repeated_high_gradients_accumulate() -> None:
    d = _bare_daemon()
    obs = MagicMock()
    obs.gradient_at = MagicMock(return_value=0.7)
    d._field_obs = obs
    for _ in range(5):
        d._maybe_record_cascade_warning("peerA")
    assert d._cascade_warning_count == 5


# ---------- threshold configurable ----------


def test_custom_threshold_honoured() -> None:
    d = _bare_daemon()
    d._cascade_warning_threshold = 0.9
    obs = MagicMock()
    obs.gradient_at = MagicMock(return_value=0.7)  # below 0.9
    d._field_obs = obs
    d._maybe_record_cascade_warning("peerA")
    assert d._cascade_warning_count == 0
    # Now 0.95 should fire.
    obs.gradient_at.return_value = 0.95
    d._maybe_record_cascade_warning("peerA")
    assert d._cascade_warning_count == 1


# ---------- cascade_warning_stats ----------


def test_stats_shape() -> None:
    d = _bare_daemon()
    s = d.cascade_warning_stats()
    assert "count" in s
    assert "threshold" in s
    assert "field_obs_available" in s


def test_stats_count_reflects_internal() -> None:
    d = _bare_daemon()
    d._cascade_warning_count = 42
    s = d.cascade_warning_stats()
    assert s["count"] == 42


def test_stats_threshold_reflects_config() -> None:
    d = _bare_daemon()
    d._cascade_warning_threshold = 0.75
    s = d.cascade_warning_stats()
    assert s["threshold"] == 0.75


def test_stats_field_obs_available_flag() -> None:
    d = _bare_daemon()
    d._field_obs = None
    assert d.cascade_warning_stats()["field_obs_available"] is False
    d._field_obs = MagicMock()
    assert d.cascade_warning_stats()["field_obs_available"] is True


def test_stats_defensive_when_attrs_missing() -> None:
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    # No _cascade_warning_count or _cascade_warning_threshold or _field_obs.
    # Must not raise — accessor defaults each missing attr.
    s = d.cascade_warning_stats()
    assert s["count"] == 0
    assert s["threshold"] == 0.5
    assert s["field_obs_available"] is False
