"""D05 wire-up — Tests for cover-traffic F4 mode-contract integration.

Exercises:
  - is_cover_mandated / is_cover_forbidden / should_run_cover helpers
  - CoverTrafficDaemon.set_user_mode / set_env_gate / effective_enabled
  - apply_mode_contract transitions (paranoid forces on, battery_save
    forces off, normal+env=on, normal+env=off)
  - start() refuses to start when mode forbids cover
  - stats() snapshot has the expected shape
  - Daemon._apply_cover_traffic_mode_contract end-to-end
  - Daemon.cover_traffic_stats inspection
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from one_link import cover_traffic as ct
from one_link import daemon as daemon_module


# ---------- pure helpers ----------


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("paranoid", True),
        ("PARANOID", True),  # case-insensitive
        ("battery_save", False),
        ("normal", False),
        ("latency_strict", False),
        ("", False),
        ("garbage", False),
    ],
)
def test_is_cover_mandated(mode, expected) -> None:
    assert ct.is_cover_mandated(mode) is expected


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("battery_save", True),
        ("BATTERY_SAVE", True),
        ("paranoid", False),
        ("normal", False),
        ("latency_strict", False),
        ("", False),
    ],
)
def test_is_cover_forbidden(mode, expected) -> None:
    assert ct.is_cover_forbidden(mode) is expected


@pytest.mark.parametrize(
    "mode,gate,expected",
    [
        # Paranoid: always on, regardless of gate.
        ("paranoid", False, True),
        ("paranoid", True, True),
        # Battery_save: always off, regardless of gate.
        ("battery_save", False, False),
        ("battery_save", True, False),
        # Opt-in modes follow the gate.
        ("normal", False, False),
        ("normal", True, True),
        ("latency_strict", False, False),
        ("latency_strict", True, True),
        # Unknown mode defaults to opt-in.
        ("garbage", False, False),
        ("garbage", True, True),
    ],
)
def test_should_run_cover(mode, gate, expected) -> None:
    assert ct.should_run_cover(mode, gate) is expected


# ---------- CoverTrafficDaemon F4 wiring ----------


pytestmark_native = pytest.mark.skipif(
    not ct.HAS_NATIVE,
    reason="one_link_native.sphinx not installed",
)


@pytestmark_native
def test_default_state_is_normal_mode_gate_off() -> None:
    d = ct.CoverTrafficDaemon(rate_hz=10.0)  # high rate so worker doesn't sleep too long
    assert d.effective_enabled is False
    s = d.stats()
    assert s["user_mode"] == "normal"
    assert s["env_gate"] is False
    assert s["effective_enabled"] is False
    assert s["running"] is False


@pytestmark_native
def test_set_user_mode_normalises_case() -> None:
    d = ct.CoverTrafficDaemon(rate_hz=10.0)
    d.set_user_mode("PARANOID")
    assert d.stats()["user_mode"] == "paranoid"
    assert d.effective_enabled is True


@pytestmark_native
def test_set_env_gate_normal_mode_toggles_effective() -> None:
    d = ct.CoverTrafficDaemon(rate_hz=10.0)
    assert d.effective_enabled is False
    d.set_env_gate(True)
    assert d.effective_enabled is True
    d.set_env_gate(False)
    assert d.effective_enabled is False


@pytestmark_native
def test_paranoid_overrides_env_gate_off() -> None:
    d = ct.CoverTrafficDaemon(rate_hz=10.0)
    d.set_env_gate(False)
    d.set_user_mode("paranoid")
    assert d.effective_enabled is True


@pytestmark_native
def test_battery_save_overrides_env_gate_on() -> None:
    d = ct.CoverTrafficDaemon(rate_hz=10.0)
    d.set_env_gate(True)
    d.set_user_mode("battery_save")
    assert d.effective_enabled is False


@pytestmark_native
def test_start_refuses_in_battery_save() -> None:
    d = ct.CoverTrafficDaemon(rate_hz=10.0)
    d.set_user_mode("battery_save")
    d.start()
    # Refused — no thread started.
    assert d.is_running is False


@pytestmark_native
def test_apply_mode_contract_starts_when_paranoid() -> None:
    d = ct.CoverTrafficDaemon(rate_hz=10.0)
    d.set_user_mode("paranoid")
    transitioned = d.apply_mode_contract()
    assert transitioned is True
    assert d.is_running is True
    # Idempotent — second call is a no-op.
    assert d.apply_mode_contract() is False
    d.stop(join_timeout=2.0)


@pytestmark_native
def test_apply_mode_contract_stops_when_switching_to_battery_save() -> None:
    d = ct.CoverTrafficDaemon(rate_hz=10.0)
    d.set_user_mode("paranoid")
    d.apply_mode_contract()
    assert d.is_running is True
    d.set_user_mode("battery_save")
    transitioned = d.apply_mode_contract()
    assert transitioned is True
    assert d.is_running is False


@pytestmark_native
def test_stats_dict_shape() -> None:
    d = ct.CoverTrafficDaemon(rate_hz=10.0)
    d.set_user_mode("paranoid")
    s = d.stats()
    expected_keys = {
        "rate_hz", "user_mode", "env_gate", "effective_enabled",
        "running", "emitted", "errors", "mandated_by_mode",
        "forbidden_by_mode",
    }
    assert set(s.keys()) >= expected_keys
    assert s["mandated_by_mode"] is True
    assert s["forbidden_by_mode"] is False


# ---------- Daemon-level cover-traffic wiring ----------


def _bare_daemon():
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d._user_mode_value = "normal"
    d._cover_traffic = None
    d._cover_traffic_env_gate = False
    return d


def test_daemon_cover_traffic_stats_when_native_missing(monkeypatch) -> None:
    d = _bare_daemon()
    # Force native-missing path.
    monkeypatch.setattr(
        ct, "HAS_NATIVE", False, raising=False,
    )
    stats = d.cover_traffic_stats()
    assert stats["available"] is False
    assert stats["running"] is False
    assert stats["user_mode"] == "normal"


def test_daemon_apply_cover_traffic_mode_contract_no_emitter_normal_mode() -> None:
    """Normal mode + env gate off + no prior emitter -> no-op."""
    d = _bare_daemon()
    transitioned = d._apply_cover_traffic_mode_contract()
    assert transitioned is False
    assert d._cover_traffic is None


def test_daemon_apply_cover_traffic_skips_battery_save_when_no_emitter() -> None:
    """battery_save + no prior emitter -> no-op (don't construct one
    just to immediately turn it off)."""
    d = _bare_daemon()
    d._user_mode_value = "battery_save"
    transitioned = d._apply_cover_traffic_mode_contract()
    assert transitioned is False
    assert d._cover_traffic is None


def test_daemon_apply_cover_traffic_battery_save_stops_existing_emitter() -> None:
    """When an emitter is already running and mode flips to
    battery_save, the contract reconciliation must stop it."""
    d = _bare_daemon()
    mock_emitter = MagicMock()
    mock_emitter.apply_mode_contract.return_value = True
    d._cover_traffic = mock_emitter
    d._user_mode_value = "battery_save"
    transitioned = d._apply_cover_traffic_mode_contract()
    assert transitioned is True
    mock_emitter.set_user_mode.assert_called_with("battery_save")
    mock_emitter.apply_mode_contract.assert_called_once()


def test_daemon_cover_traffic_stats_with_emitter() -> None:
    d = _bare_daemon()
    mock_emitter = MagicMock()
    mock_emitter.stats.return_value = {
        "user_mode": "paranoid",
        "env_gate": True,
        "effective_enabled": True,
        "running": True,
        "emitted": 7,
        "errors": 0,
    }
    d._cover_traffic = mock_emitter
    stats = d.cover_traffic_stats()
    assert stats["available"] is True
    assert stats["emitted"] == 7
    assert stats["user_mode"] == "paranoid"


def test_daemon_cover_traffic_stats_survives_emitter_exception() -> None:
    d = _bare_daemon()
    mock_emitter = MagicMock()
    mock_emitter.stats.side_effect = RuntimeError("simulated")
    d._cover_traffic = mock_emitter
    stats = d.cover_traffic_stats()
    assert "error" in stats
