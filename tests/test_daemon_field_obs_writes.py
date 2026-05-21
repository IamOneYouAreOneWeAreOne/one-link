"""Tests for daemon-side field-observation writes (D23 wiring).

Verifies:
  - _write_field_observation populates the field buffer.
  - Out-of-range values are clamped (don't crash).
  - Unknown trust falls back to 0.5 dampening.
  - _tau_for_transfer_status maps statuses sanely.
  - Writes survive missing native module.
"""

from __future__ import annotations

import math
from unittest.mock import MagicMock

import pytest

from one_link import daemon as daemon_module
from one_link.daemon import _tau_for_transfer_status


def _bare_daemon():
    """A Daemon instance without going through full __init__.

    We patch only what _write_field_observation actually touches.
    """
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d.state.get_peer.return_value = None
    d._field_obs = MagicMock()
    return d


# ---------- _tau_for_transfer_status ----------


def test_tau_terminal_success_high() -> None:
    assert _tau_for_transfer_status("done") == 0.95
    assert _tau_for_transfer_status("COMPLETED") == 0.95


def test_tau_in_progress_mid() -> None:
    assert _tau_for_transfer_status("sending") == 0.55


def test_tau_failure_low() -> None:
    assert _tau_for_transfer_status("failed") == 0.05
    assert _tau_for_transfer_status("timeout") == 0.05


def test_tau_unknown_returns_none() -> None:
    assert _tau_for_transfer_status("xyzzy") is None
    assert _tau_for_transfer_status("") is None
    assert _tau_for_transfer_status("queued") is None


def test_tau_monotone_health_ordering() -> None:
    """Sanity: terminal-success > in-flight > failure."""
    assert (_tau_for_transfer_status("done") or 0) > (
        _tau_for_transfer_status("sending") or 0
    ) > (_tau_for_transfer_status("failed") or 0)


# ---------- _write_field_observation ----------


def test_write_field_obs_calls_native() -> None:
    d = _bare_daemon()
    d._write_field_observation("peer_fp_x", 0.7, source="test")
    # Called with peer_fp, tau, trust (default 0.5 because peer is None).
    d._field_obs.update.assert_called_once()
    call_args = d._field_obs.update.call_args
    assert call_args[0][0] == "peer_fp_x"
    assert call_args[0][1] == 0.7
    # trust defaults to 0.5 since the peer is unknown.
    assert call_args[0][2] == 0.5


def test_write_field_obs_clamps_high() -> None:
    d = _bare_daemon()
    d._write_field_observation("peer1", 1.5)
    args = d._field_obs.update.call_args[0]
    assert args[1] == 1.0  # clamped


def test_write_field_obs_clamps_low() -> None:
    d = _bare_daemon()
    d._write_field_observation("peer1", -0.5)
    args = d._field_obs.update.call_args[0]
    assert args[1] == 0.0  # clamped


def test_write_field_obs_rejects_nan() -> None:
    d = _bare_daemon()
    d._write_field_observation("peer1", math.nan)
    # NaN should be dropped without calling update.
    d._field_obs.update.assert_not_called()


def test_write_field_obs_no_op_when_native_missing() -> None:
    d = _bare_daemon()
    d._field_obs = None
    # Must not raise.
    d._write_field_observation("peer1", 0.5)


def test_write_field_obs_no_op_on_empty_peer() -> None:
    d = _bare_daemon()
    d._write_field_observation("", 0.5)
    d._field_obs.update.assert_not_called()


def test_write_field_obs_survives_native_exception() -> None:
    d = _bare_daemon()
    d._field_obs.update.side_effect = ValueError("simulated")
    # Must not raise.
    d._write_field_observation("peer1", 0.5)


def test_write_field_obs_uses_real_trust_when_peer_known() -> None:
    d = _bare_daemon()
    # Patch _peer_trust_score to return a known value.
    d.state.get_peer.return_value = MagicMock(trust="pinned", last_seen_ms=1_700_000_000_000)
    # Call write
    d._write_field_observation("peer_with_trust", 0.5)
    # Should have called update with peer_fp, 0.5, and some trust value.
    d._field_obs.update.assert_called_once()
    args = d._field_obs.update.call_args[0]
    assert args[0] == "peer_with_trust"
    assert args[1] == 0.5
    # Trust should be in (0, 1] — actual value depends on staleness,
    # but it's a paired peer so should be reasonably high.
    trust = args[2]
    assert 0.0 <= trust <= 1.0
