"""v0.21.x Ship 6 behavioral tests — bandwidth throttle + quiet
hours + manual pause.

Tests the math of _time_in_window (wrap-midnight!), the actual
sleep behavior of _throttle_chunk, and the integration of all
rules in _sync_paused_or_quiet.
"""
from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from one_link.daemon import Daemon
from one_link.state import State


# ── _time_in_window math ────────────────────────────────────────────


class _FakeNow:
    """Stub for datetime.now() in _time_in_window tests."""
    def __init__(self, hour: int, minute: int):
        self.hour = hour
        self.minute = minute


def _at_time(hour: int, minute: int):
    """Context manager that pins datetime.now() globally during the
    test. _time_in_window does `from datetime import datetime` at
    call time + then calls datetime.now(), so we patch the global
    datetime class's now classmethod."""
    import datetime as _dt
    return patch.object(
        _dt, "datetime",
        type("FakeDatetime", (_dt.datetime,), {
            "now": classmethod(lambda cls, tz=None: _FakeNow(hour, minute)),
        }),
    )


def test_time_in_window_simple_range():
    """09:00 → 17:00 is on at 12:00, off at 18:00."""
    with _at_time(12, 0):
        assert Daemon._time_in_window("09:00", "17:00") is True
    with _at_time(18, 0):
        assert Daemon._time_in_window("09:00", "17:00") is False
    with _at_time(8, 59):
        assert Daemon._time_in_window("09:00", "17:00") is False


def test_time_in_window_inclusive_of_start():
    """Start boundary is inclusive (09:00:00 IS inside the window)."""
    with _at_time(9, 0):
        assert Daemon._time_in_window("09:00", "17:00") is True


def test_time_in_window_exclusive_of_end():
    """End boundary is exclusive (17:00:00 is NOT inside the window)."""
    with _at_time(17, 0):
        assert Daemon._time_in_window("09:00", "17:00") is False


def test_time_in_window_wraps_midnight():
    """22:00 → 07:00 must include 23:30 AND 03:00 AND exclude 12:00."""
    with _at_time(23, 30):
        assert Daemon._time_in_window("22:00", "07:00") is True
    with _at_time(3, 0):
        assert Daemon._time_in_window("22:00", "07:00") is True
    with _at_time(12, 0):
        assert Daemon._time_in_window("22:00", "07:00") is False
    with _at_time(22, 0):  # inclusive of start
        assert Daemon._time_in_window("22:00", "07:00") is True
    with _at_time(7, 0):  # exclusive of end
        assert Daemon._time_in_window("22:00", "07:00") is False


def test_time_in_window_equal_endpoints_is_no_window():
    """s == e means 'no quiet hours' — degenerate range."""
    with _at_time(12, 0):
        assert Daemon._time_in_window("09:00", "09:00") is False
    with _at_time(9, 0):
        assert Daemon._time_in_window("09:00", "09:00") is False


def test_time_in_window_invalid_format_returns_false():
    """A malformed time string must not crash; falsy default is safe."""
    with _at_time(12, 0):
        assert Daemon._time_in_window("not-a-time", "17:00") is False
        assert Daemon._time_in_window("09:00", "bogus") is False
        assert Daemon._time_in_window("", "") is False


# ── _throttle_chunk sleep behavior ──────────────────────────────────


@pytest.mark.asyncio
async def test_throttle_chunk_no_op_when_cap_is_zero(tmp_path: Path):
    """sync_bandwidth_kbps=0 means no cap → never sleep."""
    state = State(db_path=tmp_path / "s.db")
    state.set_setting("sync_bandwidth_kbps", "0")
    daemon = MagicMock(spec=Daemon)
    daemon.state = state
    # Bind the unbound method.
    throttle = Daemon._throttle_chunk.__get__(daemon)
    t0 = time.monotonic()
    await throttle(1_000_000_000, time.monotonic() - 0.001)
    elapsed = time.monotonic() - t0
    assert elapsed < 0.05, "no-cap path must not sleep"
    state.close()


@pytest.mark.asyncio
async def test_throttle_chunk_no_op_when_state_missing(tmp_path: Path):
    """Defensive: state=None must not crash, just no-op."""
    daemon = MagicMock(spec=Daemon)
    daemon.state = None
    throttle = Daemon._throttle_chunk.__get__(daemon)
    t0 = time.monotonic()
    await throttle(1_000_000, time.monotonic())
    assert time.monotonic() - t0 < 0.05


@pytest.mark.asyncio
async def test_throttle_chunk_sleeps_to_meet_cap(tmp_path: Path):
    """With sync_bandwidth_kbps=100 (= 100 KB/s = 102400 B/s) and
    bytes_sent=204800 (200 KB), the target time is 2.0s. If we've
    only spent 0.1s, _throttle_chunk should sleep ~1.9s."""
    state = State(db_path=tmp_path / "s.db")
    state.set_setting("sync_bandwidth_kbps", "100")
    daemon = MagicMock(spec=Daemon)
    daemon.state = state
    throttle = Daemon._throttle_chunk.__get__(daemon)
    started_at = time.monotonic() - 0.1  # we've only spent 0.1s so far
    bytes_sent = 102_400  # 100 KB → should sit at 1.0s elapsed
    t0 = time.monotonic()
    await throttle(bytes_sent, started_at)
    elapsed = time.monotonic() - t0
    # Expected sleep ≈ 0.9s. Allow 0.5–1.3s for jitter.
    assert 0.5 <= elapsed <= 1.3, f"expected ~0.9s sleep, got {elapsed:.3f}s"
    state.close()


# ── _sync_paused_or_quiet integration ───────────────────────────────


def _make_daemon_with_state(tmp_path: Path) -> tuple[Daemon, State]:
    state = State(db_path=tmp_path / "s.db")
    daemon = MagicMock(spec=Daemon)
    daemon.state = state
    # _power_state class method needs the real class, not the mock,
    # so bind it.
    daemon._power_state = lambda: {"on_battery": False, "metered": False}
    daemon._network_is_metered = lambda: False
    return daemon, state


def test_sync_paused_when_user_paused(tmp_path: Path):
    daemon, state = _make_daemon_with_state(tmp_path)
    state.set_setting("sync_paused", "true")
    bound = Daemon._sync_paused_or_quiet.__get__(daemon)
    skip, reason = bound()
    assert skip is True
    assert "paused" in reason.lower()
    state.close()


def test_sync_not_paused_when_nothing_active(tmp_path: Path):
    daemon, state = _make_daemon_with_state(tmp_path)
    bound = Daemon._sync_paused_or_quiet.__get__(daemon)
    skip, reason = bound()
    assert skip is False
    state.close()


def test_sync_paused_during_quiet_hours(tmp_path: Path):
    daemon, state = _make_daemon_with_state(tmp_path)
    state.set_setting("sync_quiet_hours_enabled", "true")
    state.set_setting("sync_quiet_start", "00:00")
    state.set_setting("sync_quiet_end", "23:59")
    bound = Daemon._sync_paused_or_quiet.__get__(daemon)
    skip, reason = bound()
    assert skip is True
    assert "quiet" in reason.lower()
    state.close()


def test_sync_paused_on_metered_when_setting_on(tmp_path: Path):
    daemon, state = _make_daemon_with_state(tmp_path)
    state.set_setting("sync_pause_on_metered", "true")
    daemon._network_is_metered = lambda: True
    bound = Daemon._sync_paused_or_quiet.__get__(daemon)
    skip, reason = bound()
    assert skip is True
    assert "metered" in reason.lower()
    state.close()


def test_sync_not_paused_on_metered_when_setting_off(tmp_path: Path):
    daemon, state = _make_daemon_with_state(tmp_path)
    state.set_setting("sync_pause_on_metered", "false")
    daemon._network_is_metered = lambda: True
    bound = Daemon._sync_paused_or_quiet.__get__(daemon)
    skip, reason = bound()
    assert skip is False
    state.close()
