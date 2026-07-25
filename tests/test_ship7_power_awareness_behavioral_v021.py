"""v0.21.x Ship 7 behavioral tests — battery + metered detection
and the cache TTL.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from unittest.mock import patch


from one_link.daemon import Daemon
from one_link.state import State


def test_detect_on_battery_false_on_non_windows():
    """The implementation short-circuits to False on any non-nt OS."""
    with patch.object(os, "name", "posix"):
        assert Daemon._detect_on_battery() is False


def test_detect_metered_false_on_non_windows():
    with patch.object(os, "name", "posix"):
        assert Daemon._detect_metered() is False


def test_power_state_caches_results():
    """The classmethod cache must skip a second OS probe within
    _POWER_CACHE_TTL_S (30s). Verify by patching _detect_on_battery
    to count calls."""
    # Reset cache so we get a fresh probe.
    Daemon._power_cache = {"ts": 0.0, "on_battery": False, "metered": False}
    calls = {"count": 0}

    def fake_probe():
        calls["count"] += 1
        return True

    with patch.object(Daemon, "_detect_on_battery", staticmethod(fake_probe)):
        with patch.object(Daemon, "_detect_metered", staticmethod(lambda: False)):
            a = Daemon._power_state()
            b = Daemon._power_state()
            # First call probed; second was cached.
            assert calls["count"] == 1
            assert a is b  # same dict
            assert a["on_battery"] is True


def test_power_state_refreshes_after_ttl():
    """After _POWER_CACHE_TTL_S elapses, the cache MUST refresh —
    otherwise the user can never see the daemon notice they
    plugged in / connected to wifi."""
    Daemon._power_cache = {"ts": 0.0, "on_battery": False, "metered": False}
    calls = {"count": 0}

    def fake_probe():
        calls["count"] += 1
        return False

    with patch.object(Daemon, "_detect_on_battery", staticmethod(fake_probe)):
        with patch.object(Daemon, "_detect_metered", staticmethod(lambda: False)):
            Daemon._power_state()  # warm
            assert calls["count"] == 1
            # Backdate the cache so it appears stale.
            Daemon._power_cache["ts"] = time.monotonic() - 100
            Daemon._power_state()
            assert calls["count"] == 2


# ── settings persistence for sync_pause_on_battery ─────────────────


def test_sync_pause_on_battery_setting_persists(tmp_path: Path):
    """Verify the new setting key round-trips through state."""
    state = State(db_path=tmp_path / "s.db")
    state.set_setting("sync_pause_on_battery", "true")
    assert state.get_setting("sync_pause_on_battery") == "true"
    state.close()
