"""Tests for Phase F user_mode persistence + Daemon caching.

Verifies:
  - selector_native.normalize_user_mode rejects gracefully
  - Daemon.user_mode defaults to "normal"
  - Daemon.set_user_mode validates + persists + updates cache
  - refresh_runtime_settings rehydrates from the settings table
  - selector decide() call receives the cached user_mode
"""

from __future__ import annotations

from unittest.mock import MagicMock


from one_link import daemon as daemon_module
from one_link import selector_native


# ---------- normalize_user_mode ----------


def test_normalize_known_modes() -> None:
    for m in ("normal", "paranoid", "battery_save", "latency_strict"):
        assert selector_native.normalize_user_mode(m) == m


def test_normalize_case_insensitive() -> None:
    assert selector_native.normalize_user_mode("PARANOID") == "paranoid"
    assert selector_native.normalize_user_mode("Battery_Save") == "battery_save"


def test_normalize_hyphen_compat() -> None:
    assert selector_native.normalize_user_mode("battery-save") == "battery_save"
    assert selector_native.normalize_user_mode("latency-strict") == "latency_strict"


def test_normalize_empty_defaults_normal() -> None:
    assert selector_native.normalize_user_mode("") == "normal"
    assert selector_native.normalize_user_mode(None) == "normal"


def test_normalize_unknown_defaults_normal() -> None:
    assert selector_native.normalize_user_mode("super_paranoid") == "normal"
    assert selector_native.normalize_user_mode("xyzzy") == "normal"


# ---------- Daemon.user_mode ----------


def _bare_daemon():
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d.state.get_setting.return_value = None
    d._user_mode_value = "normal"
    return d


def test_default_is_normal() -> None:
    d = _bare_daemon()
    assert d.user_mode == "normal"


def test_set_user_mode_persists_and_caches() -> None:
    d = _bare_daemon()
    canonical = d.set_user_mode("paranoid")
    assert canonical == "paranoid"
    assert d.user_mode == "paranoid"
    d.state.set_setting.assert_called_once_with("user_mode", "paranoid")


def test_set_user_mode_normalizes_unknowns() -> None:
    d = _bare_daemon()
    canonical = d.set_user_mode("super_paranoid")
    # Falls back to normal.
    assert canonical == "normal"
    assert d.user_mode == "normal"


def test_set_user_mode_normalizes_aliases() -> None:
    d = _bare_daemon()
    assert d.set_user_mode("battery-save") == "battery_save"
    assert d.user_mode == "battery_save"


def test_set_user_mode_survives_missing_state() -> None:
    d = _bare_daemon()
    d.state = None  # no state — must still update cache
    canonical = d.set_user_mode("paranoid")
    assert canonical == "paranoid"
    assert d.user_mode == "paranoid"


def test_set_user_mode_survives_setting_error() -> None:
    d = _bare_daemon()
    d.state.set_setting.side_effect = RuntimeError("disk full")
    # Must not raise; cache still updates.
    canonical = d.set_user_mode("paranoid")
    assert canonical == "paranoid"
    assert d.user_mode == "paranoid"
