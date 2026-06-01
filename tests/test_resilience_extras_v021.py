"""Resilience follow-ups: append-mode launch log, supervised-vs-bare
banner, and cross-platform login auto-start.

These three fixes close the gaps that turned the original "daemon died
silently" incident into a multi-step investigation:

  * The launcher used to truncate ``daemon-launch.err.log`` on every
    spawn, deleting the supervisor's startup record + every prior
    crash's traceback. Now appended; rotated by size.
  * Every ``one-link daemon`` invocation logs its supervised status,
    so a future "was that run supposed to auto-restart?" question is
    answerable from the log alone.
  * ``autostart`` registers One Link with the OS so log-off / sleep /
    reboot bring it back without the user having to click anything.
"""
from __future__ import annotations

import inspect
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest


# ─── append-mode log + rotation ────────────────────────────────────────

def test_spawn_daemon_opens_log_in_append_mode():
    """The wb-truncate behavior is what made us LOSE the supervisor's
    startup record from the original incident's log. Lock the
    append-mode contract here so a future "make it tidy" PR can't
    silently regress it."""
    from one_link import app as app_mod
    src = inspect.getsource(app_mod._spawn_daemon)
    assert '"ab"' in src and '"wb"' not in src, (
        "_spawn_daemon POSIX path must open daemon-launch.err.log in "
        "append mode, never truncate"
    )


def test_spawn_supervisor_opens_log_in_append_mode():
    from one_link import app as app_mod
    src = inspect.getsource(app_mod._spawn_supervisor)
    assert '"ab"' in src and '"wb"' not in src


def test_spawn_daemon_windows_detached_opens_log_in_append_mode():
    from one_link import app as app_mod
    src = inspect.getsource(app_mod._spawn_daemon_windows_detached)
    assert '"ab"' in src and '"wb"' not in src


def test_rotate_daemon_launch_log_under_threshold_is_noop(tmp_path):
    from one_link import app as app_mod
    log = tmp_path / "daemon-launch.err.log"
    log.write_bytes(b"small")
    app_mod._rotate_daemon_launch_log(log)
    assert log.exists()
    assert not (tmp_path / "daemon-launch.err.log.1").exists()


def test_rotate_daemon_launch_log_over_threshold_rotates(tmp_path, monkeypatch):
    """Above the size cap we rotate to .1; older rotations shift along."""
    from one_link import app as app_mod
    monkeypatch.setattr(app_mod, "DAEMON_LAUNCH_LOG_MAX_BYTES", 100)
    log = tmp_path / "daemon-launch.err.log"
    log.write_bytes(b"x" * 200)
    app_mod._rotate_daemon_launch_log(log)
    assert not log.exists(), "active log must be rotated out"
    rotated = tmp_path / "daemon-launch.err.log.1"
    assert rotated.exists()
    assert rotated.read_bytes() == b"x" * 200


def test_rotate_daemon_launch_log_shifts_existing_rotations(tmp_path, monkeypatch):
    """Pre-existing .1 / .2 / .3 files must shift before active becomes .1."""
    from one_link import app as app_mod
    monkeypatch.setattr(app_mod, "DAEMON_LAUNCH_LOG_MAX_BYTES", 100)
    monkeypatch.setattr(app_mod, "DAEMON_LAUNCH_LOG_KEEP", 3)
    log = tmp_path / "daemon-launch.err.log"
    log.write_bytes(b"NEW_TAIL")
    log.with_suffix(log.suffix + ".1").write_bytes(b"OLD_1")
    log.with_suffix(log.suffix + ".2").write_bytes(b"OLD_2")
    log.with_suffix(log.suffix + ".3").write_bytes(b"OLD_3")
    # Bump the active file over threshold and rotate.
    log.write_bytes(b"x" * 200)
    app_mod._rotate_daemon_launch_log(log)
    # .3 was the oldest → dropped.
    assert not log.with_suffix(log.suffix + ".4").exists()
    # .1 shifted to .2; .2 → .3; old .3 was dropped.
    assert log.with_suffix(log.suffix + ".2").read_bytes() == b"OLD_1"
    assert log.with_suffix(log.suffix + ".3").read_bytes() == b"OLD_2"
    # Active file was promoted to .1.
    assert log.with_suffix(log.suffix + ".1").read_bytes() == b"x" * 200


def test_rotate_daemon_launch_log_handles_missing_file(tmp_path):
    """Rotating a non-existent file is a no-op (the first launch ever)."""
    from one_link import app as app_mod
    # Must not raise.
    app_mod._rotate_daemon_launch_log(tmp_path / "never-existed.log")


# ─── supervised vs. bare banner ────────────────────────────────────────

def test_supervisor_sets_one_link_supervised_env():
    """The supervisor's spawn must mark the child env so the daemon's
    banner line can record supervised=yes."""
    from one_link import supervisor as sup_mod
    src = inspect.getsource(sup_mod._spawn_daemon_child)
    assert '"ONE_LINK_SUPERVISED": "1"' in src


def test_daemon_cli_logs_supervised_status_banner():
    """Every ``one-link daemon`` entry logs its supervised state via
    the standard logger, so a future "was that run supposed to auto-
    restart?" question is answerable from the log alone."""
    from one_link import cli as cli_mod
    # ``cli_mod.daemon`` is a click.Command — the underlying function
    # is on ``.callback``.
    src = inspect.getsource(cli_mod.daemon.callback)
    assert "ONE_LINK_SUPERVISED" in src
    assert "supervised=" in src
    assert "daemon launch" in src


# ─── autostart — Windows backend ───────────────────────────────────────

def test_autostart_launch_command_uses_supervise_and_no_browser():
    """The login-start command MUST request the supervisor (auto-
    restart) and suppress the browser (no tab in the user's face the
    moment they log in)."""
    from one_link import autostart
    cmd = autostart._launch_command()
    assert "--supervise" in cmd
    assert "--no-browser" in cmd
    assert "app" in cmd


def test_quote_for_shell_double_quotes_spaces_on_nt(monkeypatch):
    from one_link import autostart
    monkeypatch.setattr(autostart.os, "name", "nt", raising=False)
    out = autostart._quote_for_shell(["python", "with space", "plain"])
    assert '"with space"' in out
    assert "plain" in out
    assert " python " in " " + out + " "


def test_quote_for_shell_single_quotes_on_posix(monkeypatch):
    from one_link import autostart
    monkeypatch.setattr(autostart.os, "name", "posix", raising=False)
    out = autostart._quote_for_shell(["python", "with space"])
    assert "'with space'" in out
    assert "'python'" in out


def test_quote_for_shell_escapes_embedded_quotes_on_posix(monkeypatch):
    from one_link import autostart
    monkeypatch.setattr(autostart.os, "name", "posix", raising=False)
    out = autostart._quote_for_shell(["weird's name"])
    # Single quote inside single-quoted string: close, escape, reopen.
    assert "weird'\\''s name" in out


# ─── autostart — macOS backend ─────────────────────────────────────────

def test_macos_enable_writes_plist_and_round_trips(tmp_path, monkeypatch):
    from one_link import autostart
    monkeypatch.setattr(autostart.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(autostart, "_backend", lambda: "macos")
    assert autostart.is_enabled() is False
    path = autostart.enable()
    assert path.is_file()
    body = path.read_text(encoding="utf-8")
    assert "<key>RunAtLoad</key>" in body
    assert "<true/>" in body
    assert autostart.AUTOSTART_ID in body
    # Must reference the supervise + no-browser flags.
    assert "--supervise" in body
    assert "--no-browser" in body
    assert autostart.is_enabled() is True
    assert autostart.disable() is True
    assert autostart.is_enabled() is False


def test_macos_disable_idempotent_when_not_enabled(tmp_path, monkeypatch):
    from one_link import autostart
    monkeypatch.setattr(autostart.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(autostart, "_backend", lambda: "macos")
    # Never enabled; disable returns False, doesn't raise.
    assert autostart.disable() is False


# ─── autostart — Linux backend ─────────────────────────────────────────

def test_linux_enable_writes_desktop_file_and_round_trips(tmp_path, monkeypatch):
    from one_link import autostart
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(autostart, "_backend", lambda: "linux")
    assert autostart.is_enabled() is False
    path = autostart.enable()
    assert path.is_file()
    assert path.parent.name == "autostart"
    body = path.read_text(encoding="utf-8")
    assert "[Desktop Entry]" in body
    assert "Type=Application" in body
    assert "--supervise" in body
    assert "--no-browser" in body
    assert "X-GNOME-Autostart-enabled=true" in body
    assert autostart.is_enabled() is True
    assert autostart.disable() is True
    assert autostart.is_enabled() is False


def test_linux_enable_is_idempotent(tmp_path, monkeypatch):
    """Re-enabling rewrites the same file (useful after upgrading the
    binary to a different path)."""
    from one_link import autostart
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(autostart, "_backend", lambda: "linux")
    p1 = autostart.enable()
    p2 = autostart.enable()
    assert p1 == p2
    assert p1.is_file()


# ─── autostart — Windows backend (registry, only on Windows) ───────────

@pytest.mark.skipif(os.name != "nt", reason="Windows registry test")
def test_windows_enable_disable_round_trips(monkeypatch):
    """Round-trip the actual HKCU Run key. This DOES touch the user's
    real registry — but only the One Link value, which the test
    cleans up. Safe to run on a developer machine."""
    from one_link import autostart
    monkeypatch.setattr(autostart, "_backend", lambda: "windows")
    # Snapshot current state so we restore exactly.
    was_enabled = autostart.is_enabled()
    try:
        if was_enabled:
            autostart.disable()
        assert autostart.is_enabled() is False
        path = autostart.enable()
        assert "Run\\One Link" in str(path) or "Run" in str(path)
        assert autostart.is_enabled() is True
        assert autostart.disable() is True
        assert autostart.is_enabled() is False
    finally:
        if was_enabled:
            autostart.enable()


# ─── CLI surface ───────────────────────────────────────────────────────

def test_autostart_cli_group_exposes_three_subcommands():
    """``one-link autostart`` should expose status / enable / disable."""
    from click.testing import CliRunner
    from one_link import cli as cli_mod
    runner = CliRunner()
    res = runner.invoke(cli_mod.cli, ["autostart", "--help"])
    assert res.exit_code == 0
    assert "status" in res.output
    assert "enable" in res.output
    assert "disable" in res.output


def test_autostart_cli_status_prints_state(monkeypatch):
    from click.testing import CliRunner
    from one_link import autostart as autostart_mod
    from one_link import cli as cli_mod
    monkeypatch.setattr(autostart_mod, "is_enabled", lambda: True)
    monkeypatch.setattr(autostart_mod, "artifact_path",
                        lambda: Path("/fake/path/autostart"))
    runner = CliRunner()
    res = runner.invoke(cli_mod.cli, ["autostart", "status"])
    assert res.exit_code == 0
    assert "ENABLED" in res.output
    assert "/fake/path/autostart" in res.output or "fake" in res.output
