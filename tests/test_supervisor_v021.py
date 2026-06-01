"""Daemon supervisor — auto-restart on crash.

This module is small and load-bearing: it has to spawn the daemon,
wait, detect a crash vs a clean exit, back off, and circuit-break.
Every branch is exercised here with injected fakes (spawn / sleep /
clock) so we can drive a year of fake crashes in milliseconds and
assert exact behavior without ever launching a real subprocess.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from one_link import crash_log, supervisor


@pytest.fixture
def isolated_data_dir(tmp_path, monkeypatch):
    """Same isolation contract as test_crash_log_v021 — keep test
    crashes and restart logs out of the user's real data dir."""
    import one_link.paths as paths_mod
    monkeypatch.setattr(paths_mod, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(supervisor, "data_dir", lambda: tmp_path, raising=False)
    monkeypatch.setattr(crash_log, "data_dir", lambda: tmp_path, raising=False)
    return tmp_path


@pytest.fixture(autouse=True)
def silent_signal_handlers(monkeypatch):
    """pytest already owns SIGINT — replace install_signal_handlers
    with a no-op so the test harness doesn't fight the test runner."""
    monkeypatch.setattr(supervisor, "_install_signal_handlers", lambda h: None)


def _fake_proc(exit_code: int):
    """Construct a minimal Popen-shaped stub that wait() returns ``exit_code``."""
    proc = SimpleNamespace()
    proc.pid = 12345
    proc.returncode = exit_code
    proc.poll = lambda: exit_code
    proc.wait = lambda: exit_code
    proc.send_signal = lambda sig: None
    return proc


# ─── backoff schedule ──────────────────────────────────────────────────

def test_backoff_progresses_and_saturates():
    schedule = [supervisor._backoff(i) for i in range(20)]
    # Strictly non-decreasing.
    for a, b in zip(schedule, schedule[1:]):
        assert b >= a
    # Eventually saturates at the last entry.
    assert schedule[-1] == supervisor.BACKOFF_SCHEDULE_S[-1]
    # First entry is the small initial delay.
    assert schedule[0] == supervisor.BACKOFF_SCHEDULE_S[0]


def test_backoff_negative_idx_clamps_to_first():
    """Defensive: a stale counter must never index out-of-bounds."""
    assert supervisor._backoff(-7) == supervisor.BACKOFF_SCHEDULE_S[0]


# ─── clean exit path ───────────────────────────────────────────────────

def test_clean_exit_does_not_restart(isolated_data_dir):
    """exit code 0 from the daemon → supervisor exits clean, no respawn."""
    calls = []
    def fake_spawn(log_path):
        calls.append(log_path)
        return _fake_proc(0)
    fake_sleep = mock.MagicMock()
    rc = supervisor.run(spawn=fake_spawn, sleep=fake_sleep)
    assert rc == 0
    assert len(calls) == 1, "should not spawn again after clean exit"
    fake_sleep.assert_not_called()


# ─── spawn failure ─────────────────────────────────────────────────────

def test_spawn_failure_returns_2(isolated_data_dir):
    def fake_spawn(log_path):
        raise OSError("simulated exec failure")
    rc = supervisor.run(spawn=fake_spawn, sleep=lambda s: None)
    assert rc == 2


def test_spawn_failure_writes_crash_dump(isolated_data_dir):
    def fake_spawn(log_path):
        raise OSError("simulated exec failure")
    supervisor.run(spawn=fake_spawn, sleep=lambda s: None)
    crash_files = list((isolated_data_dir / "crashes").glob("*.txt"))
    assert any("supervisor-spawn-failed" in f.name for f in crash_files)


# ─── crash → restart with backoff ──────────────────────────────────────

def test_single_crash_restarts_then_clean_exit_ends(isolated_data_dir):
    exits = iter([1, 0])  # crash, then clean
    def fake_spawn(log_path):
        return _fake_proc(next(exits))
    sleeps = []
    rc = supervisor.run(
        spawn=fake_spawn,
        sleep=sleeps.append,
        max_crashes=10,
        window_s=60.0,
    )
    assert rc == 0
    assert sleeps == [supervisor.BACKOFF_SCHEDULE_S[0]], (
        "exactly one backoff sleep between the crash and the clean restart"
    )


def test_consecutive_crashes_increase_backoff(isolated_data_dir):
    exits = iter([1, 1, 1, 0])
    def fake_spawn(log_path):
        return _fake_proc(next(exits))
    sleeps = []
    rc = supervisor.run(
        spawn=fake_spawn,
        sleep=sleeps.append,
        max_crashes=10,
        window_s=60.0,
    )
    assert rc == 0
    # Three crashes → three sleeps with the first three backoff entries.
    assert sleeps == list(supervisor.BACKOFF_SCHEDULE_S[:3])


# ─── circuit breaker ───────────────────────────────────────────────────

def test_circuit_breaker_trips_after_max_crashes(isolated_data_dir):
    def fake_spawn(log_path):
        return _fake_proc(1)
    sleeps = []
    rc = supervisor.run(
        spawn=fake_spawn,
        sleep=sleeps.append,
        max_crashes=3,
        window_s=60.0,
    )
    assert rc == 3
    # 3 crashes within window → no backoff sleep for the trip itself, but
    # there are exactly 2 sleeps between the 3 crashes.
    assert len(sleeps) == 2


def test_circuit_breaker_window_slides(isolated_data_dir):
    """Crashes older than ``window_s`` drop out — the supervisor can
    survive a slow trickle indefinitely without tripping."""
    # Fake clock: each tick is 100s, so EVERY crash is "old" by the
    # next iteration and never accumulates.
    ticker = iter([0.0, 100.0, 200.0, 300.0, 400.0, 500.0])
    def fake_now():
        return next(ticker)
    # Daemon crashes 3 times, then exits clean.
    exits = iter([1, 1, 1, 0])
    def fake_spawn(log_path):
        return _fake_proc(next(exits))
    rc = supervisor.run(
        spawn=fake_spawn,
        sleep=lambda s: None,
        now=fake_now,
        max_crashes=2,
        window_s=60.0,
    )
    # Each crash falls outside the 60s window, so the counter never
    # reaches 2 in-window. Should NOT trip.
    assert rc == 0


def test_circuit_breaker_dump_records_exit_code(isolated_data_dir):
    def fake_spawn(log_path):
        return _fake_proc(137)  # SIGKILL convention
    supervisor.run(
        spawn=fake_spawn, sleep=lambda s: None,
        max_crashes=1, window_s=60.0,
    )
    crashes = list((isolated_data_dir / "crashes").glob("*daemon-supervised-exit*"))
    assert crashes
    body = crashes[0].read_text(encoding="utf-8")
    assert "exit_code: 137" in body


# ─── restart-log audit trail ───────────────────────────────────────────

def test_restart_log_records_every_lifecycle_event(isolated_data_dir):
    exits = iter([1, 1, 0])
    def fake_spawn(log_path):
        return _fake_proc(next(exits))
    supervisor.run(spawn=fake_spawn, sleep=lambda s: None,
                   max_crashes=5, window_s=60.0)
    audit = (isolated_data_dir / supervisor.RESTART_LOG_FILE).read_text(encoding="utf-8")
    lines = [l for l in audit.splitlines() if l.strip()]
    assert len(lines) == 3
    assert "daemon-crash\texit=1" in lines[0]
    assert "daemon-crash\texit=1" in lines[1]
    assert "clean-exit\texit=0" in lines[2]


def test_restart_log_records_circuit_breaker(isolated_data_dir):
    def fake_spawn(log_path):
        return _fake_proc(1)
    supervisor.run(spawn=fake_spawn, sleep=lambda s: None,
                   max_crashes=2, window_s=60.0)
    audit = (isolated_data_dir / supervisor.RESTART_LOG_FILE).read_text(encoding="utf-8")
    assert "circuit-breaker" in audit


# ─── pid file lifecycle ────────────────────────────────────────────────

def test_pid_file_written_and_cleaned_up(isolated_data_dir):
    seen_pid: list[str] = []
    def fake_spawn(log_path):
        # Check pid file exists DURING the run, while waiting on daemon.
        try:
            seen_pid.append(
                (isolated_data_dir / supervisor.SUPERVISOR_PID_FILE).read_text().strip()
            )
        except OSError:
            seen_pid.append("missing")
        return _fake_proc(0)
    supervisor.run(spawn=fake_spawn, sleep=lambda s: None)
    assert seen_pid == [str(os.getpid())]
    assert not (isolated_data_dir / supervisor.SUPERVISOR_PID_FILE).exists()


# ─── daemon argv ───────────────────────────────────────────────────────

def test_daemon_argv_source_mode(monkeypatch):
    monkeypatch.setattr(supervisor.sys, "frozen", False, raising=False)
    argv = supervisor._daemon_argv()
    assert argv[1:] == ["-m", "one_link.cli", "daemon", "-v"]


def test_daemon_argv_frozen_mode(monkeypatch):
    monkeypatch.setattr(supervisor.sys, "frozen", True, raising=False)
    argv = supervisor._daemon_argv()
    assert argv[1:] == ["daemon", "-v"]


# ─── safe_task containment ─────────────────────────────────────────────

def test_safe_task_swallows_exception(isolated_data_dir):
    """A throwing task must not propagate to the caller's await."""
    import asyncio

    async def raiser():
        raise RuntimeError("bad task")

    async def driver():
        t = crash_log.safe_task(raiser(), name="raiser-test")
        # await must NOT raise — that's the whole point of containment.
        await t
        return t

    t = asyncio.run(driver())
    # The task's exception was swallowed by the contained body, so the
    # task object reports no exception (it returned None).
    assert t.exception() is None


def test_safe_task_writes_crash_dump(isolated_data_dir):
    import asyncio

    async def raiser():
        raise KeyError("contained-failure-key")

    async def driver():
        t = crash_log.safe_task(raiser(), name="dump-test")
        await t

    asyncio.run(driver())
    files = list((isolated_data_dir / "crashes").glob("*task-dump-test*"))
    assert files, "safe_task must write a crash dump on failure"
    body = files[0].read_text(encoding="utf-8")
    assert "contained-failure-key" in body
    assert "task: dump-test" in body


def test_safe_task_re_raises_cancellation(isolated_data_dir):
    """CancelledError MUST propagate — it's how asyncio cleans up."""
    import asyncio

    async def slow():
        await asyncio.sleep(10)

    async def driver():
        t = crash_log.safe_task(slow(), name="slow-test")
        await asyncio.sleep(0)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t

    asyncio.run(driver())


def test_safe_task_calls_on_error(isolated_data_dir):
    import asyncio

    captured = []

    async def raiser():
        raise ValueError("for on_error")

    async def driver():
        t = crash_log.safe_task(
            raiser(), name="onerr-test",
            on_error=lambda e: captured.append(repr(e)),
        )
        await t

    asyncio.run(driver())
    assert captured == ["ValueError('for on_error')"]


def test_spawn_supervisor_uses_correct_argv_source_mode(tmp_path, monkeypatch):
    """Launcher must launch the supervisor CLI command, not the daemon
    directly, when --supervise is in play."""
    from one_link import app as app_mod
    captured = {}
    def fake_detached(args, log_path, **kwargs):
        captured["args"] = list(args)
        captured["env"] = kwargs.get("env")
        return SimpleNamespace()
    monkeypatch.setattr(app_mod, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(
        app_mod, "_spawn_daemon_windows_detached", fake_detached,
    )
    monkeypatch.setattr(app_mod.subprocess, "Popen", lambda *a, **k: SimpleNamespace())
    monkeypatch.setattr(app_mod.sys, "frozen", False, raising=False)
    app_mod._spawn_supervisor()
    if os.name == "nt":
        assert captured["args"][-2:] == ["-m", "one_link.cli"] or (
            captured["args"][1:] == ["-m", "one_link.cli", "supervisor"]
        )
        # The supervisor subcommand is what differentiates this from
        # _spawn_daemon. Be tolerant of how _spawn_daemon_windows_detached
        # builds the argv but insist 'supervisor' is the last token.
        assert captured["args"][-1] == "supervisor"
        assert captured["env"] is not None
        assert captured["env"].get("PYTHONUNBUFFERED") == "1"


def test_app_cli_threads_supervise_flag_to_run_app(monkeypatch):
    """The --supervise flag must reach run_app — not silently dropped."""
    from click.testing import CliRunner
    from one_link import cli as cli_mod
    captured = {}
    def fake_run_app(**kwargs):
        captured.update(kwargs)
        return 0
    monkeypatch.setattr("one_link.app.run_app", fake_run_app)
    runner = CliRunner()
    res = runner.invoke(cli_mod.cli, ["app", "--supervise", "--no-browser"])
    assert res.exit_code == 0, res.output
    assert captured.get("supervise") is True


def test_app_cli_default_supervise_is_true(monkeypatch):
    """``one-link app`` with no flags runs the daemon supervised by
    default — auto-restart on crash is the right thing for a
    production-feeling app. ``--no-supervise`` is the opt-out for
    interactive debugging or other "I want crashes to be visible"
    contexts."""
    from click.testing import CliRunner
    from one_link import cli as cli_mod
    captured = {}
    def fake_run_app(**kwargs):
        captured.update(kwargs)
        return 0
    monkeypatch.setattr("one_link.app.run_app", fake_run_app)
    runner = CliRunner()
    res = runner.invoke(cli_mod.cli, ["app", "--no-browser"])
    assert res.exit_code == 0, res.output
    assert captured.get("supervise") is True


def test_app_cli_no_supervise_flag_opts_out(monkeypatch):
    """``--no-supervise`` must reach run_app as supervise=False."""
    from click.testing import CliRunner
    from one_link import cli as cli_mod
    captured = {}
    def fake_run_app(**kwargs):
        captured.update(kwargs)
        return 0
    monkeypatch.setattr("one_link.app.run_app", fake_run_app)
    runner = CliRunner()
    res = runner.invoke(cli_mod.cli, ["app", "--no-supervise", "--no-browser"])
    assert res.exit_code == 0, res.output
    assert captured.get("supervise") is False


def test_safe_task_survives_on_error_raising(isolated_data_dir):
    """An on_error callback that itself raises must not crash the
    contained guard. The task is already in its failure path; making
    the wall fail-loud here would be doubly bad."""
    import asyncio

    async def raiser():
        raise RuntimeError("first failure")

    def bad_on_error(_e):
        raise OSError("on_error itself broke")

    async def driver():
        t = crash_log.safe_task(
            raiser(), name="onerr-bad", on_error=bad_on_error,
        )
        await t

    # No exception propagates.
    asyncio.run(driver())
