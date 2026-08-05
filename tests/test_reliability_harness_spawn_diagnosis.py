"""A crashed daemon and a slow daemon must not report the same failure.

The 50-pair soak scored 48/50 on 2026-08-05 with two `spawn_a` failures, both
reported as "A never wrote ready files". The daemon logs showed normal progress
right up to the 30-second cutoff -- keychain mint, at-rest encryption active --
so nothing had crashed. Profiling the code in that window measured 0.56-0.72s on
an idle machine, with and without the native engine, so the lost time was runner
contention rather than the product.

The defect was in the harness, not the daemon: `_wait_ready` returned `None`
for both "the process died" and "the process is still starting", and the caller
turned both into the same sentence. A gate that cannot tell broken from slow
produces false reds, and false reds train people to ignore the gate.

These tests pin the three outcomes. The last one is the control: the grace
extension must not rescue a daemon that never becomes ready, or the harness
would stop detecting the regressions it exists for.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _harness():
    """Load the script by path; scripts/ is not an importable package."""
    spec = importlib.util.spec_from_file_location(
        "reliability_harness", REPO / "scripts" / "reliability_harness.py"
    )
    module = importlib.util.module_from_spec(spec)
    # Registered BEFORE exec: @dataclass resolves annotations via
    # sys.modules[cls.__module__], so a module that is not registered yet
    # fails collection with a bare AttributeError on NoneType.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


harness = _harness()


class _FakeProc:
    """Stands in for Popen: only poll() and returncode are consulted."""

    def __init__(self, exits_after: float | None = None, code: int = 3):
        self._exits_after = exits_after
        self._born = time.time()
        self.returncode: int | None = None

    def poll(self):
        if self._exits_after is not None and time.time() - self._born >= self._exits_after:
            self.returncode = 3
            return 3
        return None


def test_a_dead_daemon_is_reported_as_dead_immediately(tmp_path):
    """The regression: a crash used to cost 30s and be called a timeout.

    Reporting it in milliseconds, with the exit code, is the difference
    between a diagnosable failure and a mystery.
    """
    proc = _FakeProc(exits_after=0.0)
    started = time.time()
    with pytest.raises(harness.SpawnDied) as excinfo:
        harness._wait_ready(tmp_path, timeout=30.0, proc=proc, label="A")
    elapsed = time.time() - started

    assert elapsed < 5.0, (
        f"a dead process took {elapsed:.1f}s to report; it must fail fast"
    )
    message = str(excinfo.value)
    assert "exited with code 3" in message, message
    assert "A" in message


def test_a_slow_daemon_gets_one_grace_extension(tmp_path):
    """Alive and still starting is not broken.

    The budget is small here so the test is fast; what is asserted is that the
    wait lasted LONGER than one budget, which only happens if the extension
    fired.
    """
    proc = _FakeProc()  # never exits
    started = time.time()
    with pytest.raises(harness.SpawnTooSlow) as excinfo:
        harness._wait_ready(
            tmp_path, timeout=0.4, proc=proc, label="A", grace_extensions=1
        )
    elapsed = time.time() - started

    assert elapsed >= 0.8, (
        f"only waited {elapsed:.2f}s; the grace extension did not fire"
    )
    message = str(excinfo.value)
    assert "1 grace extension(s) used" in message, message
    assert "still running" in message, message


def test_the_grace_extension_is_bounded(tmp_path):
    """CONTROL. Without this, the fix would be an unbounded wait.

    A harness that retried forever would never report a hung daemon, which is
    precisely the regression class this gate exists to catch. Two budgets, then
    it must give up.
    """
    proc = _FakeProc()
    started = time.time()
    with pytest.raises(harness.SpawnTooSlow):
        harness._wait_ready(
            tmp_path, timeout=0.3, proc=proc, label="A", grace_extensions=1
        )
    elapsed = time.time() - started
    assert elapsed < 3.0, (
        f"waited {elapsed:.2f}s for a budget of 0.3s x 2; the bound is not holding"
    )


def test_no_extension_is_used_when_none_are_allowed(tmp_path):
    """grace_extensions=0 must behave exactly as the old code did."""
    proc = _FakeProc()
    started = time.time()
    with pytest.raises(harness.SpawnTooSlow) as excinfo:
        harness._wait_ready(
            tmp_path, timeout=0.3, proc=proc, label="A", grace_extensions=0
        )
    elapsed = time.time() - started
    assert elapsed < 1.0
    assert "0 grace extension(s) used" in str(excinfo.value)


def test_a_ready_daemon_returns_its_port_and_token(tmp_path, monkeypatch):
    """CONTROL for every test above.

    All of them assert that something RAISES. A `_wait_ready` that always
    raised would satisfy the lot, so the success path has to be proven too.
    """
    data = tmp_path / "data"
    data.mkdir(parents=True)
    (data / "control.port").write_text("45999", encoding="utf-8")

    monkeypatch.setattr(
        harness.control_ipc, "read_private_bytes_strict",
        lambda path, **kw: b"45999",
    )
    monkeypatch.setattr(
        harness.control_ipc, "read_control_secret", lambda d: b"secret"
    )

    class _Daemon:
        server_port = 7117
        token = "tok"

    monkeypatch.setattr(
        harness.app_mod, "resolve_authenticated_daemon",
        lambda port, secret, timeout: _Daemon(),
    )

    port, token = harness._wait_ready(
        tmp_path, timeout=5.0, proc=_FakeProc(), label="A"
    )
    assert (port, token) == (7117, "tok")


def test_the_call_sites_pass_the_process_in() -> None:
    """The fast-crash path only works if the caller supplies the process.

    Without this the diagnosis silently degrades to the old behaviour while
    every unit test above keeps passing, because they call `_wait_ready`
    directly.
    """
    source = (REPO / "scripts" / "reliability_harness.py").read_text(encoding="utf-8")
    assert 'proc=a_proc, label="A"' in source
    assert 'proc=b_proc, label="B"' in source
    assert "a_ready" not in source, "the old None-returning call shape is back"
    assert "b_ready" not in source
