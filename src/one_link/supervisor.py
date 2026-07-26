"""Daemon supervisor — auto-restart on crash, with backoff + circuit breaker.

The launcher's old contract was "spawn the daemon, exit." If the daemon
died (silently or with a traceback), nothing brought it back. This
module is a tiny, single-purpose watchdog that fills that gap:

  * Spawns the daemon as an attached child (so we can wait on it).
  * On non-zero exit (crash), logs critical, dumps a crash file,
    sleeps with exponential backoff, and restarts.
  * On exit code 0 (operator-initiated clean stop), exits clean — no
    restart, no spam.
  * Circuit breaker: ``max_crashes`` crashes within ``window_s``
    seconds and we stop trying. A deterministic boot-crash loop is a
    human-attention bug, not something to mask with infinite respawn.
  * SIGINT / SIGTERM / Ctrl-Break to the supervisor forwards to the
    child (Windows: CTRL_BREAK_EVENT through the child's
    new-process-group), waits for clean shutdown, exits clean.

The complex code lives in the daemon. The supervisor is intentionally
small so it can be eyeballed end-to-end and trusted. Every public knob
has a default; every external call is in a try/except; every code path
returns a deterministic exit code.

Exit codes:
  0 — clean shutdown (operator stop OR daemon exited 0 deliberately).
  2 — supervisor failed to spawn the daemon (rare; e.g. missing exe).
  3 — circuit breaker tripped (too many crashes in window).
"""
from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable, Optional

from one_link import crash_log
from one_link.fault_observability import report_best_effort_failure
from one_link.paths import data_dir
from one_link.process_security import (
    hidden_creationflags,
    resolve_current_interpreter,
    sanitized_process_env,
)

log = logging.getLogger("one_link.supervisor")

DEFAULT_MAX_CRASHES = 5
DEFAULT_WINDOW_S = 60.0
BACKOFF_SCHEDULE_S = (1.0, 2.0, 4.0, 8.0, 16.0, 30.0)
RESTART_LOG_FILE = "supervisor.restart-log"
SUPERVISOR_PID_FILE = "supervisor.pid"
DAEMON_LAUNCH_LOG = "daemon-launch.err.log"


def _daemon_exit_is_already_running_conflict(log_path: Path) -> bool:
    """Tell apart a real crash from "another daemon owns the lock".

    Scans the tail of the launch log for the marker the daemon's
    instance-lock code raises (``One Link daemon is already running
    ... for this ONE_LINK_HOME``). When that marker is the most
    recent failure reason, retrying is pointless — the new daemon
    will hit the same wall every time. The supervisor's caller
    treats this exit code as "ask the user to close the other
    instance," not "wait + try again."
    """
    try:
        with open(log_path, "rb") as fh:
            try:
                fh.seek(-4096, os.SEEK_END)
            except OSError:
                fh.seek(0)
            tail = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return False
    return "already running" in tail and "ONE_LINK_HOME" in tail


def _backoff(idx: int) -> float:
    """Return the backoff delay for the ``idx``-th consecutive crash.

    Saturates at the last entry so an infinite crash loop (caught by
    the circuit breaker anyway) never asks for more than 30 s of sleep.
    """
    return BACKOFF_SCHEDULE_S[min(max(0, idx), len(BACKOFF_SCHEDULE_S) - 1)]


def _daemon_argv() -> list[str]:
    """Argv that re-invokes the daemon CLI.

    Mirrors ``app._spawn_daemon``'s frozen-vs-source split exactly so
    the supervisor and the no-supervise launcher path never disagree
    on what "the daemon" is.
    """
    if getattr(sys, "frozen", False):
        return [resolve_current_interpreter(), "daemon", "-v"]
    return [
        resolve_current_interpreter(),
        "-P",
        "-m",
        "one_link.cli",
        "daemon",
        "-v",
    ]


def _append_restart_log(reason: str, exit_code: Optional[int]) -> None:
    """Append a one-line audit entry to ``data_dir()/supervisor.restart-log``.

    Tab-separated for easy grep/parse. Never raises — we are usually
    on a crash path when this is called.
    """
    try:
        p = data_dir() / RESTART_LOG_FILE
        with open(p, "a", encoding="utf-8") as f:
            f.write(f"{time.time():.3f}\t{reason}\texit={exit_code}\n")
    except OSError:
        pass


def _write_pid_file() -> Optional[Path]:
    """Write the supervisor's PID to ``data_dir()/supervisor.pid``.

    Best-effort; failures are non-fatal. Mostly an aid to operators
    inspecting "what is supervising what" — not a lock.
    """
    try:
        p = data_dir() / SUPERVISOR_PID_FILE
        p.write_text(f"{os.getpid()}\n", encoding="utf-8")
        return p
    except OSError:
        return None


def _spawn_daemon_child(log_path: Path) -> subprocess.Popen:
    """Spawn the daemon as a non-detached child of this supervisor.

    Critical differences from ``app._spawn_daemon``:

      * No DETACHED_PROCESS / no breakaway-from-job — the daemon is
        OUR child so we can wait on it.
      * CREATE_NEW_PROCESS_GROUP on Windows so signals don't
        propagate up to the supervisor (we forward them explicitly).
      * Log file opened in append mode so the supervisor's restart
        cycle does not stomp the previous daemon run's tail. The tail
        is exactly the byte range we want preserved across crashes for
        forensics.
      * PYTHONUNBUFFERED=1 propagated to the child for the same
        buffering-trap reasons the launcher applies.
    """
    try:
        log_fh = open(log_path, "ab")
    except OSError:
        log_fh = None
    out = log_fh if log_fh is not None else subprocess.DEVNULL
    # ONE_LINK_SUPERVISED=1 — the daemon's startup banner reads this
    # to log "supervised=yes" so a future "was that run supposed to
    # auto-restart?" question is answerable from the log alone.
    env = {
        **sanitized_process_env(),
        "PYTHONUNBUFFERED": "1",
        "ONE_LINK_SUPERVISED": "1",
    }
    creationflags = 0
    if os.name == "nt":
        creationflags = (
            subprocess.CREATE_NEW_PROCESS_GROUP
            | hidden_creationflags()
        )
    argv = _daemon_argv()
    return subprocess.Popen(
        argv,
        stdout=out,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        env=env,
        creationflags=creationflags if os.name == "nt" else 0,
        close_fds=True,
        cwd=str(Path(argv[0]).parent),
        shell=False,
    )


def run(
    *,
    max_crashes: int = DEFAULT_MAX_CRASHES,
    window_s: float = DEFAULT_WINDOW_S,
    spawn: Callable[..., Any] = _spawn_daemon_child,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.time,
) -> int:
    """Supervise the daemon — block until clean exit or circuit-trip.

    Parameters are injectable so the test suite can drive the loop
    with fake spawn / sleep / clock plumbing. Real callers use the
    defaults.

    Returns:
      0 on clean shutdown,
      2 on spawn failure,
      3 on circuit-breaker trip.
    """
    crash_log.install_excepthooks()
    log.info(
        "supervisor starting (pid=%d, max_crashes=%d, window=%.1fs)",
        os.getpid(), max_crashes, window_s,
    )
    pid_file = _write_pid_file()
    crashes: deque[float] = deque()
    consecutive_crashes = 0
    shutdown = {"requested": False}
    proc_holder: dict[str, Optional[subprocess.Popen]] = {"proc": None}

    def _on_signal(sig: int, _frame) -> None:
        log.info("supervisor: signal %d received — forwarding to child", sig)
        shutdown["requested"] = True
        proc = proc_holder.get("proc")
        if proc is not None and proc.poll() is None:
            try:
                if os.name == "nt":
                    proc.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    proc.send_signal(sig)
            except Exception as e:
                log.debug("signal forward to child failed: %s", e)

    _install_signal_handlers(_on_signal)
    log_path = data_dir() / DAEMON_LAUNCH_LOG

    try:
        while True:
            if shutdown["requested"]:
                log.info("supervisor: shutdown requested before spawn — exiting clean")
                return 0
            try:
                proc = spawn(log_path)
            except OSError as e:
                log.critical("supervisor: spawn failed — %s", e, exc_info=True)
                crash_log.dump_crash("supervisor-spawn-failed", e)
                _append_restart_log("spawn-failed", None)
                return 2
            proc_holder["proc"] = proc
            log.info("supervisor: daemon child pid=%s", getattr(proc, "pid", "?"))

            try:
                exit_code = proc.wait()
            except KeyboardInterrupt:
                shutdown["requested"] = True
                try:
                    proc.wait(timeout=10)
                except (OSError, subprocess.SubprocessError) as exc:
                    report_best_effort_failure(
                        log,
                        "supervisor_interrupt_child_wait",
                        exc,
                    )
                exit_code = proc.returncode if proc.returncode is not None else 0

            proc_holder["proc"] = None
            if shutdown["requested"] or exit_code == 0:
                log.info(
                    "supervisor: daemon exited cleanly (code=%s) — supervisor exiting",
                    exit_code,
                )
                _append_restart_log("clean-exit", exit_code)
                return 0

            # CRASH path.
            #
            # Specific case: the daemon exited because ANOTHER One
            # Link daemon is already running for this ONE_LINK_HOME.
            # That is not a transient crash — retrying will hit the
            # same wall every time. The launcher's "replace stale
            # daemon" path failed (or wasn't invoked) and the only
            # graceful next step is to ask the user to close the
            # other instance. Bail out with a distinct exit code so
            # the launcher's friendly error dialog can recognise the
            # situation and surface the right copy instead of the
            # generic "couldn't come up" message.
            if _daemon_exit_is_already_running_conflict(log_path):
                log.critical(
                    "supervisor: another One Link daemon already owns this "
                    "ONE_LINK_HOME — refusing to retry. Close the other "
                    "One Link window/tray icon, then launch again.",
                )
                crash_log.dump_crash(
                    "daemon-already-running", None,
                    extra={"exit_code": exit_code},
                )
                _append_restart_log("already-running", exit_code)
                return 4  # distinct from 2 (spawn fail) / 3 (circuit breaker)

            t = now()
            crashes.append(t)
            consecutive_crashes += 1
            while crashes and (t - crashes[0]) > window_s:
                crashes.popleft()
            log.critical(
                "supervisor: daemon exited with code %s — %d crash(es) in last %.1fs",
                exit_code, len(crashes), window_s,
            )
            crash_log.dump_crash(
                "daemon-supervised-exit", None,
                extra={
                    "exit_code": exit_code,
                    "crashes_in_window": len(crashes),
                    "window_s": window_s,
                    "consecutive_crashes": consecutive_crashes,
                },
            )
            _append_restart_log("daemon-crash", exit_code)
            if len(crashes) >= max_crashes:
                log.critical(
                    "supervisor: CIRCUIT-BREAKER TRIPPED — %d crashes in %.1fs. "
                    "Stopping. Manual intervention needed; check %s/crashes/.",
                    len(crashes), window_s, data_dir(),
                )
                _append_restart_log("circuit-breaker", None)
                return 3
            delay = _backoff(consecutive_crashes - 1)
            log.info("supervisor: restart #%d in %.1fs", consecutive_crashes, delay)
            try:
                sleep(delay)
            except KeyboardInterrupt:
                shutdown["requested"] = True
    finally:
        if pid_file is not None:
            try: pid_file.unlink()
            except OSError: pass


def _install_signal_handlers(handler) -> None:
    """Wire SIGINT + SIGTERM + (Windows) SIGBREAK to ``handler``.

    Pulled out so the test suite can monkeypatch a no-op when running
    inside pytest (which already owns SIGINT).
    """
    try: signal.signal(signal.SIGINT, handler)
    except (ValueError, OSError): pass
    try: signal.signal(signal.SIGTERM, handler)
    except (ValueError, OSError, AttributeError): pass
    if os.name == "nt":
        try: signal.signal(signal.SIGBREAK, handler)
        except (ValueError, OSError, AttributeError): pass
