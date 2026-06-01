"""Forensic crash reporting + heartbeat-based silent-death detection.

The launcher spawns the daemon with stderr redirected to a file
(block-buffered); a final uncaught exception's traceback can be
truncated on abrupt exit. ``crash_log`` mirrors every uncaught
exception to ``data_dir()/crashes/<utc>-<reason>.txt`` with an fsync,
so a forensic record survives the buffering trap. The daemon also
writes a heartbeat every 5s; on the NEXT startup, a heartbeat newer
than HEARTBEAT_DEAD_WINDOW_S means the previous run died abruptly —
log it loudly so we know the daemon DIED rather than was stopped.
"""
from __future__ import annotations

import logging
import sys
import threading
import time
from pathlib import Path

import pytest

from one_link import crash_log


@pytest.fixture
def isolated_data_dir(tmp_path, monkeypatch):
    """Point every ``from one_link.paths import data_dir`` site at tmp.

    A bound-name import captures the function at import time; patching
    ``paths.data_dir`` alone leaves callers reading the original. We
    patch the namespace of every module that imports it AND uses it
    for crash/heartbeat IO (so test crash files do not pollute the
    user's real data dir, and heartbeat-detection tests do not read a
    real recent heartbeat from a live daemon)."""
    import one_link.paths as paths_mod
    import one_link.daemon as daemon_mod
    monkeypatch.setattr(paths_mod, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(crash_log, "data_dir", lambda: tmp_path, raising=False)
    monkeypatch.setattr(daemon_mod, "data_dir", lambda: tmp_path, raising=False)
    return tmp_path


# ─── dump_crash ─────────────────────────────────────────────────────────

def test_dump_crash_writes_file_with_metadata_and_traceback(isolated_data_dir):
    try:
        raise RuntimeError("boom-mc-boomface")
    except RuntimeError as e:
        path = crash_log.dump_crash("unit-test-1", e, extra={"who": "pytest"})
    assert path is not None
    assert path.is_file()
    body = path.read_text(encoding="utf-8")
    assert "reason : unit-test-1" in body
    assert "boom-mc-boomface" in body
    assert "RuntimeError" in body
    assert "who: pytest" in body
    assert path.parent == isolated_data_dir / "crashes"


def test_dump_crash_without_exception_captures_thread_stacks(isolated_data_dir):
    path = crash_log.dump_crash("no-exc")
    assert path is not None
    body = path.read_text(encoding="utf-8")
    assert "(no exception object" in body
    assert "thread " in body  # at least the main thread stack


def test_dump_crash_sanitizes_reason_in_filename(isolated_data_dir):
    path = crash_log.dump_crash("../../../etc/passwd!!", RuntimeError("x"))
    assert path is not None
    assert ".." not in path.name
    assert "/" not in path.name and "\\" not in path.name
    assert path.parent == isolated_data_dir / "crashes"


def test_dump_crash_prunes_to_cap(isolated_data_dir, monkeypatch):
    monkeypatch.setattr(crash_log, "_MAX_CRASH_FILES", 5)
    # Lay down 7 reports; each prune happens on every write so the dir
    # should never exceed the cap.
    for i in range(7):
        crash_log.dump_crash(f"flood-{i}", RuntimeError(f"e{i}"))
        time.sleep(0.01)  # distinct mtimes so newest-first ordering is stable
    files = sorted((isolated_data_dir / "crashes").glob("*.txt"))
    assert len(files) <= 5


def test_dump_crash_never_raises_even_when_dir_unwritable(
    isolated_data_dir, monkeypatch,
):
    def _boom(*_a, **_kw):
        raise OSError("disk full")
    monkeypatch.setattr(crash_log, "_crashes_dir", _boom)
    # Must NOT raise — we are in a crash path.
    result = crash_log.dump_crash("disk-fail", RuntimeError("inner"))
    assert result is None


# ─── excepthooks ────────────────────────────────────────────────────────

def test_install_excepthooks_is_idempotent(monkeypatch):
    monkeypatch.setattr(crash_log, "_INSTALLED", False)
    prev_sys = sys.excepthook
    prev_thread = threading.excepthook
    crash_log.install_excepthooks()
    once_sys = sys.excepthook
    once_thread = threading.excepthook
    assert once_sys is not prev_sys
    assert once_thread is not prev_thread
    crash_log.install_excepthooks()  # second call no-ops
    assert sys.excepthook is once_sys
    assert threading.excepthook is once_thread


def test_thread_excepthook_writes_crash_file(isolated_data_dir, monkeypatch):
    monkeypatch.setattr(crash_log, "_INSTALLED", False)
    crash_log.install_excepthooks()

    def boom():
        raise ValueError("worker-thread boom")

    before = set((isolated_data_dir / "crashes").glob("*.txt")) \
        if (isolated_data_dir / "crashes").exists() else set()
    t = threading.Thread(target=boom, name="crashy")
    t.start()
    t.join()
    after = set((isolated_data_dir / "crashes").glob("*.txt"))
    new_files = after - before
    assert new_files, "thread crash should have produced a crash file"
    body = next(iter(new_files)).read_text(encoding="utf-8")
    assert "worker-thread boom" in body
    assert "crashy" in body


def test_thread_excepthook_chains_to_previous_hook(monkeypatch):
    monkeypatch.setattr(crash_log, "_INSTALLED", False)
    seen: list[str] = []

    def custom_prev(args):
        seen.append(args.thread.name if args.thread else "?")

    monkeypatch.setattr(threading, "excepthook", custom_prev)
    crash_log.install_excepthooks()

    def boom():
        raise RuntimeError("boom")

    t = threading.Thread(target=boom, name="chain-test")
    t.start(); t.join()
    assert seen == ["chain-test"], "previous threading.excepthook must be chained"


# ─── asyncio loop crash hook ────────────────────────────────────────────

def test_install_loop_hook_is_idempotent_per_loop(isolated_data_dir):
    import asyncio
    loop = asyncio.new_event_loop()
    try:
        crash_log.install_loop_hook(loop)
        first = loop.get_exception_handler()
        crash_log.install_loop_hook(loop)
        second = loop.get_exception_handler()
        assert first is second
    finally:
        loop.close()


def test_install_loop_hook_dumps_task_exceptions(isolated_data_dir):
    import asyncio
    loop = asyncio.new_event_loop()
    try:
        crash_log.install_loop_hook(loop)
        # Manually invoke the handler with a synthetic context — same
        # shape as what asyncio passes for an unawaited task exception.
        handler = loop.get_exception_handler()
        try:
            raise KeyError("synthetic-task-failure")
        except KeyError as e:
            ctx = {"message": "Task exception was never retrieved", "exception": e}
            handler(loop, ctx)
        files = list((isolated_data_dir / "crashes").glob("*asyncio-task*.txt"))
        assert files, "task exception should have produced a crash file"
        body = files[0].read_text(encoding="utf-8")
        assert "synthetic-task-failure" in body
    finally:
        loop.close()


# ─── heartbeat-based silent-death detection ─────────────────────────────

def test_check_previous_heartbeat_logs_when_recent(isolated_data_dir, caplog):
    from one_link import daemon as daemon_mod
    hb = isolated_data_dir / daemon_mod.HEARTBEAT_FILE
    hb.write_text(f"{time.time() - 2.0:.3f}\n", encoding="utf-8")
    with caplog.at_level(logging.CRITICAL, logger="one_link.daemon"):
        daemon_mod._check_previous_heartbeat()
    assert any("died abruptly" in r.message for r in caplog.records), (
        "recent heartbeat at startup must log a CRITICAL silent-death warning"
    )


def test_check_previous_heartbeat_silent_when_old(isolated_data_dir, caplog):
    from one_link import daemon as daemon_mod
    hb = isolated_data_dir / daemon_mod.HEARTBEAT_FILE
    # A heartbeat from an hour ago is a normal "old run" — no warning.
    hb.write_text(f"{time.time() - 3600.0:.3f}\n", encoding="utf-8")
    with caplog.at_level(logging.CRITICAL, logger="one_link.daemon"):
        daemon_mod._check_previous_heartbeat()
    assert not any("died abruptly" in r.message for r in caplog.records)


def test_check_previous_heartbeat_silent_when_absent(isolated_data_dir, caplog):
    from one_link import daemon as daemon_mod
    with caplog.at_level(logging.CRITICAL, logger="one_link.daemon"):
        daemon_mod._check_previous_heartbeat()
    assert not any("died abruptly" in r.message for r in caplog.records)


def test_check_previous_heartbeat_silent_on_garbage(isolated_data_dir, caplog):
    from one_link import daemon as daemon_mod
    (isolated_data_dir / daemon_mod.HEARTBEAT_FILE).write_text(
        "not-a-float", encoding="utf-8",
    )
    with caplog.at_level(logging.CRITICAL, logger="one_link.daemon"):
        daemon_mod._check_previous_heartbeat()
    # Garbage = unreadable = treat as no signal (don't false-alarm).
    assert not any("died abruptly" in r.message for r in caplog.records)


# ─── launcher spawn passes PYTHONUNBUFFERED ─────────────────────────────

def test_spawn_passes_python_unbuffered():
    """The launcher MUST pass PYTHONUNBUFFERED=1 to the spawned daemon.
    Without it, the child's stdout fd to daemon-launch.err.log is
    block-buffered and a final exception's traceback can be lost on
    abrupt exit — the root cause of the original silent-death we are
    fixing."""
    import inspect
    from one_link import app as app_mod
    src = inspect.getsource(app_mod._spawn_daemon)
    assert "PYTHONUNBUFFERED" in src and '"1"' in src
    # Confirm it's actually wired into the Popen kwargs path.
    assert "env=child_env" in src or "env=" in src
