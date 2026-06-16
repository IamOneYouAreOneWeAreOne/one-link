"""Forensic crash reporting for the daemon.

Two complementary surfaces:

* ``dump_crash`` writes a self-contained crash report to
  ``data_dir()/crashes/<utc>-<reason>.txt`` so a post-mortem survives
  even when the logging stream loses its buffered tail on abrupt exit.
* ``install_excepthooks`` plants ``sys.excepthook`` +
  ``threading.excepthook`` so an uncaught exception in the main thread
  OR in any worker thread (tray, URL-pusher, open-browser helper,
  watchdog) is logged loudly via the standard logger ``exc_info=True``
  AND mirrored to a crash file.

Together with ``PYTHONUNBUFFERED=1`` in the launcher's spawn env and
the broad-except wrap around ``asyncio.run(daemon.run())``, these
guarantee that the next time the daemon dies we know *what* killed it.
A silent death is a top-level visibility bug, not just "another
crash" — fixing the visibility is what makes everything else
debuggable.
"""
from __future__ import annotations

import asyncio
import logging
import os
import platform
import sys
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from one_link import __version__
from one_link.paths import data_dir

_LOG = logging.getLogger("one_link.crash")

_CRASHES_SUBDIR = "crashes"
_MAX_CRASH_FILES = 50  # rolling cap; oldest pruned on each new dump

# Sentinel so install_excepthooks is idempotent — re-installing would
# overwrite the previous chain we built and leak the original hook.
_INSTALLED = False


def _crashes_dir() -> Path:
    p = data_dir() / _CRASHES_SUBDIR
    p.mkdir(parents=True, exist_ok=True)
    return p


def _prune_old() -> None:
    """Keep at most ``_MAX_CRASH_FILES`` reports — newest first."""
    try:
        files = sorted(
            _crashes_dir().glob("*.txt"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for old in files[_MAX_CRASH_FILES:]:
            try: old.unlink()
            except OSError: pass
    except OSError:
        pass


def dump_crash(
    reason: str,
    exc: BaseException | None = None,
    *,
    extra: dict[str, Any] | None = None,
) -> Path | None:
    """Write a forensic crash report and return its path.

    ``reason`` is a short kebab-case tag (``daemon-uncaught``,
    ``main-excepthook``, ``thread-excepthook``) used in the filename.
    Returns None when the report could not be written — never raises;
    we are already in the death path and refuse to fail-loud here.
    """
    try:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_reason = "".join(
            c if c.isalnum() or c in "-_" else "_" for c in reason
        )[:40] or "unknown"
        path = _crashes_dir() / f"{stamp}-{safe_reason}.txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write("# One Link crash report\n")
            f.write(f"version: {__version__}\n")
            f.write(f"reason : {reason}\n")
            f.write(f"utc    : {stamp}\n")
            f.write(f"local  : {datetime.now().isoformat()}\n")
            f.write(f"pid    : {os.getpid()}\n")
            f.write(f"thread : {threading.current_thread().name}\n")
            f.write(f"python : {sys.version.split()[0]}\n")
            f.write(f"platform: {platform.platform()}\n")
            if extra:
                for k, v in extra.items():
                    f.write(f"{k}: {v}\n")
            f.write("\n# traceback\n")
            if exc is not None:
                f.write("".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                ))
            else:
                # No exception — caller wanted a marker (e.g. abnormal exit
                # with no traceback). Capture current stacks of all threads
                # to at least show where everyone was when we died.
                f.write("(no exception object — current thread stacks)\n\n")
                for tid, frame in sys._current_frames().items():
                    name = next(
                        (t.name for t in threading.enumerate() if t.ident == tid),
                        f"tid-{tid}",
                    )
                    f.write(f"\n--- thread {name} ({tid}) ---\n")
                    f.write("".join(traceback.format_stack(frame)))
            f.flush()
            try: os.fsync(f.fileno())
            except OSError: pass
        _prune_old()
        return path
    except Exception:
        # Last-ditch: keep the trace on stderr so something survives.
        try:
            sys.stderr.write(f"\n!! crash_log.dump_crash failed for {reason}\n")
            if exc is not None:
                traceback.print_exception(type(exc), exc, exc.__traceback__)
            sys.stderr.flush()
        except Exception:
            pass
        return None


def install_excepthooks() -> None:
    """Plant main-thread + worker-thread + asyncio-loop hooks.

    Idempotent: re-calling is a no-op so duplicate boot paths (e.g. the
    launcher + a re-import inside an embedded test) don't chain hooks.

    The asyncio-loop hook is installed lazily when ``install_loop_hook``
    is called from inside ``daemon.run()`` — at module import time there
    is no running loop to install onto.
    """
    global _INSTALLED
    if _INSTALLED:
        return
    _INSTALLED = True

    prev_sys = sys.excepthook
    def _sys_hook(exc_type, exc, tb) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            return prev_sys(exc_type, exc, tb)
        _LOG.critical(
            "uncaught main-thread exception", exc_info=(exc_type, exc, tb),
        )
        try: dump_crash("main-excepthook", exc)
        except Exception: pass
        # Chain to the previous hook so default formatting still hits stderr.
        try: prev_sys(exc_type, exc, tb)
        except Exception: pass
    sys.excepthook = _sys_hook

    prev_thread = threading.excepthook
    def _thread_hook(args: threading.ExceptHookArgs) -> None:
        if issubclass(args.exc_type, SystemExit):
            return prev_thread(args)
        tname = args.thread.name if args.thread is not None else "?"
        _LOG.critical(
            "uncaught exception in thread %r", tname,
            exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
        )
        try:
            dump_crash(
                f"thread-{tname}",
                args.exc_value,
                extra={"thread": tname},
            )
        except Exception:
            pass
        try: prev_thread(args)
        except Exception: pass
    threading.excepthook = _thread_hook


async def _contained_coro(coro, name: str, on_error) -> None:
    """Run ``coro`` inside a contained guard: any non-cancellation
    exception is logged + crash-dumped, then SWALLOWED so it cannot
    propagate up to the loop's main coroutine and take the whole
    daemon down.

    Cancellation MUST re-raise — it is the asyncio shutdown signal,
    not a failure.
    """
    try:
        await coro
    except asyncio.CancelledError:
        raise
    except BaseException as e:  # noqa: BLE001 — last-chance task wall
        _LOG.critical(
            "background task %r failed (contained)", name, exc_info=True,
        )
        try:
            dump_crash(
                f"task-{name}", e,
                extra={"task": name, "contained": True},
            )
        except Exception:
            pass
        if on_error is not None:
            try:
                on_error(e)
            except Exception:
                _LOG.exception(
                    "task %r on_error handler itself raised", name,
                )


def safe_task(coro, *, name: str, on_error=None):
    """Spawn an asyncio task whose unhandled exception cannot crash
    the daemon.

    Use for any fire-and-forget background task — peer handler loops,
    periodic refreshers, transport probes — where a single misbehaving
    coroutine should not bring the whole event loop down. The
    exception is captured AT THE TASK BODY, logged via
    ``log.critical(exc_info=True)``, mirrored to a forensic crash
    file, then swallowed. ``on_error`` is invoked with the exception
    when the task fails (useful for "mark this peer as failed" cleanup).

    ``CancelledError`` always re-raises so asyncio's normal shutdown
    semantics keep working.

    Returns the created ``asyncio.Task`` so the caller can still
    cancel it or hold a reference for later cleanup.
    """
    import asyncio as _asyncio
    return _asyncio.create_task(_contained_coro(coro, name, on_error), name=name)


def install_loop_hook(loop) -> None:
    """Layer crash-dump onto the existing asyncio loop exception handler.

    ``daemon._install_asyncio_exception_handler`` already installs a
    handler that suppresses benign Windows transport resets and chains
    to the default for everything else. We layer ON TOP of whatever is
    there so the suppression stays intact AND we get a forensic dump
    for the real task-level crashes that surface here. Idempotent per
    loop instance via a marker attribute.
    """
    if getattr(loop, "_one_link_crash_hook_installed", False):
        return
    setattr(loop, "_one_link_crash_hook_installed", True)
    prev = loop.get_exception_handler()

    def _handler(loop, context: dict) -> None:
        exc = context.get("exception")
        # Mirror the inner handler's benign-suppress decision BEFORE
        # writing a forensic dump. Without this we write crash files
        # for things the inner handler classifies as non-crashes
        # (Windows socket cleanup, peer disconnect mid-handshake), and
        # operators chasing real bugs drown in red-herring reports.
        # The import is lazy so we don't take a circular dep at module
        # load; the only reason crash_log might be imported before
        # daemon is in standalone tests, which don't trigger this path.
        is_benign = False
        if exc is not None:
            try:
                from one_link.daemon import _is_benign_windows_transport_reset
                is_benign = _is_benign_windows_transport_reset(exc)
            except Exception:
                is_benign = False
        if exc is not None and not is_benign:
            try:
                dump_crash(
                    "asyncio-task",
                    exc,
                    extra={"message": context.get("message", "")},
                )
            except Exception:
                pass
        if prev is not None:
            prev(loop, context)
        else:
            loop.default_exception_handler(context)

    loop.set_exception_handler(_handler)
