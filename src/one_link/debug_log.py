"""v0.8.1: developer-backend error log.

Captures every interesting failure inside the daemon — server
exception paths, daemon-level raises, peer-frame rejections,
capability denials, transfer pause/fail events — with structured
context so the UI's Debug pane can show "what happened, why, and
how to fix" without the user squinting at logs.

In-memory ring buffer (default 500 entries). No sqlite — failures
shouldn't take a write lock or slow normal operation, and a daemon
restart is a perfectly reasonable point to forget old errors.

Each entry is a dict with:
  ts_ms      — wall clock
  severity   — "info" | "warn" | "error"
  source     — e.g. "send_file", "create_group", "channel.recv"
  code       — machine-readable, e.g. "capability_disabled",
               "peer_offline", "winerror_10053"
  message    — human-readable, what happened
  context    — dict of relevant ids (peer_fp, transfer_id,
               group_id, etc.)
  suggestion — what to try next, e.g. "Re-pair this device" or
               "Restart One Link to pick up the new endpoints"
"""
from __future__ import annotations

import logging
import threading
import time
import traceback
from collections import deque
from typing import Any, Iterable, Optional

log = logging.getLogger(__name__)

# Capacity of the ring buffer. 500 entries × ~1KB each = ~500 KB
# resident; small enough to be free, big enough to capture a busy
# session's worth of failures.
MAX_ENTRIES = 500


class DebugLog:
    """Process-wide debug log. Threadsafe."""

    def __init__(self, capacity: int = MAX_ENTRIES):
        self._buf: deque[dict[str, Any]] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._next_id = 1
        # Optional WS broadcaster — set by UIServer at startup so
        # new entries push live to the Debug pane without poll.
        self._broadcast = None

    def attach_broadcast(self, fn) -> None:
        """Wire a callable(dict) → broadcasts a `debug_event` WS
        notification with the new entry. Optional."""
        self._broadcast = fn

    def record(
        self,
        *,
        severity: str = "error",
        source: str,
        code: str,
        message: str,
        context: Optional[dict] = None,
        suggestion: Optional[str] = None,
        traceback_str: Optional[str] = None,
    ) -> dict:
        """Append an entry. Returns the entry dict including a
        monotonic id (1-indexed)."""
        if severity not in ("info", "warn", "error"):
            severity = "error"
        entry = {
            "id": self._next_id,
            "ts_ms": int(time.time() * 1000),
            "severity": severity,
            "source": str(source)[:80],
            "code": str(code)[:64],
            "message": str(message)[:500],
            "context": dict(context or {}),
            "suggestion": str(suggestion)[:300] if suggestion else None,
            "traceback": (str(traceback_str)[:2000] if traceback_str else None),
        }
        with self._lock:
            self._next_id += 1
            self._buf.append(entry)
        # Mirror to the standard logger so server.log shows it too.
        log_level = (
            logging.ERROR if severity == "error"
            else logging.WARNING if severity == "warn"
            else logging.INFO
        )
        log.log(
            log_level,
            "[debug_log %s] %s: %s",
            entry["source"], entry["code"], entry["message"],
        )
        # Live-push to UI subscribers if attached.
        if self._broadcast is not None:
            try:
                self._broadcast(entry)
            except Exception:
                pass
        return entry

    def record_exception(
        self,
        exc: BaseException,
        *,
        source: str,
        code: Optional[str] = None,
        suggestion: Optional[str] = None,
        context: Optional[dict] = None,
    ) -> dict:
        """Convenience: record a Python exception with traceback."""
        return self.record(
            severity="error",
            source=source,
            code=code or type(exc).__name__,
            message=str(exc) or type(exc).__name__,
            context=context,
            suggestion=suggestion or _default_suggestion(exc),
            traceback_str="".join(
                traceback.format_exception(type(exc), exc, exc.__traceback__)
            ),
        )

    def tail(
        self,
        *,
        limit: int = 200,
        since_id: Optional[int] = None,
        severity: Optional[Iterable[str]] = None,
        sources: Optional[Iterable[str]] = None,
    ) -> list[dict]:
        """Most-recent-first list of entries. since_id limits to
        entries strictly newer than the given id (for incremental
        polling)."""
        sev_set = set(severity) if severity else None
        src_set = set(sources) if sources else None
        with self._lock:
            snapshot = list(self._buf)
        # newest first
        snapshot.reverse()
        out = []
        for entry in snapshot:
            if since_id is not None and entry["id"] <= since_id:
                continue
            if sev_set and entry["severity"] not in sev_set:
                continue
            if src_set and entry["source"] not in src_set:
                continue
            out.append(entry)
            if len(out) >= limit:
                break
        return out

    def clear(self) -> int:
        """Drop all entries. Returns count removed."""
        with self._lock:
            n = len(self._buf)
            self._buf.clear()
        return n

    def __len__(self) -> int:
        with self._lock:
            return len(self._buf)


# Process-wide singleton. Imported by daemon + server; tests can
# call `_singleton.clear()` between cases.
_singleton = DebugLog()


def get_debug_log() -> DebugLog:
    return _singleton


def _default_suggestion(exc: BaseException) -> str:
    """Map common exception shapes to a human-friendly next step."""
    name = type(exc).__name__
    msg = str(exc).lower()
    if name == "TransferPausedError":
        return (
            "This transfer is paused; it will resume automatically the "
            "next time the peer's daemon comes back online."
        )
    if "winerror 10053" in msg or "winerror 10054" in msg or "connection aborted" in msg:
        return (
            "The peer's TCP connection dropped mid-stream. Often caused "
            "by Wi-Fi roam, antivirus, or a brief peer-side hiccup. "
            "Transfers retry automatically; for chat, try sending again."
        )
    if "handshake timed out" in msg or "not responsive" in msg:
        return (
            "The peer's daemon isn't answering. Make sure One Link is "
            "still running there, then try again."
        )
    if "capability" in msg and "disabled" in msg:
        return (
            "Your local policy doesn't allow this action for that peer. "
            "Open the device drawer (gear next to the peer in the "
            "sidebar) and toggle the relevant capability on."
        )
    if "rejected" in msg:
        return (
            "The peer is marked as blocked. Click 'Allow device' in the "
            "conversation header to unblock, then re-pair if needed."
        )
    if (
        "decrypt" in msg or "invalidtag" in msg
        or "wire_version_mismatch" in msg
        or "ratchet header version" in msg
    ):
        return (
            "The secure session could not be opened on this path yet. "
            "One Link will reconnect and use the best compatible route automatically."
        )
    if "peer offline" in msg or "no peer" in msg or "unreachable" in msg:
        return (
            "The peer isn't reachable right now. Outbound chat falls "
            "back to the outbox automatically; files wait for reconnect."
        )
    if "404" in msg and ("api" in msg or "request failed" in msg):
        return (
            "This window is ahead of the local background service. "
            "Close and reopen One Link if it does not refresh itself."
        )
    return ""


__all__ = ["DebugLog", "get_debug_log"]
