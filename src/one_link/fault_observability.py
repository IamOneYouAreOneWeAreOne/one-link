"""Bounded, privacy-preserving observability for best-effort failures.

Best-effort code is allowed to degrade a non-critical feature, but it must not
turn an exception into an invisible success.  This helper emits at most one
record per operation/error-class/window and never includes the exception
message (which can contain paths, peer input, URLs, or credentials).

The key cache is an LRU with a hard ceiling, so attacker-controlled failure
families cannot turn observability into unbounded memory or log growth.
"""

from __future__ import annotations

from collections import OrderedDict
import logging
import math
import threading
import time

_MAX_KEYS = 256
_DEFAULT_INTERVAL_S = 60.0
_SAFE_OPERATION_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)
_last_emitted: "OrderedDict[tuple[str, str, str], float]" = OrderedDict()
_lock = threading.Lock()


def _safe_operation(operation: object) -> str:
    try:
        raw = str(operation)[:96]
    except Exception:
        raw = "unknown"
    safe = "".join(ch if ch in _SAFE_OPERATION_CHARS else "_" for ch in raw)
    return safe or "unknown"


def report_best_effort_failure(
    logger: logging.Logger,
    operation: object,
    exc: BaseException,
    *,
    level: int = logging.WARNING,
    interval_s: float = _DEFAULT_INTERVAL_S,
    now: float | None = None,
) -> bool:
    """Emit one redacted, rate-limited best-effort failure record.

    Returns ``True`` when a record was emitted and ``False`` when the same
    operation/error class is still inside its suppression window.  Only the
    exception *class* is logged; exception text and caller-controlled values
    are deliberately excluded.
    """

    op = _safe_operation(operation)
    error_type = _safe_operation(type(exc).__name__)[:80]
    try:
        logger_name = _safe_operation(logger.name)
    except Exception:
        logger_name = "unknown"
    key = (logger_name, op, error_type)
    try:
        timestamp = time.monotonic() if now is None else float(now)
    except (TypeError, ValueError, OverflowError):
        timestamp = time.monotonic()
    if not math.isfinite(timestamp):
        timestamp = time.monotonic()
    try:
        window = float(interval_s)
    except (TypeError, ValueError, OverflowError):
        window = _DEFAULT_INTERVAL_S
    if not math.isfinite(window):
        window = _DEFAULT_INTERVAL_S
    window = max(0.0, min(window, 86_400.0))

    with _lock:
        previous = _last_emitted.get(key)
        if previous is not None and timestamp - previous < window:
            _last_emitted.move_to_end(key)
            return False
        _last_emitted[key] = timestamp
        _last_emitted.move_to_end(key)
        while len(_last_emitted) > _MAX_KEYS:
            _last_emitted.popitem(last=False)

    try:
        logger.log(
            level,
            "best-effort operation %s degraded (error_type=%s)",
            op,
            error_type,
        )
    except Exception:
        # Observability must never turn a deliberately best-effort cleanup or
        # optional feature into a new failure boundary. The cache still bounds
        # repeated attempts when a custom logging handler itself is broken.
        return False
    return True


def _reset_for_tests() -> None:
    """Clear limiter state.  Test-only; production callers must not use it."""

    with _lock:
        _last_emitted.clear()
