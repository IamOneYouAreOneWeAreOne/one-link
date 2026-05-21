"""Adapter for the radio-aware batch scheduler (``ol_radio_batcher`` via
``one_link_native``).

Decision point D06 in `intergration map.txt`. The daemon's broadcast
loop (daemon.py:12137-12140) replaces per-peer fanout with
`batcher.enqueue(...)`; the `_prune_loop` tick (daemon.py:16964-16986)
calls `batcher.drain(now_ms)` and emits the returned entries.

Forge-shootouts evidence (Gap 4 + Gap 11 + Gap 14):
  - 22-44% per-event radio energy reduction with batching enabled.
  - 50ms DRX window is the latency/energy sweet spot.
  - Urgent traffic MUST bypass batching (Gap 14 tail fix); the
    selector enforces this by tagging foreground msgs `urgent_bypass`
    so they never reach this queue.
"""

from __future__ import annotations

import logging
import time
from typing import TypedDict

log = logging.getLogger(__name__)

try:
    from one_link_native import radio_batcher as _native_batcher  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_batcher, "__version__", None)
    DEFAULT_DRX_WINDOW_MS: int = int(
        getattr(_native_batcher, "DEFAULT_DRX_WINDOW_MS", 50)
    )
    DEFAULT_MAX_QUEUE_SIZE: int = int(
        getattr(_native_batcher, "DEFAULT_MAX_QUEUE_SIZE", 4096)
    )
    DEFAULT_MAX_AGE_MS: int = int(
        getattr(_native_batcher, "DEFAULT_MAX_AGE_MS", 20_000)
    )
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    DEFAULT_DRX_WINDOW_MS = 50
    DEFAULT_MAX_QUEUE_SIZE = 4096
    DEFAULT_MAX_AGE_MS = 20_000
    _native_batcher = None  # type: ignore[assignment]
    log.info(
        "one_link_native.radio_batcher not installed (%s); radio batching "
        "unavailable (daemon will emit-now everywhere). Build via "
        "`cd native && maturin develop --release`.",
        exc,
    )


class DrainEntry(TypedDict):
    """One entry returned by drain()."""

    peer_fp: str
    payload: bytes
    priority: str  # "urgent" | "normal" | "background"
    enqueued_at_ms: int


class DrainOutcome(TypedDict):
    """Per-drain counters returned alongside the entry list."""

    drained: int
    remaining: int
    force_drained_due_to_age: int


class BatcherStats(TypedDict):
    """Aggregate counters returned by stats()."""

    enqueued_total: int
    drained_total: int
    rejected_full: int
    aged_out: int


def radio_batcher(
    drx_window_ms: int = DEFAULT_DRX_WINDOW_MS,
    max_queue_size: int = DEFAULT_MAX_QUEUE_SIZE,
    max_age_ms: int = DEFAULT_MAX_AGE_MS,
):
    """Construct a radio batcher with the given tuning.

    Daemon-side default: one instance per daemon, cached in __init__.
    """
    _require_native()
    return _native_batcher.RadioBatcher(drx_window_ms, max_queue_size, max_age_ms)


def now_ms() -> int:
    """Wall-clock helper. The daemon should use this consistently so
    enqueue/drain see the same time source.
    """
    return int(time.time() * 1000)


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.radio_batcher required but not installed; "
            "build via `cd native && maturin develop --release`."
        )
