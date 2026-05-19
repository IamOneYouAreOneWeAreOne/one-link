"""Bounded LRU eviction for the global chunk cache.

The chunk cache at ``data/file_chunks/<hash[:2]>/<hash[2:]>`` is
content-addressed and shared across every CDC inbound transfer +
every swarm-served outbound chunk. It grows monotonically as files
land: a user who has received 500 GB of distinct content over time
holds 500 GB of cached chunks forever, with no automatic cleanup.

This module is the cleanup. At daemon startup (and optionally on a
periodic timer) it walks the cache, sums sizes, and if the total
exceeds ``max_bytes`` evicts the least-recently-accessed chunks
until the total drops to ``target_bytes``. mtime is the LRU key —
``_read_chunk_cache`` calls ``os.utime(p, None)`` on every read, so
mtime tracks last-access regardless of last-write.

What gets evicted is also dropped from the State DB's
``chunk_availability`` table so a future ``has_chunk`` / swarm
query doesn't claim we still have it.

What's PROTECTED:

  * Any chunk hash in ``protected_hashes``. The daemon passes in
    the union of every in-progress transfer's CDC manifest so an
    eviction can't yank bytes out from under an active receive
    that's about to need them.
  * Chunks accessed within ``min_age_seconds`` (default: 1 hour).
    Even with no protected_hashes hint, a chunk touched seconds
    ago is almost certainly load-bearing for a transfer the
    daemon hasn't finished cataloguing.

Eviction is best-effort. A file that can't be unlinked (Windows
open handle, permission, race with `_store_chunk_cache`'s rename
operation) is left alone; the next pass picks it up. A State DB
``forget_chunk_available`` failure logs a warning and skips that
entry; the cache file is still gone, so a future ``has_chunk``
that returns true will be corrected by ``_read_chunk_cache``'s
"file missing → return None" path.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

log = logging.getLogger(__name__)


# Conservative defaults. Users with small disks can lower via
# the env vars below; users with NAS-class storage can crank up.
# Set to 512 MiB to match the prior in-daemon pruner so the
# refactor that landed alongside this module doesn't surprise
# anyone with a 20× bigger working set after upgrade.
DEFAULT_MAX_BYTES = 512 * 1024 * 1024  # 512 MiB
DEFAULT_TARGET_RATIO = 0.80  # evict down to 80 % of max
DEFAULT_MIN_AGE_SECONDS = 3600  # protect chunks accessed in the last hour

# Env-var overrides so an operator can tune without code changes.
ENV_MAX_BYTES = "ONE_LINK_CHUNK_CACHE_MAX_BYTES"
ENV_TARGET_RATIO = "ONE_LINK_CHUNK_CACHE_TARGET_RATIO"


@dataclass
class CacheEntry:
    """One scanned cache file. ``hash_hex`` is reconstructed from
    the directory layout ``<hash[:2]>/<hash[2:]>``."""

    path: Path
    hash_hex: str
    size: int
    mtime: float


@dataclass
class EvictionReport:
    """Returned to the caller for logging / telemetry."""

    scanned_files: int
    scanned_bytes: int
    evicted_files: int
    evicted_bytes: int
    skipped_protected: int
    errors: int


def _max_bytes_from_env() -> int:
    raw = os.environ.get(ENV_MAX_BYTES)
    if not raw:
        return DEFAULT_MAX_BYTES
    try:
        return max(0, int(raw))
    except ValueError:
        log.warning(
            "invalid %s=%r; falling back to default %d bytes",
            ENV_MAX_BYTES, raw, DEFAULT_MAX_BYTES,
        )
        return DEFAULT_MAX_BYTES


def _target_ratio_from_env() -> float:
    raw = os.environ.get(ENV_TARGET_RATIO)
    if not raw:
        return DEFAULT_TARGET_RATIO
    try:
        v = float(raw)
        if 0.0 < v < 1.0:
            return v
    except ValueError:
        pass
    log.warning(
        "invalid %s=%r; falling back to default %.2f",
        ENV_TARGET_RATIO, raw, DEFAULT_TARGET_RATIO,
    )
    return DEFAULT_TARGET_RATIO


def scan_cache(cache_dir: Path) -> Iterable[CacheEntry]:
    """Yield every cache entry under ``cache_dir``. Skips entries
    that ``stat`` won't read (concurrent unlink, broken symlink)
    instead of raising — the cache is a hot directory that the
    receive path mutates while we scan."""
    if not cache_dir.is_dir():
        return
    for prefix_dir in cache_dir.iterdir():
        # The cache layout is two-character prefix subdirs. Skip
        # anything else (temp files, etc.).
        if not prefix_dir.is_dir() or len(prefix_dir.name) != 2:
            continue
        for entry in prefix_dir.iterdir():
            if not entry.is_file():
                continue
            try:
                st = entry.stat()
            except OSError:
                continue
            hash_hex = f"{prefix_dir.name}{entry.name}"
            # Defensive: a 64-char BLAKE3 hex is what we expect.
            # Anything else is junk left by an interrupted write
            # (e.g., a ``.<pid>_<hex>.tmp`` from _store_chunk_cache).
            if len(hash_hex) != 64:
                continue
            yield CacheEntry(
                path=entry,
                hash_hex=hash_hex,
                size=int(st.st_size),
                mtime=float(st.st_mtime),
            )


def evict_to_target(
    cache_dir: Path,
    *,
    max_bytes: Optional[int] = None,
    target_bytes: Optional[int] = None,
    protected_hashes: Optional[set[str]] = None,
    min_age_seconds: float = DEFAULT_MIN_AGE_SECONDS,
    state: object = None,
    now: Optional[float] = None,
) -> EvictionReport:
    """Walk the cache, evict the least-recently-accessed entries
    until total bytes ≤ ``target_bytes``. Returns a report for
    callers to log.

    ``state``, if provided, must support a ``forget_chunk_available``
    method (added below in state.py); the daemon owns the State DB
    instance and passes it in.

    ``protected_hashes`` is the union of CDC hashes referenced by
    every in-progress IncomingFile. Even if those entries are old,
    they're load-bearing for an active receive.
    """
    import time as _time

    if now is None:
        now = _time.time()
    if max_bytes is None:
        max_bytes = _max_bytes_from_env()
    if target_bytes is None:
        target_bytes = int(max_bytes * _target_ratio_from_env())
    protected = protected_hashes or set()

    entries = list(scan_cache(cache_dir))
    scanned_files = len(entries)
    scanned_bytes = sum(e.size for e in entries)
    report = EvictionReport(
        scanned_files=scanned_files,
        scanned_bytes=scanned_bytes,
        evicted_files=0,
        evicted_bytes=0,
        skipped_protected=0,
        errors=0,
    )
    if scanned_bytes <= max_bytes:
        return report

    # Oldest first.
    entries.sort(key=lambda e: e.mtime)
    remaining = scanned_bytes
    age_floor = now - min_age_seconds
    for entry in entries:
        if remaining <= target_bytes:
            break
        if entry.hash_hex in protected:
            report.skipped_protected += 1
            continue
        if entry.mtime > age_floor:
            # Touched too recently — likely in flight even if not
            # in ``protected``. Stop eviction here rather than
            # racing the receive path.
            break
        try:
            entry.path.unlink()
        except FileNotFoundError:
            # Already gone — count as evicted in spirit.
            remaining -= entry.size
            continue
        except OSError as e:
            report.errors += 1
            log.warning(
                "chunk-cache evict: could not unlink %s: %s",
                entry.path, e,
            )
            continue
        # State DB cleanup is best-effort. If it fails the cache
        # row is stale ("has_chunk" lies) but ``_read_chunk_cache``
        # corrects on the next read because the file is gone.
        if state is not None and hasattr(state, "forget_chunk_available"):
            try:
                state.forget_chunk_available(entry.hash_hex)  # type: ignore[attr-defined]
            except Exception as e:
                log.debug(
                    "state.forget_chunk_available failed for %s: %s",
                    entry.hash_hex[:8], e,
                )
        report.evicted_files += 1
        report.evicted_bytes += entry.size
        remaining -= entry.size
    return report


def gather_protected_hashes(incoming_files: dict) -> set[str]:
    """Build the set of chunk hashes load-bearing for every
    in-progress CDC inbound transfer. Caller is ``Daemon.start`` /
    the periodic GC task; the dict is ``Daemon._incoming_files``.

    Returned set is used as the ``protected_hashes`` argument to
    :func:`evict_to_target`."""
    protected: set[str] = set()
    for f in incoming_files.values():
        chunks = getattr(f, "cdc_chunks", None)
        if not chunks:
            continue
        for c in chunks:
            h = c.get("hash") if isinstance(c, dict) else None
            if h:
                protected.add(str(h))
    return protected
