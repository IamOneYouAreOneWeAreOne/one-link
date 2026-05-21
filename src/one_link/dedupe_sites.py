"""D17 — Dedupe-site identification.

Maintains an in-memory ``chunk_hash -> [peer_fp]`` registry so the
transfer engine can pick a closer/lighter source for a chunk it
needs instead of always pulling from the original sender. Each entry
carries a freshness timestamp so stale "I have X" claims expire.

Sources that populate the index:
  - **Pull** path: a peer's ``BLOB_OFFER`` (folder-sync) advertising
    a blob hash. We learn the peer has that blob right now.
  - **Push** path: a peer that sends us a chunk implicitly has it.
    Recorded on successful chunk write.
  - **Folder manifests**: when an ``apply_remote_manifest`` lands a
    live entry from peer P with blob_hash H, P has H.

Sources that prune:
  - **Eviction**: a peer disconnects and their entries are dropped.
  - **TTL**: entries older than ``DEFAULT_TTL_MS`` are filtered out
    on lookup. (Lazy expiry — we don't sweep on a timer.)
  - **LRU cap**: total entries bounded by ``DEFAULT_MAX_ENTRIES``;
    oldest entries are evicted when the cap is hit.

The index is *advisory*. The transfer engine still verifies the
chunk hash on receipt; a peer that lies about having a chunk gets
caught at AEAD-decrypt + hash-check time. So the worst case for a
poisoned entry is one wasted round trip.

API is the same shape as the other adapter modules
(``observation_dispatcher`` / ``transport_priority``) so daemon-side
imports follow the same pattern.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from threading import RLock
from typing import Iterable, Optional

# Defaults tuned for v0.21:
#   - 5 min TTL: long enough to dedupe within a single share session,
#     short enough that a peer that lost a chunk doesn't get nominated
#     for hours.
#   - 32k entries: ~3 MB of index assuming 64-byte hash + ~8 peers per
#     hash on average. Bounded so a malicious peer can't OOM us by
#     advertising millions of fake hashes.
DEFAULT_TTL_MS: int = 5 * 60 * 1000
DEFAULT_MAX_ENTRIES: int = 32_768


def _now_ms() -> int:
    return int(time.time() * 1000)


class DedupeSiteIndex:
    """In-memory hash -> peer_fp registry with TTL + LRU.

    Thread-safe via an internal RLock; callers don't need to guard.
    The lock is held only for the duration of single inserts /
    lookups, so contention is minimal.
    """

    def __init__(
        self,
        *,
        ttl_ms: int = DEFAULT_TTL_MS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        if ttl_ms <= 0:
            raise ValueError("ttl_ms must be positive")
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self._ttl_ms = ttl_ms
        self._max_entries = max_entries
        # OrderedDict[(chunk_hash, peer_fp)] = recorded_at_ms.
        # Insertion-ordered; move_to_end on update + LRU evict by
        # popping the head.
        self._entries: "OrderedDict[tuple[str, str], int]" = OrderedDict()
        self._lock = RLock()
        # Counters surfaced for ops telemetry.
        self._record_count: int = 0
        self._hit_count: int = 0
        self._miss_count: int = 0
        self._evicted_for_cap: int = 0
        self._evicted_for_peer: int = 0

    # ---------- writers ----------

    def record_have(
        self,
        chunk_hash: str,
        peer_fp: str,
        *,
        now_ms: Optional[int] = None,
    ) -> None:
        """Record that ``peer_fp`` has ``chunk_hash``. Idempotent —
        re-recording just refreshes the timestamp.

        Empty or falsy inputs are silently ignored (the boundary is
        the daemon-side caller; here we just defensively no-op so a
        partial message doesn't poison the index).
        """
        if not chunk_hash or not peer_fp:
            return
        ts = now_ms if now_ms is not None else _now_ms()
        key = (chunk_hash, peer_fp)
        with self._lock:
            if key in self._entries:
                self._entries.move_to_end(key)
                self._entries[key] = ts
            else:
                self._entries[key] = ts
                self._record_count += 1
                while len(self._entries) > self._max_entries:
                    self._entries.popitem(last=False)
                    self._evicted_for_cap += 1

    def record_have_many(
        self,
        chunk_hashes: Iterable[str],
        peer_fp: str,
        *,
        now_ms: Optional[int] = None,
    ) -> None:
        """Bulk insert. Useful for ``CHUNK_HAVE`` advertisements that
        carry a batch of hashes."""
        if not peer_fp:
            return
        ts = now_ms if now_ms is not None else _now_ms()
        for h in chunk_hashes:
            self.record_have(h, peer_fp, now_ms=ts)

    def forget_peer(self, peer_fp: str) -> int:
        """Drop every entry for ``peer_fp``. Returns the number of
        entries removed. Called on peer disconnect / unpair."""
        if not peer_fp:
            return 0
        with self._lock:
            keys = [k for k in self._entries if k[1] == peer_fp]
            for k in keys:
                del self._entries[k]
            self._evicted_for_peer += len(keys)
            return len(keys)

    # ---------- readers ----------

    def sites_for(
        self,
        chunk_hash: str,
        *,
        now_ms: Optional[int] = None,
        exclude: Optional[Iterable[str]] = None,
    ) -> tuple[str, ...]:
        """Return the freshest peers that claim to have ``chunk_hash``,
        sorted newest-first. Entries older than ``ttl_ms`` are filtered
        out (and lazily deleted).

        ``exclude`` — peer fingerprints to filter out (e.g. peers we've
        already asked or the original sender). Set membership; pass
        ``frozenset`` for cheaper hits.
        """
        if not chunk_hash:
            self._miss_count += 1
            return ()
        ts = now_ms if now_ms is not None else _now_ms()
        exclude_set = frozenset(exclude or ())
        with self._lock:
            # Collect matching keys + their timestamps.
            matches: list[tuple[int, str]] = []
            stale_keys: list[tuple[str, str]] = []
            for key, recorded in self._entries.items():
                if key[0] != chunk_hash:
                    continue
                if ts - recorded > self._ttl_ms:
                    stale_keys.append(key)
                    continue
                if key[1] in exclude_set:
                    continue
                matches.append((recorded, key[1]))
            # Lazy GC of stale entries we just walked past.
            for k in stale_keys:
                del self._entries[k]
            if not matches:
                self._miss_count += 1
                return ()
            self._hit_count += 1
            # Newest first.
            matches.sort(key=lambda t: t[0], reverse=True)
            return tuple(p for _, p in matches)

    def has_site(
        self,
        chunk_hash: str,
        *,
        now_ms: Optional[int] = None,
    ) -> bool:
        """Cheap presence check. Skips sorting + tuple build."""
        return bool(self.sites_for(chunk_hash, now_ms=now_ms))

    # ---------- inspection ----------

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def stats(self) -> dict:
        with self._lock:
            return {
                "entries": len(self._entries),
                "records": self._record_count,
                "hits": self._hit_count,
                "misses": self._miss_count,
                "evicted_for_cap": self._evicted_for_cap,
                "evicted_for_peer": self._evicted_for_peer,
                "ttl_ms": self._ttl_ms,
                "max_entries": self._max_entries,
            }

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            # Counters preserved across clear() — they're cumulative
            # ops metrics, not state.
