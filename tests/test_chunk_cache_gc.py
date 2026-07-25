"""Unit tests for the chunk cache LRU eviction module.

Exercises the eviction policy in isolation from the daemon —
fake cache_dir, mock state, predictable mtimes.
"""

from __future__ import annotations

import os
import time
from pathlib import Path


from one_link.chunk_cache_gc import (
    evict_to_target,
    gather_protected_hashes,
    scan_cache,
)


def _make_chunk(cache_dir: Path, hash_hex: str, payload: bytes, mtime: float) -> Path:
    """Write a fake cache entry at <cache_dir>/<hash[:2]>/<hash[2:]>
    with the requested size and mtime."""
    prefix = cache_dir / hash_hex[:2]
    prefix.mkdir(parents=True, exist_ok=True)
    p = prefix / hash_hex[2:]
    p.write_bytes(payload)
    os.utime(p, (mtime, mtime))
    return p


def _hash_for(i: int) -> str:
    """Deterministic 64-char hex per integer id."""
    return f"{i:064x}"


class FakeState:
    def __init__(self) -> None:
        self.forgotten: list[str] = []

    def forget_chunk_available(self, chunk_hash: str) -> None:
        self.forgotten.append(chunk_hash)


def test_evict_does_nothing_when_under_cap(tmp_path: Path) -> None:
    cache = tmp_path / "file_chunks"
    cache.mkdir()
    now = time.time()
    _make_chunk(cache, _hash_for(1), b"x" * 100, now - 3600 * 24)
    _make_chunk(cache, _hash_for(2), b"y" * 100, now - 3600 * 24)
    state = FakeState()
    report = evict_to_target(
        cache,
        max_bytes=10_000,  # well above 200 bytes used
        state=state,
    )
    assert report.evicted_files == 0
    assert report.scanned_files == 2
    assert state.forgotten == []
    # Files still on disk.
    assert all(p.exists() for p in cache.rglob("*") if p.is_file())


def test_evict_oldest_first(tmp_path: Path) -> None:
    """When the cache is over-budget, eviction removes the
    least-recently-accessed entries until the total drops to
    target_bytes."""
    cache = tmp_path / "file_chunks"
    cache.mkdir()
    now = time.time()
    # Three 1 KB chunks: 1 day, 2 days, 3 days old.
    _make_chunk(cache, _hash_for(1), b"a" * 1024, now - 86400 * 1)
    _make_chunk(cache, _hash_for(2), b"b" * 1024, now - 86400 * 2)
    _make_chunk(cache, _hash_for(3), b"c" * 1024, now - 86400 * 3)
    state = FakeState()
    # Max 2 KB, target 1 KB → must evict 2 chunks (oldest two).
    report = evict_to_target(
        cache,
        max_bytes=2 * 1024,
        target_bytes=1 * 1024,
        state=state,
        now=now,
    )
    assert report.evicted_files == 2
    assert report.evicted_bytes == 2 * 1024
    # Newest survived.
    assert (cache / _hash_for(1)[:2] / _hash_for(1)[2:]).exists()
    # Oldest two are gone.
    assert not (cache / _hash_for(2)[:2] / _hash_for(2)[2:]).exists()
    assert not (cache / _hash_for(3)[:2] / _hash_for(3)[2:]).exists()
    # State DB was notified for each evicted hash.
    assert sorted(state.forgotten) == sorted([_hash_for(2), _hash_for(3)])


def test_protected_hashes_skipped(tmp_path: Path) -> None:
    """A hash in protected_hashes must NEVER be evicted even when
    it's the oldest — an in-progress transfer would lose its
    bytes mid-flight otherwise."""
    cache = tmp_path / "file_chunks"
    cache.mkdir()
    now = time.time()
    protected = _hash_for(1)
    unprotected_a = _hash_for(2)
    unprotected_b = _hash_for(3)
    _make_chunk(cache, protected, b"p" * 1024, now - 86400 * 7)  # OLDEST
    _make_chunk(cache, unprotected_a, b"a" * 1024, now - 86400 * 3)
    _make_chunk(cache, unprotected_b, b"b" * 1024, now - 86400 * 2)
    state = FakeState()
    report = evict_to_target(
        cache,
        max_bytes=2 * 1024,
        target_bytes=1 * 1024,
        protected_hashes={protected},
        state=state,
        now=now,
    )
    # The protected (oldest) entry survives; unprotected_a (next
    # oldest) is evicted; unprotected_b may or may not be — but
    # protected MUST stay.
    assert (cache / protected[:2] / protected[2:]).exists()
    assert report.skipped_protected >= 1
    assert protected not in state.forgotten


def test_min_age_seconds_protects_recent(tmp_path: Path) -> None:
    """Even without explicit protected_hashes, chunks accessed
    within min_age_seconds must not be evicted — they're likely
    load-bearing for an active transfer the daemon hasn't yet
    catalogued."""
    cache = tmp_path / "file_chunks"
    cache.mkdir()
    now = time.time()
    fresh = _hash_for(1)
    stale = _hash_for(2)
    _make_chunk(cache, fresh, b"f" * 1024, now - 30)  # 30 sec ago
    _make_chunk(cache, stale, b"s" * 1024, now - 86400 * 5)  # 5 days ago
    state = FakeState()
    report = evict_to_target(
        cache,
        max_bytes=1024,  # cache is 2 KB; over budget
        target_bytes=512,
        min_age_seconds=300,  # 5 min
        state=state,
        now=now,
    )
    # The stale one is evicted; the fresh one is preserved.
    assert (cache / fresh[:2] / fresh[2:]).exists()
    assert not (cache / stale[:2] / stale[2:]).exists()
    assert report.evicted_files == 1
    assert state.forgotten == [stale]


def test_state_failure_is_non_fatal(tmp_path: Path) -> None:
    """A State.forget_chunk_available exception must NOT abort the
    eviction pass. The cache file is already gone; an inconsistent
    DB row is corrected on the next ``_read_chunk_cache`` call.
    """
    cache = tmp_path / "file_chunks"
    cache.mkdir()
    now = time.time()
    _make_chunk(cache, _hash_for(1), b"a" * 1024, now - 86400 * 3)
    _make_chunk(cache, _hash_for(2), b"b" * 1024, now - 86400 * 2)

    class BrokenState:
        def forget_chunk_available(self, h: str) -> None:
            raise RuntimeError("db down")

    report = evict_to_target(
        cache,
        max_bytes=512,
        target_bytes=256,
        state=BrokenState(),
        now=now,
    )
    # Eviction proceeded despite DB exceptions.
    assert report.evicted_files == 2


def test_scan_cache_skips_garbage(tmp_path: Path) -> None:
    """Files outside the expected ``<hash[:2]>/<hash[2:]>`` layout
    (in-progress temp files, stray things a user dropped in)
    must be ignored, not crash the scan."""
    cache = tmp_path / "file_chunks"
    cache.mkdir()
    now = time.time()
    # Valid entry
    _make_chunk(cache, _hash_for(1), b"x" * 100, now - 3600)
    # Single-letter dir (junk)
    (cache / "z").mkdir()
    (cache / "z" / "garbage").write_bytes(b"not a chunk")
    # Top-level file (junk)
    (cache / "stray.bin").write_bytes(b"nope")
    # Wrong-length hash in valid prefix dir (truncated)
    (cache / _hash_for(1)[:2] / "short").write_bytes(b"x")
    entries = list(scan_cache(cache))
    # Only the one valid entry should be returned.
    assert len(entries) == 1
    assert entries[0].hash_hex == _hash_for(1)


def test_scan_cache_missing_dir(tmp_path: Path) -> None:
    """A non-existent cache directory yields zero entries, not an
    exception. Fresh installs may not have created the dir yet."""
    cache = tmp_path / "never_created"
    assert list(scan_cache(cache)) == []


def test_gather_protected_hashes_from_incoming_files() -> None:
    """The protected-set helper unpacks CDC manifests from an
    in-progress incoming-files dict."""
    class FakeIncoming:
        def __init__(self, chunks):
            self.cdc_chunks = chunks

    incoming = {
        "blob1": FakeIncoming([
            {"index": 0, "hash": "a" * 64, "size": 1},
            {"index": 1, "hash": "b" * 64, "size": 1},
        ]),
        "blob2": FakeIncoming([
            {"index": 0, "hash": "c" * 64, "size": 1},
        ]),
        # Non-CDC transfer (cdc_chunks=None) — contributes nothing.
        "blob3": FakeIncoming(None),
    }
    protected = gather_protected_hashes(incoming)
    assert protected == {"a" * 64, "b" * 64, "c" * 64}


def test_env_var_override(tmp_path: Path, monkeypatch) -> None:
    """ONE_LINK_CHUNK_CACHE_MAX_BYTES overrides the default cap."""
    cache = tmp_path / "file_chunks"
    cache.mkdir()
    now = time.time()
    _make_chunk(cache, _hash_for(1), b"x" * 2048, now - 86400 * 5)
    monkeypatch.setenv("ONE_LINK_CHUNK_CACHE_MAX_BYTES", "1024")
    # Don't pass max_bytes explicitly — module should read env.
    report = evict_to_target(cache, state=FakeState(), now=now)
    assert report.evicted_files == 1
    assert report.evicted_bytes == 2048
