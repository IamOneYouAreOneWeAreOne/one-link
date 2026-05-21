"""D17 — Tests for ``one_link.dedupe_sites.DedupeSiteIndex``.

Exercises:
  - record_have idempotency + timestamp refresh
  - record_have_many bulk insert
  - sites_for ordering (newest-first), TTL filter, exclude filter
  - LRU cap eviction
  - forget_peer
  - stats counters
  - bad-input defensive no-ops
"""

from __future__ import annotations

import pytest

from one_link.dedupe_sites import DEFAULT_MAX_ENTRIES, DedupeSiteIndex


# ---------- construction ----------


def test_default_construction() -> None:
    idx = DedupeSiteIndex()
    assert len(idx) == 0
    stats = idx.stats()
    assert stats["entries"] == 0
    assert stats["records"] == 0


def test_invalid_ttl_rejected() -> None:
    with pytest.raises(ValueError):
        DedupeSiteIndex(ttl_ms=0)
    with pytest.raises(ValueError):
        DedupeSiteIndex(ttl_ms=-1)


def test_invalid_max_entries_rejected() -> None:
    with pytest.raises(ValueError):
        DedupeSiteIndex(max_entries=0)


# ---------- record_have ----------


def test_record_have_inserts_entry() -> None:
    idx = DedupeSiteIndex()
    idx.record_have("hash1", "peerA", now_ms=1000)
    assert len(idx) == 1
    assert idx.has_site("hash1", now_ms=1000)


def test_record_have_idempotent() -> None:
    idx = DedupeSiteIndex()
    idx.record_have("hash1", "peerA", now_ms=1000)
    idx.record_have("hash1", "peerA", now_ms=2000)
    # Still one entry; recorded count NOT incremented on duplicate.
    assert len(idx) == 1
    assert idx.stats()["records"] == 1


def test_record_have_refreshes_timestamp() -> None:
    idx = DedupeSiteIndex(ttl_ms=5_000)
    idx.record_have("hash1", "peerA", now_ms=1_000)
    # 6000ms later, original entry would be stale (>5000 TTL).
    # Refresh at 6000 — should still be live.
    idx.record_have("hash1", "peerA", now_ms=6_000)
    assert idx.sites_for("hash1", now_ms=8_000) == ("peerA",)


def test_record_have_ignores_empty() -> None:
    idx = DedupeSiteIndex()
    idx.record_have("", "peerA")
    idx.record_have("hash1", "")
    idx.record_have("", "")
    assert len(idx) == 0


# ---------- record_have_many ----------


def test_record_have_many_bulk_insert() -> None:
    idx = DedupeSiteIndex()
    hashes = ["h1", "h2", "h3"]
    idx.record_have_many(hashes, "peerA", now_ms=1000)
    assert len(idx) == 3
    for h in hashes:
        assert idx.has_site(h, now_ms=1000)


def test_record_have_many_empty_peer_no_op() -> None:
    idx = DedupeSiteIndex()
    idx.record_have_many(["h1", "h2"], "")
    assert len(idx) == 0


# ---------- sites_for ----------


def test_sites_for_returns_newest_first() -> None:
    idx = DedupeSiteIndex()
    idx.record_have("hash1", "peerA", now_ms=1000)
    idx.record_have("hash1", "peerB", now_ms=2000)
    idx.record_have("hash1", "peerC", now_ms=1500)
    # peerB recorded latest, then peerC, then peerA.
    assert idx.sites_for("hash1", now_ms=3000) == ("peerB", "peerC", "peerA")


def test_sites_for_filters_stale() -> None:
    idx = DedupeSiteIndex(ttl_ms=1000)
    idx.record_have("hash1", "peerA", now_ms=0)
    idx.record_have("hash1", "peerB", now_ms=500)
    # At t=1500: peerA stale (>1000ms), peerB live (1000ms exactly).
    assert idx.sites_for("hash1", now_ms=1500) == ("peerB",)
    # Stale entry was lazily reaped.
    assert len(idx) == 1


def test_sites_for_excludes_listed_peers() -> None:
    idx = DedupeSiteIndex()
    idx.record_have("hash1", "peerA", now_ms=1000)
    idx.record_have("hash1", "peerB", now_ms=2000)
    out = idx.sites_for("hash1", now_ms=3000, exclude=["peerB"])
    assert out == ("peerA",)


def test_sites_for_empty_hash_returns_empty() -> None:
    idx = DedupeSiteIndex()
    assert idx.sites_for("", now_ms=1000) == ()


def test_sites_for_unknown_hash_returns_empty() -> None:
    idx = DedupeSiteIndex()
    idx.record_have("hash1", "peerA", now_ms=1000)
    assert idx.sites_for("hash_other", now_ms=1000) == ()


def test_has_site_cheap_presence_check() -> None:
    idx = DedupeSiteIndex()
    idx.record_have("hash1", "peerA", now_ms=1000)
    assert idx.has_site("hash1", now_ms=1000) is True
    assert idx.has_site("nope", now_ms=1000) is False


# ---------- LRU cap ----------


def test_lru_cap_evicts_oldest() -> None:
    idx = DedupeSiteIndex(max_entries=3)
    idx.record_have("h1", "p1", now_ms=1)
    idx.record_have("h2", "p2", now_ms=2)
    idx.record_have("h3", "p3", now_ms=3)
    assert len(idx) == 3
    # Adding a 4th evicts the oldest (h1/p1).
    idx.record_have("h4", "p4", now_ms=4)
    assert len(idx) == 3
    # h1 is gone.
    assert idx.sites_for("h1", now_ms=10) == ()
    assert idx.sites_for("h4", now_ms=10) == ("p4",)
    assert idx.stats()["evicted_for_cap"] == 1


def test_lru_refresh_moves_to_end() -> None:
    idx = DedupeSiteIndex(max_entries=3)
    idx.record_have("h1", "p1", now_ms=1)
    idx.record_have("h2", "p2", now_ms=2)
    idx.record_have("h3", "p3", now_ms=3)
    # Refresh h1/p1 — should move it to MRU position.
    idx.record_have("h1", "p1", now_ms=4)
    # Now add a 4th — h2/p2 is the oldest, not h1/p1.
    idx.record_have("h4", "p4", now_ms=5)
    assert idx.sites_for("h1", now_ms=10) == ("p1",)
    assert idx.sites_for("h2", now_ms=10) == ()


# ---------- forget_peer ----------


def test_forget_peer_drops_all_entries() -> None:
    idx = DedupeSiteIndex()
    idx.record_have("h1", "peerA", now_ms=1000)
    idx.record_have("h2", "peerA", now_ms=1001)
    idx.record_have("h1", "peerB", now_ms=1002)
    n = idx.forget_peer("peerA")
    assert n == 2
    assert idx.sites_for("h1", now_ms=2000) == ("peerB",)
    assert idx.sites_for("h2", now_ms=2000) == ()
    assert idx.stats()["evicted_for_peer"] == 2


def test_forget_peer_unknown_returns_zero() -> None:
    idx = DedupeSiteIndex()
    idx.record_have("h1", "peerA", now_ms=1000)
    assert idx.forget_peer("ghost") == 0


def test_forget_peer_empty_returns_zero() -> None:
    idx = DedupeSiteIndex()
    idx.record_have("h1", "peerA", now_ms=1000)
    assert idx.forget_peer("") == 0


# ---------- stats / clear ----------


def test_stats_reflects_activity() -> None:
    idx = DedupeSiteIndex()
    idx.record_have("h1", "p1")
    idx.sites_for("h1")  # hit
    idx.sites_for("h2")  # miss
    s = idx.stats()
    assert s["entries"] == 1
    assert s["records"] == 1
    assert s["hits"] == 1
    assert s["misses"] == 1


def test_clear_drops_state_keeps_counters() -> None:
    idx = DedupeSiteIndex()
    idx.record_have("h1", "p1")
    idx.sites_for("h1")
    idx.clear()
    assert len(idx) == 0
    # Cumulative counters are ops metrics, not state.
    s = idx.stats()
    assert s["records"] == 1
    assert s["hits"] == 1


# ---------- thread-safety smoke ----------


def test_concurrent_inserts() -> None:
    """Smoke test the RLock: many threads writing should not crash and
    should produce a consistent final state."""
    import threading

    idx = DedupeSiteIndex(max_entries=DEFAULT_MAX_ENTRIES)

    def writer(start: int) -> None:
        for i in range(200):
            idx.record_have(f"h{start + i}", f"peer{start}")

    threads = [threading.Thread(target=writer, args=(k * 1000,)) for k in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # 8 threads * 200 unique entries = 1600 total unique inserts.
    assert idx.stats()["records"] == 1600
    assert len(idx) == 1600
