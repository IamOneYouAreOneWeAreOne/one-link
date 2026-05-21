"""Tests for ``one_link.radio_batcher_native`` — D06 radio-aware batcher.

Exercises the deterministic batcher contract:
  - enqueue / drain semantics across priorities
  - DRX window timing
  - max age force-drain
  - queue full error path
  - radio state set/get
  - stats counters
"""

from __future__ import annotations

import pytest

from one_link import radio_batcher_native as rb


pytestmark = pytest.mark.skipif(
    not rb.HAS_NATIVE,
    reason="one_link_native.radio_batcher not installed; run "
    "`cd native && maturin develop --release`",
)


# ---------- Construction ----------


def test_module_metadata() -> None:
    assert rb.NATIVE_VERSION is not None
    assert rb.DEFAULT_DRX_WINDOW_MS == 50
    assert rb.DEFAULT_MAX_QUEUE_SIZE >= 1024


def test_default_constructor() -> None:
    b = rb.radio_batcher()
    assert b.len == 0
    assert b.is_empty is True
    assert b.drx_window_ms == 50
    assert b.radio_state() == "active"


def test_custom_config() -> None:
    b = rb.radio_batcher(drx_window_ms=100, max_queue_size=10, max_age_ms=5000)
    assert b.drx_window_ms == 100


def test_zero_window_rejected() -> None:
    with pytest.raises(ValueError):
        rb.radio_batcher(drx_window_ms=0)


def test_zero_max_size_rejected() -> None:
    with pytest.raises(ValueError):
        rb.radio_batcher(max_queue_size=0)


# ---------- Enqueue + drain ----------


def test_fresh_entry_not_drained_immediately() -> None:
    b = rb.radio_batcher()
    b.enqueue("peer1", b"hello", "normal", 1000)
    entries, outcome = b.drain(1000)
    assert entries == []
    assert outcome["drained"] == 0
    assert outcome["remaining"] == 1


def test_entry_drains_after_window() -> None:
    b = rb.radio_batcher()
    b.enqueue("peer1", b"hello", "normal", 1000)
    entries, outcome = b.drain(1100)
    assert len(entries) == 1
    assert entries[0]["peer_fp"] == "peer1"
    assert entries[0]["payload"] == b"hello"
    assert entries[0]["priority"] == "normal"
    assert entries[0]["enqueued_at_ms"] == 1000
    assert outcome["drained"] == 1
    assert outcome["remaining"] == 0


def test_urgent_drains_at_same_ms() -> None:
    b = rb.radio_batcher()
    b.enqueue("peer1", b"hello", "urgent", 1000)
    entries, _ = b.drain(1000)
    assert len(entries) == 1


def test_background_waits_longer() -> None:
    b = rb.radio_batcher(drx_window_ms=50)
    b.enqueue("p_normal", b"n", "normal", 1000)
    b.enqueue("p_bg", b"b", "background", 1000)
    # Past 1× DRX window: normal drains, background does not.
    entries, _ = b.drain(1060)
    assert len(entries) == 1
    assert entries[0]["peer_fp"] == "p_normal"
    # Past 3× DRX window: background also drains.
    entries, _ = b.drain(1200)
    assert len(entries) == 1
    assert entries[0]["peer_fp"] == "p_bg"


# ---------- FIFO ordering ----------


def test_fifo_order_preserved() -> None:
    b = rb.radio_batcher()
    for i in range(5):
        b.enqueue(f"peer{i}", bytes([i]), "normal", 1000 + i)
    entries, _ = b.drain(2000)
    assert len(entries) == 5
    for i, e in enumerate(entries):
        assert e["payload"] == bytes([i])


# ---------- Age force-drain ----------


def test_max_age_force_drains() -> None:
    b = rb.radio_batcher(drx_window_ms=1000, max_age_ms=500)
    b.enqueue("p1", b"x", "normal", 1000)
    # After 600ms: window (1000ms) NOT met, age (500ms) met.
    entries, outcome = b.drain(1600)
    assert len(entries) == 1
    assert outcome["force_drained_due_to_age"] == 1


# ---------- Queue full ----------


def test_queue_full_raises_value_error() -> None:
    b = rb.radio_batcher(max_queue_size=3)
    for i in range(3):
        b.enqueue(f"p{i}", b"x", "normal", 1000)
    with pytest.raises(ValueError, match="queue_full"):
        b.enqueue("p4", b"x", "normal", 1000)


# ---------- Drain all ----------


def test_drain_all_flushes_regardless_of_age() -> None:
    b = rb.radio_batcher()
    b.enqueue("p1", b"x", "background", 1000)
    b.enqueue("p2", b"y", "normal", 1010)
    entries = b.drain_all()
    assert len(entries) == 2
    assert b.is_empty is True


# ---------- Radio state ----------


def test_radio_state_round_trip() -> None:
    b = rb.radio_batcher()
    assert b.radio_state() == "active"
    b.set_radio_state("long_drx")
    assert b.radio_state() == "long_drx"
    b.set_radio_state("short_drx")
    assert b.radio_state() == "short_drx"


def test_radio_state_unknown_defaults_active() -> None:
    b = rb.radio_batcher()
    b.set_radio_state("long_drx")
    b.set_radio_state("garbage_label")
    assert b.radio_state() == "active"


# ---------- Stats ----------


def test_stats_track_lifecycle() -> None:
    b = rb.radio_batcher()
    b.enqueue("p1", b"x", "normal", 1000)
    b.enqueue("p2", b"y", "normal", 1000)
    s = b.stats()
    assert s["enqueued_total"] == 2
    assert s["drained_total"] == 0
    b.drain(2000)
    s = b.stats()
    assert s["drained_total"] == 2


def test_stats_track_full_rejection() -> None:
    b = rb.radio_batcher(max_queue_size=2)
    b.enqueue("p1", b"x", "normal", 1000)
    b.enqueue("p2", b"x", "normal", 1000)
    with pytest.raises(ValueError):
        b.enqueue("p3", b"x", "normal", 1000)
    s = b.stats()
    assert s["rejected_full"] == 1


# ---------- Priority error ----------


def test_unknown_priority_rejected() -> None:
    b = rb.radio_batcher()
    with pytest.raises(ValueError, match="unknown priority"):
        b.enqueue("p1", b"x", "supercritical", 1000)


# ---------- Time skew tolerance ----------


def test_time_skew_backward_does_not_lose_entries() -> None:
    b = rb.radio_batcher()
    b.enqueue("p1", b"x", "normal", 5000)
    # Time goes backward (NTP adjust).
    entries, _ = b.drain(4000)
    assert entries == []
    assert b.len == 1
    # When time moves forward, drain works normally.
    entries, _ = b.drain(6000)
    assert len(entries) == 1


# ---------- Repr ----------


def test_repr_includes_state() -> None:
    b = rb.radio_batcher()
    r = repr(b)
    assert "RadioBatcher" in r
    assert "drx_window_ms" in r


# ---------- now_ms helper ----------


def test_now_ms_returns_recent_timestamp() -> None:
    t1 = rb.now_ms()
    t2 = rb.now_ms()
    assert t2 >= t1
    # Sanity: roughly current epoch (> 1.7 trillion ms = 2023+).
    assert t1 > 1_700_000_000_000


# ---------- Realistic scenario ----------


def test_typical_daemon_broadcast_scenario() -> None:
    """Simulates the daemon's broadcast_endpoint_to_paired flow:
    enqueue presence frames to N peers, drain on the next tick.
    """
    b = rb.radio_batcher()
    t0 = 100_000

    # Enqueue 50 paired peers' presence frames as background.
    for i in range(50):
        b.enqueue(f"peer_{i}", f"presence_{i}".encode(), "background", t0)

    # 60ms later: too early for background (needs 3× window = 150ms).
    entries, _ = b.drain(t0 + 60)
    assert len(entries) == 0

    # 200ms later: all 50 ready.
    entries, outcome = b.drain(t0 + 200)
    assert len(entries) == 50
    assert outcome["remaining"] == 0
    assert outcome["drained"] == 50
    # FIFO preserved.
    assert entries[0]["peer_fp"] == "peer_0"
    assert entries[49]["peer_fp"] == "peer_49"
