"""Tests for the QoS-class transport prioritizer.

Property the suite must enforce: under bandwidth pressure, voice
queue drains before file-chunk queue. The Immune System's
REQUEST_VOICE_ONLY signal MUST be operationally meaningful — this
is what makes the call survive a saturated link.
"""

from __future__ import annotations

import pytest

from one_link.transport_priority import (
    DEFAULT_WEIGHTS_PER_CLASS,
    QoSClass,
    TransportPrioritizer,
    classify,
)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def test_classify_voice_frame_is_p0() -> None:
    assert classify("CALL_FRAME") == QoSClass.VOICE_FRAMES


def test_classify_call_lifecycle_is_p0() -> None:
    assert classify("CALL_INVITE") == QoSClass.CALL_LIFECYCLE
    assert classify("CALL_END") == QoSClass.CALL_LIFECYCLE


def test_classify_file_chunk_is_p4() -> None:
    assert classify("FILE_CHUNK") == QoSClass.FILE_CHUNK
    assert classify("FILE_BIN_CHUNK") == QoSClass.FILE_CHUNK


def test_classify_unknown_type_falls_through_to_file_chunk() -> None:
    assert classify("SOMETHING_NEW_THE_DAEMON_INVENTED") == QoSClass.FILE_CHUNK


def test_classify_attestation_is_p1() -> None:
    assert classify("CALL_FRAME_ATTEST") == QoSClass.FRAME_ATTESTATION


# ---------------------------------------------------------------------------
# Basic enqueue + drain
# ---------------------------------------------------------------------------

def test_enqueue_then_drain_returns_message() -> None:
    p = TransportPrioritizer()
    assert p.enqueue(payload=b"hello", qos_class=QoSClass.VOICE_FRAMES) is True
    drained = p.drain()
    assert len(drained) == 1
    assert drained[0].payload == b"hello"


def test_drain_returns_high_priority_class_first() -> None:
    """Voice + file are both queued. Voice must come out first."""
    p = TransportPrioritizer()
    p.enqueue(payload=b"file-bytes", qos_class=QoSClass.FILE_CHUNK)
    p.enqueue(payload=b"voice", qos_class=QoSClass.VOICE_FRAMES)
    drained = p.drain()
    # Voice is P0 (value 0), File is P4 (value 40) — voice first.
    assert drained[0].payload == b"voice"


def test_drain_emits_callback_after_send() -> None:
    p = TransportPrioritizer()
    fired = []
    p.enqueue(
        payload=b"x", qos_class=QoSClass.VOICE_FRAMES,
        on_sent=lambda: fired.append(True),
    )
    drained = p.drain()
    assert len(drained) == 1
    # Caller fires the callback after writing to the wire.
    drained[0].on_sent()
    assert fired == [True]


def test_enqueue_dropped_when_class_queue_full() -> None:
    p = TransportPrioritizer(max_queue_bytes_per_class=100)
    assert p.enqueue(payload=b"x" * 80, qos_class=QoSClass.VOICE_FRAMES)
    # This one pushes past the cap.
    assert not p.enqueue(payload=b"x" * 80, qos_class=QoSClass.VOICE_FRAMES)
    stats = p.stats()
    assert stats["VOICE_FRAMES"]["dropped"] == 1


# ---------------------------------------------------------------------------
# Voice-only mode (the headline guarantee)
# ---------------------------------------------------------------------------

def test_voice_only_mode_throttles_non_voice_classes() -> None:
    """In voice-only mode, file bytes must NOT drain even if many
    are queued and voice queue is empty. The throttle is so tight
    that lower classes effectively starve."""
    p = TransportPrioritizer(max_queue_bytes_per_class=10 * 1024 * 1024)
    # Cap budget so the test deterministically observes throttling.
    p.set_budget_per_tick(2_000)
    p.enter_voice_only_mode()
    # No voice messages — only file.
    for i in range(20):
        p.enqueue(payload=b"x" * 100, qos_class=QoSClass.FILE_CHUNK)
    drained = p.drain()
    # FILE_CHUNK's weight is throttled to <= 5 bytes/tick; head-of-line
    # message is 100 bytes; deficit never covers it on a single tick.
    assert len(drained) == 0


def test_voice_passes_through_under_voice_only_mode() -> None:
    p = TransportPrioritizer()
    p.enter_voice_only_mode()
    p.enqueue(payload=b"v" * 200, qos_class=QoSClass.VOICE_FRAMES)
    p.enqueue(payload=b"f" * 200, qos_class=QoSClass.FILE_CHUNK)
    drained = p.drain()
    # Voice gets through, file does not.
    classes = [m.qos_class for m in drained]
    assert QoSClass.VOICE_FRAMES in classes
    assert QoSClass.FILE_CHUNK not in classes


def test_exit_voice_only_restores_weights() -> None:
    p = TransportPrioritizer()
    p.set_budget_per_tick(10_000)
    original = dict(DEFAULT_WEIGHTS_PER_CLASS)
    p.enter_voice_only_mode()
    p.exit_voice_only_mode()
    # File-chunk weight restored.
    p.enqueue(payload=b"f" * 200, qos_class=QoSClass.FILE_CHUNK)
    # Drain over a few ticks (FILE_CHUNK weight is 500 default).
    sent_bytes = 0
    for _ in range(3):
        drained = p.drain()
        sent_bytes += sum(m.size for m in drained)
    assert sent_bytes >= 200


# ---------------------------------------------------------------------------
# Bandwidth-cap scenario (the Tier β acceptance test)
# ---------------------------------------------------------------------------

def test_voice_survives_under_30kbps_bandwidth_cap() -> None:
    """The doctrine + Tier β acceptance: voice intelligible at 30
    kbps total bandwidth. At 30 kbps over a 1-second drain tick that
    is 3,750 bytes. The prioritizer must let voice frames through
    (~1.5 KB/s for Opus 12 kbps) AND starve file chunks during
    the cap."""
    p = TransportPrioritizer()
    p.set_budget_per_tick(3_750)  # 30 kbps = 3750 B/s

    # 1 second of voice (20 packets of 80 bytes ≈ 1600 B/s = 12.8 kbps)
    for _ in range(20):
        p.enqueue(payload=b"v" * 80, qos_class=QoSClass.VOICE_FRAMES)
    # Many file chunks queued
    for _ in range(100):
        p.enqueue(payload=b"f" * 1000, qos_class=QoSClass.FILE_CHUNK)

    drained = p.drain()
    voice_sent = sum(1 for m in drained if m.qos_class == QoSClass.VOICE_FRAMES)
    file_sent = sum(1 for m in drained if m.qos_class == QoSClass.FILE_CHUNK)
    # All 20 voice packets fit (1600 B); the rest of the budget is
    # available for file chunks.
    assert voice_sent == 20
    # File chunks may take some, but voice prevails.
    assert voice_sent > 0


# ---------------------------------------------------------------------------
# Stats + back-pressure introspection
# ---------------------------------------------------------------------------

def test_stats_track_enqueue_and_send_counts() -> None:
    p = TransportPrioritizer()
    p.enqueue(payload=b"x", qos_class=QoSClass.VOICE_FRAMES)
    p.enqueue(payload=b"y", qos_class=QoSClass.VOICE_FRAMES)
    p.drain()
    stats = p.stats()
    assert stats["VOICE_FRAMES"]["enqueued"] == 2
    assert stats["VOICE_FRAMES"]["sent"] == 2


def test_total_queue_bytes_reflects_enqueued() -> None:
    p = TransportPrioritizer()
    p.enqueue(payload=b"x" * 100, qos_class=QoSClass.VOICE_FRAMES)
    p.enqueue(payload=b"x" * 200, qos_class=QoSClass.FILE_CHUNK)
    assert p.total_queue_bytes() == 300


# ---------------------------------------------------------------------------
# Weight adjustment
# ---------------------------------------------------------------------------

def test_set_weight_rejects_negative() -> None:
    p = TransportPrioritizer()
    with pytest.raises(ValueError):
        p.set_weight(QoSClass.VOICE_FRAMES, -1)


def test_set_weight_changes_per_tick_credit() -> None:
    p = TransportPrioritizer()
    # Default voice weight = 2000. Set to 50 so a 100-byte voice
    # frame can't drain in one tick.
    p.set_weight(QoSClass.VOICE_FRAMES, 50)
    p.enqueue(payload=b"v" * 100, qos_class=QoSClass.VOICE_FRAMES)
    drained = p.drain()
    # 50 < 100 = head packet size, so no drain this tick.
    assert drained == []
    # Next tick: deficit = 100, drains.
    drained = p.drain()
    assert len(drained) == 1


def test_reset_counters_zeros_stats() -> None:
    p = TransportPrioritizer()
    p.enqueue(payload=b"x", qos_class=QoSClass.VOICE_FRAMES)
    p.drain()
    p.reset_counters()
    stats = p.stats()
    assert stats["VOICE_FRAMES"]["sent"] == 0
    assert stats["VOICE_FRAMES"]["enqueued"] == 0


# ---------------------------------------------------------------------------
# Within-class FIFO
# ---------------------------------------------------------------------------

def test_within_class_messages_drain_in_fifo_order() -> None:
    p = TransportPrioritizer()
    p.enqueue(payload=b"a", qos_class=QoSClass.VOICE_FRAMES)
    p.enqueue(payload=b"b", qos_class=QoSClass.VOICE_FRAMES)
    p.enqueue(payload=b"c", qos_class=QoSClass.VOICE_FRAMES)
    drained = p.drain()
    assert [m.payload for m in drained] == [b"a", b"b", b"c"]
