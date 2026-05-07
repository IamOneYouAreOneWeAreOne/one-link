from __future__ import annotations

from one_link.replay_window import (
    ACCEPT_NEW,
    ACCEPT_REORDER,
    REJECT_BAD_TIMESTAMP,
    REJECT_REPLAY,
    REJECT_TOO_OLD,
    ReplayWindow,
)


def test_accepts_new_sequences_and_moves_high_water():
    rw = ReplayWindow(window_size=8)
    now = 1_000_000
    d1 = rw.check(seq=1, now_ms=now, ts_ms=now)
    d2 = rw.check(seq=2, now_ms=now, ts_ms=now)
    assert d1.accepted and d1.outcome == ACCEPT_NEW
    assert d2.accepted and d2.high_water == 2


def test_rejects_exact_replay():
    rw = ReplayWindow(window_size=8)
    now = 1_000_000
    assert rw.check(seq=10, now_ms=now, ts_ms=now).accepted
    replay = rw.check(seq=10, now_ms=now, ts_ms=now)
    assert replay.accepted is False
    assert replay.outcome == REJECT_REPLAY


def test_accepts_reordered_frame_inside_window_once():
    rw = ReplayWindow(window_size=8)
    now = 1_000_000
    for seq in (10, 12):
        assert rw.check(seq=seq, now_ms=now, ts_ms=now).accepted
    reorder = rw.check(seq=11, now_ms=now, ts_ms=now)
    assert reorder.accepted
    assert reorder.outcome == ACCEPT_REORDER
    assert rw.check(seq=11, now_ms=now, ts_ms=now).outcome == REJECT_REPLAY


def test_rejects_too_old_sequence_outside_window():
    rw = ReplayWindow(window_size=4)
    now = 1_000_000
    assert rw.check(seq=10, now_ms=now, ts_ms=now).accepted
    assert rw.check(seq=6, now_ms=now, ts_ms=now).outcome == REJECT_TOO_OLD


def test_rejects_bad_timestamps_without_mutating_window():
    rw = ReplayWindow(window_size=8, max_age_ms=100, max_future_skew_ms=100)
    now = 1_000_000
    old = rw.check(seq=1, now_ms=now, ts_ms=now - 101)
    future = rw.check(seq=1, now_ms=now, ts_ms=now + 101)
    assert old.outcome == REJECT_BAD_TIMESTAMP
    assert future.outcome == REJECT_BAD_TIMESTAMP
    assert rw.high_water is None


def test_large_jump_resets_bitmap_and_still_rejects_old_tail():
    rw = ReplayWindow(window_size=4)
    now = 1_000_000
    assert rw.check(seq=1, now_ms=now, ts_ms=now).accepted
    assert rw.check(seq=100, now_ms=now, ts_ms=now).accepted
    assert rw.check(seq=1, now_ms=now, ts_ms=now).outcome == REJECT_TOO_OLD
