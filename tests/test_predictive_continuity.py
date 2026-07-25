"""Tests for the Predictive Continuity Engine."""

from __future__ import annotations

import threading

import pytest

from one_link.frame_provenance import FrameKind
from one_link.predictive_continuity import (
    MAX_LOOKAHEAD_AUDIO_FRAMES,
    MAX_LOOKAHEAD_VIDEO_FRAMES,
    CorrectionEvent,
    HoldLastExtrapolator,
    MediaFrame,
    MediaKind,
    PredictiveContinuity,
    _content_novelty,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _real(stream: str, seq: int, content: bytes, *, ts_us: int = 0) -> MediaFrame:
    return MediaFrame(
        stream_id=stream,
        media_kind=MediaKind.AUDIO,
        seq=seq,
        timestamp_us=ts_us,
        content=content,
        frame_kind=FrameKind.REAL,
    )


# ---------------------------------------------------------------------------
# Novelty metric
# ---------------------------------------------------------------------------

def test_novelty_identical_is_zero() -> None:
    assert _content_novelty(b"hello", b"hello") == 0.0


def test_novelty_completely_different_same_length() -> None:
    assert _content_novelty(b"\x00\x00\x00\x00", b"\xff\xff\xff\xff") == 1.0


def test_novelty_empty_both() -> None:
    assert _content_novelty(b"", b"") == 0.0


def test_novelty_one_empty_one_not() -> None:
    assert _content_novelty(b"", b"x") == 1.0
    assert _content_novelty(b"x", b"") == 1.0


def test_novelty_length_mismatch_penalised() -> None:
    """A wrong-length prediction never reads as a confirm."""
    # Two bytes identical, predicted is shorter than real by 2 bytes.
    n = _content_novelty(b"\x00\x00", b"\x00\x00\xff\xff")
    # 2 of 4 bytes mismatch (length penalty).
    assert n == 0.5


# ---------------------------------------------------------------------------
# Engine stream registration
# ---------------------------------------------------------------------------

def test_register_stream_idempotent() -> None:
    eng = PredictiveContinuity()
    eng.register_stream("voice-a", MediaKind.AUDIO)
    eng.register_stream("voice-a", MediaKind.AUDIO)
    assert eng.has_stream("voice-a")


def test_unregistered_stream_raises() -> None:
    eng = PredictiveContinuity()
    with pytest.raises(KeyError, match="not registered"):
        eng.on_frame_due(stream_id="ghost", expected_seq=0, now_us=0)


# ---------------------------------------------------------------------------
# Frame-due path
# ---------------------------------------------------------------------------

def test_no_seed_returns_no_frame() -> None:
    """Without a real frame to extrapolate from, no prediction
    is emitted — the caller renders silence/blank."""
    eng = PredictiveContinuity()
    eng.register_stream("voice-a", MediaKind.AUDIO)
    result = eng.on_frame_due(stream_id="voice-a", expected_seq=0, now_us=0)
    assert result.frame is None
    assert result.reason_code == "no_seed"


def test_predicted_frame_after_real_seed() -> None:
    eng = PredictiveContinuity()
    eng.register_stream("voice-a", MediaKind.AUDIO)
    eng.on_real_frame_arrives(real=_real("voice-a", seq=10, content=b"audio-frame-10"))
    result = eng.on_frame_due(stream_id="voice-a", expected_seq=11, now_us=100)
    assert result.frame is not None
    assert result.frame.frame_kind == FrameKind.PREDICTED
    assert result.frame.seq == 11
    # HoldLastExtrapolator returns the last-real content
    assert result.frame.content == b"audio-frame-10"
    assert result.reason_code == "predicted"


def test_duplicate_seq_does_not_repredict() -> None:
    """Calling on_frame_due twice for the same seq returns None
    the second time — predictions are idempotent per slot."""
    eng = PredictiveContinuity()
    eng.register_stream("voice-a", MediaKind.AUDIO)
    eng.on_real_frame_arrives(real=_real("voice-a", seq=10, content=b"seed"))
    r1 = eng.on_frame_due(stream_id="voice-a", expected_seq=11, now_us=100)
    r2 = eng.on_frame_due(stream_id="voice-a", expected_seq=11, now_us=200)
    assert r1.frame is not None
    assert r2.frame is None
    assert r2.reason_code == "duplicate_seq"


def test_lookahead_cap_audio() -> None:
    """After MAX_LOOKAHEAD_AUDIO_FRAMES predictions, the engine
    emits a BLANK rather than continuing to extrapolate."""
    eng = PredictiveContinuity()
    eng.register_stream("voice-a", MediaKind.AUDIO)
    eng.on_real_frame_arrives(real=_real("voice-a", seq=10, content=b"seed"))
    for i in range(MAX_LOOKAHEAD_AUDIO_FRAMES):
        r = eng.on_frame_due(stream_id="voice-a", expected_seq=11 + i, now_us=100)
        assert r.frame is not None
        assert r.frame.frame_kind == FrameKind.PREDICTED
    # Next call: budget exhausted → BLANK
    over = eng.on_frame_due(
        stream_id="voice-a",
        expected_seq=11 + MAX_LOOKAHEAD_AUDIO_FRAMES,
        now_us=100,
    )
    assert over.frame is not None
    assert over.frame.frame_kind == FrameKind.BLANK
    assert over.reason_code == "blank_budget_exceeded"


def test_lookahead_cap_video_larger_than_audio() -> None:
    """Video tolerates more lookahead than audio."""
    assert MAX_LOOKAHEAD_VIDEO_FRAMES > MAX_LOOKAHEAD_AUDIO_FRAMES


def test_lookahead_cap_video() -> None:
    eng = PredictiveContinuity()
    eng.register_stream("video-a", MediaKind.VIDEO)
    eng.on_real_frame_arrives(real=MediaFrame(
        stream_id="video-a", media_kind=MediaKind.VIDEO,
        seq=10, timestamp_us=0, content=b"seed",
        frame_kind=FrameKind.REAL,
    ))
    # MAX_LOOKAHEAD_VIDEO_FRAMES predictions allowed
    for i in range(MAX_LOOKAHEAD_VIDEO_FRAMES):
        r = eng.on_frame_due(stream_id="video-a", expected_seq=11 + i, now_us=100)
        assert r.frame is not None and r.frame.frame_kind == FrameKind.PREDICTED
    over = eng.on_frame_due(
        stream_id="video-a",
        expected_seq=11 + MAX_LOOKAHEAD_VIDEO_FRAMES,
        now_us=100,
    )
    assert over.frame is not None
    assert over.frame.frame_kind == FrameKind.BLANK


# ---------------------------------------------------------------------------
# Real-frame arrival + confirm/correct
# ---------------------------------------------------------------------------

def test_real_frame_resets_predicted_count() -> None:
    eng = PredictiveContinuity()
    eng.register_stream("voice-a", MediaKind.AUDIO)
    eng.on_real_frame_arrives(real=_real("voice-a", seq=10, content=b"seed"))
    eng.on_frame_due(stream_id="voice-a", expected_seq=11, now_us=100)
    eng.on_frame_due(stream_id="voice-a", expected_seq=12, now_us=200)
    state_before = eng.stream_state("voice-a")
    assert state_before.predicted_count_since_real == 2
    # Real frame arrives
    eng.on_real_frame_arrives(real=_real("voice-a", seq=12, content=b"seed"))
    state_after = eng.stream_state("voice-a")
    assert state_after.predicted_count_since_real == 0


def test_confirm_when_prediction_close_to_real() -> None:
    """HoldLastExtrapolator returns the seed content. If the real
    frame at the predicted seq is the SAME content (perfectly
    stationary signal), novelty = 0 → confirmed."""
    eng = PredictiveContinuity()
    eng.register_stream("voice-a", MediaKind.AUDIO)
    eng.on_real_frame_arrives(real=_real("voice-a", seq=10, content=b"steady"))
    # Predict seq 11 (will return b"steady")
    eng.on_frame_due(stream_id="voice-a", expected_seq=11, now_us=100)
    # Real frame at seq 11 is also b"steady" → confirmed
    correction = eng.on_real_frame_arrives(
        real=_real("voice-a", seq=11, content=b"steady")
    )
    assert correction is None
    state = eng.stream_state("voice-a")
    assert state.confirm_count == 1
    assert state.corrected_count == 0


def test_correct_when_prediction_far_from_real() -> None:
    eng = PredictiveContinuity()
    eng.register_stream("voice-a", MediaKind.AUDIO)
    eng.on_real_frame_arrives(real=_real("voice-a", seq=10, content=b"\x00\x00\x00\x00"))
    # Predict seq 11 — will return b"\x00\x00\x00\x00"
    eng.on_frame_due(stream_id="voice-a", expected_seq=11, now_us=100)
    # Real frame at seq 11 is totally different → corrected
    correction = eng.on_real_frame_arrives(
        real=_real("voice-a", seq=11, content=b"\xff\xff\xff\xff")
    )
    assert correction is not None
    assert correction.seq == 11
    assert correction.novelty > 0.5
    state = eng.stream_state("voice-a")
    assert state.confirm_count == 0
    assert state.corrected_count == 1


def test_real_frame_with_no_prior_prediction_does_not_count() -> None:
    """If no prediction was made for a given slot, the real arrival
    doesn't increment confirm OR correct."""
    eng = PredictiveContinuity()
    eng.register_stream("voice-a", MediaKind.AUDIO)
    eng.on_real_frame_arrives(real=_real("voice-a", seq=10, content=b"a"))
    eng.on_real_frame_arrives(real=_real("voice-a", seq=11, content=b"b"))
    state = eng.stream_state("voice-a")
    assert state.confirm_count == 0
    assert state.corrected_count == 0


# ---------------------------------------------------------------------------
# Confirm ratio dashboard metric
# ---------------------------------------------------------------------------

def test_confirm_ratio_default_is_one() -> None:
    """Empty sample = 1.0 (nothing has been wrong)."""
    eng = PredictiveContinuity()
    eng.register_stream("voice-a", MediaKind.AUDIO)
    assert eng.confirm_ratio("voice-a") == 1.0


def test_confirm_ratio_arithmetic() -> None:
    eng = PredictiveContinuity()
    eng.register_stream("voice-a", MediaKind.AUDIO)
    eng.on_real_frame_arrives(real=_real("voice-a", seq=0, content=b"steady"))

    # 3 confirms
    for seq in (1, 3, 5):
        eng.on_frame_due(stream_id="voice-a", expected_seq=seq, now_us=0)
        eng.on_real_frame_arrives(real=_real("voice-a", seq=seq, content=b"steady"))

    # 1 correct
    eng.on_frame_due(stream_id="voice-a", expected_seq=7, now_us=0)
    eng.on_real_frame_arrives(real=_real("voice-a", seq=7, content=b"NEWNEW"))

    # 3 / (3+1) = 0.75
    assert eng.confirm_ratio("voice-a") == 0.75


# ---------------------------------------------------------------------------
# Multi-stream independence
# ---------------------------------------------------------------------------

def test_streams_are_independent() -> None:
    eng = PredictiveContinuity()
    eng.register_stream("voice-a", MediaKind.AUDIO)
    eng.register_stream("video-a", MediaKind.VIDEO)

    eng.on_real_frame_arrives(real=_real("voice-a", seq=0, content=b"audio-seed"))
    # Predicting voice doesn't affect video state.
    eng.on_frame_due(stream_id="voice-a", expected_seq=1, now_us=0)
    eng.on_frame_due(stream_id="voice-a", expected_seq=2, now_us=0)
    video_state = eng.stream_state("video-a")
    assert video_state.predicted_count_since_real == 0


# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------

def test_predicted_sink_fires_for_predicted_frames() -> None:
    received: list[MediaFrame] = []
    eng = PredictiveContinuity(predicted_sink=received.append)
    eng.register_stream("voice-a", MediaKind.AUDIO)
    eng.on_real_frame_arrives(real=_real("voice-a", seq=0, content=b"seed"))
    eng.on_frame_due(stream_id="voice-a", expected_seq=1, now_us=0)
    assert len(received) == 1
    assert received[0].frame_kind == FrameKind.PREDICTED


def test_correction_sink_fires_only_on_mismatch() -> None:
    received: list[CorrectionEvent] = []
    eng = PredictiveContinuity(correction_sink=received.append)
    eng.register_stream("voice-a", MediaKind.AUDIO)

    # Seed
    eng.on_real_frame_arrives(real=_real("voice-a", seq=0, content=b"\x00\x00"))

    # Match — no correction
    eng.on_frame_due(stream_id="voice-a", expected_seq=1, now_us=0)
    eng.on_real_frame_arrives(real=_real("voice-a", seq=1, content=b"\x00\x00"))
    assert received == []

    # Mismatch — correction fires
    eng.on_frame_due(stream_id="voice-a", expected_seq=2, now_us=0)
    eng.on_real_frame_arrives(real=_real("voice-a", seq=2, content=b"\xff\xff"))
    assert len(received) == 1


def test_sink_raising_does_not_crash() -> None:
    def bad_sink(_f):
        raise RuntimeError("oh no")
    eng = PredictiveContinuity(predicted_sink=bad_sink)
    eng.register_stream("voice-a", MediaKind.AUDIO)
    eng.on_real_frame_arrives(real=_real("voice-a", seq=0, content=b"seed"))
    # Must not raise
    result = eng.on_frame_due(stream_id="voice-a", expected_seq=1, now_us=0)
    assert result.frame is not None


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

def test_concurrent_predictions_and_arrivals_safe() -> None:
    """Multiple threads predicting + arriving don't corrupt state.
    Final counts add up cleanly."""
    eng = PredictiveContinuity()
    eng.register_stream("voice-a", MediaKind.AUDIO)
    eng.on_real_frame_arrives(real=_real("voice-a", seq=0, content=b"seed"))

    errors: list[BaseException] = []

    def writer(start_seq: int) -> None:
        try:
            for i in range(50):
                seq = start_seq + i * 10
                eng.on_frame_due(stream_id="voice-a", expected_seq=seq, now_us=0)
                eng.on_real_frame_arrives(
                    real=_real("voice-a", seq=seq, content=b"seed")
                )
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# ---------------------------------------------------------------------------
# Hold-last extrapolator
# ---------------------------------------------------------------------------

def test_hold_last_extrapolator_returns_last_real_content() -> None:
    ext = HoldLastExtrapolator()
    last = _real("voice-a", seq=10, content=b"audio-frame-10")
    out = ext.extrapolate(last_real=last, steps_ahead=3, now_us=100)
    assert out == b"audio-frame-10"
