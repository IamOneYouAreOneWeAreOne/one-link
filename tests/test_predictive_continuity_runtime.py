"""Tests for the Predictive Continuity live runtime.

Verifies the per-call adapter correctly aggregates browser-reported
frame events into running confirm ratios that the Immune System's
vitals composer can read.
"""

from __future__ import annotations


from one_link.predictive_continuity import MediaKind
from one_link.predictive_continuity_runtime import PredictiveContinuityRuntime


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def test_open_call_then_default_confirm_ratio_is_one() -> None:
    """Trivially confirmed when no media has flowed yet."""
    r = PredictiveContinuityRuntime()
    r.open_call("c1")
    assert r.confirm_ratio_voice("c1") == 1.0
    assert r.confirm_ratio_video("c1") == 1.0


def test_close_call_releases_state() -> None:
    r = PredictiveContinuityRuntime()
    r.open_call("c1")
    r.close_call("c1")
    # Confirm-ratio for missing call falls back to 1.0.
    assert r.confirm_ratio_voice("c1") == 1.0


def test_open_call_is_idempotent() -> None:
    r = PredictiveContinuityRuntime()
    r.open_call("c1")
    r.open_call("c1")  # Must not raise.
    assert r.confirm_ratio_voice("c1") == 1.0


# ---------------------------------------------------------------------------
# Real frame observation
# ---------------------------------------------------------------------------

def test_real_frame_increments_decision_counter() -> None:
    r = PredictiveContinuityRuntime()
    r.open_call("c1")
    r.observe_real_frame(
        call_id="c1", media_kind=MediaKind.AUDIO,
        seq=1, timestamp_us=0, content=b"a",
    )
    stats = r.stats("c1")
    assert stats["decisions_audio"] == 1
    # First real frame — counted as a confirmation (no prior prediction).
    assert stats["confirm_ratio_voice"] == 1.0


def test_audio_and_video_tracked_separately() -> None:
    r = PredictiveContinuityRuntime()
    r.open_call("c1")
    r.observe_real_frame(
        call_id="c1", media_kind=MediaKind.AUDIO,
        seq=1, timestamp_us=0, content=b"a",
    )
    r.observe_real_frame(
        call_id="c1", media_kind=MediaKind.VIDEO,
        seq=1, timestamp_us=0, content=b"v",
    )
    stats = r.stats("c1")
    assert stats["decisions_audio"] == 1
    assert stats["decisions_video"] == 1


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

def test_request_prediction_without_seed_refuses() -> None:
    r = PredictiveContinuityRuntime()
    r.open_call("c1")
    # No real frame yet; can't predict.
    result = r.request_prediction(
        call_id="c1", media_kind=MediaKind.AUDIO,
        due_seq=1, now_us=1000,
    )
    assert result is not None
    assert result.frame is None
    assert result.reason_code == "no_seed"


def test_request_prediction_after_real_frame_emits_predicted() -> None:
    r = PredictiveContinuityRuntime()
    r.open_call("c1")
    r.observe_real_frame(
        call_id="c1", media_kind=MediaKind.AUDIO,
        seq=1, timestamp_us=0, content=b"audio-1",
    )
    result = r.request_prediction(
        call_id="c1", media_kind=MediaKind.AUDIO,
        due_seq=2, now_us=20_000,
    )
    assert result is not None
    assert result.frame is not None
    # Frame is tagged PREDICTED so the Reality dot will show it.
    from one_link.frame_provenance import FrameKind
    assert result.frame.frame_kind == FrameKind.PREDICTED


def test_request_prediction_for_unknown_call_returns_none() -> None:
    r = PredictiveContinuityRuntime()
    result = r.request_prediction(
        call_id="ghost", media_kind=MediaKind.AUDIO,
        due_seq=1, now_us=0,
    )
    assert result is None


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_stats_for_unknown_call_is_empty() -> None:
    r = PredictiveContinuityRuntime()
    assert r.stats("ghost") == {}


def test_stats_includes_last_seq_for_each_stream() -> None:
    r = PredictiveContinuityRuntime()
    r.open_call("c1")
    r.observe_real_frame(
        call_id="c1", media_kind=MediaKind.AUDIO,
        seq=42, timestamp_us=0, content=b"a",
    )
    stats = r.stats("c1")
    assert stats["last_real_seq_audio"] == 42
    assert stats["last_real_seq_video"] == -1
