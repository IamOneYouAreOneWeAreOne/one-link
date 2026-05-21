"""Tests for the Tier η neural extrapolator.

Verifies the voice-predictor-backed extrapolator produces
plausible continuations + falls back gracefully when seed data
isn't available.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest


torch = pytest.importorskip("torch", exc_type=(ImportError, OSError))

CKPT_PATH = Path(__file__).resolve().parents[1] / "assets" / "models" / "voice_predictor_v3_librispeech" / "checkpoint.pt"
if not CKPT_PATH.exists():
    pytest.skip(
        f"voice checkpoint not vendored at {CKPT_PATH}",
        allow_module_level=True,
    )

from one_link.frame_provenance import FrameKind  # noqa: E402
from one_link.neural_extrapolator import (  # noqa: E402
    VoiceNeuralExtrapolator,
    _IdentityExtrapolator,
    predictive_confidence,
)
from one_link.predictive_continuity import (  # noqa: E402
    MediaFrame,
    MediaKind,
)


# ---------------------------------------------------------------------------
# Identity extrapolator (reference)
# ---------------------------------------------------------------------------

def test_identity_extrapolator_holds_last_content() -> None:
    frame = MediaFrame(
        stream_id="s", media_kind=MediaKind.AUDIO,
        seq=1, timestamp_us=0, content=b"hello",
        frame_kind=FrameKind.REAL,
    )
    out = _IdentityExtrapolator().extrapolate(
        last_real=frame, steps_ahead=1, now_us=0,
    )
    assert out == b"hello"


# ---------------------------------------------------------------------------
# Voice neural extrapolator
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def extrapolator() -> VoiceNeuralExtrapolator:
    return VoiceNeuralExtrapolator(CKPT_PATH, device="cpu")


def test_no_seed_falls_back_to_hold_last(
    extrapolator: VoiceNeuralExtrapolator,
) -> None:
    extrapolator.reset()
    frame = MediaFrame(
        stream_id="never-seen", media_kind=MediaKind.AUDIO,
        seq=0, timestamp_us=0, content=b"fallback-content",
        frame_kind=FrameKind.REAL,
    )
    out = extrapolator.extrapolate(
        last_real=frame, steps_ahead=1, now_us=0,
    )
    assert out == frame.content


def test_seeded_stream_returns_model_output(
    extrapolator: VoiceNeuralExtrapolator,
) -> None:
    extrapolator.reset()
    # Seed with some MFCC features.
    seed = np.random.randn(60).astype(np.float32)
    extrapolator.observe_real("stream-A", seed)
    frame = MediaFrame(
        stream_id="stream-A", media_kind=MediaKind.AUDIO,
        seq=1, timestamp_us=0,
        content=seed.tobytes(),
        frame_kind=FrameKind.REAL,
    )
    out = extrapolator.extrapolate(
        last_real=frame, steps_ahead=1, now_us=0,
    )
    # 60 float32 features = 240 bytes
    assert len(out) == 60 * 4
    # The model produced something — at least it's not identical to
    # the seed bytes (the model would have to produce identical
    # prediction for that, which is vanishingly unlikely).
    assert out != frame.content


def test_video_stream_falls_back_to_hold_last(
    extrapolator: VoiceNeuralExtrapolator,
) -> None:
    """Voice extrapolator only handles AUDIO. Video streams degrade
    to hold-last (a video extrapolator would be the scene predictor)."""
    extrapolator.reset()
    frame = MediaFrame(
        stream_id="v", media_kind=MediaKind.VIDEO,
        seq=1, timestamp_us=0, content=b"video-frame",
        frame_kind=FrameKind.REAL,
    )
    out = extrapolator.extrapolate(
        last_real=frame, steps_ahead=1, now_us=0,
    )
    assert out == frame.content


def test_reset_clears_seed_history(
    extrapolator: VoiceNeuralExtrapolator,
) -> None:
    seed = np.random.randn(60).astype(np.float32)
    extrapolator.observe_real("stream-X", seed)
    extrapolator.reset()
    frame = MediaFrame(
        stream_id="stream-X", media_kind=MediaKind.AUDIO,
        seq=1, timestamp_us=0, content=b"original",
        frame_kind=FrameKind.REAL,
    )
    out = extrapolator.extrapolate(
        last_real=frame, steps_ahead=1, now_us=0,
    )
    # After reset, no seed → hold last.
    assert out == b"original"


def test_extrapolator_continues_consistently(
    extrapolator: VoiceNeuralExtrapolator,
) -> None:
    """Multiple successive calls should not crash. The hidden state
    of the underlying GRU is shared; we verify only that subsequent
    calls produce same-shape output."""
    extrapolator.reset()
    seed = np.random.randn(60).astype(np.float32)
    extrapolator.observe_real("s", seed)
    frame = MediaFrame(
        stream_id="s", media_kind=MediaKind.AUDIO,
        seq=0, timestamp_us=0, content=seed.tobytes(),
        frame_kind=FrameKind.REAL,
    )
    sizes = []
    for steps in range(1, 6):
        out = extrapolator.extrapolate(
            last_real=frame, steps_ahead=steps, now_us=steps * 1000,
        )
        sizes.append(len(out))
    assert all(s == 240 for s in sizes)


# ---------------------------------------------------------------------------
# Confidence ramp
# ---------------------------------------------------------------------------

def test_predictive_confidence_at_step_zero_is_one() -> None:
    assert predictive_confidence(0) == 1.0


def test_predictive_confidence_decreases_with_steps() -> None:
    c1 = predictive_confidence(1)
    c2 = predictive_confidence(2)
    c3 = predictive_confidence(3)
    assert c1 > c2 > c3


def test_predictive_confidence_floor_at_half() -> None:
    """Confidence ramps to 0.5 at the budget cap — never goes lower
    while still emitting predicted frames."""
    assert predictive_confidence(100) >= 0.5


def test_predictive_confidence_for_video_uses_longer_budget() -> None:
    """Video budget = 8 frames vs audio = 4. So at step 4, video
    should still be above audio confidence."""
    audio_4 = predictive_confidence(4, MediaKind.AUDIO)
    video_4 = predictive_confidence(4, MediaKind.VIDEO)
    assert video_4 > audio_4
