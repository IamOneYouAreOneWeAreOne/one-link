"""Research-only neural extrapolator for :mod:`predictive_continuity`.

The stable metadata engine uses ``HoldLastExtrapolator``: when a frame is
due and its real packet hasn't arrived, the predictor re-emits the
LAST real frame. That's a correct reference implementation but
limited — long gaps in voice / video produce audible / visible
"stuck frame" artifacts.

This module can replace the isolated predictor's content-generation step with
the actual trained voice predictor's next-frame output. The
predictor's hidden state already encodes temporal context, so the
predicted frame is a real model-generated continuation, not a
silly hold.

Architecture:
  - VoiceNeuralExtrapolator wraps a TrainedVoiceOracle.
  - On each predict call, the predictor's hidden GRU state advances
    one step. The output 60-dim MFCC is encoded back into the
    PCM-like bytes the engine expects.
  - Confidence (produce_confidence in FrameProvenance) decreases
    linearly with steps_ahead so that the Reality dot's PREDICTED
    label degrades gracefully.

It is not connected to browser media capture or receiver playout, is excluded
from stable artifacts, and must not be treated as predictive-continuity product
capability evidence.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.7
"""

from __future__ import annotations

import threading
from pathlib import Path

import numpy as np

from one_link.predictive_continuity import (
    MediaFrame,
    MediaKind,
)


class VoiceNeuralExtrapolator:
    """Voice-track extrapolator backed by the trained voice predictor.

    Uses the same checkpoint as :mod:`semantic_voice_codec`. The
    GRU hidden state advances on each prediction so successive
    predict calls produce coherent continuations rather than a
    constant repeat.

    Thread-safe.
    """

    def __init__(self, ckpt_path: Path, device: str = "cpu") -> None:
        from one_link.ml.trained_voice_oracle import TrainedVoiceOracle
        self._lock = threading.Lock()
        self._oracle = TrainedVoiceOracle(ckpt_path, device=device)
        # Remember the last MFCC features observed per stream so the
        # extrapolator has a seed.
        self._last_mfcc: dict[str, np.ndarray] = {}

    def observe_real(self, stream_id: str, mfcc_frame: np.ndarray) -> None:
        """Caller feeds a real arriving frame's MFCC features in so
        the predictor can extend from real context."""
        with self._lock:
            self._last_mfcc[stream_id] = mfcc_frame
            # Advance the GRU hidden state with this real frame.
            self._oracle.predict_next(mfcc_frame)

    def reset(self) -> None:
        with self._lock:
            self._last_mfcc.clear()
            self._oracle.reset()

    def extrapolate(
        self,
        *,
        last_real: MediaFrame,
        steps_ahead: int,
        now_us: int,
    ) -> bytes:
        """Predict the content of the next missing frame slot.

        Falls back to repeating ``last_real.content`` if the oracle
        has never seen this stream's features (no seed) OR the
        media_kind isn't AUDIO (the scene predictor is the video
        counterpart and lives in semantic_scene_codec)."""
        with self._lock:
            if last_real.media_kind != MediaKind.AUDIO:
                return last_real.content
            seed = self._last_mfcc.get(last_real.stream_id)
            if seed is None:
                # No oracle context for this stream — degrade to hold-last.
                return last_real.content
            try:
                pred_mfcc = self._oracle.predict_next(seed)
            except Exception:
                return last_real.content
            # MFCC features → bytes via canonical float32 serialization.
            # The receiver's codec uses the same canonical format so
            # this can be plugged back into the audio rendering path.
            return pred_mfcc.astype(np.float32).tobytes()


class _IdentityExtrapolator:
    """Reference extrapolator that strictly holds the last frame.

    Used by tests + by the engine when neither voice nor scene
    predictors are available (e.g., during the early seed phase
    of a call before any real frames have flowed)."""

    def extrapolate(
        self,
        *,
        last_real: MediaFrame,
        steps_ahead: int,
        now_us: int,
    ) -> bytes:
        return last_real.content


# ---------------------------------------------------------------------------
# Audio confidence — degrades with steps_ahead
# ---------------------------------------------------------------------------

def predictive_confidence(steps_ahead: int, kind: MediaKind = MediaKind.AUDIO) -> float:
    """Confidence score the Reality Engine attaches to a PREDICTED
    frame. Linear ramp-down from 1.0 at the first predicted slot
    to 0.5 at the budget cap (4 for audio, 8 for video)."""
    cap = 8 if kind == MediaKind.VIDEO else 4
    if steps_ahead <= 0:
        return 1.0
    return max(0.5, 1.0 - 0.5 * min(steps_ahead, cap) / cap)
