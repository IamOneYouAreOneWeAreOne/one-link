"""Predictive Continuity Engine — render-ahead-and-correct.

When a frame is due but its real packet hasn't arrived, the
receiver renders an educated guess (a *predicted* frame) so the
user experiences continuous motion + audio. When the real frame
arrives later, the engine compares it against what it predicted:

  - If the prediction was close to reality: counted as ``confirmed``
  - If it was far off: counted as ``corrected`` and a correction
    is emitted so the renderer can snap to truth

Predictions are bounded — voice cap at 4 frames ahead, video at 8 —
so prolonged loss eventually leads to a BLANK frame rather than
ever-diverging speculation.

**Predicted frames are never confused with real ones.** Each frame
emitted by this engine carries ``FrameKind.PREDICTED`` so the
Reality Engine tags it accordingly. The Doctrine of Invisibility
(§4.c, §3.5.c) requires this: the user trusts what they see
because the surface tells them what kind of frame they're seeing.

**Confirm ratio** is the dashboard metric. When
``confirm / (confirm + corrected) >= 0.98``, the receiver is
effectively rendering AHEAD of the sender — predictive negative
latency in production.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.7
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Callable, Optional, Protocol

from one_link.frame_provenance import FrameKind


# ---------------------------------------------------------------------------
# Frame primitive
# ---------------------------------------------------------------------------

class MediaKind(IntEnum):
    """What kind of stream the frame belongs to."""

    AUDIO = 0
    VIDEO = 1


@dataclass(frozen=True)
class MediaFrame:
    """One unit of media. Content is opaque to this module; we only
    look at the kind, the sequence number, the timestamp, and a
    feature vector / hash used to compute novelty."""

    stream_id: str
    media_kind: MediaKind
    seq: int
    timestamp_us: int
    content: bytes
    # FrameKind from the Reality Engine: REAL on the sender side,
    # PREDICTED for ones this engine generates, REPAIRED for codec
    # PLC output, etc.
    frame_kind: FrameKind = FrameKind.REAL


# ---------------------------------------------------------------------------
# Extrapolator interface
# ---------------------------------------------------------------------------

class Extrapolator(Protocol):
    """How to produce a predicted frame from the last-real frame.

    Tier ζ+ will ship a learned predictor (per the voice.cl /
    video.cl scaffold). For Tier α-pre we ship a trivial
    'hold-last' extrapolator as the reference. The interface lets
    a smarter predictor be swapped in later without touching the
    controller."""

    def extrapolate(
        self,
        *,
        last_real: MediaFrame,
        steps_ahead: int,
        now_us: int,
    ) -> bytes: ...


class HoldLastExtrapolator:
    """Reference extrapolator: emit the last real content again.

    Crude but correct for testing the controller. A real
    extrapolator would carry forward the motion of the last few
    frames; for audio it would synthesize via LPC / WaveRNN. The
    controller's job is the same regardless."""

    def extrapolate(
        self,
        *,
        last_real: MediaFrame,
        steps_ahead: int,
        now_us: int,
    ) -> bytes:
        return last_real.content


# ---------------------------------------------------------------------------
# Per-stream state
# ---------------------------------------------------------------------------

@dataclass
class PredictiveState:
    """Per-stream prediction state. Mutated in-place by the engine
    (under the engine's lock). The dataclass is mutable on purpose
    to keep tick-loop overhead minimal."""

    stream_id: str
    media_kind: MediaKind
    last_real: Optional[MediaFrame] = None
    last_real_at_us: int = 0
    predicted_count_since_real: int = 0
    # Tally counters for the confirm_ratio metric.
    confirm_count: int = 0
    corrected_count: int = 0
    # Sequence number of the most-recent predicted frame emitted —
    # so the engine never re-predicts the same slot twice.
    last_predicted_seq: int = -1


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

# Lookahead caps per LIVING_PRESENCE_ARCHITECTURE.md §4.7.
MAX_LOOKAHEAD_AUDIO_FRAMES = 4
MAX_LOOKAHEAD_VIDEO_FRAMES = 8

# Novelty threshold: below this, a prediction is "confirmed";
# above, it's "corrected." Pluggable per-stream via the
# ``novelty_threshold_for`` parameter on the engine constructor.
DEFAULT_CONFIRM_NOVELTY_AUDIO = 0.10
DEFAULT_CONFIRM_NOVELTY_VIDEO = 0.15


@dataclass(frozen=True)
class PredictionResult:
    """One emission from ``on_frame_due``: either a predicted frame,
    a BLANK frame (lookahead budget exhausted), or None when we
    refuse to predict (no real frame yet to extrapolate from)."""

    frame: Optional[MediaFrame]
    reason_code: str            # "predicted", "blank_budget_exceeded",
                                # "no_seed", "duplicate_seq"


@dataclass(frozen=True)
class CorrectionEvent:
    """Emitted when a real frame arrives and the engine had
    previously predicted that slot's content very differently. The
    renderer should snap to ``real`` at this seq."""

    stream_id: str
    seq: int
    real_frame: MediaFrame
    novelty: float


# Optional callback type — used by the Reality Engine to mark
# subsequent frames with their FrameKind. Set None by default.
PredictedFrameSink = Callable[[MediaFrame], None]
CorrectionSink = Callable[[CorrectionEvent], None]


class PredictiveContinuity:
    """Per-call, multi-stream prediction controller.

    Holds a :class:`PredictiveState` per stream_id. The same engine
    instance handles audio and video; lookahead cap depends on
    media_kind.

    Thread-safe under a single internal lock — the tick loop and
    the receive loop can both call into the engine.
    """

    def __init__(
        self,
        *,
        extrapolator: Optional[Extrapolator] = None,
        novelty_audio: float = DEFAULT_CONFIRM_NOVELTY_AUDIO,
        novelty_video: float = DEFAULT_CONFIRM_NOVELTY_VIDEO,
        predicted_sink: Optional[PredictedFrameSink] = None,
        correction_sink: Optional[CorrectionSink] = None,
    ) -> None:
        self._extrap = extrapolator or HoldLastExtrapolator()
        self._novelty_audio = novelty_audio
        self._novelty_video = novelty_video
        self._predicted_sink = predicted_sink
        self._correction_sink = correction_sink
        self._streams: dict[str, PredictiveState] = {}
        self._lock = threading.Lock()

    # ── Stream registration ───────────────────────────────────

    def register_stream(self, stream_id: str, media_kind: MediaKind) -> None:
        """Idempotent: registering an existing stream is a no-op."""
        with self._lock:
            if stream_id not in self._streams:
                self._streams[stream_id] = PredictiveState(
                    stream_id=stream_id,
                    media_kind=media_kind,
                )

    def has_stream(self, stream_id: str) -> bool:
        with self._lock:
            return stream_id in self._streams

    def _state(self, stream_id: str) -> PredictiveState:
        s = self._streams.get(stream_id)
        if s is None:
            raise KeyError(f"stream {stream_id!r} not registered")
        return s

    # ── on_frame_due (tick path) ──────────────────────────────

    def on_frame_due(
        self,
        *,
        stream_id: str,
        expected_seq: int,
        now_us: int,
    ) -> PredictionResult:
        """A frame for ``expected_seq`` was due but did not arrive.
        Decide what to render in its place."""
        with self._lock:
            state = self._state(stream_id)
            cap = self._lookahead_cap(state.media_kind)

            # Duplicate-seq guard: don't re-predict the same slot.
            if expected_seq == state.last_predicted_seq:
                return PredictionResult(frame=None, reason_code="duplicate_seq")

            if state.last_real is None:
                # No seed frame yet — can't extrapolate. Caller will
                # emit silence/blank as appropriate.
                return PredictionResult(frame=None, reason_code="no_seed")

            if state.predicted_count_since_real >= cap:
                # Budget exhausted: emit a BLANK so the Reality
                # badge surfaces "blank" instead of growing
                # speculation.
                blank = MediaFrame(
                    stream_id=stream_id,
                    media_kind=state.media_kind,
                    seq=expected_seq,
                    timestamp_us=now_us,
                    content=b"",
                    frame_kind=FrameKind.BLANK,
                )
                state.last_predicted_seq = expected_seq
                return PredictionResult(
                    frame=blank, reason_code="blank_budget_exceeded",
                )

            steps = state.predicted_count_since_real + 1
            content = self._extrap.extrapolate(
                last_real=state.last_real,
                steps_ahead=steps,
                now_us=now_us,
            )
            predicted = MediaFrame(
                stream_id=stream_id,
                media_kind=state.media_kind,
                seq=expected_seq,
                timestamp_us=now_us,
                content=content,
                frame_kind=FrameKind.PREDICTED,
            )
            state.predicted_count_since_real += 1
            state.last_predicted_seq = expected_seq

            sink = self._predicted_sink

        # Call sink outside the lock so a slow consumer can't
        # back-pressure the tick loop.
        if sink is not None:
            try:
                sink(predicted)
            except Exception:
                pass
        return PredictionResult(frame=predicted, reason_code="predicted")

    # ── on_real_frame_arrives (receive path) ──────────────────

    def on_real_frame_arrives(
        self,
        *,
        real: MediaFrame,
    ) -> Optional[CorrectionEvent]:
        """A real frame arrived. Update the seed + counters; emit a
        correction event if our prediction (if any) was wrong by
        more than the novelty threshold for this kind."""
        with self._lock:
            state = self._state(real.stream_id)
            correction: Optional[CorrectionEvent] = None

            if state.last_real is not None and state.predicted_count_since_real > 0:
                # We had been predicting in this gap. Compare to
                # what we extrapolated for THIS seq if we made one.
                if real.seq == state.last_predicted_seq:
                    predicted_content = self._extrap.extrapolate(
                        last_real=state.last_real,
                        steps_ahead=state.predicted_count_since_real,
                        now_us=real.timestamp_us,
                    )
                    novelty = _content_novelty(predicted_content, real.content)
                    threshold = self._novelty_threshold(state.media_kind)
                    if novelty <= threshold:
                        state.confirm_count += 1
                    else:
                        state.corrected_count += 1
                        correction = CorrectionEvent(
                            stream_id=real.stream_id,
                            seq=real.seq,
                            real_frame=real,
                            novelty=novelty,
                        )

            # Always advance state to the new real frame.
            state.last_real = real
            state.last_real_at_us = real.timestamp_us
            state.predicted_count_since_real = 0
            state.last_predicted_seq = -1

            sink = self._correction_sink

        if correction is not None and sink is not None:
            try:
                sink(correction)
            except Exception:
                pass
        return correction

    # ── Introspection ─────────────────────────────────────────

    def confirm_ratio(self, stream_id: str) -> float:
        """``confirm / (confirm + corrected)``.

        Returns 1.0 if no predictions have been compared yet (no
        observations = nothing to be wrong about). Above 0.98 means
        the receiver is rendering effectively ahead of the wire."""
        with self._lock:
            state = self._state(stream_id)
            total = state.confirm_count + state.corrected_count
            if total == 0:
                return 1.0
            return state.confirm_count / total

    def stream_state(self, stream_id: str) -> PredictiveState:
        """Return a SNAPSHOT (immutable copy) of the stream state."""
        with self._lock:
            return replace(self._state(stream_id))

    # ── Helpers ───────────────────────────────────────────────

    @staticmethod
    def _lookahead_cap(kind: MediaKind) -> int:
        if kind == MediaKind.AUDIO:
            return MAX_LOOKAHEAD_AUDIO_FRAMES
        return MAX_LOOKAHEAD_VIDEO_FRAMES

    def _novelty_threshold(self, kind: MediaKind) -> float:
        if kind == MediaKind.AUDIO:
            return self._novelty_audio
        return self._novelty_video


# ---------------------------------------------------------------------------
# Novelty metric
# ---------------------------------------------------------------------------

def _content_novelty(predicted: bytes, real: bytes) -> float:
    """How different is predicted from real, in [0.0, 1.0]?

    Simple byte-level distance: fraction of byte positions that
    differ, normalised by the longer of the two. For Tier α-pre
    this is the reference; a real extrapolator would compare
    feature vectors (LPC coefficients, face-landmark deltas) and
    this becomes a learned distance.

    Equal-length identical content → 0.0. Completely-different
    content of the same length → 1.0. Different lengths add a
    proportional penalty so a wrong-length prediction never reads
    as a confirm.
    """
    if not predicted and not real:
        return 0.0
    if not predicted or not real:
        return 1.0
    n_common = min(len(predicted), len(real))
    n_long = max(len(predicted), len(real))
    diff_bytes = sum(
        1 for i in range(n_common) if predicted[i] != real[i]
    )
    diff_bytes += n_long - n_common   # length-mismatch penalty
    return diff_bytes / n_long
