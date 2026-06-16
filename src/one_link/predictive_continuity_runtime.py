"""Live-call adapter for the Predictive Continuity engine.

The :mod:`predictive_continuity` module is pure: it consumes
:class:`MediaFrame` records and emits predictions / corrections.
This module is the per-call runtime that:

  - Holds one :class:`PredictiveContinuity` instance per active call.
  - Bridges browser-reported "frame missed" events from the RTC
    receive path into the engine's ``on_frame_due`` /
    ``on_frame_received`` API.
  - Exposes the running confirm-ratio so the Immune System's
    vitals composer can read it.
  - Surfaces a tail event when the confirm-ratio drops below a
    floor, so the UI's Reality dot reflects "predictive support
    active."

Pure module: no I/O. The daemon wires the HTTP action + WebSocket
tail through here.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.7 (predictive continuity)
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional

from one_link.frame_provenance import FrameKind
from one_link.predictive_continuity import (
    HoldLastExtrapolator,
    MediaFrame,
    MediaKind,
    PredictionResult,
    PredictiveContinuity,
)


# ---------------------------------------------------------------------------
# Per-call state
# ---------------------------------------------------------------------------

@dataclass
class _CallPredictorState:
    """Holds the per-call PredictiveContinuity + a small ring of
    recently-received frames for replay matching."""

    engine: PredictiveContinuity
    last_real_seq_audio: int = -1
    last_real_seq_video: int = -1
    # Running confirm ratio (windowed average over recent decisions).
    confirm_count_audio: int = 0
    decision_count_audio: int = 0
    confirm_count_video: int = 0
    decision_count_video: int = 0


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------

class PredictiveContinuityRuntime:
    """One instance per daemon. Tracks per-call predictor state and
    bridges browser events into the engine.

    Thread-safe.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._calls: dict[str, _CallPredictorState] = {}

    def open_call(self, call_id: str) -> None:
        """Reserve a predictor for ``call_id``. Idempotent."""
        with self._lock:
            if call_id in self._calls:
                return
            engine = PredictiveContinuity(
                extrapolator=HoldLastExtrapolator(),
            )
            self._calls[call_id] = _CallPredictorState(engine=engine)

    def close_call(self, call_id: str) -> None:
        with self._lock:
            self._calls.pop(call_id, None)

    def observe_real_frame(
        self,
        *,
        call_id: str,
        media_kind: MediaKind,
        seq: int,
        timestamp_us: int,
        content: bytes,
    ) -> None:
        """Browser reports an arriving real frame. Engine compares
        against any earlier prediction for this slot + records a
        confirmation / correction."""
        with self._lock:
            state = self._calls.get(call_id)
            if state is None:
                return
            stream_id = f"{call_id}-{media_kind.name.lower()}"
            state.engine.register_stream(stream_id, media_kind)
            frame = MediaFrame(
                stream_id=stream_id,
                media_kind=media_kind,
                seq=seq,
                timestamp_us=timestamp_us,
                content=content,
                frame_kind=FrameKind.REAL,
            )
            correction = state.engine.on_real_frame_arrives(real=frame)
            if media_kind == MediaKind.AUDIO:
                state.last_real_seq_audio = seq
                state.decision_count_audio += 1
                if correction is None:
                    state.confirm_count_audio += 1
            else:
                state.last_real_seq_video = seq
                state.decision_count_video += 1
                if correction is None:
                    state.confirm_count_video += 1

    def request_prediction(
        self,
        *,
        call_id: str,
        media_kind: MediaKind,
        due_seq: int,
        now_us: int,
    ) -> Optional[PredictionResult]:
        """Browser reports a missed frame slot. Engine produces a
        prediction (or refuses if budget exhausted / no anchor).
        Returns the result for the browser to render."""
        with self._lock:
            state = self._calls.get(call_id)
            if state is None:
                return None
            stream_id = f"{call_id}-{media_kind.name.lower()}"
            state.engine.register_stream(stream_id, media_kind)
            return state.engine.on_frame_due(
                stream_id=stream_id,
                expected_seq=due_seq,
                now_us=now_us,
            )

    def confirm_ratio_voice(self, call_id: str) -> float:
        """Running audio confirm ratio. Default 1.0 when no decisions
        have been recorded yet (no media to evaluate ⇒ trivially
        confirmed). The Immune System's vitals composer reads this."""
        with self._lock:
            state = self._calls.get(call_id)
            if state is None or state.decision_count_audio == 0:
                return 1.0
            return state.confirm_count_audio / state.decision_count_audio

    def confirm_ratio_video(self, call_id: str) -> float:
        with self._lock:
            state = self._calls.get(call_id)
            if state is None or state.decision_count_video == 0:
                return 1.0
            return state.confirm_count_video / state.decision_count_video

    def stats(self, call_id: str) -> dict[str, float]:
        """Per-call summary for the audit log / debug UI."""
        with self._lock:
            state = self._calls.get(call_id)
            if state is None:
                return {}
            return {
                "confirm_ratio_voice": (
                    state.confirm_count_audio / state.decision_count_audio
                    if state.decision_count_audio else 1.0
                ),
                "confirm_ratio_video": (
                    state.confirm_count_video / state.decision_count_video
                    if state.decision_count_video else 1.0
                ),
                "decisions_audio": state.decision_count_audio,
                "decisions_video": state.decision_count_video,
                "last_real_seq_audio": state.last_real_seq_audio,
                "last_real_seq_video": state.last_real_seq_video,
            }
