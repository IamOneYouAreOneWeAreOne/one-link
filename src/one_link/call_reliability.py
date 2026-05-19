"""Backend reliability fabric for live One Link calls.

This module is intentionally server-side and privacy-safe. It keeps a
bounded per-call timeline of aggregate media health, classifies the
current route, and emits calm orchestration guidance the browser can
act on. It never stores SDP bodies, ICE candidate strings, IP
addresses, device labels, message contents, or media content.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_TIMELINE_ROWS = 512
MAX_TRACE_ROWS = 256


MEDIA_HEALTH_STATES = frozenset({
    "healthy",
    "signaling_incomplete",
    "ice_failed",
    "ice_unstable",
    "remote_media_missing",
    "renderer_detached",
    "playback_frozen",
    "media_starved",
})


@dataclass(frozen=True)
class PathRecommendation:
    """One server-owned path decision for a call."""

    action: str
    reason: str
    severity: int
    route_preference: str
    video_policy: str
    audio_priority: bool

    def to_json(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reason": self.reason,
            "severity": self.severity,
            "route_preference": self.route_preference,
            "video_policy": self.video_policy,
            "audio_priority": self.audio_priority,
        }


class CallReliabilityBackend:
    """Bounded in-memory + JSONL-backed call reliability timeline.

    The in-memory timeline gives the UI and repair loop instant access
    to the latest facts. The JSONL trace makes failures inspectable
    after the call ends without collecting sensitive media material.
    """

    def __init__(
        self,
        *,
        log_path: Path | None = None,
        max_rows_per_call: int = MAX_TIMELINE_ROWS,
    ) -> None:
        self._lock = threading.Lock()
        self._max_rows = max(32, int(max_rows_per_call))
        self._metrics: dict[str, list[dict[str, Any]]] = {}
        self._events: dict[str, list[dict[str, Any]]] = {}
        self._state: dict[str, dict[str, Any]] = {}
        self._log_path = Path(log_path) if log_path is not None else None
        if self._log_path is not None:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)

    def record_metrics(self, body: dict[str, Any]) -> PathRecommendation:
        call_id = _clean_call_id(body.get("call_id"))
        if not call_id:
            return PathRecommendation(
                action="ignore", reason="missing_call_id", severity=0,
                route_preference="auto", video_policy="auto",
                audio_priority=False,
            )
        row = self._sanitize_metrics(body)
        recommendation = self._recommend(row)
        row["recommendation"] = recommendation.to_json()
        with self._lock:
            self._append_locked(self._metrics, call_id, row)
            state = self._state.setdefault(call_id, {})
            state["last_metrics"] = row
            state["recommendation"] = recommendation.to_json()
            state["updated_at_ms"] = row["ts_ms"]
        self._append_jsonl(row)
        return recommendation

    def record_event(self, body: dict[str, Any]) -> None:
        call_id = _clean_call_id(body.get("call_id"))
        if not call_id:
            return
        row = self._sanitize_event(body)
        with self._lock:
            self._append_locked(self._events, call_id, row)
            state = self._state.setdefault(call_id, {})
            state["last_event"] = row
            state["updated_at_ms"] = row["ts_ms"]
        self._append_jsonl(row)

    def recommendation_for(self, call_id: str) -> dict[str, Any]:
        with self._lock:
            rec = dict(self._state.get(call_id, {}).get("recommendation") or {})
        if rec:
            return rec
        return PathRecommendation(
            action="observe", reason="no_metrics_yet", severity=0,
            route_preference="auto", video_policy="auto",
            audio_priority=False,
        ).to_json()

    def trace_for(self, call_id: str, *, limit: int = MAX_TRACE_ROWS) -> dict[str, Any]:
        limit = max(16, min(MAX_TRACE_ROWS, int(limit)))
        with self._lock:
            metrics = list(self._metrics.get(call_id, []))[-limit:]
            events = list(self._events.get(call_id, []))[-limit:]
            state = dict(self._state.get(call_id, {}))
        rows = sorted(metrics + events, key=lambda r: int(r.get("ts_ms") or 0))[-limit:]
        return {
            "ok": True,
            "call_id": call_id,
            "privacy": "aggregate media state only; no SDP, ICE candidates, IP addresses, device names, or media content",
            "recommendation": dict(state.get("recommendation") or self.recommendation_for(call_id)),
            "last_metrics": state.get("last_metrics"),
            "last_event": state.get("last_event"),
            "rows": rows,
        }

    def clear_call(self, call_id: str) -> None:
        with self._lock:
            self._metrics.pop(call_id, None)
            self._events.pop(call_id, None)
            self._state.pop(call_id, None)

    def _append_locked(
        self,
        bucket: dict[str, list[dict[str, Any]]],
        call_id: str,
        row: dict[str, Any],
    ) -> None:
        rows = bucket.setdefault(call_id, [])
        rows.append(row)
        if len(rows) > self._max_rows:
            del rows[: len(rows) - self._max_rows]

    def _append_jsonl(self, row: dict[str, Any]) -> None:
        if self._log_path is None:
            return
        try:
            with self._log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        except OSError:
            return

    def _sanitize_metrics(self, body: dict[str, Any]) -> dict[str, Any]:
        health = _clean_token(body.get("media_health_state"), MEDIA_HEALTH_STATES) or "healthy"
        route = _clean_token(body.get("selected_candidate_type"), {"host", "srflx", "prflx", "relay"}) or ""
        return {
            "ts_ms": int(time.time() * 1000),
            "row_type": "metrics",
            "call_id": _clean_call_id(body.get("call_id")),
            "media_health_state": health,
            "media_health_severity": _bounded_int(body.get("media_health_severity"), 0, 3),
            "ice_connection_state": _clean_token(body.get("ice_connection_state"), {
                "new", "checking", "connected", "completed", "failed", "disconnected", "closed",
            }),
            "connection_state": _clean_token(body.get("connection_state"), {
                "new", "connecting", "connected", "failed", "disconnected", "closed",
            }),
            "signaling_state": _clean_token(body.get("signaling_state"), {
                "stable", "have-local-offer", "have-remote-offer",
                "have-local-pranswer", "have-remote-pranswer", "closed",
            }),
            "selected_candidate_type": route,
            "rtt_ms": _bounded_float(body.get("rtt_ms"), 0.0, 60_000.0),
            "jitter_ms": _bounded_float(body.get("jitter_ms"), 0.0, 60_000.0),
            "loss_rate": _bounded_float(body.get("loss_rate"), 0.0, 1.0),
            "bandwidth_estimate_kbps": _bounded_float(body.get("bandwidth_estimate_kbps"), 0.0, 10_000_000.0),
            "remote_audio_tracks": _bounded_int(body.get("remote_audio_tracks"), 0, 32),
            "remote_video_tracks": _bounded_int(body.get("remote_video_tracks"), 0, 32),
            "remote_live_audio_tracks": _bounded_int(body.get("remote_live_audio_tracks"), 0, 32),
            "remote_live_video_tracks": _bounded_int(body.get("remote_live_video_tracks"), 0, 32),
            "remote_video_width": _bounded_int(body.get("remote_video_width"), 0, 16384),
            "remote_video_height": _bounded_int(body.get("remote_video_height"), 0, 16384),
            "remote_video_src_attached": _as_bool(body.get("remote_video_src_attached")),
            "remote_audio_src_attached": _as_bool(body.get("remote_audio_src_attached")),
            "inbound_audio_packets": _bounded_int(body.get("inbound_audio_packets"), 0, 10_000_000_000),
            "inbound_video_packets": _bounded_int(body.get("inbound_video_packets"), 0, 10_000_000_000),
            "inbound_video_frames_decoded": _bounded_int(body.get("inbound_video_frames_decoded"), 0, 10_000_000_000),
        }

    def _sanitize_event(self, body: dict[str, Any]) -> dict[str, Any]:
        return {
            "ts_ms": int(time.time() * 1000),
            "row_type": "event",
            "call_id": _clean_call_id(body.get("call_id")),
            "event": _clean_slug(body.get("event")),
            "reason": _clean_slug(body.get("reason")),
            "media_kind": _clean_token(body.get("media_kind"), {"audio", "video"}),
            "state": _clean_slug(body.get("state")),
            "repair_stage": _bounded_int(body.get("repair_stage"), 0, 3),
        }

    def _recommend(self, row: dict[str, Any]) -> PathRecommendation:
        health = str(row.get("media_health_state") or "healthy")
        ice = str(row.get("ice_connection_state") or "")
        route = str(row.get("selected_candidate_type") or "")
        rtt = float(row.get("rtt_ms") or 0.0)
        jitter = float(row.get("jitter_ms") or 0.0)
        loss = float(row.get("loss_rate") or 0.0)
        severity = int(row.get("media_health_severity") or 0)
        if health in {"signaling_incomplete", "remote_media_missing"}:
            return PathRecommendation("renegotiate", health, max(2, severity), "auto", "audio-first", True)
        if health == "renderer_detached":
            return PathRecommendation("revive_playback", health, max(1, severity), "same", "auto", False)
        if health in {"playback_frozen", "media_starved"}:
            return PathRecommendation("audio_first_repair", health, max(1, severity), "auto", "downshift", True)
        if ice in {"failed", "disconnected"}:
            return PathRecommendation("ice_restart", f"ice_{ice}", 3 if ice == "failed" else 2, "relay" if route != "relay" else "auto", "downshift", True)
        if loss >= 0.08 or rtt >= 450 or jitter >= 180:
            return PathRecommendation("downshift", "network_pressure", 2, "relay" if route != "relay" else "auto", "downshift", True)
        if loss >= 0.025 or rtt >= 180 or jitter >= 70:
            return PathRecommendation("watch", "network_caution", 1, "auto", "steady", False)
        return PathRecommendation("hold", "healthy", 0, "auto", "auto", False)


def _clean_call_id(value: Any) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 96:
        return ""
    return "".join(ch for ch in text if ch.isalnum() or ch in "-_:")


def _clean_slug(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text or len(text) > 64:
        return None
    clean = "".join(ch for ch in text if ch.isalnum() or ch in "-_")
    return clean or None


def _clean_token(value: Any, allowed: set[str] | frozenset[str]) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    return text if text in allowed else None


def _as_bool(value: Any) -> bool | None:
    if value is None:
        return None
    return bool(value)


def _bounded_int(value: Any, lo: int, hi: int) -> int | None:
    if value is None:
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return max(lo, min(hi, n))


def _bounded_float(value: Any, lo: float, hi: float) -> float | None:
    if value is None:
        return None
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if n != n:
        return None
    return max(lo, min(hi, n))
