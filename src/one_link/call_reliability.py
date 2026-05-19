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


SESSION_STATES = frozenset({
    "negotiating",
    "connected",
    "degraded",
    "reconnecting",
    "recovered",
    "ended",
    "failed",
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
    confidence: float = 0.5
    ttl_ms: int = 4_000
    pressure_score: float = 0.0

    def to_json(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reason": self.reason,
            "severity": self.severity,
            "route_preference": self.route_preference,
            "video_policy": self.video_policy,
            "audio_priority": self.audio_priority,
            "confidence": round(float(self.confidence), 3),
            "ttl_ms": int(self.ttl_ms),
            "pressure_score": round(float(self.pressure_score), 3),
        }


@dataclass(frozen=True)
class RecoveryIntent:
    """One executable backend repair intent for the browser call engine."""

    action: str
    reason: str
    priority: int
    route_preference: str
    video_policy: str
    audio_first: bool
    run_after_ms: int = 0
    cooldown_ms: int = 4_000
    confidence: float = 0.5

    def to_json(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reason": self.reason,
            "priority": max(0, min(3, int(self.priority))),
            "route_preference": self.route_preference,
            "video_policy": self.video_policy,
            "audio_first": bool(self.audio_first),
            "run_after_ms": max(0, int(self.run_after_ms)),
            "cooldown_ms": max(1_000, int(self.cooldown_ms)),
            "confidence": round(float(self.confidence), 3),
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
        with self._lock:
            self._append_locked(self._metrics, call_id, row)
            recent = self._recent_metrics_locked(call_id, newest=row)
            recommendation = self._recommend(row, recent)
            row["recommendation"] = recommendation.to_json()
            state = self._state.setdefault(call_id, {})
            state["last_metrics"] = row
            state["recommendation"] = recommendation.to_json()
            state["window"] = self._window_summary(recent)
            state["session"] = self._update_session_from_metrics(
                state, row, recommendation,
            )
            intent = self._recovery_intent(
                state["session"], recommendation, latest=row,
            )
            row["recovery_intent"] = intent.to_json()
            state["recovery_intent"] = intent.to_json()
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
            state["session"] = self._update_session_from_event(state, row)
            recommendation = self._recommendation_from_state(state)
            state["recovery_intent"] = self._recovery_intent(
                state["session"], recommendation, latest=state.get("last_metrics"),
            ).to_json()
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

    def session_for(self, call_id: str) -> dict[str, Any]:
        with self._lock:
            session = dict(self._state.get(call_id, {}).get("session") or {})
        if session:
            return session
        return self._new_session(
            "negotiating",
            "no_media_truth_yet",
            ts_ms=int(time.time() * 1000),
            previous=None,
            confidence=0.35,
        )

    def recovery_intent_for(self, call_id: str) -> dict[str, Any]:
        with self._lock:
            intent = dict(self._state.get(call_id, {}).get("recovery_intent") or {})
            session = dict(self._state.get(call_id, {}).get("session") or {})
            recommendation = self._recommendation_from_state(self._state.get(call_id, {}))
            latest = self._state.get(call_id, {}).get("last_metrics")
        if intent:
            return intent
        return self._recovery_intent(
            session or self.session_for(call_id),
            recommendation,
            latest=latest,
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
            "session_authority": dict(state.get("session") or self.session_for(call_id)),
            "recovery_intent": dict(state.get("recovery_intent") or self.recovery_intent_for(call_id)),
            "window": state.get("window"),
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

    def _recent_metrics_locked(
        self,
        call_id: str,
        *,
        newest: dict[str, Any],
        max_age_ms: int = 20_000,
        limit: int = 8,
    ) -> list[dict[str, Any]]:
        now = int(newest.get("ts_ms") or int(time.time() * 1000))
        rows = [
            r for r in self._metrics.get(call_id, [])
            if now - int(r.get("ts_ms") or 0) <= max_age_ms
        ]
        return rows[-limit:]

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
            "ice_relay_ready": _as_bool(body.get("ice_relay_ready")),
            "relay_escape_active": _as_bool(body.get("relay_escape_active")),
            "best_relay_health": _clean_token(body.get("best_relay_health"), {
                "healthy", "degraded", "poor", "unknown",
            }),
            "best_relay_score": _bounded_float(body.get("best_relay_score"), 0.0, 10.0),
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

    def _recommend(
        self,
        row: dict[str, Any],
        recent: list[dict[str, Any]] | None = None,
    ) -> PathRecommendation:
        recent = recent or [row]
        health = str(row.get("media_health_state") or "healthy")
        ice = str(row.get("ice_connection_state") or "")
        route = str(row.get("selected_candidate_type") or "")
        rtt = _avg_recent(recent, "rtt_ms")
        jitter = _avg_recent(recent, "jitter_ms")
        loss = _avg_recent(recent, "loss_rate")
        severity = int(row.get("media_health_severity") or 0)
        bad_health_count = sum(
            1 for r in recent
            if str(r.get("media_health_state") or "healthy") != "healthy"
        )
        network_pressure_count = sum(
            1 for r in recent
            if _metric_pressure(r) >= 0.55
        )
        ice_bad_count = sum(
            1 for r in recent
            if str(r.get("ice_connection_state") or "") in {"failed", "disconnected"}
        )
        renderer_detach_count = sum(
            1 for r in recent
            if str(r.get("media_health_state") or "") == "renderer_detached"
        )
        pressure = min(
            1.0,
            (_metric_pressure(row) * 0.55)
            + ((_avg_pressure(recent)) * 0.45)
            + min(0.25, bad_health_count * 0.04),
        )
        confidence = min(0.98, 0.5 + (len(recent) * 0.05) + (pressure * 0.25))

        def rec(
            action: str,
            reason: str,
            sev: int,
            route_pref: str,
            video_policy: str,
            audio_priority: bool,
            ttl_ms: int = 4_000,
        ) -> PathRecommendation:
            return PathRecommendation(
                action,
                reason,
                max(0, min(3, int(sev))),
                route_pref,
                video_policy,
                audio_priority,
                confidence=confidence,
                ttl_ms=ttl_ms,
                pressure_score=pressure,
            )

        if health in {"signaling_incomplete", "remote_media_missing"}:
            return rec("renegotiate", health, max(2, severity), "auto", "audio-first", True, 3_000)
        if health == "renderer_detached":
            if renderer_detach_count >= 3:
                return rec("renegotiate", "renderer_repeatedly_detached", 2, "same", "audio-first", True, 3_000)
            return rec("revive_playback", health, max(1, severity), "same", "auto", False, 2_500)
        if health in {"playback_frozen", "media_starved"}:
            if bad_health_count >= 3 and route != "relay":
                return rec("ice_restart", f"sustained_{health}", 3, "relay", "downshift", True, 5_000)
            return rec("audio_first_repair", health, max(1, severity), "auto", "downshift", True, 4_000)
        if ice in {"failed", "disconnected"}:
            return rec("ice_restart", f"ice_{ice}", 3 if ice == "failed" else 2, "relay" if route != "relay" else "auto", "downshift", True, 4_000)
        if ice_bad_count >= 2:
            return rec("ice_restart", "repeated_ice_instability", 3, "relay" if route != "relay" else "auto", "downshift", True, 4_000)
        if pressure >= 0.78 or network_pressure_count >= 3:
            if route != "relay" and network_pressure_count >= 3:
                return rec("ice_restart", "sustained_network_pressure", 3, "relay", "downshift", True, 5_000)
            return rec("downshift", "network_pressure", 2, "auto", "downshift", True, 4_000)
        if pressure >= 0.35 or loss >= 0.025 or rtt >= 180 or jitter >= 70:
            return rec("watch", "network_caution", 1, "auto", "steady", False, 5_000)
        return rec("hold", "healthy", 0, "auto", "auto", False, 6_000)

    def _window_summary(self, recent: list[dict[str, Any]]) -> dict[str, Any]:
        if not recent:
            return {
                "sample_count": 0,
                "pressure_score": 0.0,
                "bad_health_samples": 0,
                "ice_bad_samples": 0,
            }
        return {
            "sample_count": len(recent),
            "pressure_score": round(_avg_pressure(recent), 3),
            "avg_rtt_ms": round(_avg_recent(recent, "rtt_ms"), 3),
            "avg_jitter_ms": round(_avg_recent(recent, "jitter_ms"), 3),
            "avg_loss_rate": round(_avg_recent(recent, "loss_rate"), 5),
            "bad_health_samples": sum(
                1 for r in recent
                if str(r.get("media_health_state") or "healthy") != "healthy"
            ),
            "ice_bad_samples": sum(
                1 for r in recent
                if str(r.get("ice_connection_state") or "") in {"failed", "disconnected"}
            ),
        }

    def _update_session_from_metrics(
        self,
        state: dict[str, Any],
        row: dict[str, Any],
        recommendation: PathRecommendation,
    ) -> dict[str, Any]:
        previous = dict(state.get("session") or {})
        ts_ms = int(row.get("ts_ms") or int(time.time() * 1000))
        health = str(row.get("media_health_state") or "healthy")
        ice = str(row.get("ice_connection_state") or "")
        conn = str(row.get("connection_state") or "")
        signaling = str(row.get("signaling_state") or "")
        has_remote_audio = int(row.get("remote_live_audio_tracks") or 0) > 0
        has_remote_video = int(row.get("remote_live_video_tracks") or 0) > 0
        audio_packets = int(row.get("inbound_audio_packets") or 0)
        video_packets = int(row.get("inbound_video_packets") or 0)
        video_frames = int(row.get("inbound_video_frames_decoded") or 0)
        media_flowing = (
            (has_remote_audio and audio_packets > 0)
            or (has_remote_video and (video_packets > 0 or video_frames > 0))
        )
        if ice == "failed" or conn == "failed":
            return self._new_session(
                "reconnecting", "ice_failed", ts_ms=ts_ms,
                previous=previous, confidence=recommendation.confidence,
                recommendation=recommendation,
            )
        if ice == "disconnected" or conn == "disconnected":
            return self._new_session(
                "reconnecting", "transport_disconnected", ts_ms=ts_ms,
                previous=previous, confidence=recommendation.confidence,
                recommendation=recommendation,
            )
        if health in {"signaling_incomplete", "remote_media_missing"}:
            return self._new_session(
                "negotiating", health, ts_ms=ts_ms, previous=previous,
                confidence=recommendation.confidence,
                recommendation=recommendation,
            )
        if health in {"ice_unstable", "playback_frozen", "media_starved", "renderer_detached"}:
            return self._new_session(
                "degraded", health, ts_ms=ts_ms, previous=previous,
                confidence=recommendation.confidence,
                recommendation=recommendation,
            )
        if (
            health == "healthy"
            and ice in {"connected", "completed"}
            and conn in {"", "connected"}
            and signaling in {"", "stable"}
            and media_flowing
        ):
            old_state = str(previous.get("state") or "")
            state_name = "recovered" if old_state in {
                "degraded", "reconnecting", "failed",
            } else "connected"
            return self._new_session(
                state_name, "media_flowing", ts_ms=ts_ms, previous=previous,
                confidence=max(0.75, recommendation.confidence),
                recommendation=recommendation,
            )
        if health == "healthy" and ice in {"connected", "completed"}:
            return self._new_session(
                "connected", "transport_connected", ts_ms=ts_ms,
                previous=previous, confidence=recommendation.confidence,
                recommendation=recommendation,
            )
        return self._new_session(
            "negotiating", "awaiting_media_truth", ts_ms=ts_ms,
            previous=previous, confidence=recommendation.confidence,
            recommendation=recommendation,
        )

    def _update_session_from_event(
        self,
        state: dict[str, Any],
        row: dict[str, Any],
    ) -> dict[str, Any]:
        previous = dict(state.get("session") or {})
        ts_ms = int(row.get("ts_ms") or int(time.time() * 1000))
        event = str(row.get("event") or "")
        reason = str(row.get("reason") or event or "event")
        if event in {
            "network_offline",
            "network_resume_repair",
            "ice_restart_requested",
            "pc_rebuild_start",
            "pc_rebuild_offer_sent",
            "media_path_repair",
        }:
            return self._new_session(
                "reconnecting", reason, ts_ms=ts_ms, previous=previous,
                confidence=0.8,
            )
        if event == "backend_recommendation_applied" and reason in {
            "ice_restart", "renegotiate", "audio_first_repair",
        }:
            return self._new_session(
                "reconnecting", reason, ts_ms=ts_ms, previous=previous,
                confidence=0.85,
            )
        if event in {
            "remote_track_connected",
            "remote_surface_synced",
            "remote_video_playing",
        }:
            old_state = str(previous.get("state") or "")
            state_name = "recovered" if old_state in {
                "degraded", "reconnecting", "failed",
            } else "connected"
            return self._new_session(
                state_name, reason, ts_ms=ts_ms, previous=previous,
                confidence=0.82,
            )
        if event in {
            "remote_video_waiting",
            "remote_video_stalled",
            "remote_media_frozen",
            "remote_video_no_frames",
        }:
            return self._new_session(
                "degraded", reason, ts_ms=ts_ms, previous=previous,
                confidence=0.75,
            )
        if event in {"remote_track_ended", "remote_video_error"}:
            return self._new_session(
                "reconnecting", reason, ts_ms=ts_ms, previous=previous,
                confidence=0.78,
            )
        return previous or self._new_session(
            "negotiating", "event_seen", ts_ms=ts_ms, previous=None,
            confidence=0.45,
        )

    def _new_session(
        self,
        state_name: str,
        reason: str,
        *,
        ts_ms: int,
        previous: dict[str, Any] | None,
        confidence: float,
        recommendation: PathRecommendation | None = None,
    ) -> dict[str, Any]:
        state_name = state_name if state_name in SESSION_STATES else "negotiating"
        previous = previous or {}
        changed = state_name != previous.get("state")
        since_ms = ts_ms if changed else int(previous.get("since_ms") or ts_ms)
        sequence = int(previous.get("sequence") or 0) + (1 if changed else 0)
        row = {
            "state": state_name,
            "reason": _clean_slug(reason) or "unknown",
            "since_ms": since_ms,
            "updated_at_ms": ts_ms,
            "sequence": sequence,
            "confidence": round(max(0.0, min(1.0, float(confidence))), 3),
        }
        if recommendation is not None:
            row["recommendation_action"] = recommendation.action
            row["route_preference"] = recommendation.route_preference
            row["video_policy"] = recommendation.video_policy
        return row

    def _recommendation_from_state(self, state: dict[str, Any]) -> PathRecommendation:
        raw = dict(state.get("recommendation") or {})
        if not raw:
            return PathRecommendation(
                action="observe", reason="no_metrics_yet", severity=0,
                route_preference="auto", video_policy="auto",
                audio_priority=False,
            )
        return PathRecommendation(
            action=_clean_slug(raw.get("action")) or "observe",
            reason=_clean_slug(raw.get("reason")) or "state",
            severity=_bounded_int(raw.get("severity"), 0, 3) or 0,
            route_preference=_clean_slug(raw.get("route_preference")) or "auto",
            video_policy=_clean_slug(raw.get("video_policy")) or "auto",
            audio_priority=bool(raw.get("audio_priority")),
            confidence=_bounded_float(raw.get("confidence"), 0.0, 1.0) or 0.5,
            ttl_ms=_bounded_int(raw.get("ttl_ms"), 1_000, 60_000) or 4_000,
            pressure_score=_bounded_float(raw.get("pressure_score"), 0.0, 1.0) or 0.0,
        )

    def _recovery_intent(
        self,
        session: dict[str, Any],
        recommendation: PathRecommendation,
        *,
        latest: dict[str, Any] | None,
    ) -> RecoveryIntent:
        state = str(session.get("state") or "negotiating")
        reason = _clean_slug(session.get("reason")) or recommendation.reason
        action = recommendation.action
        route = recommendation.route_preference or "auto"
        video = recommendation.video_policy or "auto"
        audio_first = bool(recommendation.audio_priority)
        priority = max(int(session.get("sequence") or 0) and 1, recommendation.severity)
        cooldown = max(2_000, min(12_000, int(recommendation.ttl_ms or 4_000)))

        if state in {"connected", "recovered"}:
            return RecoveryIntent(
                action="hold", reason=reason or "media_flowing", priority=0,
                route_preference="same", video_policy="auto", audio_first=False,
                cooldown_ms=6_000, confidence=max(0.7, recommendation.confidence),
            )
        if state == "failed":
            return RecoveryIntent(
                action="rebuild_peer_connection", reason=reason or "failed",
                priority=3, route_preference="relay", video_policy="audio-first",
                audio_first=True, cooldown_ms=9_000,
                confidence=max(0.75, recommendation.confidence),
            )
        if action == "revive_playback":
            return RecoveryIntent(
                action="revive_playback", reason=reason, priority=max(1, priority),
                route_preference="same", video_policy=video, audio_first=False,
                cooldown_ms=3_000, confidence=recommendation.confidence,
            )
        if action == "downshift":
            return RecoveryIntent(
                action="downshift", reason=reason, priority=max(1, priority),
                route_preference=route, video_policy="downshift",
                audio_first=audio_first, cooldown_ms=6_000,
                confidence=recommendation.confidence,
            )
        if action == "audio_first_repair":
            return RecoveryIntent(
                action="audio_first_repair", reason=reason,
                priority=max(2, priority), route_preference=route,
                video_policy="audio-first", audio_first=True,
                cooldown_ms=7_000, confidence=recommendation.confidence,
            )
        if action == "ice_restart":
            relay_ready = bool((latest or {}).get("ice_relay_ready"))
            relay_health = str((latest or {}).get("best_relay_health") or "")
            relay_usable = relay_ready and relay_health not in {"poor"}
            preferred_route = "relay" if route == "relay" and relay_usable else "auto"
            if state == "reconnecting" and relay_usable and preferred_route != "relay":
                preferred_route = "relay"
            return RecoveryIntent(
                action="restart_ice", reason=reason, priority=max(2, priority),
                route_preference=preferred_route, video_policy="downshift",
                audio_first=True, cooldown_ms=9_000,
                confidence=max(0.65, recommendation.confidence),
            )
        if action in {"renegotiate", "rebuild_peer_connection"}:
            latest = latest or {}
            repeated_renderer = str(latest.get("media_health_state") or "") == "renderer_detached"
            return RecoveryIntent(
                action="rebuild_peer_connection" if repeated_renderer else "renegotiate",
                reason=reason, priority=max(2, priority),
                route_preference=route, video_policy="audio-first",
                audio_first=True, cooldown_ms=9_000,
                confidence=recommendation.confidence,
            )
        if state in {"degraded", "reconnecting"}:
            latest = latest or {}
            relay_ready = bool(latest.get("ice_relay_ready"))
            relay_health = str(latest.get("best_relay_health") or "")
            reconnect_route = "relay" if relay_ready and relay_health != "poor" else "auto"
            return RecoveryIntent(
                action="audio_first_repair" if state == "degraded" else "restart_ice",
                reason=reason, priority=2 if state == "degraded" else 3,
                route_preference=reconnect_route if state == "reconnecting" else "auto",
                video_policy="downshift", audio_first=True,
                cooldown_ms=7_000 if state == "degraded" else 9_000,
                confidence=max(0.6, recommendation.confidence),
            )
        return RecoveryIntent(
            action="observe", reason=reason or "negotiating", priority=0,
            route_preference="auto", video_policy="auto", audio_first=False,
            run_after_ms=500, cooldown_ms=4_000,
            confidence=max(0.35, recommendation.confidence),
        )


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


def _avg_recent(rows: list[dict[str, Any]], key: str) -> float:
    values = [
        float(r[key]) for r in rows
        if isinstance(r.get(key), (int, float))
    ]
    if not values:
        return 0.0
    return sum(values) / len(values)


def _metric_pressure(row: dict[str, Any]) -> float:
    rtt = float(row.get("rtt_ms") or 0.0)
    jitter = float(row.get("jitter_ms") or 0.0)
    loss = float(row.get("loss_rate") or 0.0)
    severity = float(row.get("media_health_severity") or 0.0)
    ice = str(row.get("ice_connection_state") or "")
    health = str(row.get("media_health_state") or "healthy")
    score = 0.0
    score += min(0.32, rtt / 1_600.0)
    score += min(0.22, jitter / 900.0)
    score += min(0.32, loss * 3.2)
    score += min(0.22, severity * 0.08)
    if ice in {"failed", "disconnected"}:
        score += 0.28
    if health not in {"healthy", "renderer_detached"}:
        score += 0.16
    return min(1.0, score)


def _avg_pressure(rows: list[dict[str, Any]]) -> float:
    if not rows:
        return 0.0
    return sum(_metric_pressure(r) for r in rows) / len(rows)
