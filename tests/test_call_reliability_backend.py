from __future__ import annotations

import json
from pathlib import Path

from one_link.call_reliability import CallReliabilityBackend


def test_reliability_backend_records_metrics_and_recommends_relay(tmp_path: Path) -> None:
    backend = CallReliabilityBackend(log_path=tmp_path / "call_reliability.jsonl")
    rec = backend.record_metrics({
        "call_id": "call-1",
        "media_health_state": "playback_frozen",
        "media_health_severity": 1,
        "ice_connection_state": "connected",
        "connection_state": "connected",
        "selected_candidate_type": "host",
        "rtt_ms": 40,
        "loss_rate": 0.0,
        "inbound_audio_packets": 100,
        "inbound_video_packets": 100,
        "inbound_video_frames_decoded": 0,
    })
    assert rec.action == "audio_first_repair"
    assert rec.audio_priority is True
    trace = backend.trace_for("call-1")
    assert trace["ok"] is True
    assert trace["recommendation"]["action"] == "audio_first_repair"
    assert trace["recovery_intent"]["action"] == "audio_first_repair"
    assert trace["recovery_intent"]["audio_first"] is True
    assert trace["rows"][0]["row_type"] == "metrics"
    rows_text = json.dumps(trace["rows"])
    assert "candidate:" not in rows_text
    assert "v=0" not in rows_text


def test_reliability_backend_sanitizes_and_bounds_trace(tmp_path: Path) -> None:
    backend = CallReliabilityBackend(log_path=tmp_path / "call_reliability.jsonl", max_rows_per_call=40)
    for i in range(80):
        backend.record_event({
            "call_id": "call/unsafe-1",
            "event": "Remote Surface Synced!!!",
            "reason": "renderer_detached",
            "media_kind": "video",
            "repair_stage": 99,
        })
    trace = backend.trace_for("callunsafe-1", limit=32)
    assert len(trace["rows"]) == 32
    assert trace["rows"][-1]["event"] == "remotesurfacesynced"
    assert trace["rows"][-1]["repair_stage"] == 3


def test_reliability_backend_recommends_ice_restart_on_failure(tmp_path: Path) -> None:
    backend = CallReliabilityBackend(log_path=tmp_path / "call_reliability.jsonl")
    rec = backend.record_metrics({
        "call_id": "call-2",
        "media_health_state": "healthy",
        "ice_connection_state": "failed",
        "selected_candidate_type": "host",
    })
    assert rec.action == "ice_restart"
    assert rec.route_preference == "relay"
    assert rec.severity == 3
    intent = backend.recovery_intent_for("call-2")
    assert intent["action"] == "restart_ice"
    assert intent["route_preference"] == "auto"
    assert intent["priority"] == 3


def test_reliability_backend_escalates_sustained_direct_path_pressure(tmp_path: Path) -> None:
    backend = CallReliabilityBackend(log_path=tmp_path / "call_reliability.jsonl")
    rec = None
    for _ in range(4):
        rec = backend.record_metrics({
            "call_id": "call-pressure",
            "media_health_state": "healthy",
            "ice_connection_state": "connected",
            "selected_candidate_type": "host",
            "rtt_ms": 520,
            "jitter_ms": 210,
            "loss_rate": 0.11,
        })
    assert rec is not None
    assert rec.action == "ice_restart"
    assert rec.reason == "sustained_network_pressure"
    assert rec.route_preference == "relay"
    assert rec.pressure_score > 0.5
    assert rec.confidence > 0.6


def test_reliability_backend_recovers_to_hold_after_stable_samples(tmp_path: Path) -> None:
    backend = CallReliabilityBackend(log_path=tmp_path / "call_reliability.jsonl")
    backend.record_metrics({
        "call_id": "call-recover",
        "media_health_state": "media_starved",
        "media_health_severity": 2,
        "ice_connection_state": "connected",
        "selected_candidate_type": "host",
        "rtt_ms": 600,
        "loss_rate": 0.12,
    })
    rec = None
    for _ in range(8):
        rec = backend.record_metrics({
            "call_id": "call-recover",
            "media_health_state": "healthy",
            "ice_connection_state": "connected",
            "selected_candidate_type": "host",
            "rtt_ms": 18,
            "jitter_ms": 2,
            "loss_rate": 0.0,
            "inbound_audio_packets": 200,
            "inbound_video_packets": 200,
            "inbound_video_frames_decoded": 200,
        })
    assert rec is not None
    assert rec.action == "hold"
    assert rec.reason == "healthy"
    trace = backend.trace_for("call-recover")
    assert trace["window"]["sample_count"] == 8
    assert trace["window"]["pressure_score"] < 0.1


def test_reliability_backend_trace_exposes_window_and_decision_confidence(tmp_path: Path) -> None:
    backend = CallReliabilityBackend(log_path=tmp_path / "call_reliability.jsonl")
    rec = backend.record_metrics({
        "call_id": "call-window",
        "media_health_state": "renderer_detached",
        "ice_connection_state": "connected",
        "selected_candidate_type": "host",
        "rtt_ms": 30,
        "loss_rate": 0.0,
    })
    trace = backend.trace_for("call-window")
    assert trace["recommendation"]["action"] == rec.action
    assert trace["recovery_intent"]["action"] == "revive_playback"
    assert trace["rows"][0]["recovery_intent"]["action"] == "revive_playback"
    assert trace["recommendation"]["confidence"] >= 0.5
    assert trace["recommendation"]["ttl_ms"] > 0
    assert trace["window"]["sample_count"] == 1
    assert "avg_rtt_ms" in trace["window"]


def test_reliability_backend_tracks_session_authority_recovery(tmp_path: Path) -> None:
    backend = CallReliabilityBackend(log_path=tmp_path / "call_reliability.jsonl")
    backend.record_metrics({
        "call_id": "call-session",
        "media_health_state": "playback_frozen",
        "media_health_severity": 2,
        "ice_connection_state": "connected",
        "connection_state": "connected",
        "signaling_state": "stable",
        "remote_live_audio_tracks": 1,
        "remote_live_video_tracks": 1,
        "inbound_audio_packets": 100,
        "inbound_video_packets": 100,
        "inbound_video_frames_decoded": 0,
    })
    degraded = backend.session_for("call-session")
    assert degraded["state"] == "degraded"
    assert degraded["reason"] == "playback_frozen"

    backend.record_event({
        "call_id": "call-session",
        "event": "ice_restart_requested",
        "reason": "backend_ice_restart",
    })
    reconnecting = backend.session_for("call-session")
    assert reconnecting["state"] == "reconnecting"
    assert reconnecting["sequence"] > degraded["sequence"]

    backend.record_metrics({
        "call_id": "call-session",
        "media_health_state": "healthy",
        "ice_connection_state": "connected",
        "connection_state": "connected",
        "signaling_state": "stable",
        "remote_live_audio_tracks": 1,
        "remote_live_video_tracks": 1,
        "inbound_audio_packets": 200,
        "inbound_video_packets": 200,
        "inbound_video_frames_decoded": 30,
    })
    recovered = backend.session_for("call-session")
    assert recovered["state"] == "recovered"
    assert recovered["reason"] == "media_flowing"
    assert recovered["sequence"] > reconnecting["sequence"]
    trace = backend.trace_for("call-session")
    assert trace["session_authority"]["state"] == "recovered"
    assert trace["recovery_intent"]["action"] == "hold"


def test_reliability_backend_recovery_intent_escalates_reconnects(tmp_path: Path) -> None:
    backend = CallReliabilityBackend(log_path=tmp_path / "call_reliability.jsonl")
    backend.record_event({
        "call_id": "call-intent",
        "event": "network_offline",
    })
    intent = backend.recovery_intent_for("call-intent")
    assert intent["action"] == "restart_ice"
    assert intent["route_preference"] == "auto"
    assert intent["audio_first"] is True
    assert intent["priority"] == 3

    backend.record_metrics({
        "call_id": "call-intent",
        "media_health_state": "healthy",
        "ice_connection_state": "connected",
        "connection_state": "connected",
        "signaling_state": "stable",
        "remote_live_audio_tracks": 1,
        "remote_live_video_tracks": 1,
        "inbound_audio_packets": 500,
        "inbound_video_packets": 500,
        "inbound_video_frames_decoded": 80,
    })
    recovered = backend.recovery_intent_for("call-intent")
    assert recovered["action"] == "hold"
    assert recovered["route_preference"] == "same"


def test_reliability_backend_recovery_intent_uses_relay_truth(tmp_path: Path) -> None:
    backend = CallReliabilityBackend(log_path=tmp_path / "call_reliability.jsonl")
    backend.record_metrics({
        "call_id": "call-relay-truth",
        "media_health_state": "healthy",
        "ice_connection_state": "failed",
        "selected_candidate_type": "host",
        "ice_relay_ready": True,
        "best_relay_health": "healthy",
        "best_relay_score": 0.05,
    })
    usable = backend.recovery_intent_for("call-relay-truth")
    assert usable["action"] == "restart_ice"
    assert usable["route_preference"] == "relay"

    backend.record_metrics({
        "call_id": "call-relay-poor",
        "media_health_state": "healthy",
        "ice_connection_state": "failed",
        "selected_candidate_type": "host",
        "ice_relay_ready": True,
        "best_relay_health": "poor",
        "best_relay_score": 0.98,
    })
    poor = backend.recovery_intent_for("call-relay-poor")
    assert poor["action"] == "restart_ice"
    assert poor["route_preference"] == "auto"


def test_reliability_backend_session_authority_handles_network_events(tmp_path: Path) -> None:
    backend = CallReliabilityBackend(log_path=tmp_path / "call_reliability.jsonl")
    backend.record_event({
        "call_id": "call-network",
        "event": "network_offline",
    })
    offline = backend.session_for("call-network")
    assert offline["state"] == "reconnecting"
    assert offline["reason"] == "network_offline"

    backend.record_event({
        "call_id": "call-network",
        "event": "remote_surface_synced",
        "reason": "playback_revive",
        "media_kind": "video",
    })
    recovered = backend.session_for("call-network")
    assert recovered["state"] == "recovered"
    assert recovered["reason"] == "playback_revive"


def test_reliability_backend_marks_client_rejoin_as_reconnecting(tmp_path: Path) -> None:
    backend = CallReliabilityBackend(log_path=tmp_path / "call_reliability.jsonl")
    backend.record_event({
        "call_id": "call-rejoin",
        "event": "client_rejoin_requested",
        "reason": "browser_rejoin",
    })
    requested = backend.session_for("call-rejoin")
    assert requested["state"] == "reconnecting"
    assert requested["reason"] == "browser_rejoin"

    backend.record_event({
        "call_id": "call-rejoin",
        "event": "client_rejoin_media_ready",
        "reason": "media_rejoin",
    })
    ready = backend.session_for("call-rejoin")
    assert ready["state"] == "reconnecting"
    assert ready["reason"] == "media_rejoin"
