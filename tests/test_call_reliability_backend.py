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
