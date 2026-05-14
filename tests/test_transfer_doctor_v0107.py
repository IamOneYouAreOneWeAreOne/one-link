from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

from one_link.transfer_doctor import (
    RouteMemory,
    RouteObservation,
    diagnose_transfer,
    enrich_transfer_event,
    transfer_autopilot_truth,
)


def _rec(status: str, metadata: dict):
    return SimpleNamespace(
        id="t",
        status=status,
        direction="out",
        metadata=metadata,
    )


def test_doctor_turns_offline_pause_into_quiet_waiting_state():
    diag = diagnose_transfer(
        _rec("paused", {
            "delivery_state": "waiting_for_device",
            "error_class": "PeerOffline",
            "next_retry_ms": 2000,
        }),
        now_ms=1000,
    )

    assert diag.code == "waiting_for_device"
    assert diag.label == "Waiting for device"
    assert diag.automatic is True
    assert diag.retry_in_ms == 1000
    assert diag.route_action == "refresh_route"
    assert "resume" in diag.user_message.lower()


def test_doctor_auto_heals_secure_session_desync():
    diag = diagnose_transfer(
        _rec("paused", {
            "delivery_state": "waiting_for_device",
            "error_class": "UnsupportedRatchetHeader",
            "error": "unsupported ratchet header version: 152",
        }),
    )

    assert diag.code == "secure_session_desync"
    assert diag.action == "reopen_secure_session"
    assert diag.automatic is True
    assert diag.label == "Resuming"


def test_doctor_retries_only_bad_chunks():
    diag = diagnose_transfer(
        _rec("paused", {
            "delivery_state": "resuming",
            "error_class": "ChunkIntegrityError",
            "error": "chunk hash mismatch",
        }),
    )

    assert diag.code in {"resuming", "chunk_retry"}
    assert diag.action == "retry_missing_chunk"
    assert diag.automatic is True


def test_doctor_marks_source_file_missing_as_manual():
    diag = diagnose_transfer(
        _rec("failed", {
            "error_class": "FileNotFoundError",
            "error": "source file no longer exists",
        }),
    )

    assert diag.code == "source_missing"
    assert diag.automatic is False
    assert diag.severity == "error"


def test_enrich_transfer_event_adds_flat_display_fields():
    event = {
        "id": "t",
        "status": "complete",
        "direction": "out",
        "metadata": {
            "performance_summary": {"effective_mbps": 420.0, "route": "lan"},
            "autopilot_plan": {"frame_kind": "cdc_binary"},
        },
    }

    enriched = enrich_transfer_event(event)

    assert enriched["doctor"]["code"] == "done"
    assert enriched["display_state"] == "Done"
    assert "verified" in enriched["user_message"].lower()
    assert enriched["autopilot_truth"]["speed_mbps"] == 420.0
    assert "Finished at 420 Mbps" in enriched["autopilot_truth"]["facts"]
    assert "Using fast binary path" in enriched["autopilot_truth"]["facts"]
    assert "Route: Wi-Fi direct" in enriched["autopilot_truth"]["facts"]


def test_autopilot_truth_explains_prior_knowledge_and_swarm_assist():
    truth = transfer_autopilot_truth({
        "id": "t",
        "status": "complete",
        "direction": "out",
        "progress_bytes": 1000,
        "total_bytes": 1000,
        "wire_bytes": 20,
        "metadata": {
            "performance_summary": {
                "effective_mbps": 7753.869,
                "wire_mbps": 155.0,
                "bandwidth_savings_ratio": 0.98,
                "saved_bytes": 980,
                "route": "wifi_direct",
                "frame_kind": "cdc_binary",
            },
            "swarm_assist": {
                "strategy": "multi_source_chunk_pull",
                "pulled": 12,
                "source_count": 3,
                "assisted_bytes": 500,
            },
        },
    })

    assert truth["state_label"] == "Done"
    assert truth["known_pct"] == 98.0
    assert truth["saved_bytes"] == 980
    assert truth["wire_bytes"] == 20
    assert truth["sent_only_missing_pieces"] is True
    assert truth["fast_path_label"] == "Fast binary path"
    assert truth["route_label"] == "Wi-Fi direct"
    assert "98% already known" in truth["facts"]
    assert "Only sent missing pieces" in truth["facts"]
    assert "Using fast binary path" in truth["facts"]
    assert "Pulled 12 chunks from 3 trusted devices" in truth["facts"]


def test_autopilot_truth_explains_swarm_source_healing():
    truth = transfer_autopilot_truth({
        "id": "t",
        "status": "active",
        "direction": "in",
        "metadata": {
            "swarm_assist": {
                "strategy": "multi_source_chunk_pull",
                "pulled": 4,
                "source_count": 2,
                "healed": 1,
            },
        },
    })

    assert "Pulled 4 chunks from 2 trusted devices" in truth["facts"]
    assert "Healed 1 chunk by switching source" in truth["facts"]


def test_route_memory_prefers_reliable_fast_route():
    mem = RouteMemory()
    mem.observe(RouteObservation("relay", ok=True, latency_ms=100, bandwidth_bps=20_000_000))
    mem.observe(RouteObservation("relay", ok=False, error_code="timeout"))
    mem.observe(RouteObservation("lan", ok=True, latency_ms=5, bandwidth_bps=200_000_000))
    mem.observe(RouteObservation("lan", ok=True, latency_ms=6, bandwidth_bps=180_000_000))

    ranked = mem.candidates()

    assert ranked[0].route == "lan"
    assert mem.best_route() == "lan"
    assert ranked[0].successes == 2


def test_ui_uses_transfer_doctor_display_state():
    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    idx = html.find("function statusLabel(")
    assert idx > 0
    snippet = html[idx:idx + 700]
    assert "t.display_state" in snippet
    assert "meta.doctor?.label" in snippet


def test_ui_paused_detail_uses_doctor_message():
    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    idx = html.find("const autoMsg =")
    assert idx > 0
    snippet = html[idx:idx + 350]
    assert "t.user_message" in snippet
    assert "metadata?.doctor?.user_message" in snippet
