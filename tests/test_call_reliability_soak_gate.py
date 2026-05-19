from __future__ import annotations

import json

from scripts.call_reliability_soak_gate import build_report, evaluate_gate, main


def test_call_reliability_gate_passes_privacy_safe_soak(tmp_path) -> None:
    out = tmp_path / "call-reliability-gate.json"
    report = build_report(
        iterations=32,
        out=out,
        min_auto_trace_ratio=1.0,
        min_recovery_ratio=1.0,
        min_relay_escalations=1,
        max_p95_us=5000,
    )

    assert report["ok"] is True
    assert report["privacy"] == {
        "contains_media": False,
        "contains_sdp": False,
        "contains_ice_candidates": False,
        "contains_ip_addresses": False,
        "contains_user_content": False,
    }
    timeline = out.with_suffix(".jsonl").read_text(encoding="utf-8")
    assert '"row_type":"auto_trace"' in timeline
    assert "candidate:" not in timeline
    assert "v=0" not in timeline


def test_call_reliability_gate_fails_regressions() -> None:
    failures = evaluate_gate(
        {
            "passed": True,
            "iterations": 10,
            "latency_p95_us": 6001,
            "auto_trace_calls": 8,
            "recovery_calls": 9,
            "relay_escalation_calls": 0,
            "failures": [],
        },
        min_auto_trace_ratio=1.0,
        min_recovery_ratio=1.0,
        min_relay_escalations=1,
        max_p95_us=5000,
    )

    assert any("auto-trace coverage" in failure for failure in failures)
    assert any("call recovery coverage" in failure for failure in failures)
    assert any("relay escalation coverage" in failure for failure in failures)
    assert any("p95 latency" in failure for failure in failures)


def test_call_reliability_gate_cli_writes_json(tmp_path, capsys) -> None:
    out = tmp_path / "gate.json"
    code = main([
        "--iterations",
        "12",
        "--min-relay-escalations",
        "1",
        "--out",
        str(out),
        "--json",
    ])

    assert code == 0
    stored = json.loads(out.read_text(encoding="utf-8"))
    printed = json.loads(capsys.readouterr().out)
    assert stored["ok"] is True
    assert printed["ok"] is True
