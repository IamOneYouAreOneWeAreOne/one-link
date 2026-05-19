from __future__ import annotations

import json
import os
from pathlib import Path

from one_link.call_reliability_soak import (
    build_reliability_soak_scenario,
    run_reliability_soak,
)


def test_reliability_soak_scenarios_are_deterministic() -> None:
    a = build_reliability_soak_scenario(17)
    b = build_reliability_soak_scenario(17)
    c = build_reliability_soak_scenario(18)
    assert a == b
    assert a != c
    assert a.call_id == "reliability-soak-17"
    assert len(a.samples) >= 14
    assert all("candidate:" not in json.dumps(row) for row in a.samples)
    assert all("v=0" not in json.dumps(row) for row in a.samples)


def test_reliability_soak_survives_repeated_degradation(tmp_path: Path) -> None:
    report = run_reliability_soak(
        iterations=int(os.getenv("ONE_LINK_RELIABILITY_SOAK_ITERS", "160")),
        log_path=tmp_path / "call_reliability_soak.jsonl",
    )
    assert report.passed, report.to_json()
    assert report.auto_trace_calls == report.iterations
    assert report.recovery_calls == report.iterations
    assert report.relay_escalation_calls > 0
    assert report.latency_p95_us < 5_000

    log_text = (tmp_path / "call_reliability_soak.jsonl").read_text(encoding="utf-8")
    assert '"row_type":"auto_trace"' in log_text
    assert "candidate:" not in log_text
    assert "v=0" not in log_text


def test_reliability_soak_report_is_json_ready(tmp_path: Path) -> None:
    report = run_reliability_soak(iterations=8, log_path=tmp_path / "trace.jsonl")
    payload = report.to_json()
    assert payload["passed"] is True
    assert payload["iterations"] == 8
    assert isinstance(payload["failures"], list)
    json.dumps(payload, sort_keys=True)
