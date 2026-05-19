"""CI/release gate for One Link call reliability.

The gate is deliberately privacy-safe and deterministic. It does not record or
generate media, SDP, ICE candidate strings, IP addresses, device names, or user
content. It exercises the backend call reliability state machine with synthetic
WebRTC health counters and fails the build when regression evidence appears.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from one_link.call_reliability_soak import run_reliability_soak


DEFAULT_OUT = Path("benchmarks") / "results" / "call-reliability-soak-gate.json"


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _nonnegative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be zero or positive")
    return parsed


def evaluate_gate(
    report: dict[str, Any],
    *,
    min_auto_trace_ratio: float,
    min_recovery_ratio: float,
    min_relay_escalations: int,
    max_p95_us: int,
) -> list[str]:
    """Convert soak evidence into release-blocking failures."""
    iterations = max(1, int(report.get("iterations") or 0))
    auto_trace_ratio = float(report.get("auto_trace_calls") or 0) / iterations
    recovery_ratio = float(report.get("recovery_calls") or 0) / iterations
    relay_escalations = int(report.get("relay_escalation_calls") or 0)
    p95_us = int(report.get("latency_p95_us") or 0)
    failures = list(report.get("failures") or [])

    if not report.get("passed"):
        failures.append("soak harness reported failed scenarios")
    if auto_trace_ratio < float(min_auto_trace_ratio):
        failures.append(
            "auto-trace coverage below gate: "
            f"{auto_trace_ratio:.3f} < {float(min_auto_trace_ratio):.3f}"
        )
    if recovery_ratio < float(min_recovery_ratio):
        failures.append(
            "call recovery coverage below gate: "
            f"{recovery_ratio:.3f} < {float(min_recovery_ratio):.3f}"
        )
    if relay_escalations < int(min_relay_escalations):
        failures.append(
            "relay escalation coverage below gate: "
            f"{relay_escalations} < {int(min_relay_escalations)}"
        )
    if p95_us > int(max_p95_us):
        failures.append(f"backend p95 latency above gate: {p95_us}us > {int(max_p95_us)}us")
    return _dedupe(failures)


def build_report(
    *,
    iterations: int,
    out: Path,
    min_auto_trace_ratio: float,
    min_recovery_ratio: float,
    min_relay_escalations: int,
    max_p95_us: int,
) -> dict[str, Any]:
    """Run the soak and return a JSON-ready report with gate verdict."""
    log_path = out.with_suffix(".jsonl")
    soak = run_reliability_soak(iterations=iterations, log_path=log_path)
    report = soak.to_json()
    failures = evaluate_gate(
        report,
        min_auto_trace_ratio=min_auto_trace_ratio,
        min_recovery_ratio=min_recovery_ratio,
        min_relay_escalations=min_relay_escalations,
        max_p95_us=max_p95_us,
    )
    report.update({
        "ok": not failures,
        "created_at": int(time.time()),
        "gate": {
            "min_auto_trace_ratio": float(min_auto_trace_ratio),
            "min_recovery_ratio": float(min_recovery_ratio),
            "min_relay_escalations": int(min_relay_escalations),
            "max_p95_us": int(max_p95_us),
        },
        "log_path": str(log_path),
        "gate_failures": failures,
        "privacy": {
            "contains_media": False,
            "contains_sdp": False,
            "contains_ice_candidates": False,
            "contains_ip_addresses": False,
            "contains_user_content": False,
        },
    })
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=_positive_int, default=320)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--min-auto-trace-ratio", type=float, default=1.0)
    parser.add_argument("--min-recovery-ratio", type=float, default=1.0)
    parser.add_argument("--min-relay-escalations", type=_nonnegative_int, default=24)
    parser.add_argument("--max-p95-us", type=_positive_int, default=5000)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    out = args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    report = build_report(
        iterations=int(args.iterations),
        out=out,
        min_auto_trace_ratio=float(args.min_auto_trace_ratio),
        min_recovery_ratio=float(args.min_recovery_ratio),
        min_relay_escalations=int(args.min_relay_escalations),
        max_p95_us=int(args.max_p95_us),
    )
    out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        verdict = "PASS" if report["ok"] else "FAIL"
        print(
            f"{verdict}: call reliability soak "
            f"iterations={report['iterations']} "
            f"p95={report['latency_p95_us']}us "
            f"auto_trace={report['auto_trace_calls']} "
            f"recovered={report['recovery_calls']} "
            f"relay_escalations={report['relay_escalation_calls']}"
        )
        print(f"report: {out}")
        print(f"timeline: {report['log_path']}")
        for failure in report["gate_failures"]:
            print(f"  - {failure}")
    return 0 if report["ok"] else 1


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
