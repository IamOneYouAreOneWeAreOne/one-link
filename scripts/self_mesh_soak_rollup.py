"""Run repeated self-mesh budget probes and write a rollup artifact."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.self_mesh_soak_gate import RESULTS_DIR, _fetch_performance, evaluate


def rollup(samples: list[dict[str, Any]]) -> dict[str, Any]:
    failures = [s for s in samples if not s.get("ok")]
    warning_items: list[dict[str, Any]] = []
    missing: dict[str, int] = {}
    for sample in samples:
        result = sample.get("result") or {}
        warning_items.extend(result.get("warnings") or [])
        for item in result.get("missing_observation_metrics") or []:
            metric = str(item.get("metric") or "")
            if metric:
                missing[metric] = missing.get(metric, 0) + 1
    return {
        "ok": not failures,
        "sample_count": len(samples),
        "failure_count": len(failures),
        "warning_count": len(warning_items),
        "missing_observation_counts": missing,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-s", type=float, default=60.0)
    parser.add_argument("--interval-s", type=float, default=10.0)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    duration = max(0.0, float(args.duration_s))
    interval = max(1.0, float(args.interval_s))
    deadline = time.time() + duration
    samples: list[dict[str, Any]] = []
    while True:
        payload = _fetch_performance()
        result = evaluate(payload)
        samples.append({
            "ok": bool(result["ok"]),
            "ts": int(time.time()),
            "result": result,
        })
        if time.time() >= deadline:
            break
        time.sleep(min(interval, max(0.0, deadline - time.time())))

    report: dict[str, Any] = {
        "created_at": int(time.time()),
        "duration_s": duration,
        "interval_s": interval,
        "summary": rollup(samples),
        "samples": samples,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = args.out or RESULTS_DIR / (
        f"self-mesh-soak-rollup-{time.strftime('%Y%m%d-%H%M%S')}.json"
    )
    out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"report: {out}")
        print("PASS: self-mesh soak rollup green" if report["summary"]["ok"] else "FAIL: self-mesh soak rollup failed")
    return 0 if report["summary"]["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
