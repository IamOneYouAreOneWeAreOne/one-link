"""Self-mesh production telemetry gate.

Reads the live daemon's `/api/self-mesh/performance` endpoint, evaluates the
server-provided latency budgets, and writes a JSON release artifact. This is
the short-run gate; 24h jobs should run this periodically and archive every
artifact.

Example:
    python scripts/self_mesh_soak_gate.py --out benchmarks/results/self-mesh.json
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from one_link import server as server_mod


RESULTS_DIR = Path("benchmarks") / "results"


def _fetch_performance(*, timeout: float = 10.0) -> dict[str, Any]:
    port = server_mod.read_server_port()
    token = server_mod.read_ui_token()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/self-mesh/performance",
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"self-mesh performance HTTP {exc.code}: {body}") from exc


def evaluate(payload: dict[str, Any]) -> dict[str, Any]:
    budgets = payload.get("budgets") or {}
    items = list(budgets.get("items") or [])
    warnings = [
        item for item in items
        if str(item.get("status") or "") != "pass"
    ]
    missing = [
        item for item in items
        if int(item.get("sample_count") or 0) == 0
        and item.get("metric") not in {"route_probe_avg_ms"}
    ]
    return {
        "ok": not warnings,
        "status": "pass" if not warnings else "warn",
        "warnings": warnings,
        "missing_observation_metrics": missing,
        "budget_count": len(items),
        "history_count": len(payload.get("history") or []),
        "performance": payload.get("performance") or {},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--strict-observations", action="store_true")
    args = parser.parse_args()

    payload = _fetch_performance()
    result = evaluate(payload)
    if args.strict_observations and result["missing_observation_metrics"]:
        result["ok"] = False
        result["status"] = "missing_observations"
    report = {
        "ok": bool(result["ok"]),
        "created_at": int(time.time()),
        "result": result,
        "payload": payload,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = args.out or RESULTS_DIR / (
        f"self-mesh-soak-{time.strftime('%Y%m%d-%H%M%S')}.json"
    )
    out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"report: {out}")
        print("PASS: self-mesh budgets green" if report["ok"] else "FAIL: self-mesh budgets failed")
        for item in result["warnings"]:
            print(
                "  - {metric}: worst={worst_ms}ms limit={limit_ms}ms".format(
                    **item
                )
            )
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
