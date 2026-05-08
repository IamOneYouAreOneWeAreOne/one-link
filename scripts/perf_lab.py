"""Run One Link's local performance lab and write a JSON report."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from one_link.perf_lab import compare_reports, run_perf_lab, write_report


def _default_output(scale: str) -> Path:
    ts = time.strftime("%Y%m%d-%H%M%S")
    return Path("benchmarks") / "results" / f"perf-{scale}-{ts}.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scale", choices=("quick", "standard", "heavy"), default="quick")
    ap.add_argument("--seed", type=int, default=20260507)
    ap.add_argument("--output", type=Path, default=None)
    ap.add_argument("--compare", type=Path, default=None, help="Compare new report against an older JSON report.")
    ap.add_argument("--print-json", action="store_true")
    ns = ap.parse_args()

    report = run_perf_lab(scale=ns.scale, seed=ns.seed)
    out = write_report(report, ns.output or _default_output(ns.scale))
    comparison = None
    if ns.compare is not None:
        old = json.loads(ns.compare.read_text(encoding="utf-8"))
        comparison = compare_reports(old, report)
    if ns.print_json:
        payload = {"report": report}
        if comparison is not None:
            payload["comparison"] = comparison
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"One Link performance lab ({ns.scale})")
        for b in report["benchmarks"]:
            metrics = b["metrics"]
            if b["name"] == "hash_only_manifest":
                print(f"  Hash-only manifest: {metrics['mib_per_s']} MiB/s")
            elif b["name"] == "fixed_indexing":
                print(
                    "  Fixed indexing: "
                    f"{metrics['mib_per_s']} MiB/s ({metrics['chunks']} chunks)"
                )
            elif b["name"] == "cdc_indexing":
                print(
                    "  CDC indexing: "
                    f"{metrics['mib_per_s']} MiB/s ({metrics['chunks']} chunks, "
                    f"engine={metrics.get('engine', 'python')})"
                )
            elif b["name"] == "prior_knowledge_dedup":
                print(
                    "  Prior knowledge: "
                    f"{metrics['bandwidth_reduction'] * 100:.2f}% bytes skipped "
                    f"({metrics['bytes_to_send']} bytes sent)"
                )
            elif b["name"] == "swarm_scheduler":
                print(
                    "  Swarm scheduler: "
                    f"{metrics['chunks_per_s']} chunks/s, "
                    f"{metrics['missing']} missing"
                )
            elif b["name"] == "never_lose_torture_sim":
                print(
                    "  Torture sim: "
                    f"delivered={metrics['delivered']} retries={metrics['retries']} "
                    f"offline_waits={metrics['offline_waits']}"
                )
            elif b["name"] == "sqlite_transfer_ledger":
                print(f"  SQLite ledger: {metrics['writes_per_s']} writes/s")
            elif b["name"] == "zlib_level1_compression":
                print(f"  Compression: {metrics['mib_per_s']} MiB/s ratio={metrics['ratio']}")
            elif b["name"] == "adaptive_transfer_brain":
                print(
                    "  Transfer brain: "
                    f"{metrics['decisions_per_s']} decisions/s, "
                    f"low-prior={metrics['low_prior_mode']}, "
                    f"high-prior-python={metrics['high_prior_python_mode']}, "
                    f"high-prior-accelerated={metrics['high_prior_accelerated_mode']}"
                )
            elif b["name"] == "stream_pipeline_profiles":
                print(
                    "  Stream pipeline: "
                    f"huge chunk={metrics['huge_chunk']} bytes, "
                    f"window={metrics['huge_window_bytes']} bytes/"
                    f"{metrics['huge_window_chunks']} chunks"
                )
        print(f"  Report: {out}")
        if comparison is not None:
            print("  Comparison:")
            for name, metrics in comparison["benchmarks"].items():
                interesting = [
                    k for k in ("mib_per_s", "chunks_per_s", "writes_per_s", "bandwidth_reduction")
                    if k in metrics
                ]
                if not interesting:
                    continue
                parts = []
                for k in interesting:
                    ratio = metrics[k].get("ratio")
                    if ratio is not None:
                        parts.append(f"{k} {ratio:.3f}x")
                if parts:
                    print(f"    {name}: {', '.join(parts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
