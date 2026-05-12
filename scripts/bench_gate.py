#!/usr/bin/env python3
"""File engine v2 benchmark regression gate.

Compares a fresh ``perf_lab_native --json`` output against a baseline JSON
committed at ``bench_baselines/native_chunk.json``. Fails if any baseline
metric regresses by more than the threshold, default 5%.

The gate is intentionally one-way: regressions fail the PR; improvements are
silent. To accept a regression, a maintainer updates the baseline in the same
PR with a justification commit message. There is no auto-update path.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _index_results(payload: dict) -> dict[str, float]:
    """Index benchmark name to bytes_per_second_median."""
    out: dict[str, float] = {}
    for r in payload.get("results", []):
        out[r["name"]] = float(r["bytes_per_second_median"])
    return out


def _read_json(path: Path) -> dict:
    # PowerShell redirection can write UTF-16LE with a BOM on Windows, while CI
    # shell redirection normally writes UTF-8. Accept both so the gate measures
    # performance instead of failing on host console encoding.
    raw = path.read_bytes()
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return json.loads(raw.decode("utf-16"))
    return json.loads(raw.decode("utf-8-sig"))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--results", required=True, help="Fresh perf_lab_native JSON")
    p.add_argument("--baseline", required=True, help="Committed baseline JSON")
    p.add_argument(
        "--max-regression-percent",
        type=float,
        default=5.0,
        help="Maximum allowed regression vs baseline, in percent (default 5).",
    )
    args = p.parse_args(argv)

    results_path = Path(args.results)
    baseline_path = Path(args.baseline)

    if not results_path.is_file():
        print(f"FAIL: results file missing: {results_path}", file=sys.stderr)
        return 2
    if not baseline_path.is_file():
        print(
            f"NEUTRAL: baseline file missing ({baseline_path}); commit current "
            f"results as the initial baseline.",
            file=sys.stderr,
        )
        return 0

    fresh = _index_results(_read_json(results_path))
    baseline = _index_results(_read_json(baseline_path))

    if not baseline:
        print(f"FAIL: baseline empty: {baseline_path}", file=sys.stderr)
        return 2

    threshold = args.max_regression_percent / 100.0
    failures: list[str] = []

    for name, base_bps in baseline.items():
        fresh_bps = fresh.get(name)
        if fresh_bps is None:
            failures.append(
                f"  - {name}: baseline tracks but fresh results missing this metric"
            )
            continue
        if base_bps <= 0:
            continue
        ratio = fresh_bps / base_bps
        if ratio < (1.0 - threshold):
            regress_pct = (1.0 - ratio) * 100.0
            failures.append(
                f"  - {name}: regressed {regress_pct:.2f}% "
                f"({base_bps / 1e6:.2f} MB/s -> {fresh_bps / 1e6:.2f} MB/s)"
            )
        else:
            delta_pct = (ratio - 1.0) * 100.0
            sign = "+" if delta_pct >= 0 else ""
            print(
                f"  ok {name}: {sign}{delta_pct:.2f}% "
                f"({base_bps / 1e6:.2f} MB/s -> {fresh_bps / 1e6:.2f} MB/s)"
            )

    if failures:
        print(
            f"\nFAIL: {len(failures)} benchmark(s) regressed > "
            f"{args.max_regression_percent}% vs baseline:",
            file=sys.stderr,
        )
        for f in failures:
            print(f, file=sys.stderr)
        print(
            "\nIf this regression is intended, update bench_baselines/ in the "
            "same PR with a justification commit message.",
            file=sys.stderr,
        )
        return 1

    print(f"\nPASS: all {len(baseline)} tracked metrics within threshold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
