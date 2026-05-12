#!/usr/bin/env python3
"""Produce a deterministic perf snapshot of ``ol_coherence_field`` for
the per-PR regression gate.

Drives the Python adapter through a fixed set of operations (the same
ones the daemon hits in production), measures wall-clock per call, and
emits a JSON file compatible with ``scripts/bench_gate.py``.

Output format matches the existing bench gate:

    {"results": [{"name": "...", "bytes_per_second_median": <num>}, ...]}

For non-throughput operations (CG solves, scalar BE-RAR evaluations) we
emit ``operations_per_second_median`` as the metric, treating each call
as one "byte" for ratio purposes. The gate's comparison logic doesn't
care about the unit — only the ratio between fresh and baseline.

Usage:
    python scripts/coherence_field_perf_snapshot.py --out perf.json
    python scripts/bench_gate.py \
        --results perf.json --baseline bench_baselines/coherence_field.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Callable


SAMPLES = 200
WARMUP = 20


def _bench(name: str, fn: Callable[[], Any]) -> dict[str, Any]:
    for _ in range(WARMUP):
        fn()
    times = []
    for _ in range(SAMPLES):
        t0 = time.perf_counter_ns()
        fn()
        times.append(time.perf_counter_ns() - t0)
    times.sort()
    median_ns = times[len(times) // 2]
    ops_per_sec = 1e9 / median_ns if median_ns > 0 else float("inf")
    return {
        "name": name,
        "samples": SAMPLES,
        "median_ns": median_ns,
        "min_ns": min(times),
        "max_ns": max(times),
        "bytes_per_second_median": ops_per_sec,
    }


def run_snapshot() -> dict[str, Any]:
    from one_link_native import coherence_field as cf

    results = []

    # Scalar microbenches.
    results.append(_bench("scalar/be_rar_y1", lambda: cf.be_rar(1.0)))
    results.append(_bench("scalar/be_rar_y_small", lambda: cf.be_rar(1e-3)))
    results.append(_bench("scalar/be_rar_y_large", lambda: cf.be_rar(100.0)))
    results.append(
        _bench(
            "scalar/apparent_horizon",
            lambda: cf.apparent_horizon_anchor(1e9, 0.01),
        )
    )
    results.append(
        _bench(
            "scalar/screening_length",
            lambda: cf.screening_length(100.0, 0.01),
        )
    )

    # Calibration dict construction.
    results.append(_bench("calibration/one_link", cf.one_link_calibration))

    # Graph + solve at 100 / 1000 / 5000 peers.
    for n_peers in [100, 1000, 5000]:
        g = cf.GraphLaplacian(n_peers)
        for i in range(n_peers):
            g.add_edge(i, (i + 1) % n_peers, 1.0)
        # Force CSR build out of the timed loop.
        source = [0.0] * n_peers
        source[n_peers // 2] = 1.0
        cf.solve_helmholtz(g, 1.0, 0.1, source, 2000, 1e-6)
        results.append(
            _bench(
                f"solve/helmholtz_{n_peers}",
                lambda g=g, s=source: cf.solve_helmholtz(
                    g, 1.0, 0.1, s, 2000, 1e-6
                ),
            )
        )

    # Couplings.
    n = 1000
    field = [0.5 + i / 1000 for i in range(n)]
    holders = list(range(1, n, 4))
    results.append(
        _bench(
            "coupling/prefetch_priorities_1k",
            lambda: cf.prefetch_priorities(field, 0, holders, 1.0),
        )
    )
    results.append(
        _bench(
            "coupling/rotation_cadence_1k",
            lambda: cf.rotation_cadence_multiplier(field, 1_000_000, 4.0, 2.0),
        )
    )

    return {
        "version": "ol_coherence_field",
        "samples_per_bench": SAMPLES,
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)
    try:
        snapshot = run_snapshot()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    args.out.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    if not args.quiet:
        print(
            f"Wrote perf snapshot with {len(snapshot['results'])} benches "
            f"to {args.out}"
        )
        # Brief table.
        for r in snapshot["results"]:
            ops = r["bytes_per_second_median"]
            print(f"  {r['name']:40s} {ops:>15,.0f} ops/s "
                  f"({r['median_ns']:>10,} ns median)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
