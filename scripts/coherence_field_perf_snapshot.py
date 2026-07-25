#!/usr/bin/env python3
"""Produce a repeatable end-to-end snapshot of ``ol_coherence_field``.

Drives the Python adapter through a fixed set of operations (the same
ones the daemon hits in production), measures wall-clock per call, and
emits a JSON file consumed by ``scripts/coherence_field_slo_gate.py``.
The legacy throughput-shaped field remains compatible with
``scripts/bench_gate.py`` for environment-qualified laboratory comparisons.

Each result includes both its directly measured median latency and the legacy
throughput-shaped field expected by the relative benchmark tool:

    {"results": [{"name": "...", "bytes_per_second_median": <num>}, ...]}

For non-throughput operations (CG solves, scalar BE-RAR evaluations), one
operation is represented as one legacy "byte". The portable production gate
uses ``median_ns`` and does not compare snapshots from unlike environments.

Usage:
    python scripts/coherence_field_perf_snapshot.py --out perf.json
    python scripts/bench_gate.py \
        --results perf.json --baseline bench_baselines/coherence_field.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
from pathlib import Path
from typing import Any, Callable


SAMPLES = 200
WARMUP = 20


def _native_artifact_metadata(module: Any) -> dict[str, Any]:
    """Return verifiable identity data without exposing an absolute path."""

    raw_path = getattr(module, "__file__", None)
    if not isinstance(raw_path, str) or not raw_path:
        return {
            "file_name": None,
            "size_bytes": None,
            "sha256": None,
        }

    artifact = Path(raw_path)
    metadata: dict[str, Any] = {
        "file_name": artifact.name,
        "size_bytes": None,
        "sha256": None,
    }
    try:
        metadata["size_bytes"] = artifact.stat().st_size
        with artifact.open("rb") as stream:
            metadata["sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError:
        # The benchmark remains usable for exotic import loaders. Null fields
        # honestly record that artifact identity could not be established.
        pass
    return metadata


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
    import one_link_native
    from one_link_native import coherence_field as cf

    native_extension = getattr(one_link_native, "one_link_native", one_link_native)

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

        def solve_once() -> Any:
            return cf.solve_helmholtz(g, 1.0, 0.1, source, 2000, 1e-6)

        results.append(
            _bench(
                f"solve/helmholtz_{n_peers}",
                solve_once,
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
        "schema_version": 2,
        "version": "ol_coherence_field",
        "samples_per_bench": SAMPLES,
        "measurement": {
            "contract": "python_ffi_end_to_end",
            "clock": "perf_counter_ns",
            "clock_resolution_ns": max(
                1,
                round(time.get_clock_info("perf_counter").resolution * 1e9),
            ),
            "warmup_calls": WARMUP,
            "samples_per_bench": SAMPLES,
            "statistic": "upper_middle_median_of_individual_calls",
        },
        "environment": {
            "operating_system": platform.system(),
            "operating_system_release": platform.release(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "native_version": getattr(cf, "__version__", None),
            "native_artifact": _native_artifact_metadata(native_extension),
        },
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
