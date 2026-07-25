#!/usr/bin/env python3
"""Portable production SLO gate for the coherence-field Python FFI.

This gate answers a deliberately different question from the historical
relative benchmark in ``bench_baselines/coherence_field.json``:

    Is this build comfortably fast enough for the production field tick?

Relative microbenchmark comparisons require the same CPU class, operating
system, Python minor version, Rust toolchain, PyO3 version, build flags, and
runner isolation.  A local pre-release audit cannot guarantee those
conditions, especially on heterogeneous CPUs, so it must not reject a
release by comparing an arbitrary workstation run with an unqualified
historical sample.

The budgets below are absolute end-to-end FFI limits.  They include Python
argument/result conversion as well as the Rust operation.  The daemon runs
the field snapshot on a five-second cadence, and the native Phase E plan
allows one second for a solve.  The strictest production-scale budget here,
10 ms for a 5,000-peer solve, therefore consumes at most 0.2% of one field
tick and 1% of the documented solve allowance while retaining enough
headroom for supported CPUs and busy operator workstations.

Use ``scripts/bench_gate.py`` with the historical baseline only on a pinned,
dedicated benchmark runner; see ``bench_baselines/README.md``.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


EXPECTED_VERSION = "ol_coherence_field"
EXPECTED_SCHEMA_VERSION = 2
EXPECTED_MEASUREMENT_CONTRACT = "python_ffi_end_to_end"
EXPECTED_STATISTIC = "upper_middle_median_of_individual_calls"
MIN_SAMPLES_PER_BENCH = 100


@dataclass(frozen=True)
class SloBudget:
    """One end-to-end FFI latency ceiling."""

    max_median_ns: int
    rationale: str


# These are production SLOs, not claims about benchmark precision.  Scalar
# and coupling limits intentionally retain broad cross-platform headroom;
# they still catch debug builds, accidental Python fallbacks, pathological
# conversion behavior, and algorithmic blow-ups.  Solve limits tighten with
# scale and keep the 5k production path below the required 10 ms ceiling.
SLO_BUDGETS: dict[str, SloBudget] = {
    "scalar/be_rar_y1": SloBudget(100_000, "per-route scalar interpolation"),
    "scalar/be_rar_y_small": SloBudget(100_000, "per-route scalar interpolation"),
    "scalar/be_rar_y_large": SloBudget(100_000, "per-route scalar interpolation"),
    "scalar/apparent_horizon": SloBudget(100_000, "diagnostic scalar anchor"),
    "scalar/screening_length": SloBudget(100_000, "diagnostic scalar calibration"),
    "calibration/one_link": SloBudget(500_000, "calibration mapping construction"),
    "solve/helmholtz_100": SloBudget(2_000_000, "small-swarm field solve"),
    "solve/helmholtz_1000": SloBudget(5_000_000, "normal-swarm field solve"),
    "solve/helmholtz_5000": SloBudget(10_000_000, "large-swarm field solve"),
    "coupling/prefetch_priorities_1k": SloBudget(
        2_000_000,
        "field-driven holder ranking",
    ),
    "coupling/rotation_cadence_1k": SloBudget(
        5_000_000,
        "field-driven ratchet cadence",
    ),
}


def _latency_text(nanoseconds: float) -> str:
    if nanoseconds >= 1_000_000:
        return f"{nanoseconds / 1_000_000:.3f} ms"
    if nanoseconds >= 1_000:
        return f"{nanoseconds / 1_000:.3f} us"
    return f"{nanoseconds:.0f} ns"


def _index_results(payload: Any) -> tuple[dict[str, float], list[str]]:
    """Validate and index tracked medians from a snapshot payload."""

    failures: list[str] = []
    indexed: dict[str, float] = {}

    if not isinstance(payload, dict):
        return indexed, ["snapshot root must be a JSON object"]
    if payload.get("schema_version") != EXPECTED_SCHEMA_VERSION:
        failures.append(
            f"snapshot schema_version must be {EXPECTED_SCHEMA_VERSION}, "
            f"got {payload.get('schema_version')!r}"
        )
    if payload.get("version") != EXPECTED_VERSION:
        failures.append(
            f"snapshot version must be {EXPECTED_VERSION!r}, "
            f"got {payload.get('version')!r}"
        )

    measurement = payload.get("measurement")
    if not isinstance(measurement, dict):
        failures.append("snapshot measurement metadata must be a JSON object")
    else:
        if measurement.get("contract") != EXPECTED_MEASUREMENT_CONTRACT:
            failures.append(
                "measurement contract must be "
                f"{EXPECTED_MEASUREMENT_CONTRACT!r}"
            )
        if measurement.get("clock") != "perf_counter_ns":
            failures.append("measurement clock must be 'perf_counter_ns'")
        if measurement.get("statistic") != EXPECTED_STATISTIC:
            failures.append(f"measurement statistic must be {EXPECTED_STATISTIC!r}")
        samples = measurement.get("samples_per_bench")
        if (
            isinstance(samples, bool)
            or not isinstance(samples, int)
            or samples < MIN_SAMPLES_PER_BENCH
        ):
            failures.append(
                "measurement samples_per_bench must be an integer >= "
                f"{MIN_SAMPLES_PER_BENCH}"
            )
        elif payload.get("samples_per_bench") != samples:
            failures.append(
                "top-level samples_per_bench must match measurement metadata"
            )

    rows = payload.get("results")
    if not isinstance(rows, list):
        failures.append("snapshot results must be a JSON array")
        return indexed, failures

    seen: set[str] = set()
    for position, row in enumerate(rows):
        if not isinstance(row, dict):
            failures.append(f"result {position} must be a JSON object")
            continue
        name = row.get("name")
        if not isinstance(name, str):
            failures.append(f"result {position} has no string name")
            continue
        if name not in SLO_BUDGETS:
            continue
        if name in seen:
            failures.append(f"duplicate tracked metric: {name}")
            continue
        seen.add(name)

        raw_median = row.get("median_ns")
        if isinstance(raw_median, bool) or not isinstance(
            raw_median,
            (int, float),
        ):
            failures.append(f"{name}: median_ns must be a finite positive number")
            continue
        median_ns = float(raw_median)
        if not math.isfinite(median_ns) or median_ns <= 0:
            failures.append(f"{name}: median_ns must be a finite positive number")
            continue
        indexed[name] = median_ns

    for name in SLO_BUDGETS:
        if name not in seen:
            failures.append(f"missing tracked metric: {name}")

    return indexed, failures


def evaluate_snapshot(payload: Any) -> tuple[list[str], list[str]]:
    """Return human-readable passing measurements and gate failures."""

    indexed, failures = _index_results(payload)
    passing: list[str] = []

    for name, budget in SLO_BUDGETS.items():
        median_ns = indexed.get(name)
        if median_ns is None:
            continue
        if median_ns > budget.max_median_ns:
            failures.append(
                f"{name}: {_latency_text(median_ns)} exceeds "
                f"{_latency_text(float(budget.max_median_ns))} SLO "
                f"({budget.rationale})"
            )
            continue
        headroom = budget.max_median_ns / median_ns
        passing.append(
            f"{name}: {_latency_text(median_ns)} <= "
            f"{_latency_text(float(budget.max_median_ns))} "
            f"({headroom:.1f}x headroom)"
        )

    return passing, failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        payload = json.loads(args.results.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        print(f"ERROR: results file missing: {args.results}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read results {args.results}: {exc}", file=sys.stderr)
        return 2

    passing, failures = evaluate_snapshot(payload)
    for line in passing:
        print(f"  ok {line}")

    if failures:
        print(
            f"\nFAIL: coherence-field FFI missed {len(failures)} portable "
            "production SLO requirement(s):",
            file=sys.stderr,
        )
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"\nPASS: all {len(SLO_BUDGETS)} coherence-field FFI SLOs met.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
