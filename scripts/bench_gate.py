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


def _host(payload: dict) -> dict:
    """The machine a result set was measured on, if it recorded one."""
    host = payload.get("host")
    return host if isinstance(host, dict) else {}


def _describe_host(host: dict) -> str:
    if not host:
        return "UNRECORDED"
    return (
        f"{host.get('platform', '?')} / python {host.get('python', '?')} "
        f"/ {host.get('cpu_count', '?')} cpus"
    )


_ARCHITECTURES = ("x86_64", "amd64", "aarch64", "arm64")


def _host_identity(host: dict) -> tuple[str, str, int | None, str]:
    """The parts of a host that actually move throughput.

    Deliberately NOT the whole platform string. GitHub rotates runner images,
    so `Linux-6.17.0-1020-azure-...` becomes `Linux-6.19.0-...` on its own
    schedule. Gating on that would turn this red on the next image bump and
    teach everyone to ignore it -- a gate that cries wolf is worse than the
    broken one it replaced, because this one is meant to be believed.

    OS family, CPU architecture, core count and the Python minor version are
    what separate a 24-core Windows desktop from a 4-core Linux VM. Kernel and
    patch revisions are noise for a throughput comparison.
    """
    platform = str(host.get("platform", ""))
    family = platform.split("-", 1)[0] or "?"
    lowered = platform.lower()
    architecture = next((a for a in _ARCHITECTURES if a in lowered), "?")
    # x86_64 and amd64 are the same machine under two spellings.
    if architecture == "amd64":
        architecture = "x86_64"
    if architecture == "aarch64":
        architecture = "arm64"
    cpu_count = host.get("cpu_count")
    python = ".".join(str(host.get("python", "")).split(".")[:2])
    return family, architecture, cpu_count if isinstance(cpu_count, int) else None, python


def _hosts_are_comparable(a: dict, b: dict) -> tuple[bool, str]:
    """Throughput numbers only mean something between like machines.

    A raw MB/s comparison across different hardware measures the hardware, not
    the change. This gate ran for months comparing CI against a baseline
    recorded on a 24-core Windows workstation, which is why a dependency bump
    could show ChaCha "regressing" 12% while AES "improved" 293% in the same
    run: AES-NI and core count, not code.
    """
    if not a or not b:
        return False, (
            "one or both result sets record no host provenance, so they cannot "
            "be shown to be comparable"
        )
    left = _host_identity(a)
    right = _host_identity(b)
    if left != right:
        labels = ("os family", "architecture", "cpu count", "python")
        differences = [
            f"{label} {x!r} vs {y!r}"
            for label, x, y in zip(labels, left, right)
            if x != y
        ]
        return False, "; ".join(differences)
    return True, ""


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
    p.add_argument(
        "--require-comparable-host",
        action="store_true",
        help=(
            "Refuse to compare result sets measured on different machines. The "
            "CI gate passes this: it benchmarks the PR head and its merge base "
            "on the SAME runner, so a difference is attributable to the change."
        ),
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

    fresh_payload = _read_json(results_path)
    baseline_payload = _read_json(baseline_path)
    fresh = _index_results(fresh_payload)
    baseline = _index_results(baseline_payload)

    fresh_host = _host(fresh_payload)
    baseline_host = _host(baseline_payload)
    print(f"  measured on: {_describe_host(fresh_host)}")
    print(f"  compared to: {_describe_host(baseline_host)}")

    if args.require_comparable_host:
        comparable, why = _hosts_are_comparable(fresh_host, baseline_host)
        if not comparable:
            print(
                f"FAIL: refusing to compare throughput across machines -- {why}.\n"
                "      A raw MB/s comparison between different hardware measures "
                "the hardware, not the change.",
                file=sys.stderr,
            )
            return 2

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
