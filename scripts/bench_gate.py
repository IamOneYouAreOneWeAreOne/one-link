#!/usr/bin/env python3
"""File engine v2 benchmark regression gate.

Compares two ``perf_lab_native --json`` result sets and fails if any tracked
metric regresses by more than the threshold. The gate is one-way: regressions
fail, improvements are silent.

Both sides must be MEASURED, not remembered. Comparing a fresh run against a
committed file of MB/s does not work, and the two ways it fails were both
observed here:

  * A baseline recorded on a 24-core Windows workstation, compared against
    ubuntu-latest, reported ChaCha down 12% and AES up 293% in one run. That
    is AES-NI and core count, not code.
  * A baseline recorded on the SAME runner class one commit earlier reported
    AES-256KiB down 37% on an unchanged tree. Same class is not the same
    machine; shared CI has noisy neighbours.

So callers benchmark both sides on one runner in one job, and pass repeated
runs of each. ``--require-comparable-host`` refuses a mismatched comparison
outright rather than reporting a meaningless delta.

Repetition matters: even paired on one machine, a single run of a byte-
identical tree showed AES-256KiB down 9.03%. Throughput noise is one-sided --
interference only ever slows a run down -- so the fastest observation per
metric is taken across repetitions.
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


def _reduce_best(payloads: list[dict]) -> dict[str, float]:
    """Per metric, the FASTEST observation across repeated runs.

    Throughput noise on shared CI is one-sided: a neighbour can steal cycles
    and make a run slower, but nothing makes it spuriously faster. So the
    maximum across repetitions is the closest estimate of what the machine can
    actually do, and taking it suppresses interference without inventing
    headroom.

    Measured need: with `native/` byte-identical between the two sides, a
    single paired run still reported native_aead_aes_encrypt_256KiB down 9.03%
    -- entirely noise. A 5% gate on single runs cannot hold.
    """
    best: dict[str, float] = {}
    for payload in payloads:
        for name, value in _index_results(payload).items():
            if value > best.get(name, 0.0):
                best[name] = value
    return best


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
    p.add_argument(
        "--results",
        required=True,
        nargs="+",
        help=(
            "Fresh perf_lab_native JSON. Pass repeated runs of the SAME build "
            "and the fastest observation per metric is used."
        ),
    )
    p.add_argument(
        "--baseline",
        required=True,
        nargs="+",
        help="The other side's JSON, same repetition rule.",
    )
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

    results_paths = [Path(p) for p in args.results]
    baseline_paths = [Path(p) for p in args.baseline]

    missing = [p for p in results_paths if not p.is_file()]
    if missing:
        print(f"FAIL: results file missing: {missing[0]}", file=sys.stderr)
        return 2
    absent = [p for p in baseline_paths if not p.is_file()]
    if absent:
        print(
            f"NEUTRAL: baseline file missing ({absent[0]}); commit current "
            f"results as the initial baseline.",
            file=sys.stderr,
        )
        return 0

    results_payloads = [_read_json(p) for p in results_paths]
    baseline_payloads = [_read_json(p) for p in baseline_paths]
    fresh = _reduce_best(results_payloads)
    baseline = _reduce_best(baseline_payloads)

    fresh_host = _host(results_payloads[0])
    baseline_host = _host(baseline_payloads[0])
    print(
        f"  measured on: {_describe_host(fresh_host)} "
        f"(best of {len(results_payloads)})"
    )
    print(
        f"  compared to: {_describe_host(baseline_host)} "
        f"(best of {len(baseline_payloads)})"
    )

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
        print(f"FAIL: baseline empty: {baseline_paths[0]}", file=sys.stderr)
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
