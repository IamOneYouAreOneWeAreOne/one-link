"""A throughput gate must compare machines to themselves.

`file-engine v2 bench gate` failed every PR it ever ran on. The cause was not
in any PR: `bench_baselines/native_chunk.json` records

    host: Windows-11-10.0.26200-SP0, python 3.14.3, cpu_count 24

a 24-core Windows workstation committed 2026-05-10, and the gate runs on
ubuntu-latest -- a 2-4 core Linux VM. Every PR touching native/** was being
judged against a desktop.

The lz4_flex bump shows what that produces in a single run:

    regressed  chacha encrypt/decrypt 5-12%, chunk_store_locate 41%
    improved   AES +61%, +93%, +293%, wal_group_commit +159%

AES-NI and core count, not code. The gate had no host check at all -- it would
compare raw MB/s from any two files.

These tests pin the two properties that make the number mean something: the
comparator refuses mismatched hosts, and it still catches a real regression on
a matched one. The second is the control: a comparator that refused everything
would pass the first test while gating nothing.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
GATE = REPO / "scripts" / "bench_gate.py"
WORKFLOW = REPO / ".github" / "workflows" / "native_bench_gate.yml"

WORKSTATION = {
    "platform": "Windows-11-10.0.26200-SP0",
    "python": "3.14.3",
    "cpu_count": 24,
}
CI_RUNNER = {
    "platform": "Linux-6.8.0-1014-azure-x86_64",
    "python": "3.12.7",
    "cpu_count": 4,
}


def payload(host: dict, metrics: dict[str, float]) -> dict:
    return {
        "host": dict(host),
        "results": [
            {"name": name, "bytes_per_second_median": bps}
            for name, bps in metrics.items()
        ],
    }


def write(tmp_path: Path, name: str, data: dict) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def run_gate(results: Path, baseline: Path, *, require_host: bool = True):
    argv = [
        sys.executable,
        str(GATE),
        "--results",
        str(results),
        "--baseline",
        str(baseline),
        "--max-regression-percent",
        "5",
    ]
    if require_host:
        argv.append("--require-comparable-host")
    return subprocess.run(argv, capture_output=True, text=True, check=False)


BASE_METRICS = {"native_cdc_scan_128MiB": 3_250_000_000.0, "native_aead_aes": 900_000_000.0}


def test_the_gate_script_exists() -> None:
    # A missing script would make every subprocess assertion below meaningless.
    assert GATE.is_file()


def test_it_refuses_to_compare_across_machines(tmp_path: Path) -> None:
    fresh = write(tmp_path, "fresh.json", payload(CI_RUNNER, BASE_METRICS))
    base = write(tmp_path, "base.json", payload(WORKSTATION, BASE_METRICS))
    proc = run_gate(fresh, base)
    assert proc.returncode == 2, (
        f"expected a refusal (2), got {proc.returncode}\n{proc.stdout}{proc.stderr}"
    )
    assert "across machines" in proc.stderr


def test_identical_numbers_on_the_same_machine_pass(tmp_path: Path) -> None:
    fresh = write(tmp_path, "fresh.json", payload(CI_RUNNER, BASE_METRICS))
    base = write(tmp_path, "base.json", payload(CI_RUNNER, BASE_METRICS))
    proc = run_gate(fresh, base)
    assert proc.returncode == 0, f"{proc.stdout}{proc.stderr}"


def test_it_still_catches_a_real_regression_on_a_matched_host(tmp_path: Path) -> None:
    """The control. A gate that refused everything would pass the test above."""
    slower = copy.deepcopy(BASE_METRICS)
    slower["native_cdc_scan_128MiB"] *= 0.90  # 10%, over the 5% threshold
    fresh = write(tmp_path, "fresh.json", payload(CI_RUNNER, slower))
    base = write(tmp_path, "base.json", payload(CI_RUNNER, BASE_METRICS))
    proc = run_gate(fresh, base)
    assert proc.returncode == 1, f"{proc.stdout}{proc.stderr}"
    assert "native_cdc_scan_128MiB" in proc.stderr, (
        f"the failure must name the metric: {proc.stderr}"
    )


def test_a_runner_image_bump_does_not_break_the_gate(tmp_path: Path) -> None:
    """The other failure mode, and the one that would have bitten quietly.

    GitHub rotates runner images on its own schedule, so the recorded platform
    string moves from `Linux-6.17.0-1020-azure-...` to a newer kernel without
    anyone touching this repository. A host check that compared the whole
    string would turn drift_watch permanently red at that moment, and a gate
    that cries wolf gets ignored -- which is how the previous one survived so
    long. Same machine class must still compare.
    """
    older = {
        "platform": "Linux-6.17.0-1020-azure-x86_64-with-glibc2.39",
        "python": "3.12.13",
        "cpu_count": 4,
    }
    newer = {
        "platform": "Linux-6.19.2-1004-azure-x86_64-with-glibc2.41",
        "python": "3.12.14",
        "cpu_count": 4,
    }
    fresh = write(tmp_path, "fresh.json", payload(newer, BASE_METRICS))
    base = write(tmp_path, "base.json", payload(older, BASE_METRICS))
    proc = run_gate(fresh, base)
    assert proc.returncode == 0, (
        "a kernel/patch bump on the same runner class must still compare:\n"
        f"{proc.stdout}{proc.stderr}"
    )


def test_a_different_core_count_is_still_refused(tmp_path: Path) -> None:
    """...but the thing that actually moves throughput must still refuse."""
    small = {"platform": "Linux-6.17.0-azure-x86_64", "python": "3.12.13", "cpu_count": 4}
    large = {"platform": "Linux-6.17.0-azure-x86_64", "python": "3.12.13", "cpu_count": 24}
    fresh = write(tmp_path, "fresh.json", payload(small, BASE_METRICS))
    base = write(tmp_path, "base.json", payload(large, BASE_METRICS))
    proc = run_gate(fresh, base)
    assert proc.returncode == 2, f"{proc.stdout}{proc.stderr}"
    assert "cpu count" in proc.stderr


def test_a_different_architecture_is_refused(tmp_path: Path) -> None:
    x86 = {"platform": "Linux-6.17.0-azure-x86_64", "python": "3.12.13", "cpu_count": 4}
    arm = {"platform": "Linux-6.17.0-azure-aarch64", "python": "3.12.13", "cpu_count": 4}
    fresh = write(tmp_path, "fresh.json", payload(x86, BASE_METRICS))
    base = write(tmp_path, "base.json", payload(arm, BASE_METRICS))
    assert run_gate(fresh, base).returncode == 2


def test_the_original_defect_is_still_refused(tmp_path: Path) -> None:
    """The exact pair that shipped: CI runner vs the committed workstation."""
    fresh = write(tmp_path, "fresh.json", payload(CI_RUNNER, BASE_METRICS))
    base = write(tmp_path, "base.json", payload(WORKSTATION, BASE_METRICS))
    proc = run_gate(fresh, base)
    assert proc.returncode == 2
    for expected in ("os family", "cpu count"):
        assert expected in proc.stderr, f"{expected} not reported: {proc.stderr}"


def test_a_regression_under_the_threshold_is_allowed(tmp_path: Path) -> None:
    nearly = copy.deepcopy(BASE_METRICS)
    nearly["native_cdc_scan_128MiB"] *= 0.97  # 3%, under 5%
    fresh = write(tmp_path, "fresh.json", payload(CI_RUNNER, nearly))
    base = write(tmp_path, "base.json", payload(CI_RUNNER, BASE_METRICS))
    assert run_gate(fresh, base).returncode == 0


def test_missing_host_provenance_is_refused_not_assumed(tmp_path: Path) -> None:
    # "No host recorded" must not be treated as "same host".
    fresh = write(tmp_path, "fresh.json", {"results": []})
    base = write(tmp_path, "base.json", payload(CI_RUNNER, BASE_METRICS))
    proc = run_gate(fresh, base)
    assert proc.returncode == 2, f"{proc.stdout}{proc.stderr}"


@pytest.mark.parametrize("job", ["bench_gate", "drift_watch"])
def test_both_ci_jobs_require_a_comparable_host(job: str) -> None:
    yaml = pytest.importorskip("yaml")
    spec = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = spec["jobs"][job]["steps"]
    gate_steps = [s for s in steps if "bench_gate.py" in (s.get("run") or "")]
    assert len(gate_steps) == 1, f"{job} must run the gate exactly once"
    assert "--require-comparable-host" in gate_steps[0]["run"], (
        f"{job} would compare across machines again"
    )


def test_the_pr_job_measures_the_merge_base_on_the_same_runner() -> None:
    yaml = pytest.importorskip("yaml")
    spec = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    runs = "\n".join(s.get("run") or "" for s in spec["jobs"]["bench_gate"]["steps"])
    # Both sides measured here, in this job, on this machine.
    assert runs.count("perf_lab_native") == 2, (
        "the PR job must benchmark BOTH the head and the merge base"
    )
    assert "git checkout --force" in runs
    assert "--results head.json" in runs and "--baseline base.json" in runs


def test_the_stale_workstation_baseline_is_no_longer_a_gate() -> None:
    # It is kept for local laboratory comparison, but nothing may gate on it:
    # it cannot be compared against CI hardware, so it could only ever fail.
    yaml = pytest.importorskip("yaml")
    spec = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    for job_name, job in spec["jobs"].items():
        blob = "\n".join(s.get("run") or "" for s in job["steps"])
        assert "bench_baselines/native_chunk.json" not in blob, (
            f"{job_name} still gates on the workstation-recorded baseline"
        )
