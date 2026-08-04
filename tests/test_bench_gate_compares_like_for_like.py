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
import re
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
    assert "head-5.json" in runs and "--baseline base-1.json" in runs


def test_the_stale_workstation_baseline_is_no_longer_a_gate() -> None:
    # It is kept for local laboratory comparison, but nothing may gate on it:
    # it cannot be compared against CI hardware, so it could only ever fail.
    yaml = pytest.importorskip("yaml")
    spec = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    # Without this the loop is vacuous: a workflow that lost its jobs would
    # pass having checked nothing.
    assert set(spec["jobs"]) == {"bench_gate", "drift_watch"}, sorted(spec["jobs"])
    for job_name, job in spec["jobs"].items():
        blob = "\n".join(s.get("run") or "" for s in job["steps"])
        assert "bench_baselines/native_chunk.json" not in blob, (
            f"{job_name} still gates on the workstation-recorded baseline"
        )


def test_no_gate_compares_against_a_committed_number() -> None:
    """Same runner CLASS is still not the same machine.

    Recording a baseline on ubuntu-latest and comparing later ubuntu-latest
    runs to it was tried, and its first real run reported
    native_aead_aes_encrypt_256KiB down 37% (3574 -> 2251 MB/s) on an
    UNCHANGED tree. Shared CI has noisy neighbours and that variance swamps a
    5% threshold, so any committed MB/s file can only be flaky or meaningless.
    Both gates must measure both sides themselves.
    """
    yaml = pytest.importorskip("yaml")
    spec = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert set(spec["jobs"]) == {"bench_gate", "drift_watch"}, sorted(spec["jobs"])
    checked = 0
    for job_name, job in spec["jobs"].items():
        blob = "\n".join(s.get("run") or "" for s in job["steps"])
        for line in blob.splitlines():
            if "--baseline" in line:
                target = line.split("--baseline")[1].split()[0].strip("\\ ")
                checked += 1
                assert not target.startswith("bench_baselines/"), (
                    f"{job_name} compares against the committed file {target}; "
                    "it must benchmark both sides on this runner instead"
                )
    # Both jobs must actually HAVE a --baseline to check. Without this, a
    # workflow that stopped comparing anything would pass this test.
    assert checked == 2, f"expected one --baseline per job, found {checked}"


def test_drift_is_measured_against_an_anchor_commit_built_here() -> None:
    yaml = pytest.importorskip("yaml")
    spec = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    runs = "\n".join(s.get("run") or "" for s in spec["jobs"]["drift_watch"]["steps"])
    assert runs.count("perf_lab_native") == 2, (
        "drift_watch must benchmark BOTH the anchor and master on this runner"
    )
    assert "DRIFT_ANCHOR" in runs
    assert "master-5.json" in runs and "--baseline anchor-1.json" in runs


def test_repeated_runs_take_the_fastest_observation(tmp_path: Path) -> None:
    """Throughput noise is one-sided, so the max is the honest estimate.

    Even paired on one machine, a single run of a byte-identical tree reported
    native_aead_aes_encrypt_256KiB down 9.03%. A neighbour stealing cycles can
    only ever make a run slower; nothing makes it spuriously faster. So one
    slow sample on either side must not decide the gate.
    """
    fast = dict(BASE_METRICS)
    slow = {k: v * 0.80 for k, v in BASE_METRICS.items()}  # a 20% noise event
    results = [
        write(tmp_path, "r1.json", payload(CI_RUNNER, slow)),
        write(tmp_path, "r2.json", payload(CI_RUNNER, fast)),
        write(tmp_path, "r3.json", payload(CI_RUNNER, slow)),
    ]
    base = write(tmp_path, "base.json", payload(CI_RUNNER, fast))
    proc = subprocess.run(
        [
            sys.executable, str(GATE),
            "--results", *[str(p) for p in results],
            "--baseline", str(base),
            "--require-comparable-host",
            "--max-regression-percent", "5",
        ],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0, (
        "two slow samples out of three must not fail the gate when a clean "
        f"observation exists:\n{proc.stdout}{proc.stderr}"
    )
    assert "best of 3" in proc.stdout


def test_a_real_regression_survives_repetition(tmp_path: Path) -> None:
    """The control: taking the max must not erase a genuine slowdown.

    If every repetition is slow, that is the machine's actual capability and
    the gate must still fail. Otherwise best-of-N would be a way to launder
    regressions away.
    """
    slower = {k: v * 0.85 for k, v in BASE_METRICS.items()}
    results = [
        write(tmp_path, f"r{i}.json", payload(CI_RUNNER, slower)) for i in (1, 2, 3)
    ]
    bases = [
        write(tmp_path, f"b{i}.json", payload(CI_RUNNER, BASE_METRICS)) for i in (1, 2, 3)
    ]
    proc = subprocess.run(
        [
            sys.executable, str(GATE),
            "--results", *[str(p) for p in results],
            "--baseline", *[str(p) for p in bases],
            "--require-comparable-host",
            "--max-regression-percent", "5",
        ],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 1, f"{proc.stdout}{proc.stderr}"


def _run(results: list[Path], bases: list[Path], *extra: str):
    return subprocess.run(
        [
            sys.executable, str(GATE),
            "--results", *[str(p) for p in results],
            "--baseline", *[str(p) for p in bases],
            "--require-comparable-host",
            "--max-regression-percent", "5",
            *extra,
        ],
        capture_output=True, text=True, check=False,
    )


M = "native_quic_round_trip_16KiB_x200"


def test_a_drop_inside_the_base_spread_is_not_a_regression(tmp_path: Path) -> None:
    """Separation, and the reason the threshold stopped being tuned.

    On byte-identical code, three successive runs each pushed a DIFFERENT
    metric past whatever line was drawn: -9.03% AES, then -7.75% QUIC, then
    -6.20% AES and -25.37% QUIC. A point estimate cannot tell a regression
    from a noisy neighbour, so a fourth constant would have been fitting noise.

    A metric now fails only if the head's best run is also slower than the
    base's WORST run. These numbers are the real ones from that third run: the
    head's best QUIC-16KiB was 419.83 MB/s while the base ranged down to
    393.12, so the sample sets overlap and the drop is not attributable.
    """
    bases = [
        write(tmp_path, f"b{i}.json", payload(CI_RUNNER, {M: v}))
        for i, v in enumerate([562.58e6, 460.0e6, 393.12e6])
    ]
    heads = [
        write(tmp_path, f"h{i}.json", payload(CI_RUNNER, {M: v}))
        for i, v in enumerate([419.83e6, 410.0e6, 400.0e6])
    ]
    proc = _run(heads, bases)
    assert proc.returncode == 0, (
        "a 25% drop that sits inside the base's own spread must not fail:\n"
        f"{proc.stdout}{proc.stderr}"
    )
    assert "not separable" in proc.stdout, (
        f"the measured drop must still be REPORTED, not swallowed: {proc.stdout}"
    )


def test_a_drop_below_every_base_run_is_a_regression(tmp_path: Path) -> None:
    """The control. Separation must not become a way to pass everything.

    Same base spread; the head is now slower than even the worst base run, so
    the effect survived the machine's own variance.
    """
    bases = [
        write(tmp_path, f"b{i}.json", payload(CI_RUNNER, {M: v}))
        for i, v in enumerate([562.58e6, 460.0e6, 393.12e6])
    ]
    heads = [
        write(tmp_path, f"h{i}.json", payload(CI_RUNNER, {M: v}))
        for i, v in enumerate([350.0e6, 340.0e6, 330.0e6])
    ]
    proc = _run(heads, bases)
    assert proc.returncode == 1, f"{proc.stdout}{proc.stderr}"
    assert "every base run was faster" in proc.stderr, proc.stderr


def test_separation_alone_does_not_fail_a_tiny_difference(tmp_path: Path) -> None:
    """Both conditions are required, not either.

    A 1% drop that happens to separate is not worth failing a build over; the
    effect-size threshold still has to be crossed.
    """
    bases = [
        write(tmp_path, f"b{i}.json", payload(CI_RUNNER, {M: v}))
        for i, v in enumerate([1000.0e6, 999.0e6, 998.0e6])
    ]
    heads = [
        write(tmp_path, f"h{i}.json", payload(CI_RUNNER, {M: v}))
        for i, v in enumerate([997.0e6, 996.0e6, 995.0e6])
    ]
    assert _run(heads, bases).returncode == 0


def test_both_jobs_repeat_each_side() -> None:
    yaml = pytest.importorskip("yaml")
    spec = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    for job_name, job in spec["jobs"].items():
        blob = "\n".join(s.get("run") or "" for s in job["steps"])
        assert blob.count("for i in 1 2 3 4 5") == 2, (
            f"{job_name} must benchmark BOTH sides more than once; a single "
            "sample per side cannot support a 5% threshold"
        )


def test_the_anchor_names_a_commit_not_a_measurement() -> None:
    anchor_file = REPO / "bench_baselines" / "DRIFT_ANCHOR"
    assert anchor_file.is_file(), "DRIFT_ANCHOR is missing"
    lines = [
        line.strip()
        for line in anchor_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert len(lines) == 1, f"expected exactly one commit, got {lines}"
    assert re.fullmatch(r"[0-9a-f]{40}", lines[0]), (
        f"the anchor must be a full commit sha: {lines[0]!r}"
    )
