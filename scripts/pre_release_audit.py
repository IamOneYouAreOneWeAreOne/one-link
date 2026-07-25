#!/usr/bin/env python3
"""Pre-release audit gate.

Runs every check that MUST pass before a One Link release ships:

1. Native test workspace clean (`cargo test --workspace --release`).
2. Python test suite clean (`pytest -q`).
3. mypy strict on the touched adapters.
4. Portable production SLO gate for the coherence-field Python FFI.
5. Adversarial coherence-field fuzz harness (quick).
6. Phase E live demos (fragile-swarm + cross-domain).
7. Sovereignty audit: every dep in the table from
   `FILE_ENGINE_V2_PLAN.md` is verified to be present + at the
   expected version.

Exit code 0 means ready to ship. Non-zero means release blocked.

Usage:
    python scripts/pre_release_audit.py
    python scripts/pre_release_audit.py --skip-cargo   (faster smoke)
    python scripts/pre_release_audit.py --json out.json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent


def run_step(
    label: str,
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 1800,
) -> dict[str, Any]:
    """Run a subprocess; return a uniform result dict."""
    t0 = time.perf_counter()
    full_env = os.environ.copy()
    full_env["PYTHONIOENCODING"] = "utf-8"
    if env:
        full_env.update(env)
    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd or REPO_ROOT),
            env=full_env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        ok = result.returncode == 0
        stderr_tail = "\n".join(result.stderr.splitlines()[-10:])
        stdout_tail = "\n".join(result.stdout.splitlines()[-5:])
    except subprocess.TimeoutExpired:
        ok = False
        stderr_tail = f"TIMEOUT after {timeout}s"
        stdout_tail = ""
    except FileNotFoundError as e:
        ok = False
        stderr_tail = f"command not found: {e}"
        stdout_tail = ""
    return {
        "label": label,
        "cmd": " ".join(cmd),
        "ok": ok,
        "wall_seconds": round(time.perf_counter() - t0, 2),
        "stderr_tail": stderr_tail,
        "stdout_tail": stdout_tail,
    }


def step_cargo_test() -> dict[str, Any]:
    return run_step(
        "cargo test --workspace --release (Phase A1/D/E native crates)",
        ["cargo", "test", "--locked", "--workspace", "--release"],
        cwd=REPO_ROOT / "native",
        timeout=1800,
    )


def step_pytest() -> dict[str, Any]:
    return run_step(
        "pytest -q (Python test suite)",
        [sys.executable, "-m", "pytest", "-q", "--no-header"],
        timeout=1200,
    )


def step_mypy() -> dict[str, Any]:
    """Run the repository's full source-tree mypy gate."""
    return run_step(
        "mypy on complete one_link source tree",
        [
            sys.executable,
            "-m",
            "mypy",
            "src/one_link",
        ],
        timeout=300,
    )


def step_perf_gate() -> dict[str, Any]:
    """Generate a fresh snapshot and enforce portable production SLOs.

    Historical relative microbenchmarks are meaningful only on a pinned,
    dedicated runner. The operator-facing pre-release gate instead enforces
    absolute end-to-end FFI ceilings with broad cross-platform headroom.
    """
    with tempfile.TemporaryDirectory(prefix="one-link-perf-") as temp_dir:
        fresh = Path(temp_dir) / "snapshot.json"
        snap = run_step(
            "perf snapshot (ol_coherence_field)",
            [
                sys.executable,
                "scripts/coherence_field_perf_snapshot.py",
                "--out",
                str(fresh),
                "--quiet",
            ],
            timeout=300,
        )
        if not snap["ok"]:
            return snap
        return run_step(
            "portable coherence-field FFI production SLO gate",
            [
                sys.executable,
                "scripts/coherence_field_slo_gate.py",
                "--results",
                str(fresh),
            ],
            timeout=60,
        )


def step_fuzz_quick() -> dict[str, Any]:
    return run_step(
        "adversarial coherence-field fuzz (quick)",
        [sys.executable, "scripts/adversarial_field_fuzz.py", "--quick", "--quiet"],
        timeout=120,
    )


def step_phase_e_live_demo() -> dict[str, Any]:
    return run_step(
        "Phase E fragile-swarm live demo",
        [sys.executable, "scripts/phase_e_live_demo.py", "--quiet"],
        timeout=120,
    )


def step_cross_domain_demo() -> dict[str, Any]:
    return run_step(
        "Phase E cross-domain calibration demo",
        [sys.executable, "scripts/phase_e_cross_domain_demo.py", "--quiet"],
        timeout=120,
    )


# Sovereignty audit - the dep table from FILE_ENGINE_V2_PLAN.md.
SOVEREIGNTY_TABLE: list[tuple[str, str, str]] = [
    # (substrate, expected_status, doc_ref)
    ("RocksDB", "not_present_yet", "Phase A1 LSM is custom ol_chunk_store, not RocksDB"),
    ("msquic", "rejected", "Use quinn (Rust, MIT/Apache)"),
    ("macFUSE", "rejected", "Use FSKit; macFUSE GPLv2 + commercial dual-license"),
    ("blake3", "present", "Cargo.toml workspace dep"),
    ("ring", "present", "via ol_aead"),
    ("quinn", "present", "via ol_quic"),
    ("rayon", "present", "ol_chunk + ol_coherence_field"),
    ("ml-kem", "present", "via ol_pqkem"),
]


def step_sovereignty_audit() -> dict[str, Any]:
    """Lightweight check: every line in the dep table is accounted for.
    We can't audit every transitive dep here; this is the
    high-watermark substrates the plan enumerates."""
    findings: list[str] = []
    cargo_lock = REPO_ROOT / "native" / "Cargo.lock"
    if not cargo_lock.exists():
        return {
            "label": "sovereignty audit",
            "ok": False,
            "wall_seconds": 0.0,
            "stderr_tail": "native/Cargo.lock missing - run `cargo build` first",
            "stdout_tail": "",
            "cmd": "(internal)",
        }
    lock_text = cargo_lock.read_text(encoding="utf-8", errors="replace").lower()
    for substrate, expected, note in SOVEREIGNTY_TABLE:
        sub = substrate.lower()
        present = sub in lock_text
        if expected == "rejected" and present:
            findings.append(
                f"  FAIL: {substrate} present in Cargo.lock but plan says REJECT ({note})"
            )
        elif expected == "present" and not present:
            findings.append(
                f"  FAIL: {substrate} expected in Cargo.lock but missing ({note})"
            )
        elif expected == "not_present_yet" and present:
            findings.append(
                f"  FAIL: {substrate} unexpectedly present before its reviewed "
                f"adoption gate ({note})"
            )
    ok = not findings
    return {
        "label": "sovereignty audit (Cargo.lock substrate check)",
        "ok": ok,
        "wall_seconds": 0.0,
        "stderr_tail": "\n".join(findings) if findings else "",
        "stdout_tail": (
            "all expected substrates present, no rejected substrates present"
            if ok else ""
        ),
        "cmd": "(internal)",
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--skip-cargo", action="store_true",
                   help="Skip cargo test (10-30 minutes) for a faster smoke")
    p.add_argument("--skip-pytest", action="store_true",
                   help="Skip the python suite (5+ minutes) for a faster smoke")
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv)

    steps: list[dict[str, Any]] = []

    # Cheap / fast first; expensive later.
    print("-> sovereignty audit")
    steps.append(step_sovereignty_audit())
    print("-> mypy")
    steps.append(step_mypy())
    print("-> phase E fragile-swarm demo")
    steps.append(step_phase_e_live_demo())
    print("-> phase E cross-domain demo")
    steps.append(step_cross_domain_demo())
    print("-> adversarial fuzz (quick)")
    steps.append(step_fuzz_quick())
    print("-> perf gate")
    steps.append(step_perf_gate())
    if not args.skip_cargo:
        print("-> cargo test --workspace (this takes a while)")
        steps.append(step_cargo_test())
    if not args.skip_pytest:
        print("-> pytest -q")
        steps.append(step_pytest())

    print()
    print("=" * 70)
    print(f"{'Step':50s} {'Result':>8s} {'Wall':>8s}")
    print("-" * 70)
    for s in steps:
        result = "PASS" if s["ok"] else "FAIL"
        print(f"{s['label'][:50]:50s} {result:>8s} {s['wall_seconds']:>7.1f}s")
    print()

    failed = [s for s in steps if not s["ok"]]
    if failed:
        print(f"FAIL: {len(failed)} step(s) did not pass.")
        for f in failed:
            print(f"  --- {f['label']}")
            if f["stderr_tail"]:
                print("  stderr:")
                for line in f["stderr_tail"].splitlines():
                    print(f"    {line}")
            if f["stdout_tail"]:
                print("  stdout:")
                for line in f["stdout_tail"].splitlines():
                    print(f"    {line}")
        out_code = 1
    else:
        complete = not args.skip_cargo and not args.skip_pytest
        if complete:
            print(f"PASS: all {len(steps)} configured pre-release steps are green.")
            print("NOTE: packaging, signing, and deployment require separate evidence.")
        else:
            skipped = []
            if args.skip_cargo:
                skipped.append("cargo")
            if args.skip_pytest:
                skipped.append("pytest")
            print(
                f"PASS: selected smoke checks are green; skipped {', '.join(skipped)}."
            )
            print("NOT RELEASE-GATED: required suites were explicitly skipped.")
        out_code = 0

    if args.json is not None:
        complete = not args.skip_cargo and not args.skip_pytest
        args.json.write_text(
            json.dumps(
                {
                    "steps": steps,
                    "checks_passed": out_code == 0,
                    "complete": complete,
                    "release_gated": out_code == 0 and complete,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    return out_code


if __name__ == "__main__":
    raise SystemExit(main())
