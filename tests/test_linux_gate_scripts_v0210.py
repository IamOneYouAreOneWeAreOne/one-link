"""Static production contracts for the Linux/WSL verification scripts.

The scripts are intentionally not executed here because the test suite may run
without WSL, libfuse, or a Linux native wheel. Linux CI still parses every file
with Bash, while all platforms enforce the no-bootstrap, no-hardcoded-path,
strict-failure, and disposable-lock invariants from source.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest


REPO = Path(__file__).resolve().parent.parent
SHELL_SCRIPTS = (
    REPO / "scripts" / "install_url_protocol_linux.sh",
    REPO / "scripts" / "install_url_protocol_macos.sh",
    REPO / "scripts" / "wsl_linux_gates.sh",
    REPO / "scripts" / "wsl_linux_run_demos.sh",
    REPO / "scripts" / "wsl_fuse_mount_test.sh",
)
WSL_SCRIPTS = SHELL_SCRIPTS[2:]
PINNED_RUST_DECLARATION = 'REQUIRED_RUST_VERSION="1.96.0"'


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("script", SHELL_SCRIPTS, ids=lambda path: path.name)
def test_shell_scripts_are_lf_only_and_bash_syntax_valid(script: Path):
    raw = script.read_bytes()
    assert raw.startswith(b"#!/usr/bin/env bash\n")
    assert b"\r" not in raw, f"{script.name} contains CR/CRLF bytes"

    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable on this test host")
    relative_script = script.relative_to(REPO).as_posix()
    result = subprocess.run(
        [bash, "-n", relative_script],
        cwd=REPO,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_repository_enforces_lf_checkout_for_shell_scripts():
    attributes = (REPO / ".gitattributes").read_text(encoding="utf-8")
    assert "*.sh text eol=lf" in attributes


@pytest.mark.parametrize("script", WSL_SCRIPTS, ids=lambda path: path.name)
def test_wsl_scripts_derive_paths_and_never_bootstrap_rust(script: Path):
    source = _source(script)
    assert PINNED_RUST_DECLARATION in source
    assert 'SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"' in source
    assert 'REPO="${ONE_LINK_REPO:-' in source
    assert 'NATIVE="${REPO}/native"' in source
    assert "set -euo pipefail" in source

    for forbidden in (
        "/Users/Alex",
        "/root/ol_native_linux",
        "/root/ol_venv",
        "sh.rustup.rs",
        "rustup toolchain install",
        "rustup default",
        "--default-toolchain stable",
    ):
        assert forbidden not in source

    assert '"$(rustc --version)"' in source or "rustc_version=" in source
    assert '"$(cargo --version)"' in source or "cargo_version=" in source


def test_linux_gate_has_no_skip_or_best_effort_success_path():
    source = _source(REPO / "scripts" / "wsl_linux_gates.sh")
    lowered = source.lower()
    assert "best-effort" not in lowered
    assert "skip_no" not in lowered
    assert "skipping ingest" not in lowered
    assert 'fail_gate "native_build"' in source
    assert 'fail_gate "cargo_test"' in source
    assert 'fail_gate "native_import"' in source
    assert 'fail_gate "ingest_harness"' in source
    assert 'fail_gate "fuse_mount_round_trip"' in source
    assert '"$SCRIPT_DIR/wsl_fuse_mount_test.sh"' in source
    assert 'record_result "overall" "PASS"' in source


def test_fuse_gate_creates_lock_before_locked_offline_build():
    source = _source(REPO / "scripts" / "wsl_fuse_mount_test.sh")
    generate = "cargo generate-lockfile --offline"
    build = "cargo build --locked --offline --release"
    assert generate in source
    assert build in source
    assert source.index(generate) < source.index(build)
    assert "[[ -s Cargo.lock ]]" in source
    assert 'ol_fuse = { path = "native/ol_fuse"' in source
    assert 'ln -s -- "$NATIVE" "$BIN_CRATE/native"' in source
    assert 'ln -s -- "$NATIVE/ol_fuse"' not in source


def test_fuse_gate_propagates_every_operational_failure():
    source = _source(REPO / "scripts" / "wsl_fuse_mount_test.sh")
    assert "timeout --foreground 30s" in source
    assert "fn main() -> Result<(), Box<dyn Error>>" in source
    assert "if !unmount_status.success()" in source
    assert ".join()" in source
    assert "mount_result.map_err" in source
    assert "READ FAILED" not in source
    assert "READDIR FAILED" not in source
    assert "let _ = handle.join" not in source
    assert 'die "strict FUSE gate failed with exit code $run_exit"' in source


def test_demo_runner_uses_locked_workspace_benchmark_and_fails_without_samples():
    source = _source(REPO / "scripts" / "wsl_linux_run_demos.sh")
    assert 'cd -- "$NATIVE"' in source
    assert "cargo bench --locked" in source
    assert "grep -m 12 -E 'time:'" in source
    assert "benchmark completed without any timing samples" in source
    assert 'banner "ALL LINUX GATES PASSED"' in source
