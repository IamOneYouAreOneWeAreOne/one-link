"""v0.21.x `one-link verify-this-install` CLI command.

The trust gate for production: an auditor (or a paranoid user) can
run this on their install and compare the rollup hash against the
figure published in the release notes. Mismatch = tampering OR
local patching. Either way, the user finds out without trusting
anything that isn't on their disk.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from one_link.cli import cli


# ── command registration + basic shape ─────────────────────────────


def test_verify_command_is_registered():
    """Top-level `one-link verify-this-install` exists and shows
    help text mentioning the trust property."""
    result = CliRunner().invoke(cli, ["verify-this-install", "--help"])
    assert result.exit_code == 0
    out = result.output.lower()
    assert "version" in out
    assert "rollup" in out or "hash" in out


def test_verify_command_runs_clean_on_source_install():
    """A source-tree run should exit 0 + emit the version + rollup
    + per-file hashes for every load-bearing file. No file should
    show as MISSING (the test runs against the repo itself, so
    every file in _FINGERPRINT_FILES exists)."""
    result = CliRunner().invoke(cli, ["verify-this-install"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "One Link version:" in out
    assert "Rollup" in out
    assert "MISSING" not in out, (
        "load-bearing source files reported missing; either the "
        "fingerprint list is stale or the repo install is incomplete"
    )


# ── JSON mode for tooling ─────────────────────────────────────────


def test_verify_command_json_mode_emits_parseable_output():
    """--json flag emits a single JSON object the CI release pipeline
    can parse to compare hashes across rebuilds."""
    result = CliRunner().invoke(cli, ["verify-this-install", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "version" in data
    assert "rollup_blake2s_128" in data
    assert "files" in data
    assert isinstance(data["files"], dict)
    assert "frozen_binary_blake2s_256" in data
    # Source install -> frozen_binary is null.
    assert data["frozen_binary_blake2s_256"] is None


def test_verify_command_rollup_is_deterministic():
    """Two consecutive runs MUST emit the same rollup. If the rollup
    depends on mtime / non-deterministic ordering, an auditor's
    'compare against release notes' workflow breaks."""
    r1 = CliRunner().invoke(cli, ["verify-this-install", "--json"])
    r2 = CliRunner().invoke(cli, ["verify-this-install", "--json"])
    d1 = json.loads(r1.output)
    d2 = json.loads(r2.output)
    assert d1["rollup_blake2s_128"] == d2["rollup_blake2s_128"]
    assert d1["files"] == d2["files"]


def test_verify_command_rollup_changes_when_a_load_bearing_file_changes(tmp_path, monkeypatch):
    """If ANY load-bearing source file's bytes change, the rollup
    must change too. Otherwise tampering would be invisible to the
    verify command, which defeats its whole purpose."""
    # Read the baseline.
    r0 = CliRunner().invoke(cli, ["verify-this-install", "--json"])
    baseline = json.loads(r0.output)
    baseline_rollup = baseline["rollup_blake2s_128"]

    # Temporarily redirect the build_identity's package_root to a
    # tmp copy with one file mutated; verify the rollup changes.
    import shutil
    from one_link import build_identity
    real_root = build_identity.package_root()

    fake_root = tmp_path / "one_link_fake"
    fake_root.mkdir()
    # Copy every fingerprint file into the fake root.
    for rel in build_identity._FINGERPRINT_FILES:
        src = real_root / rel
        dst = fake_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_file():
            shutil.copy2(src, dst)
    # Mutate one file by appending a byte.
    (fake_root / "__init__.py").open("ab").write(b"\n# tamper\n")

    monkeypatch.setattr(build_identity, "package_root", lambda: fake_root)
    r1 = CliRunner().invoke(cli, ["verify-this-install", "--json"])
    mutated = json.loads(r1.output)
    assert mutated["rollup_blake2s_128"] != baseline_rollup, (
        "rollup did NOT change after tampering with __init__.py; "
        "the verify command is not tamper-detecting which is the "
        "whole point of the trust gate"
    )


def test_verify_command_surfaces_missing_files_as_warning(tmp_path, monkeypatch):
    """If a load-bearing file is missing, the command must exit 0
    (it's a diagnostic, not a gate) BUT must print a clear
    WARNING + list the missing files. Silent omission would let
    a stripped install pass the trust check."""
    from one_link import build_identity
    fake_root = tmp_path / "stripped"
    fake_root.mkdir()
    # Don't copy any files - every fingerprint file is "missing".
    monkeypatch.setattr(build_identity, "package_root", lambda: fake_root)
    result = CliRunner().invoke(cli, ["verify-this-install"])
    assert result.exit_code == 0  # diagnostic, not a gate
    # Should be visible in either stdout or stderr - check both.
    full = (result.output or "") + (result.stderr or "")
    assert "WARNING" in full
    assert "MISSING" in (result.output or "")
    for rel in build_identity._FINGERPRINT_FILES:
        assert rel in (result.output or ""), (
            f"missing-file list does not name {rel!r}"
        )


def test_verify_command_json_mode_lists_missing_files_under_missing_key(tmp_path, monkeypatch):
    """JSON mode promotes 'missing' from a string in the human
    output to a structured list - lets a release pipeline gate
    on missing-file presence."""
    from one_link import build_identity
    fake_root = tmp_path / "stripped"
    fake_root.mkdir()
    monkeypatch.setattr(build_identity, "package_root", lambda: fake_root)
    result = CliRunner().invoke(cli, ["verify-this-install", "--json"])
    data = json.loads(result.output)
    assert isinstance(data["missing"], list)
    # Every fingerprint file should be in the missing list.
    assert set(data["missing"]) == set(build_identity._FINGERPRINT_FILES)
