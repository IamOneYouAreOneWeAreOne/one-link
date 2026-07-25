"""Regression gates for exhaustive, pinned TLA+ model checking."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from scripts.run_formal_models import FormalGateError, _git_commit, load_manifest, verify_tool


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "formal" / "models.json"
WORKFLOW = ROOT / ".github" / "workflows" / "formal_verification.yml"


def test_manifest_covers_every_formal_model_exactly() -> None:
    manifest = load_manifest(MANIFEST)
    formal = MANIFEST.parent
    assert len(manifest.models) >= 14
    assert {model.spec.name for model in manifest.models} == {
        path.name for path in formal.glob("*.tla")
    }
    assert {model.config.name for model in manifest.models} == {
        path.name for path in formal.glob("*.cfg")
    }
    assert manifest.tool.version == "1.7.4"
    assert len(manifest.tool.sha256) == 64


def test_manifest_rejects_unlisted_model(tmp_path: Path) -> None:
    formal = tmp_path / "formal"
    formal.mkdir()
    (formal / "one.tla").write_text("---- MODULE one ----\n====\n", encoding="utf-8")
    (formal / "one.cfg").write_text("SPECIFICATION Spec\n", encoding="utf-8")
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    payload["models"] = [
        {
            "id": "one",
            "spec": "one.tla",
            "config": "one.cfg",
            "timeout_seconds": 10,
        }
    ]
    target = formal / "models.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    (formal / "forgotten.tla").write_text("---- MODULE forgotten ----\n====\n", encoding="utf-8")
    with pytest.raises(FormalGateError, match="cover every"):
        load_manifest(target)


def test_manifest_rejects_module_filename_case_drift(tmp_path: Path) -> None:
    formal = tmp_path / "formal"
    formal.mkdir()
    (formal / "Wrong.tla").write_text(
        "---------------- MODULE Right ----------------\n====\n", encoding="utf-8"
    )
    (formal / "Wrong.cfg").write_text("SPECIFICATION Spec\n", encoding="utf-8")
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    payload["models"] = [
        {
            "id": "wrong",
            "spec": "Wrong.tla",
            "config": "Wrong.cfg",
            "timeout_seconds": 10,
        }
    ]
    target = formal / "models.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(FormalGateError, match="module/filename mismatch"):
        load_manifest(target)


def test_manifest_rejects_config_stem_drift(tmp_path: Path) -> None:
    formal = tmp_path / "formal"
    formal.mkdir()
    (formal / "Right.tla").write_text(
        "---------------- MODULE Right ----------------\n====\n", encoding="utf-8"
    )
    (formal / "wrong.cfg").write_text("SPECIFICATION Spec\n", encoding="utf-8")
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    payload["models"] = [
        {
            "id": "right",
            "spec": "Right.tla",
            "config": "wrong.cfg",
            "timeout_seconds": 10,
        }
    ]
    target = formal / "models.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(FormalGateError, match="config/spec mismatch"):
        load_manifest(target)


def test_tool_digest_is_a_hard_authority(tmp_path: Path) -> None:
    manifest = load_manifest(MANIFEST)
    jar = tmp_path / "tla2tools.jar"
    jar.write_bytes(b"not the reviewed TLC binary")
    actual = hashlib.sha256(jar.read_bytes()).hexdigest()
    assert actual != manifest.tool.sha256
    with pytest.raises(FormalGateError, match="digest mismatch"):
        verify_tool(manifest, jar)


def test_commit_evidence_falls_back_to_valid_ci_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit = "a" * 40
    monkeypatch.setenv("GITHUB_SHA", commit)
    assert _git_commit(tmp_path) == commit


def test_commit_evidence_rejects_malformed_ci_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_SHA", "not-a-commit")
    with pytest.raises(FormalGateError, match="GITHUB_SHA"):
        _git_commit(tmp_path)


def test_commit_evidence_rejects_ci_checkout_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "formal-gate@example.invalid"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Formal Gate"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    (tmp_path / "evidence.txt").write_text("bound\n", encoding="utf-8")
    subprocess.run(["git", "add", "evidence.txt"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-qm", "bind evidence"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    checked_out = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    ci_commit = "f" * 40 if checked_out != "f" * 40 else "e" * 40
    monkeypatch.setenv("GITHUB_SHA", ci_commit)
    with pytest.raises(FormalGateError, match="does not match GITHUB_SHA"):
        _git_commit(tmp_path)


def test_workflow_runs_on_every_change_and_retains_evidence() -> None:
    raw = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.load(raw, Loader=yaml.BaseLoader)
    triggers = workflow["on"]
    assert {"push", "pull_request", "workflow_dispatch", "workflow_call"} <= set(triggers)
    job = workflow["jobs"]["model_check"]
    uses = [step["uses"] for step in job["steps"] if step.get("uses")]
    assert all("@" in action and not action.endswith(("@main", "@master")) for action in uses)
    assert "actions/setup-java@03ad4de0992f5dab5e18fcb136590ce7c4a0ac95" in uses
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in uses
    assert "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88" in raw
    assert "scripts/run_formal_models.py" in raw
    assert "if: always()" in raw
