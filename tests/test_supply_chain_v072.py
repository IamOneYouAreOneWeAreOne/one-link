"""v0.7.2 supply-chain gate tests (audit finding C).

These tests don't run pip-audit / bandit / cyclonedx for real (they
need internet + heavy install); they pin the *configuration* surface
so a future PR can't silently drop a security gate.

Pin:
  - pyproject.toml declares a `security` extra with the four tools
    the audit prescribes (pip-audit, bandit, cyclonedx-bom, pip-tools).
  - pyproject.toml has a [tool.bandit] section with `exclude_dirs`
    that skips tests/scripts (they hit fixtures bandit would flag)
    AND production code is fully scanned.
  - The bandit `skips` list contains only documented exemptions
    with a justification (B101/B404/B603 for assert + subprocess).
  - scripts/lock_deps.py and scripts/gen_sbom.py exist and are
    syntactically importable (so the GH Action can invoke them).
  - .github/workflows/security.yml exists and runs the four gates
    (pip-audit, bandit, cyclonedx-bom, lockfile drift check).
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Any

import pytest


_REPO = Path(__file__).resolve().parent.parent


def _read_pyproject() -> dict:
    text = (_REPO / "pyproject.toml").read_text(encoding="utf-8")
    if sys.version_info >= (3, 11):
        import tomllib
        return tomllib.loads(text)
    import tomli  # type: ignore[import-not-found]
    return tomli.loads(text)


# ─── pyproject.toml: security extras ───────────────────────────────

def test_pyproject_declares_security_extras():
    p = _read_pyproject()
    extras = p["project"]["optional-dependencies"]
    assert "security" in extras, (
        "pyproject [project.optional-dependencies] must declare a"
        " `security` group covering pip-audit / bandit / cyclonedx-bom /"
        " pip-tools (audit finding C, supply-chain gates)."
    )


def test_security_extras_includes_each_audit_tool():
    p = _read_pyproject()
    sec = p["project"]["optional-dependencies"]["security"]
    names = {dep.split(">=")[0].split("==")[0].split("[")[0].lower() for dep in sec}
    assert "pip-audit" in names
    assert "bandit" in names
    # cyclonedx-bom (the package) installs the cyclonedx_py module.
    assert "cyclonedx-bom" in names or "cyclonedx-py" in names
    assert "pip-tools" in names


# ─── pyproject.toml: [tool.bandit] ─────────────────────────────────

def test_pyproject_has_bandit_config():
    p = _read_pyproject()
    bandit = p.get("tool", {}).get("bandit")
    assert bandit is not None, "pyproject must include a [tool.bandit] section"


def test_bandit_excludes_tests_and_scripts():
    p = _read_pyproject()
    excludes = p["tool"]["bandit"]["exclude_dirs"]
    assert "tests" in excludes
    assert "scripts" in excludes


def test_bandit_skips_are_only_documented_exemptions():
    """Each skip is allowed only if listed below; new skips need
    justification. Audit doc treats this as a security boundary —
    don't widen silently."""
    p = _read_pyproject()
    skips = set(p["tool"]["bandit"].get("skips", []))
    # Each entry below has a documented reason in pyproject.toml.
    # B104 (2026-06-04): hardcoded bind to 0.0.0.0 IS the intentional,
    # documented `--lan` feature (binding all interfaces is how a phone
    # on your Wi-Fi reaches the UI); justified in pyproject.toml.
    allowed = {"B101", "B404", "B603", "B104"}
    extra = skips - allowed
    assert not extra, (
        f"bandit skips include undocumented entries: {sorted(extra)}. "
        "Add them to the allowed set with a justification comment."
    )


# ─── scripts ───────────────────────────────────────────────────────

@pytest.mark.parametrize("name", ["lock_deps.py", "gen_sbom.py"])
def test_security_scripts_exist_and_parse(name: str):
    p = _REPO / "scripts" / name
    assert p.is_file(), f"scripts/{name} missing"
    # Must parse — catches broken edits before CI runs.
    ast.parse(p.read_text(encoding="utf-8"), filename=str(p))


def test_lock_deps_script_invokes_pip_compile():
    text = (_REPO / "scripts" / "lock_deps.py").read_text(encoding="utf-8")
    assert "piptools" in text and "compile" in text


def test_gen_sbom_script_invokes_cyclonedx():
    text = (_REPO / "scripts" / "gen_sbom.py").read_text(encoding="utf-8")
    assert "cyclonedx_py" in text


# ─── .github/workflows/security.yml ────────────────────────────────

def test_security_workflow_exists():
    p = _REPO / ".github" / "workflows" / "security.yml"
    assert p.is_file(), (
        ".github/workflows/security.yml missing — supply-chain gates"
        " are unwired in CI."
    )


def test_security_workflow_runs_pip_audit():
    text = (_REPO / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    assert "pip_audit" in text or "pip-audit" in text


def test_security_workflow_runs_bandit():
    text = (_REPO / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    assert "bandit" in text


def test_security_workflow_generates_sbom():
    text = (_REPO / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    assert "gen_sbom.py" in text or "cyclonedx" in text


def test_security_workflow_uploads_artifacts():
    text = (_REPO / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    # The supply-chain artifact bundle must include at least the SBOM
    # and the audit JSONs so consumers can re-verify.
    assert "upload-artifact" in text
    assert "sbom" in text.lower()
    assert "pip-audit.json" in text
    assert "bandit.json" in text


def test_security_workflow_runs_on_schedule():
    """Weekly schedule catches newly-published OSV records against
    deps that haven't otherwise changed in the repo."""
    text = (_REPO / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    assert "schedule:" in text
    assert "cron:" in text


def test_security_workflow_runs_lockfile_drift_check():
    text = (_REPO / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    assert "lock_deps.py --check" in text
