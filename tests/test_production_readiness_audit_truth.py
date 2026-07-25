from __future__ import annotations

import json

from scripts import pre_release_audit
from scripts import production_readiness_audit as audit


def test_scoped_wiring_pass_never_claims_product_is_production_ready(
    monkeypatch,
    tmp_path,
    capsys,
):
    blocking_names = (
        "_check_native_crates_present",
        "_check_capabilities_advertised",
        "_check_daemon_wiring",
        "_check_native_diagnostics_blocks",
        "_check_field_snapshot_manager_safe_defaults",
        "_check_coherence_perf_gates_configured",
    )
    advisory_names = (
        "_advisory_facade_migration",
        "_advisory_bloom_honor_state",
        "_advisory_filesystem_mount_state",
    )
    for name in blocking_names:
        monkeypatch.setattr(
            audit,
            name,
            lambda name=name: {"category": name, "status": "PASS"},
        )
    for name in advisory_names:
        monkeypatch.setattr(
            audit,
            name,
            lambda name=name: {"category": name, "status": "ADVISORY"},
        )

    report_path = tmp_path / "report.json"
    assert audit.main(["--json", str(report_path)]) == 0

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["file_engine_v2_wiring_ready"] is True
    assert report["production_ready"] is False
    assert "cannot establish whole-product" in report["production_ready_reason"]
    assert "not a whole-product production or release verdict" in capsys.readouterr().out


def test_skipped_pre_release_suites_can_never_emit_release_gated(
    monkeypatch,
    tmp_path,
    capsys,
):
    smoke_steps = (
        "step_sovereignty_audit",
        "step_mypy",
        "step_phase_e_live_demo",
        "step_cross_domain_demo",
        "step_fuzz_quick",
        "step_perf_gate",
    )
    for name in smoke_steps:
        monkeypatch.setattr(
            pre_release_audit,
            name,
            lambda name=name: {
                "label": name,
                "ok": True,
                "wall_seconds": 0.0,
                "stderr_tail": "",
                "stdout_tail": "",
                "cmd": "test",
            },
        )

    report_path = tmp_path / "pre-release.json"
    assert pre_release_audit.main(
        ["--skip-cargo", "--skip-pytest", "--json", str(report_path)]
    ) == 0

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["checks_passed"] is True
    assert report["complete"] is False
    assert report["release_gated"] is False
    assert "NOT RELEASE-GATED" in capsys.readouterr().out


def test_sovereignty_audit_rejects_not_yet_approved_substrate(
    monkeypatch,
    tmp_path,
):
    native = tmp_path / "native"
    native.mkdir()
    (native / "Cargo.lock").write_text(
        '[[package]]\nname = "rocksdb"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(pre_release_audit, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        pre_release_audit,
        "SOVEREIGNTY_TABLE",
        [("RocksDB", "not_present_yet", "review required")],
    )

    result = pre_release_audit.step_sovereignty_audit()
    assert result["ok"] is False
    assert "unexpectedly present" in result["stderr_tail"]


def test_filesystem_advisory_reports_linux_binding_without_promoting_other_platforms():
    result = audit._advisory_filesystem_mount_state()

    assert result["status"] == "ADVISORY"
    assert result["crates"]["ol_fuse"] == "linux_fuser_adapter"
    assert result["crates"]["one_link_native.fuse"] == "python_binding"
    assert result["crates"]["ol_fskit"] == "scaffold_unimplemented"
    assert result["crates"]["ol_winfs"] == "scaffold_unimplemented"
    assert isinstance(result["runtime"]["ready"], bool)
    assert "real read-only callback-backed fuser adapter" in result["note"]
    assert "unimplemented" in result["note"]
