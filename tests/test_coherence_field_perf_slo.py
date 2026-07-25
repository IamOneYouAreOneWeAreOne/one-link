"""Regression coverage for the portable coherence-field FFI SLO gate."""

from __future__ import annotations

import ast
import hashlib
import json
import math
from pathlib import Path

import pytest

from scripts import coherence_field_slo_gate as slo
from scripts import coherence_field_perf_snapshot as perf_snapshot


REPO = Path(__file__).resolve().parent.parent


def test_native_artifact_metadata_is_verifiable_and_path_private(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "one_link_native.pyd"
    content = b"test-native-artifact"
    artifact.write_bytes(content)

    class _Module:
        __file__ = str(artifact)

    metadata = perf_snapshot._native_artifact_metadata(_Module())

    assert metadata == {
        "file_name": "one_link_native.pyd",
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    assert str(tmp_path) not in json.dumps(metadata)


def _passing_payload() -> dict[str, object]:
    return {
        "schema_version": slo.EXPECTED_SCHEMA_VERSION,
        "version": slo.EXPECTED_VERSION,
        "samples_per_bench": slo.MIN_SAMPLES_PER_BENCH,
        "measurement": {
            "contract": slo.EXPECTED_MEASUREMENT_CONTRACT,
            "clock": "perf_counter_ns",
            "samples_per_bench": slo.MIN_SAMPLES_PER_BENCH,
            "statistic": slo.EXPECTED_STATISTIC,
        },
        "results": [
            {
                "name": name,
                "median_ns": budget.max_median_ns,
            }
            for name, budget in slo.SLO_BUDGETS.items()
        ],
    }


def test_snapshot_at_every_budget_passes() -> None:
    passing, failures = slo.evaluate_snapshot(_passing_payload())

    assert not failures
    assert len(passing) == len(slo.SLO_BUDGETS)


def test_snapshot_over_budget_fails_with_metric_and_limit() -> None:
    payload = _passing_payload()
    rows = payload["results"]
    assert isinstance(rows, list)
    metric = "solve/helmholtz_5000"
    for row in rows:
        if isinstance(row, dict) and row.get("name") == metric:
            row["median_ns"] = slo.SLO_BUDGETS[metric].max_median_ns + 1

    _, failures = slo.evaluate_snapshot(payload)

    assert any(metric in failure and "exceeds 10.000 ms" in failure for failure in failures)


def test_snapshot_missing_tracked_metric_fails_closed() -> None:
    payload = _passing_payload()
    rows = payload["results"]
    assert isinstance(rows, list)
    missing = "coupling/prefetch_priorities_1k"
    payload["results"] = [
        row for row in rows if not isinstance(row, dict) or row.get("name") != missing
    ]

    _, failures = slo.evaluate_snapshot(payload)

    assert f"missing tracked metric: {missing}" in failures


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf, "NaN"])
def test_snapshot_nonfinite_metric_fails_closed(value: object) -> None:
    payload = _passing_payload()
    rows = payload["results"]
    assert isinstance(rows, list)
    metric = "solve/helmholtz_1000"
    for row in rows:
        if isinstance(row, dict) and row.get("name") == metric:
            row["median_ns"] = value

    _, failures = slo.evaluate_snapshot(payload)

    assert any(
        failure == f"{metric}: median_ns must be a finite positive number"
        for failure in failures
    )
    assert f"missing tracked metric: {metric}" not in failures


@pytest.mark.parametrize("value", [True, 0, -1, "1000", None])
def test_snapshot_rejects_nonpositive_or_non_numeric_metric(value: object) -> None:
    payload = _passing_payload()
    rows = payload["results"]
    assert isinstance(rows, list)
    metric = "solve/helmholtz_100"
    for row in rows:
        if isinstance(row, dict) and row.get("name") == metric:
            row["median_ns"] = value

    _, failures = slo.evaluate_snapshot(payload)

    assert f"{metric}: median_ns must be a finite positive number" in failures


def test_snapshot_duplicate_tracked_metric_fails_closed() -> None:
    payload = _passing_payload()
    rows = payload["results"]
    assert isinstance(rows, list)
    duplicate = dict(rows[0])
    rows.append(duplicate)

    _, failures = slo.evaluate_snapshot(payload)

    assert f"duplicate tracked metric: {duplicate['name']}" in failures


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("schema_version", 1, "snapshot schema_version must be 2"),
        ("version", "other", "snapshot version must be"),
        ("measurement", None, "measurement metadata must be a JSON object"),
    ],
)
def test_snapshot_contract_mismatch_fails_closed(
    field: str,
    value: object,
    expected: str,
) -> None:
    payload = _passing_payload()
    payload[field] = value

    _, failures = slo.evaluate_snapshot(payload)

    assert any(expected in failure for failure in failures)


def test_cli_returns_zero_for_pass_and_one_for_slo_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    results = tmp_path / "perf.json"
    results.write_text(json.dumps(_passing_payload()), encoding="utf-8")

    assert slo.main(["--results", str(results)]) == 0
    assert "PASS: all" in capsys.readouterr().out

    payload = _passing_payload()
    rows = payload["results"]
    assert isinstance(rows, list)
    first = rows[0]
    assert isinstance(first, dict)
    first["median_ns"] = slo.SLO_BUDGETS[str(first["name"])].max_median_ns + 1
    results.write_text(json.dumps(payload), encoding="utf-8")

    assert slo.main(["--results", str(results)]) == 1
    assert "portable production SLO" in capsys.readouterr().err


def test_cli_missing_results_file_is_usage_error(tmp_path: Path) -> None:
    assert slo.main(["--results", str(tmp_path / "missing.json")]) == 2


def test_cli_invalid_json_is_usage_error(tmp_path: Path) -> None:
    results = tmp_path / "invalid.json"
    results.write_text("not json", encoding="utf-8")

    assert slo.main(["--results", str(results)]) == 2


def test_pre_release_uses_portable_slo_not_unqualified_relative_baseline() -> None:
    source = (REPO / "scripts" / "pre_release_audit.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    step = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "step_perf_gate"
    )
    literals = {
        node.value
        for node in ast.walk(step)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }

    assert "scripts/coherence_field_slo_gate.py" in literals
    assert "bench_baselines/coherence_field.json" not in literals
    assert "--max-regression-percent" not in literals
    assert "_fresh_perf.json" not in literals


def test_historical_relative_baseline_is_explicitly_lab_only() -> None:
    documentation = (REPO / "bench_baselines" / "README.md").read_text(
        encoding="utf-8"
    )

    assert "dedicated-runner tooling only" in documentation
    assert "Do not rebase this file from a busy workstation" in documentation
    assert "scripts/bench_gate.py" in documentation

    runbook = (REPO / "docs" / "PHASE_E_OPERATOR_RUNBOOK.md").read_text(
        encoding="utf-8"
    )
    assert "coherence_field_slo_gate.py" in runbook
    assert "Dedicated-runner regression lab" in runbook
    assert "5% regression vs baseline" not in runbook


def test_production_readiness_describes_relative_baseline_as_lab_only() -> None:
    from scripts.production_readiness_audit import (
        _check_coherence_perf_gates_configured,
    )

    check = _check_coherence_perf_gates_configured()

    assert check["status"] == "PASS"
    assert check["portable_gate"] == "coherence_field_slo_gate.py"
    assert check["historical_baseline_scope"] == (
        "dedicated environment-qualified runner only"
    )
