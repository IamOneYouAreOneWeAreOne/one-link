from __future__ import annotations

import json

from one_link.perf_lab import compare_reports, run_perf_lab, write_report


def test_perf_lab_quick_report_schema(tmp_path):
    report = run_perf_lab(scale="quick", seed=123)

    assert report["schema"] == "one-link-perf-lab-v1"
    assert report["scale"] == "quick"
    names = {b["name"] for b in report["benchmarks"]}
    assert {
        "cdc_indexing",
        "prior_knowledge_dedup",
        "swarm_scheduler",
        "never_lose_torture_sim",
        "sqlite_transfer_ledger",
        "zlib_level1_compression",
    } <= names

    by_name = {b["name"]: b for b in report["benchmarks"]}
    assert by_name["cdc_indexing"]["metrics"]["mib_per_s"] > 0
    assert by_name["prior_knowledge_dedup"]["metrics"]["bytes_saved"] > 0
    assert by_name["swarm_scheduler"]["metrics"]["chunks_per_s"] > 0
    assert by_name["never_lose_torture_sim"]["metrics"]["delivered"] is True
    assert by_name["sqlite_transfer_ledger"]["metrics"]["writes_per_s"] > 0
    assert by_name["zlib_level1_compression"]["metrics"]["mib_per_s"] > 0

    out = write_report(report, tmp_path / "perf.json")
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["schema"] == report["schema"]


def test_perf_lab_rejects_unknown_scale():
    try:
        run_perf_lab(scale="galaxy")  # type: ignore[arg-type]
    except ValueError as e:
        assert "scale" in str(e)
    else:
        raise AssertionError("unknown scale accepted")


def test_perf_lab_compare_reports_ratios():
    old = {
        "scale": "quick",
        "benchmarks": [
            {"name": "cdc_indexing", "metrics": {"mib_per_s": 10.0}},
            {"name": "never_lose_torture_sim", "metrics": {"delivered": True}},
        ],
    }
    new = {
        "scale": "quick",
        "benchmarks": [
            {"name": "cdc_indexing", "metrics": {"mib_per_s": 15.0}},
            {"name": "never_lose_torture_sim", "metrics": {"delivered": True}},
        ],
    }

    cmp = compare_reports(old, new)

    assert cmp["schema"] == "one-link-perf-compare-v1"
    assert cmp["benchmarks"]["cdc_indexing"]["mib_per_s"]["ratio"] == 1.5
    assert cmp["benchmarks"]["never_lose_torture_sim"]["delivered"]["changed"] is False
