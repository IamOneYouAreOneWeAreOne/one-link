from scripts.self_mesh_soak_rollup import rollup


def test_self_mesh_soak_rollup_passes_all_green_samples():
    summary = rollup([
        {"ok": True, "result": {"warnings": []}},
        {"ok": True, "result": {"warnings": []}},
    ])

    assert summary["ok"] is True
    assert summary["sample_count"] == 2
    assert summary["failure_count"] == 0


def test_self_mesh_soak_rollup_counts_failures_and_missing_metrics():
    summary = rollup([
        {
            "ok": False,
            "result": {
                "warnings": [{"metric": "api_poll"}],
                "missing_observation_metrics": [{"metric": "command_total"}],
            },
        },
        {
            "ok": True,
            "result": {
                "warnings": [],
                "missing_observation_metrics": [{"metric": "command_total"}],
            },
        },
    ])

    assert summary["ok"] is False
    assert summary["failure_count"] == 1
    assert summary["warning_count"] == 1
    assert summary["missing_observation_counts"] == {"command_total": 2}
