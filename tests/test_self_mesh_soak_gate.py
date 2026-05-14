from scripts.self_mesh_soak_gate import evaluate


def test_self_mesh_soak_gate_passes_clean_budgets():
    result = evaluate({
        "budgets": {
            "items": [
                {
                    "metric": "route_probe_avg_ms",
                    "status": "pass",
                    "sample_count": 1,
                    "worst_ms": 1.0,
                    "limit_ms": 50.0,
                },
                {
                    "metric": "command_verify",
                    "status": "pass",
                    "sample_count": 2,
                    "worst_ms": 0.2,
                    "limit_ms": 5.0,
                },
            ],
        },
        "history": [{"id": 1}],
        "performance": {"route_probe_avg_ms": 1.0},
    })

    assert result["ok"] is True
    assert result["status"] == "pass"
    assert result["budget_count"] == 2
    assert result["history_count"] == 1


def test_self_mesh_soak_gate_reports_budget_warnings():
    result = evaluate({
        "budgets": {
            "items": [
                {
                    "metric": "api_poll",
                    "status": "warn",
                    "sample_count": 3,
                    "worst_ms": 40.0,
                    "limit_ms": 25.0,
                }
            ],
        },
        "history": [],
        "performance": {},
    })

    assert result["ok"] is False
    assert result["status"] == "warn"
    assert result["warnings"][0]["metric"] == "api_poll"


def test_self_mesh_soak_gate_reports_missing_observation_metrics():
    result = evaluate({
        "budgets": {
            "items": [
                {
                    "metric": "command_total",
                    "status": "pass",
                    "sample_count": 0,
                    "worst_ms": 0,
                    "limit_ms": 300.0,
                }
            ],
        },
        "history": [],
        "performance": {},
    })

    assert result["ok"] is True
    assert result["missing_observation_metrics"][0]["metric"] == "command_total"
