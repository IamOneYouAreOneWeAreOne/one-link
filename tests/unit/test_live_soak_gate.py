from __future__ import annotations

from scripts.live_soak_gate import Thresholds, _evaluate


def test_live_soak_gate_skips_tiny_file_throughput_noise() -> None:
    failures = _evaluate(
        [
            {
                "ok": True,
                "size_mib": 1,
                "run": 2,
                "effective_mbps": 20.0,
                "bandwidth_savings_ratio": 1.0,
            }
        ],
        Thresholds(
            min_fresh_mbps=25.0,
            min_repeat_effective_mbps=250.0,
            min_repeat_savings_ratio=0.9,
        ),
    )

    assert failures == []


def test_live_soak_gate_enforces_repeat_savings() -> None:
    failures = _evaluate(
        [
            {
                "ok": True,
                "size_mib": 16,
                "run": 2,
                "effective_mbps": 500.0,
                "bandwidth_savings_ratio": 0.1,
            }
        ],
        Thresholds(
            min_fresh_mbps=25.0,
            min_repeat_effective_mbps=250.0,
            min_repeat_savings_ratio=0.9,
        ),
    )

    assert failures
    assert "repeat savings below" in failures[0]
