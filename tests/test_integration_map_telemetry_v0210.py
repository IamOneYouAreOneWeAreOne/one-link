"""Integration map §11 — Tests for the missing telemetry counters.

Exercises:
  - capability_denials counter by reason + capability
  - selector regret EWMA per user_mode (alpha = 0.1)
  - alignment_trust histogram (5 buckets, 0..1 range)
  - All accessors return fresh dicts (caller can't mutate internal)
  - Defensive against missing internal state (test fixtures)
"""

from __future__ import annotations

import pytest

from one_link import daemon as daemon_module


def _bare_daemon():
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d._user_mode_value = "normal"
    d._capability_denial_counters = {
        "total": 0,
        "by_reason": {
            "seed_tamper": 0,
            "policy_denied": 0,
            "low_trust_blocked": 0,
            "scope_mismatch": 0,
        },
        "by_capability": {},
    }
    d._selector_regret_ewma = {
        "normal": 0.0,
        "paranoid": 0.0,
        "battery_save": 0.0,
        "latency_strict": 0.0,
    }
    d._selector_regret_ewma_alpha = 0.1
    d._alignment_trust_histogram = [0, 0, 0, 0, 0]
    return d


# ---------- capability_denials ----------


def test_record_denial_increments_total() -> None:
    d = _bare_daemon()
    d._record_capability_denial(reason="policy_denied", capability="files")
    assert d._capability_denial_counters["total"] == 1


def test_record_denial_increments_by_reason() -> None:
    d = _bare_daemon()
    d._record_capability_denial(reason="seed_tamper", capability="chat")
    d._record_capability_denial(reason="seed_tamper", capability="files")
    d._record_capability_denial(reason="policy_denied", capability="chat")
    c = d._capability_denial_counters
    assert c["by_reason"]["seed_tamper"] == 2
    assert c["by_reason"]["policy_denied"] == 1


def test_record_denial_increments_by_capability() -> None:
    d = _bare_daemon()
    d._record_capability_denial(reason="policy_denied", capability="files")
    d._record_capability_denial(reason="policy_denied", capability="files")
    d._record_capability_denial(reason="policy_denied", capability="folder_sync")
    by_cap = d._capability_denial_counters["by_capability"]
    assert by_cap["files"] == 2
    assert by_cap["folder_sync"] == 1


def test_record_denial_unknown_reason_buckets_as_other() -> None:
    d = _bare_daemon()
    d._record_capability_denial(reason="mystery_reason", capability="x")
    c = d._capability_denial_counters
    assert c["by_reason"].get("other", 0) == 1
    # Known buckets unchanged.
    assert c["by_reason"]["seed_tamper"] == 0


def test_capability_denial_stats_returns_fresh_dict() -> None:
    d = _bare_daemon()
    d._record_capability_denial(reason="seed_tamper", capability="chat")
    s1 = d.capability_denial_stats()
    s2 = d.capability_denial_stats()
    s1["total"] = 999
    assert s2["total"] == 1


def test_capability_denial_stats_defensive_when_missing() -> None:
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    # No counter dict set.
    s = d.capability_denial_stats()
    assert s["total"] == 0
    assert s["by_reason"] == {}
    assert s["by_capability"] == {}


# ---------- selector_regret_ewma ----------


def test_record_regret_updates_current_mode() -> None:
    d = _bare_daemon()
    d._user_mode_value = "paranoid"
    d._record_selector_regret(1.0)
    # EWMA: 0.9 * 0.0 + 0.1 * 1.0 = 0.1
    assert d._selector_regret_ewma["paranoid"] == pytest.approx(0.1)


def test_record_regret_converges_toward_steady() -> None:
    """Repeated 1.0 inputs should drive the EWMA toward 1.0."""
    d = _bare_daemon()
    for _ in range(100):
        d._record_selector_regret(1.0)
    # After 100 iterations with alpha=0.1, very close to 1.0.
    assert d._selector_regret_ewma["normal"] > 0.99


def test_record_regret_isolated_per_mode() -> None:
    """Regret in paranoid mode shouldn't bleed into normal."""
    d = _bare_daemon()
    d._user_mode_value = "paranoid"
    d._record_selector_regret(1.0)
    d._user_mode_value = "normal"
    d._record_selector_regret(0.0)
    assert d._selector_regret_ewma["paranoid"] == pytest.approx(0.1)
    assert d._selector_regret_ewma["normal"] == 0.0


def test_record_regret_ignores_non_numeric() -> None:
    d = _bare_daemon()
    d._record_selector_regret("not-a-number")  # type: ignore[arg-type]
    assert d._selector_regret_ewma["normal"] == 0.0


def test_selector_regret_stats_returns_fresh_dict() -> None:
    d = _bare_daemon()
    d._record_selector_regret(1.0)
    s1 = d.selector_regret_ewma_stats()
    s2 = d.selector_regret_ewma_stats()
    s1["normal"] = 999
    assert s2["normal"] != 999


def test_selector_regret_stats_defensive_when_missing() -> None:
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    s = d.selector_regret_ewma_stats()
    assert s == {}


# ---------- alignment_trust_histogram ----------


@pytest.mark.parametrize(
    "score,expected_bucket",
    [
        (0.0, 0),
        (0.1, 0),
        (0.2, 1),
        (0.35, 1),
        (0.4, 2),
        (0.55, 2),
        (0.6, 3),
        (0.79, 3),
        (0.8, 4),
        (1.0, 4),
    ],
)
def test_record_trust_bucketing(score, expected_bucket) -> None:
    d = _bare_daemon()
    d._record_alignment_trust_score(score)
    assert d._alignment_trust_histogram[expected_bucket] == 1
    # Other buckets unchanged.
    for i, count in enumerate(d._alignment_trust_histogram):
        if i != expected_bucket:
            assert count == 0


def test_record_trust_ignores_out_of_range() -> None:
    d = _bare_daemon()
    d._record_alignment_trust_score(-0.5)
    d._record_alignment_trust_score(1.5)
    assert sum(d._alignment_trust_histogram) == 0


def test_record_trust_ignores_non_numeric() -> None:
    d = _bare_daemon()
    d._record_alignment_trust_score("not-a-number")  # type: ignore[arg-type]
    d._record_alignment_trust_score(None)  # type: ignore[arg-type]
    assert sum(d._alignment_trust_histogram) == 0


def test_alignment_trust_histogram_shape() -> None:
    d = _bare_daemon()
    d._record_alignment_trust_score(0.5)
    out = d.alignment_trust_histogram()
    assert "buckets" in out
    assert "labels" in out
    assert "total" in out
    assert len(out["buckets"]) == 5
    assert len(out["labels"]) == 5
    assert out["total"] == 1


def test_alignment_trust_histogram_defensive_when_missing() -> None:
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    out = d.alignment_trust_histogram()
    # Default 5 zeros + total 0.
    assert out["buckets"] == [0, 0, 0, 0, 0]
    assert out["total"] == 0
