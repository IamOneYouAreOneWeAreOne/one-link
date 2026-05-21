"""Tests for the selector-decision counter telemetry.

Exercises:
  - _record_selector_decision_counters updates every counter field
  - Defensive against malformed decisions (missing keys, wrong types,
    None, non-dict)
  - selector_decision_stats returns a fresh dict (callers can't mutate
    internal state)
  - Derived ratios (cover_ratio, f4_violation_ratio) compute correctly
  - Counters survive zero total (no division-by-zero)
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from one_link import daemon as daemon_module


def _bare_daemon():
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d._selector_decision_counters = {
        "total": 0,
        "transport": {
            "quic_stream": 0, "quic_datagram": 0,
            "webrtc": 0, "relay": 0,
        },
        "path": {"classical": 0, "coherence": 0},
        "onion_hops": {1: 0, 3: 0, 5: 0},
        "cover_traffic_on": 0,
        "cover_traffic_off": 0,
        "batch_decision": {
            "emit_now": 0, "batch": 0, "urgent_bypass": 0,
        },
        "anchor_lay_on": 0,
        "anchor_lay_off": 0,
        "predictor_warm_on": 0,
        "predictor_warm_off": 0,
        "f4_violations": 0,
    }
    return d


_FULL_DECISION = {
    "transport": "quic_stream",
    "path": "classical",
    "onion_hops": 3,
    "cover_traffic": True,
    "batch_decision": "emit_now",
    "anchor_lay": False,
    "predictor_warm": True,
}


# ---------- _record_selector_decision_counters ----------


def test_record_updates_total() -> None:
    d = _bare_daemon()
    d._record_selector_decision_counters(dict(_FULL_DECISION))
    assert d._selector_decision_counters["total"] == 1
    d._record_selector_decision_counters(dict(_FULL_DECISION))
    assert d._selector_decision_counters["total"] == 2


def test_record_updates_transport_counter() -> None:
    d = _bare_daemon()
    d._record_selector_decision_counters(dict(_FULL_DECISION))
    assert d._selector_decision_counters["transport"]["quic_stream"] == 1


def test_record_updates_path_counter() -> None:
    d = _bare_daemon()
    decision = dict(_FULL_DECISION)
    decision["path"] = "coherence"
    d._record_selector_decision_counters(decision)
    assert d._selector_decision_counters["path"]["coherence"] == 1


def test_record_updates_onion_hops_counter() -> None:
    d = _bare_daemon()
    for h in (1, 3, 5):
        decision = dict(_FULL_DECISION)
        decision["onion_hops"] = h
        d._record_selector_decision_counters(decision)
    counters = d._selector_decision_counters["onion_hops"]
    assert counters[1] == 1
    assert counters[3] == 1
    assert counters[5] == 1


def test_record_updates_cover_counters() -> None:
    d = _bare_daemon()
    on = dict(_FULL_DECISION, cover_traffic=True)
    off = dict(_FULL_DECISION, cover_traffic=False)
    d._record_selector_decision_counters(on)
    d._record_selector_decision_counters(on)
    d._record_selector_decision_counters(off)
    assert d._selector_decision_counters["cover_traffic_on"] == 2
    assert d._selector_decision_counters["cover_traffic_off"] == 1


def test_record_updates_batch_decision_counter() -> None:
    d = _bare_daemon()
    for kind in ("emit_now", "batch", "urgent_bypass"):
        decision = dict(_FULL_DECISION)
        decision["batch_decision"] = kind
        d._record_selector_decision_counters(decision)
    counters = d._selector_decision_counters["batch_decision"]
    assert counters["emit_now"] == 1
    assert counters["batch"] == 1
    assert counters["urgent_bypass"] == 1


def test_record_updates_anchor_predictor_counters() -> None:
    d = _bare_daemon()
    d._record_selector_decision_counters(
        dict(_FULL_DECISION, anchor_lay=True, predictor_warm=False),
    )
    d._record_selector_decision_counters(
        dict(_FULL_DECISION, anchor_lay=False, predictor_warm=True),
    )
    c = d._selector_decision_counters
    assert c["anchor_lay_on"] == 1
    assert c["anchor_lay_off"] == 1
    assert c["predictor_warm_on"] == 1
    assert c["predictor_warm_off"] == 1


def test_record_violation_increments_violation_counter() -> None:
    d = _bare_daemon()
    d._record_selector_decision_counters(
        dict(_FULL_DECISION), had_violation=True,
    )
    assert d._selector_decision_counters["f4_violations"] == 1
    # Other counters still updated.
    assert d._selector_decision_counters["total"] == 1


# ---------- defensive against malformed decisions ----------


def test_record_skips_non_dict() -> None:
    d = _bare_daemon()
    d._record_selector_decision_counters(None)  # type: ignore[arg-type]
    d._record_selector_decision_counters("not-a-dict")  # type: ignore[arg-type]
    d._record_selector_decision_counters(42)  # type: ignore[arg-type]
    assert d._selector_decision_counters["total"] == 0


def test_record_tolerates_missing_fields() -> None:
    d = _bare_daemon()
    # Only one field set.
    d._record_selector_decision_counters({"transport": "quic_stream"})
    assert d._selector_decision_counters["total"] == 1
    assert d._selector_decision_counters["transport"]["quic_stream"] == 1
    # Missing fields default to off counters where applicable.
    assert d._selector_decision_counters["cover_traffic_off"] == 1
    assert d._selector_decision_counters["cover_traffic_on"] == 0


def test_record_tolerates_unknown_transport_value() -> None:
    d = _bare_daemon()
    d._record_selector_decision_counters({"transport": "made_up_transport"})
    # total still incremented; known-transport counter unaffected.
    assert d._selector_decision_counters["total"] == 1
    assert d._selector_decision_counters["transport"]["quic_stream"] == 0


def test_record_tolerates_unknown_onion_hops() -> None:
    d = _bare_daemon()
    d._record_selector_decision_counters({"onion_hops": 99})  # unknown
    d._record_selector_decision_counters({"onion_hops": "three"})  # not int
    # No 1/3/5 increment.
    assert sum(d._selector_decision_counters["onion_hops"].values()) == 0
    assert d._selector_decision_counters["total"] == 2


# ---------- selector_decision_stats ----------


def test_stats_returns_fresh_dict() -> None:
    d = _bare_daemon()
    d._record_selector_decision_counters(dict(_FULL_DECISION))
    s1 = d.selector_decision_stats()
    s2 = d.selector_decision_stats()
    # Mutating one doesn't affect the other (deep-copy of nested dicts).
    s1["total"] = 999
    assert s2["total"] == 1


def test_stats_includes_derived_ratios() -> None:
    d = _bare_daemon()
    # 3 cover-on + 1 cover-off + 0 violations.
    for _ in range(3):
        d._record_selector_decision_counters(
            dict(_FULL_DECISION, cover_traffic=True),
        )
    d._record_selector_decision_counters(
        dict(_FULL_DECISION, cover_traffic=False),
    )
    stats = d.selector_decision_stats()
    assert stats["total"] == 4
    assert stats["cover_traffic_on"] == 3
    assert stats["cover_ratio"] == 0.75
    assert stats["f4_violation_ratio"] == 0.0


def test_stats_violation_ratio() -> None:
    d = _bare_daemon()
    d._record_selector_decision_counters(
        dict(_FULL_DECISION), had_violation=True,
    )
    d._record_selector_decision_counters(
        dict(_FULL_DECISION), had_violation=False,
    )
    stats = d.selector_decision_stats()
    assert stats["f4_violation_ratio"] == 0.5


def test_stats_zero_total_no_division_error() -> None:
    d = _bare_daemon()
    stats = d.selector_decision_stats()
    assert stats["total"] == 0
    assert stats["cover_ratio"] == 0.0
    assert stats["f4_violation_ratio"] == 0.0


def test_stats_shape_complete() -> None:
    d = _bare_daemon()
    d._record_selector_decision_counters(dict(_FULL_DECISION))
    stats = d.selector_decision_stats()
    expected_keys = {
        "total", "transport", "path", "onion_hops",
        "cover_traffic_on", "cover_traffic_off",
        "batch_decision", "anchor_lay_on", "anchor_lay_off",
        "predictor_warm_on", "predictor_warm_off",
        "f4_violations", "cover_ratio", "f4_violation_ratio",
    }
    assert set(stats.keys()) >= expected_keys
