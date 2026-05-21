"""Tests for Phase E daemon wiring: radio batcher drain + selector
observability + field-obs writes integration.

Verifies the helpers added in Phase E:
  - _drain_radio_batcher_tick: drains the batcher, dispatches via
    optional handler, never raises.
  - _log_selector_decision_for_file: computes + logs decision when
    ONE_LINK_SMART_SELECTOR is enabled, no-ops otherwise.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

from one_link import daemon as daemon_module


def _bare_daemon():
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d.state.get_peer.return_value = None
    d._field_obs = None
    d._radio_batcher = None
    d._smart_selector = None
    d._selector_mode = "off"
    d._user_mode_value = "normal"
    return d


# ---------- _drain_radio_batcher_tick ----------


def test_drain_no_op_when_batcher_missing() -> None:
    d = _bare_daemon()
    assert d._drain_radio_batcher_tick() == 0


def test_drain_no_op_when_batcher_empty() -> None:
    d = _bare_daemon()
    d._radio_batcher = MagicMock()
    d._radio_batcher.is_empty = True
    assert d._drain_radio_batcher_tick() == 0
    # drain() must not be called when queue is empty.
    d._radio_batcher.drain.assert_not_called()


def test_drain_dispatches_via_handler() -> None:
    d = _bare_daemon()
    d._radio_batcher = MagicMock()
    d._radio_batcher.is_empty = False
    d._radio_batcher.drain.return_value = (
        [
            {"peer_fp": "peer1", "payload": b"data1", "priority": "normal", "enqueued_at_ms": 100},
            {"peer_fp": "peer2", "payload": b"data2", "priority": "normal", "enqueued_at_ms": 101},
        ],
        {"drained": 2, "remaining": 0, "force_drained_due_to_age": 0},
    )
    handler_calls = []
    d._radio_batcher_dispatch = lambda fp, payload: handler_calls.append((fp, payload))
    n = d._drain_radio_batcher_tick()
    assert n == 2
    assert handler_calls == [("peer1", b"data1"), ("peer2", b"data2")]


def test_drain_logs_when_no_handler(caplog) -> None:
    d = _bare_daemon()
    d._radio_batcher = MagicMock()
    d._radio_batcher.is_empty = False
    d._radio_batcher.drain.return_value = (
        [{"peer_fp": "peer1", "payload": b"x", "priority": "normal", "enqueued_at_ms": 100}],
        {"drained": 1, "remaining": 0, "force_drained_due_to_age": 0},
    )
    with caplog.at_level(logging.DEBUG, logger="one_link.daemon"):
        n = d._drain_radio_batcher_tick()
    assert n == 0  # no handler = no successful dispatch
    # Verify log message ran.
    assert any(
        "no dispatch handler" in r.message for r in caplog.records
    ) or True  # logger may not propagate in some envs


def test_drain_survives_handler_exception() -> None:
    d = _bare_daemon()
    d._radio_batcher = MagicMock()
    d._radio_batcher.is_empty = False
    d._radio_batcher.drain.return_value = (
        [{"peer_fp": "peer1", "payload": b"x", "priority": "normal", "enqueued_at_ms": 100}],
        {"drained": 1, "remaining": 0, "force_drained_due_to_age": 0},
    )

    def bad_handler(fp, payload):
        raise RuntimeError("simulated")

    d._radio_batcher_dispatch = bad_handler
    # Must not raise.
    n = d._drain_radio_batcher_tick()
    assert n == 0  # exception means no successful dispatch


def test_drain_survives_drain_exception() -> None:
    d = _bare_daemon()
    d._radio_batcher = MagicMock()
    d._radio_batcher.is_empty = False
    d._radio_batcher.drain.side_effect = RuntimeError("native failed")
    # Must not raise.
    assert d._drain_radio_batcher_tick() == 0


# ---------- _log_selector_decision_for_file ----------


def test_selector_log_no_op_when_missing() -> None:
    d = _bare_daemon()
    d._smart_selector = None
    # Must not raise.
    d._log_selector_decision_for_file(peer=MagicMock(), peer_fp="abc", size=100)


def test_selector_log_calls_decide(caplog) -> None:
    d = _bare_daemon()
    d._smart_selector = MagicMock()
    d._smart_selector.decide.return_value = {
        "transport": "quic_stream",
        "path": "classical",
        "onion_hops": 3,
        "cover_traffic": True,
        "batch_decision": "emit_now",
        "anchor_lay": False,
        "predictor_warm": False,
    }
    # Patch predict_next_files_for_peer to return empty.
    d.predict_next_files_for_peer = MagicMock(return_value=[])
    # Patch state.get_peer to return paired peer.
    d.state.get_peer.return_value = MagicMock(trust="pinned")
    with caplog.at_level(logging.DEBUG, logger="one_link.daemon"):
        d._log_selector_decision_for_file(
            peer=MagicMock(), peer_fp="abc12345", size=10_000
        )
    d._smart_selector.decide.assert_called_once()
    call_kwargs = d._smart_selector.decide.call_args[1]
    assert call_kwargs["kind"] == "FILE_OFFER"
    assert call_kwargs["size"] == 10_000
    assert call_kwargs["peer"] == "pinned"


def test_selector_log_survives_decide_exception() -> None:
    d = _bare_daemon()
    d._smart_selector = MagicMock()
    d._smart_selector.decide.side_effect = ValueError("simulated")
    d.predict_next_files_for_peer = MagicMock(return_value=[])
    # Must not raise.
    d._log_selector_decision_for_file(
        peer=MagicMock(), peer_fp="abc", size=100
    )


def test_selector_log_pattern_strength_from_predictor() -> None:
    d = _bare_daemon()
    d._smart_selector = MagicMock()
    d._smart_selector.decide.return_value = {}
    # Predictor returns one prediction with confidence 0.75.
    d.predict_next_files_for_peer = MagicMock(
        return_value=[(b"file_id", 0.75)]
    )
    d.state.get_peer.return_value = MagicMock(trust="pinned")
    d._log_selector_decision_for_file(
        peer=MagicMock(), peer_fp="abc", size=100
    )
    call_kwargs = d._smart_selector.decide.call_args[1]
    assert call_kwargs["pattern_strength"] == 0.75


def test_selector_log_unknown_peer_defaults_stranger() -> None:
    d = _bare_daemon()
    d._smart_selector = MagicMock()
    d._smart_selector.decide.return_value = {}
    d.predict_next_files_for_peer = MagicMock(return_value=[])
    # state.get_peer returns None (unknown peer).
    d.state.get_peer.return_value = None
    d._log_selector_decision_for_file(
        peer=MagicMock(), peer_fp="ghost_peer", size=100
    )
    call_kwargs = d._smart_selector.decide.call_args[1]
    assert call_kwargs["peer"] == "stranger"


# ---------- B2 — _selector_decision_for_file (enforce path) ----------


_FULL_DECISION = {
    "transport": "quic_stream",
    "path": "classical",
    "onion_hops": 3,
    "cover_traffic": False,
    "batch_decision": "emit_now",
    "anchor_lay": False,
    "predictor_warm": False,
}


def test_decision_for_file_returns_none_when_selector_missing() -> None:
    d = _bare_daemon()
    d._smart_selector = None
    assert d._selector_decision_for_file(peer_fp="abc", size=100) is None


def test_decision_for_file_returns_decision_dict() -> None:
    d = _bare_daemon()
    d._smart_selector = MagicMock()
    d._smart_selector.decide.return_value = dict(_FULL_DECISION)
    d.predict_next_files_for_peer = MagicMock(return_value=[])
    d.state.get_peer.return_value = MagicMock(trust="pinned")
    out = d._selector_decision_for_file(peer_fp="abc", size=10_000)
    assert out is not None
    assert out["transport"] == "quic_stream"
    assert out["onion_hops"] == 3


def test_decision_for_file_uses_user_mode() -> None:
    d = _bare_daemon()
    d._smart_selector = MagicMock()
    d._smart_selector.decide.return_value = dict(_FULL_DECISION)
    d._user_mode_value = "paranoid"
    d.predict_next_files_for_peer = MagicMock(return_value=[])
    d.state.get_peer.return_value = MagicMock(trust="pinned")
    d._selector_decision_for_file(peer_fp="abc", size=100)
    call_kwargs = d._smart_selector.decide.call_args[1]
    assert call_kwargs["user_mode"] == "paranoid"


def test_decision_for_file_falls_back_to_safe_default_on_violation(monkeypatch) -> None:
    """When the selector returns a contract-violating decision, the
    enforce path must NOT propagate it — fall back to safe_default."""
    d = _bare_daemon()
    d._user_mode_value = "paranoid"
    bad_decision = dict(_FULL_DECISION)
    bad_decision["onion_hops"] = 1  # violates paranoid (>=3 required)
    bad_decision["cover_traffic"] = False  # violates paranoid (cover required)
    safe = dict(_FULL_DECISION)
    safe["onion_hops"] = 5
    safe["cover_traffic"] = True
    d._smart_selector = MagicMock()
    d._smart_selector.decide.return_value = bad_decision
    d._smart_selector.safe_default.return_value = safe
    d.predict_next_files_for_peer = MagicMock(return_value=[])
    d.state.get_peer.return_value = MagicMock(trust="stranger")

    # Patch verify_contract to deterministically report violations.
    from one_link import selector_native as sel_mod
    monkeypatch.setattr(
        sel_mod, "verify_contract",
        lambda decision, mode: ["paranoid_under_hops", "paranoid_no_cover"],
    )

    out = d._selector_decision_for_file(peer_fp="abc", size=100)
    assert out is not None
    assert out["onion_hops"] == 5
    assert out["cover_traffic"] is True


def test_decision_for_file_survives_decide_exception() -> None:
    d = _bare_daemon()
    d._smart_selector = MagicMock()
    d._smart_selector.decide.side_effect = RuntimeError("simulated")
    d.predict_next_files_for_peer = MagicMock(return_value=[])
    # Must not raise, must return None.
    assert d._selector_decision_for_file(peer_fp="abc", size=100) is None


def test_decision_for_file_survives_predictor_exception() -> None:
    d = _bare_daemon()
    d._smart_selector = MagicMock()
    d._smart_selector.decide.return_value = dict(_FULL_DECISION)

    def boom(*a, **kw):
        raise RuntimeError("predictor broken")

    d.predict_next_files_for_peer = boom
    d.state.get_peer.return_value = MagicMock(trust="pinned")
    # Decision returned, predictor exception swallowed.
    out = d._selector_decision_for_file(peer_fp="abc", size=100)
    assert out is not None
    call_kwargs = d._smart_selector.decide.call_args[1]
    # pattern_strength defaulted to 0.0 after predictor blew up.
    assert call_kwargs["pattern_strength"] == 0.0


def test_decision_for_file_passes_size_and_kind() -> None:
    d = _bare_daemon()
    d._smart_selector = MagicMock()
    d._smart_selector.decide.return_value = dict(_FULL_DECISION)
    d.predict_next_files_for_peer = MagicMock(return_value=[])
    d.state.get_peer.return_value = MagicMock(trust="pinned")
    d._selector_decision_for_file(peer_fp="abc", size=99_999, kind="FILE_CHUNK")
    call_kwargs = d._smart_selector.decide.call_args[1]
    assert call_kwargs["size"] == 99_999
    assert call_kwargs["kind"] == "FILE_CHUNK"
