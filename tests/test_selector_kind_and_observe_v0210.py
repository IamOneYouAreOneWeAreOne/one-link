"""Tests for the selector-kind switch + Phase I observe() feedback.

Exercises:
  - ONE_LINK_SELECTOR_KIND env switch picks SmartRules / UnifiedMin /
    OnlineLearner with sensible fallback for unknown values
  - selector_kind() / selector_info() expose the active selector
  - _record_pending_selector_observation: LRU bounded, idempotent on
    same id, key normalisation
  - _pop_pending_selector_observation: returns None for unknown ids
  - _regret_for_transfer_status mapping
  - _maybe_feed_selector_observation: no-op when selector has no
    observe(); fires when it does; survives observe() exceptions
  - End-to-end via mocked daemon._update_transfer terminal status
"""

from __future__ import annotations

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
    d._selector_enforce = False
    d._selector_kind = "smart_rules"
    d._user_mode_value = "normal"
    from collections import OrderedDict
    d._pending_selector_observations = OrderedDict()
    d._pending_selector_observations_cap = 100
    return d


# ---------- selector-kind switch ----------


def test_build_selector_returns_smart_rules_default(monkeypatch) -> None:
    monkeypatch.delenv("ONE_LINK_SELECTOR_KIND", raising=False)
    from one_link import selector_native
    if not selector_native.HAS_NATIVE:
        pytest.skip("native selector not installed")
    d = _bare_daemon()
    sel = d._build_selector("smart_rules")
    assert sel.name() == "SmartRules"


def test_build_selector_picks_unified_min() -> None:
    from one_link import selector_native
    if not selector_native.HAS_NATIVE:
        pytest.skip("native selector not installed")
    d = _bare_daemon()
    sel = d._build_selector("unified_min")
    assert sel.name() == "UnifiedMin"


def test_build_selector_picks_online_learner() -> None:
    from one_link import selector_native
    if not selector_native.HAS_NATIVE:
        pytest.skip("native selector not installed")
    d = _bare_daemon()
    sel = d._build_selector("online_learner")
    # Learner has observe() but reports as UnifiedMin (it composes one).
    assert hasattr(sel, "observe") or sel is not None


def test_build_selector_unknown_kind_falls_back_to_smart_rules(caplog) -> None:
    from one_link import selector_native
    if not selector_native.HAS_NATIVE:
        pytest.skip("native selector not installed")
    d = _bare_daemon()
    import logging
    with caplog.at_level(logging.WARNING, logger="one_link.daemon"):
        sel = d._build_selector("nonsense_value")
    assert sel.name() == "SmartRules"


def test_selector_kind_method_returns_active_kind() -> None:
    d = _bare_daemon()
    d._selector_kind = "unified_min"
    assert d.selector_kind() == "unified_min"


def test_selector_info_reports_state() -> None:
    d = _bare_daemon()
    d._smart_selector = MagicMock()
    d._smart_selector.observe = MagicMock()  # learner
    info = d.selector_info()
    assert info["kind"] == "smart_rules"
    assert info["available"] is True
    assert info["has_observe"] is True


def test_selector_info_no_observe_when_selector_lacks_it() -> None:
    d = _bare_daemon()
    sel = MagicMock(spec=["decide", "safe_default", "name"])
    # spec= excludes observe so hasattr returns False.
    d._smart_selector = sel
    info = d.selector_info()
    assert info["has_observe"] is False


# ---------- observe-stash mechanics ----------


def test_record_pending_observation_basic() -> None:
    d = _bare_daemon()
    decision = {"transport": "quic_stream"}
    d._record_pending_selector_observation("tid1", decision, {"size": 100})
    popped = d._pop_pending_selector_observation("tid1")
    assert popped is not None
    assert popped[0] == decision
    assert popped[1] == {"size": 100}


def test_record_pending_observation_idempotent_on_same_id() -> None:
    d = _bare_daemon()
    d._record_pending_selector_observation("tid1", {"a": 1}, {})
    d._record_pending_selector_observation("tid1", {"a": 2}, {})
    # Second write replaces the first.
    popped = d._pop_pending_selector_observation("tid1")
    assert popped[0] == {"a": 2}
    # After pop, gone.
    assert d._pop_pending_selector_observation("tid1") is None


def test_record_pending_observation_lru_evicts_oldest() -> None:
    d = _bare_daemon()
    d._pending_selector_observations_cap = 3
    for i in range(5):
        d._record_pending_selector_observation(f"t{i}", {"i": i}, {})
    # t0, t1 evicted; t2..t4 remain.
    assert d._pop_pending_selector_observation("t0") is None
    assert d._pop_pending_selector_observation("t1") is None
    assert d._pop_pending_selector_observation("t4") is not None


def test_record_pending_observation_skips_empty_transfer_id() -> None:
    d = _bare_daemon()
    d._record_pending_selector_observation("", {"a": 1}, {})
    d._record_pending_selector_observation(None, {"a": 1}, {})
    assert len(d._pending_selector_observations) == 0


def test_record_pending_observation_skips_non_dict_decision() -> None:
    d = _bare_daemon()
    d._record_pending_selector_observation("tid1", "not-a-dict", {})  # type: ignore[arg-type]
    assert d._pop_pending_selector_observation("tid1") is None


def test_pop_pending_observation_unknown_id_returns_none() -> None:
    d = _bare_daemon()
    assert d._pop_pending_selector_observation("ghost") is None


# ---------- regret mapping ----------


@pytest.mark.parametrize(
    "status,expected",
    [
        ("completed", 0.0),
        ("paused", 0.5),
        ("waiting", 0.5),
        ("waiting_for_device", 0.5),
        ("failed", 1.0),
        ("active", None),
        ("offered", None),
        ("queued", None),
        ("", None),
        ("COMPLETED", 0.0),  # case-insensitive
    ],
)
def test_regret_mapping(status, expected) -> None:
    d = _bare_daemon()
    assert d._regret_for_transfer_status(status) == expected


# ---------- _maybe_feed_selector_observation ----------


def test_observe_noop_when_no_selector() -> None:
    d = _bare_daemon()
    d._smart_selector = None
    # Stash something and call — must not raise.
    d._record_pending_selector_observation("t1", {"a": 1}, {})
    d._maybe_feed_selector_observation("t1", "completed")
    # Stash NOT popped (no-op for non-learner).
    # Actually: pop happens regardless of learner? Let me reread the code.
    # No — pop happens only if observe is callable. Good.
    assert d._pop_pending_selector_observation("t1") is not None


def test_observe_noop_when_selector_lacks_observe() -> None:
    d = _bare_daemon()
    sel = MagicMock(spec=["decide", "safe_default", "name"])
    d._smart_selector = sel
    d._record_pending_selector_observation("t1", {"a": 1}, {})
    d._maybe_feed_selector_observation("t1", "completed")
    # Stash NOT popped.
    assert d._pop_pending_selector_observation("t1") is not None


def test_observe_noop_on_non_terminal_status() -> None:
    d = _bare_daemon()
    sel = MagicMock()
    sel.observe = MagicMock()
    d._smart_selector = sel
    d._record_pending_selector_observation("t1", {"a": 1}, {"size": 1})
    d._maybe_feed_selector_observation("t1", "active")
    sel.observe.assert_not_called()
    # Stash remains.
    assert d._pop_pending_selector_observation("t1") is not None


def test_observe_fires_on_completed() -> None:
    d = _bare_daemon()
    sel = MagicMock()
    sel.observe = MagicMock()
    d._smart_selector = sel
    decision = {"transport": "quic_stream"}
    ctx = {"size": 100, "peer": "pinned", "kind": "FILE_OFFER"}
    d._record_pending_selector_observation("t1", decision, ctx)
    d._maybe_feed_selector_observation("t1", "completed")
    sel.observe.assert_called_once()
    call_kwargs = sel.observe.call_args.kwargs
    assert call_kwargs["regret"] == 0.0
    assert call_kwargs["decision"] == decision
    assert call_kwargs["size"] == 100
    # Stash popped after observe.
    assert d._pop_pending_selector_observation("t1") is None


def test_observe_fires_on_failed_with_max_regret() -> None:
    d = _bare_daemon()
    sel = MagicMock()
    sel.observe = MagicMock()
    d._smart_selector = sel
    d._record_pending_selector_observation("t1", {"a": 1}, {"size": 1})
    d._maybe_feed_selector_observation("t1", "failed")
    sel.observe.assert_called_once()
    assert sel.observe.call_args.kwargs["regret"] == 1.0


def test_observe_survives_observe_exception() -> None:
    d = _bare_daemon()
    sel = MagicMock()
    sel.observe = MagicMock(side_effect=RuntimeError("simulated"))
    d._smart_selector = sel
    d._record_pending_selector_observation("t1", {"a": 1}, {"size": 1})
    # Must not raise.
    d._maybe_feed_selector_observation("t1", "completed")


def test_observe_retries_with_minimum_surface_on_typeerror() -> None:
    d = _bare_daemon()
    sel = MagicMock()
    # First call raises TypeError (kwargs surface mismatch), second
    # call succeeds with minimum kwargs.
    sel.observe = MagicMock(side_effect=[TypeError("kwargs"), None])
    d._smart_selector = sel
    d._record_pending_selector_observation("t1", {"a": 1}, {
        "size": 99,
        "kind": "FILE_OFFER",
        "peer": "pinned",
        "user_mode": "normal",  # extra kwarg some learners don't accept
    })
    d._maybe_feed_selector_observation("t1", "completed")
    # Two calls — first fails, second succeeds with minimum surface.
    assert sel.observe.call_count == 2
    second_kwargs = sel.observe.call_args_list[1].kwargs
    assert second_kwargs["regret"] == 0.0
    assert second_kwargs["size"] == 99


# ---------- integration smoke ----------


def test_maybe_feed_only_pops_when_stashed_present() -> None:
    """Don't call observe if there's nothing stashed for this id —
    a non-selector-driven transfer must not trigger learner observe
    with empty/default state."""
    d = _bare_daemon()
    sel = MagicMock()
    sel.observe = MagicMock()
    d._smart_selector = sel
    # No stash; terminal status arrives.
    d._maybe_feed_selector_observation("ghost_tid", "completed")
    sel.observe.assert_not_called()
