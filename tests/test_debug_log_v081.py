"""v0.8.1 developer-backend (debug log + health check) tests.

Pin the contract:
  - DebugLog ring buffer respects capacity, threadsafe, monotonic ids.
  - tail() filters by since_id / severity / source.
  - record_exception() captures traceback and uses _default_suggestion
    to fill in human-friendly hints for common cases.
  - clear() drops everything.
  - /api/debug/log surfaces entries; ?since_id=N gives incremental.
  - /api/debug/log/clear flushes.
  - /api/debug/health returns structured pass/fail per check.
  - HTML structural pin: pane + buttons + filter dropdown.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from one_link.debug_log import DebugLog, _default_suggestion, get_debug_log
from one_link.state import State


# ─── DebugLog primitive ───────────────────────────────────────────

def test_record_assigns_monotonic_ids():
    log = DebugLog(capacity=10)
    e1 = log.record(source="a", code="x", message="m1")
    e2 = log.record(source="a", code="x", message="m2")
    assert e2["id"] == e1["id"] + 1


def test_record_clamps_severity():
    log = DebugLog()
    e = log.record(severity="catastrophic", source="a", code="x", message="m")
    assert e["severity"] == "error"


def test_capacity_drops_oldest():
    log = DebugLog(capacity=3)
    for i in range(5):
        log.record(source="a", code="x", message=f"m{i}")
    assert len(log) == 3
    tail = log.tail(limit=10)
    msgs = [e["message"] for e in tail]
    # newest-first
    assert msgs[0] == "m4"
    assert msgs[-1] == "m2"
    # m0 + m1 evicted
    assert "m0" not in msgs and "m1" not in msgs


def test_tail_filters_by_severity():
    log = DebugLog()
    log.record(severity="info", source="a", code="x", message="info1")
    log.record(severity="error", source="a", code="x", message="err1")
    log.record(severity="warn", source="a", code="x", message="warn1")
    only_err = log.tail(severity={"error"})
    assert len(only_err) == 1
    assert only_err[0]["message"] == "err1"


def test_tail_filters_by_source():
    log = DebugLog()
    log.record(source="send_file", code="x", message="a")
    log.record(source="create_group", code="x", message="b")
    only_send = log.tail(sources={"send_file"})
    assert len(only_send) == 1
    assert only_send[0]["source"] == "send_file"


def test_tail_since_id_skips_older():
    log = DebugLog()
    e1 = log.record(source="a", code="x", message="m1")
    log.record(source="a", code="x", message="m2")
    e3 = log.record(source="a", code="x", message="m3")
    after_e1 = log.tail(since_id=e1["id"])
    msgs = {e["message"] for e in after_e1}
    assert msgs == {"m2", "m3"}


def test_clear_drops_all():
    log = DebugLog()
    log.record(source="a", code="x", message="m1")
    log.record(source="a", code="x", message="m2")
    n = log.clear()
    assert n == 2
    assert len(log) == 0


def test_record_exception_captures_traceback():
    log = DebugLog()
    try:
        raise ValueError("boom")
    except ValueError as e:
        entry = log.record_exception(e, source="test")
    assert entry["code"] == "ValueError"
    assert "boom" in entry["message"]
    assert "Traceback" in (entry["traceback"] or "")


def test_record_exception_fills_default_suggestion():
    log = DebugLog()
    try:
        raise RuntimeError("file send to abc: handshake timed out")
    except RuntimeError as e:
        entry = log.record_exception(e, source="send_file")
    assert "Make sure" in entry["suggestion"] or "answering" in entry["suggestion"]


def test_attach_broadcast_called_on_record():
    log = DebugLog()
    seen: list[dict] = []
    log.attach_broadcast(lambda e: seen.append(e))
    log.record(source="x", code="c", message="m")
    assert len(seen) == 1
    assert seen[0]["message"] == "m"


def test_attach_broadcast_swallows_callback_errors():
    """If the broadcast callback raises, it should NOT prevent the
    entry from being added to the buffer."""
    log = DebugLog()
    def boom(_): raise RuntimeError("WS dead")
    log.attach_broadcast(boom)
    e = log.record(source="x", code="c", message="m")
    assert e["id"] >= 1
    assert len(log) == 1


# ─── _default_suggestion mapping ──────────────────────────────────

def test_default_suggestion_handshake():
    s = _default_suggestion(RuntimeError("handshake timed out after 8s"))
    assert "answering" in s.lower() or "responsive" in s.lower() or "Make sure" in s


def test_default_suggestion_capability():
    s = _default_suggestion(RuntimeError("files capability disabled for peer"))
    assert "policy" in s.lower() or "drawer" in s.lower()


def test_default_suggestion_404():
    s = _default_suggestion(RuntimeError("request failed (404) on /api/groups"))
    # The exact wording is allowed to evolve; what matters is that
    # the suggestion mentions reloading / restarting / refreshing.
    s_lower = s.lower()
    assert any(
        w in s_lower
        for w in ("restart", "reopen", "refresh", "endpoints", "close")
    ), f"404 suggestion didn't tell the user to reload: {s!r}"


def test_default_suggestion_unknown_returns_empty():
    s = _default_suggestion(RuntimeError("something really unusual"))
    assert s == ""


# ─── /api/debug/log endpoint ──────────────────────────────────────

@pytest.mark.asyncio
async def test_api_debug_log_returns_recent_entries(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(
        state=state,
        me=SimpleNamespace(fingerprint="me", short_id="me", hostname="me"),
    )
    log = get_debug_log()
    log.clear()
    log.record(source="test", code="t1", message="hello")
    log.record(source="test", code="t2", message="world")

    server = UIServer(daemon)

    class _Req:
        query: dict = {}

    resp = await server.api_debug_log(_Req())
    body = json.loads(resp.text)
    assert len(body["entries"]) == 2
    # newest-first
    assert body["entries"][0]["message"] == "world"
    state.close()


@pytest.mark.asyncio
async def test_api_debug_log_clear(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(
        state=state,
        me=SimpleNamespace(fingerprint="me", short_id="me", hostname="me"),
    )
    log = get_debug_log()
    log.clear()
    log.record(source="t", code="x", message="m")
    server = UIServer(daemon)

    class _Req:
        pass

    resp = await server.api_debug_clear(_Req())
    body = json.loads(resp.text)
    assert body["ok"] is True
    assert len(log) == 0
    state.close()


# ─── /api/debug/health endpoint ───────────────────────────────────

@pytest.mark.asyncio
async def test_api_debug_health_runs_checks(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(
        state=state,
        discovery=None,
        me=SimpleNamespace(fingerprint="me", short_id="me", hostname="me"),
        _outbound_sessions={},
        _peer_server=None,
        _rendezvous_peer_port=0,
    )
    server = UIServer(daemon)

    class _Req:
        pass

    resp = await server.api_debug_health(_Req())
    body = json.loads(resp.text)
    # Must include version + a list of checks.
    assert "version" in body
    assert "checks" in body
    names = {c["name"] for c in body["checks"]}
    # Every category we promised.
    for must_have in (
        "state_db", "discovery", "peer_server",
        "outbound_sessions", "outbox", "paused_transfers",
    ):
        assert must_have in names, f"health check missing: {must_have}"
    state.close()


# ─── HTML structural pin ──────────────────────────────────────────

def test_index_html_has_debug_pane():
    p = (
        Path(__file__).resolve().parent.parent
        / "src" / "one_link" / "web" / "index.html"
    )
    text = p.read_text(encoding="utf-8")
    for needle in [
        'id="debug-panel"',
        'id="btn-debug"',
        'data-pane="debug"',
        'id="btn-debug-health"',
        'id="btn-debug-clear"',
        'id="debug-severity"',
        'id="debug-log-list"',
        'id="debug-health-result"',
        'id="debug-error-count"',
        "function refreshDebugLog",
        "function renderDebugLog",
        '"debug_event"',
        ".debug-row",
        ".debug-fix",
        ".debug-health-row",
    ]:
        assert needle in text, f"index.html missing {needle!r}"
