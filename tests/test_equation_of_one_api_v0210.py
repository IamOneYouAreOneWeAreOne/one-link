"""Tests for the ``/api/v1/equation-of-one/stats`` operator dashboard.

Verifies that:
  - The endpoint aggregates every equation-of-ONE subsystem's stats
  - Each subsystem's snapshot is well-formed (correct keys present)
  - A failure in any single subsystem doesn't take down the whole
    response — the failing subsystem reports ``{"error": ...}`` and
    the rest of the dashboard still renders.
  - The user_mode is included for context.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from one_link.server import UIServer


class _Req:
    """Minimal request stand-in (the handler doesn't read anything)."""


def _daemon_with_full_stats():
    d = SimpleNamespace()
    d._user_mode_value = "paranoid"
    d.selector_info = lambda: {
        "kind": "online_learner",
        "available": True,
        "enforce": True,
        "mode": "1",
        "has_observe": True,
    }
    d.selector_decision_stats = lambda: {
        "total": 42,
        "transport": {"quic_stream": 30, "relay": 12},
        "path": {"classical": 42, "coherence": 0},
        "onion_hops": {1: 0, 3: 5, 5: 37},
        "cover_traffic_on": 42,
        "cover_traffic_off": 0,
        "batch_decision": {"emit_now": 42, "batch": 0, "urgent_bypass": 0},
        "anchor_lay_on": 5,
        "anchor_lay_off": 37,
        "predictor_warm_on": 3,
        "predictor_warm_off": 39,
        "f4_violations": 0,
        "cover_ratio": 1.0,
        "f4_violation_ratio": 0.0,
    }
    d.cover_traffic_stats = lambda: {
        "available": True,
        "user_mode": "paranoid",
        "env_gate": False,
        "effective_enabled": True,
        "running": True,
        "emitted": 18,
        "errors": 0,
        "mandated_by_mode": True,
        "forbidden_by_mode": False,
        "rate_hz": 0.5,
    }
    d.dedupe_sites_stats = lambda: {
        "entries": 7,
        "records": 12,
        "hits": 4,
        "misses": 2,
        "evicted_for_cap": 0,
        "evicted_for_peer": 1,
        "ttl_ms": 300000,
        "max_entries": 32768,
    }
    d.fuse_capabilities = lambda: {
        "platform": "windows_unsupported",
        "ready": False,
        "message": "Windows requires WinFSP.",
        "native_loaded": True,
    }
    return d


def _daemon_with_readiness():
    d = _daemon_with_full_stats()
    d._radio_batcher = object()
    d._radio_batcher_enabled = False
    d._call_registry = object()
    d.wave_forecast_stats = lambda: {
        "available": True,
        "enabled": False,
        "steps": 0,
        "warnings": 0,
    }
    d.adaptive_transport_stats = lambda: {
        "capability_fail_open_count": 0,
        "discovery_interval_s": 20,
    }
    d.selector_regret_ewma_stats = lambda: {
        "normal": 0.0,
        "paranoid": 0.0,
        "battery_save": 0.0,
        "latency_strict": 0.0,
    }
    d.capability_denial_stats = lambda: {"total": 0}
    d.alignment_trust_histogram = lambda: {"total": 0}
    d.cascade_warning_stats = lambda: {"count": 0}
    return d


# ---------- happy path ----------


@pytest.mark.asyncio
async def test_endpoint_returns_all_subsystems() -> None:
    d = _daemon_with_full_stats()
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_equation_of_one_stats(_Req())
    body = json.loads(resp.text)
    assert "selector" in body
    assert "cover_traffic" in body
    assert "dedupe_sites" in body
    assert "fuse" in body
    assert body["user_mode"] == "paranoid"


@pytest.mark.asyncio
async def test_selector_envelope_includes_kind_and_decisions() -> None:
    d = _daemon_with_full_stats()
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_equation_of_one_stats(_Req())
    body = json.loads(resp.text)
    sel = body["selector"]
    assert sel["kind"] == "online_learner"
    assert sel["available"] is True
    assert sel["enforce"] is True
    assert sel["has_observe"] is True
    # decision-distribution counters embedded
    assert sel["decisions"]["total"] == 42
    assert sel["decisions"]["cover_ratio"] == 1.0
    # JSON serialization converts int dict keys to strings.
    assert sel["decisions"]["onion_hops"]["5"] == 37


@pytest.mark.asyncio
async def test_cover_traffic_envelope_shape() -> None:
    d = _daemon_with_full_stats()
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_equation_of_one_stats(_Req())
    body = json.loads(resp.text)
    ct = body["cover_traffic"]
    for key in (
        "available", "user_mode", "env_gate", "effective_enabled",
        "running", "emitted", "errors", "mandated_by_mode",
        "forbidden_by_mode",
    ):
        assert key in ct


@pytest.mark.asyncio
async def test_dedupe_sites_envelope_shape() -> None:
    d = _daemon_with_full_stats()
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_equation_of_one_stats(_Req())
    body = json.loads(resp.text)
    ds = body["dedupe_sites"]
    for key in ("entries", "records", "hits", "misses", "ttl_ms"):
        assert key in ds


@pytest.mark.asyncio
async def test_fuse_envelope_shape() -> None:
    d = _daemon_with_full_stats()
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_equation_of_one_stats(_Req())
    body = json.loads(resp.text)
    fuse = body["fuse"]
    for key in ("platform", "ready", "message", "native_loaded"):
        assert key in fuse


# ---------- per-subsystem failure isolation ----------


@pytest.mark.asyncio
async def test_selector_subsystem_failure_doesnt_break_rest() -> None:
    d = _daemon_with_full_stats()
    d.selector_info = MagicMock(side_effect=RuntimeError("simulated"))
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_equation_of_one_stats(_Req())
    body = json.loads(resp.text)
    assert "error" in body["selector"]
    # Other subsystems still rendered.
    assert body["cover_traffic"]["available"] is True
    assert body["dedupe_sites"]["entries"] == 7
    assert body["fuse"]["platform"] == "windows_unsupported"


@pytest.mark.asyncio
async def test_cover_traffic_failure_isolated() -> None:
    d = _daemon_with_full_stats()
    d.cover_traffic_stats = MagicMock(side_effect=RuntimeError("simulated"))
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_equation_of_one_stats(_Req())
    body = json.loads(resp.text)
    assert "error" in body["cover_traffic"]
    assert "decisions" in body["selector"]


@pytest.mark.asyncio
async def test_dedupe_failure_isolated() -> None:
    d = _daemon_with_full_stats()
    d.dedupe_sites_stats = MagicMock(side_effect=RuntimeError("simulated"))
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_equation_of_one_stats(_Req())
    body = json.loads(resp.text)
    assert "error" in body["dedupe_sites"]


@pytest.mark.asyncio
async def test_fuse_failure_isolated() -> None:
    d = _daemon_with_full_stats()
    d.fuse_capabilities = MagicMock(side_effect=RuntimeError("simulated"))
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_equation_of_one_stats(_Req())
    body = json.loads(resp.text)
    assert "error" in body["fuse"]


# ---------- defaults / missing data ----------


@pytest.mark.asyncio
async def test_user_mode_defaults_to_normal() -> None:
    d = SimpleNamespace()
    # No _user_mode_value set.
    d.selector_info = lambda: {}
    d.selector_decision_stats = lambda: {}
    d.cover_traffic_stats = lambda: {}
    d.dedupe_sites_stats = lambda: {}
    d.fuse_capabilities = lambda: {}
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_equation_of_one_stats(_Req())
    body = json.loads(resp.text)
    assert body["user_mode"] == "normal"


@pytest.mark.asyncio
async def test_endpoint_returns_200_ok() -> None:
    d = _daemon_with_full_stats()
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_equation_of_one_stats(_Req())
    assert resp.status == 200


@pytest.mark.asyncio
async def test_endpoint_content_type_json() -> None:
    d = _daemon_with_full_stats()
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_equation_of_one_stats(_Req())
    assert "application/json" in resp.content_type


# ---------- integration readiness ----------


@pytest.mark.asyncio
async def test_integration_readiness_reports_gated_ready_state() -> None:
    d = _daemon_with_readiness()
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_integration_readiness(_Req())
    body = json.loads(resp.text)
    assert body["ok"] is True
    assert body["status"] == "ready_gated"
    assert body["score"] >= 80
    keys = {c["key"] for c in body["checks"]}
    for key in (
        "selector",
        "selector_decisions",
        "cover_traffic",
        "radio_batcher",
        "wave_forecast",
        "dedupe_sites",
        "adaptive_transport",
        "call_trace",
    ):
        assert key in keys
    radio = next(c for c in body["checks"] if c["key"] == "radio_batcher")
    assert radio["state"] == "gated"
    assert body["promotion"]["selector_enforce"] is True


@pytest.mark.asyncio
async def test_integration_readiness_blocks_when_required_selector_missing() -> None:
    d = _daemon_with_readiness()
    d.selector_info = MagicMock(side_effect=RuntimeError("simulated"))
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_integration_readiness(_Req())
    body = json.loads(resp.text)
    assert body["ok"] is False
    assert body["status"] == "blocked"
    selector = next(c for c in body["checks"] if c["key"] == "selector")
    assert selector["state"] == "error"


def test_integration_readiness_route_registered() -> None:
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    assert '"/api/v1/integration/readiness"' in src
    assert "api_integration_readiness" in src
