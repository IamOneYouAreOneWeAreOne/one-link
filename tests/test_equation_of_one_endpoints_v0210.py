"""Integration map §6 — Tests for the dedicated user-mode +
coherence-field REST endpoints.

Exercises:
  - GET /api/v1/user-mode returns current mode + valid list
  - POST /api/v1/user-mode accepts canonical labels + 400s on garbage
  - POST /api/v1/user-mode propagates to daemon.set_user_mode
  - GET /api/v1/coherence-field returns per-peer + summary stats
  - GET /api/v1/coherence-field handles missing field_obs gracefully
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from one_link.server import UIServer


class _Req:
    def __init__(self, body=None):
        self._body = body

    async def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


# ---------- GET /api/v1/user-mode ----------


@pytest.mark.asyncio
async def test_get_user_mode_returns_current() -> None:
    d = SimpleNamespace(_user_mode_value="paranoid")
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_get_user_mode(_Req())
    body = json.loads(resp.text)
    assert body["mode"] == "paranoid"
    # Valid list includes all four F4 modes.
    valid = set(body["valid"])
    assert {"normal", "paranoid", "battery_save", "latency_strict"} <= valid


@pytest.mark.asyncio
async def test_get_user_mode_defaults_to_normal() -> None:
    d = SimpleNamespace()  # no _user_mode_value
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_get_user_mode(_Req())
    body = json.loads(resp.text)
    assert body["mode"] == "normal"


@pytest.mark.asyncio
async def test_get_user_mode_survives_attr_error() -> None:
    d = MagicMock()
    type(d)._user_mode_value = property(
        lambda self: (_ for _ in ()).throw(RuntimeError("simulated")),
    )
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_get_user_mode(_Req())
    body = json.loads(resp.text)
    assert body["mode"] == "normal"


# ---------- POST /api/v1/user-mode ----------


@pytest.mark.asyncio
async def test_post_user_mode_canonical_persists() -> None:
    d = MagicMock()
    d.set_user_mode = MagicMock(return_value="paranoid")
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_set_user_mode(_Req({"mode": "paranoid"}))
    body = json.loads(resp.text)
    assert body["ok"] is True
    assert body["mode"] == "paranoid"
    d.set_user_mode.assert_called_once_with("paranoid")


@pytest.mark.asyncio
async def test_post_user_mode_battery_save() -> None:
    d = MagicMock()
    d.set_user_mode = MagicMock(return_value="battery_save")
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_set_user_mode(_Req({"mode": "battery_save"}))
    assert resp.status == 200


@pytest.mark.asyncio
async def test_post_user_mode_invalid_returns_400() -> None:
    d = MagicMock()
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_set_user_mode(_Req({"mode": "bogus_value"}))
    assert resp.status == 400
    body = json.loads(resp.text)
    assert "error" in body
    d.set_user_mode.assert_not_called()


@pytest.mark.asyncio
async def test_post_user_mode_missing_body_returns_400() -> None:
    s = UIServer.__new__(UIServer)
    s.daemon = MagicMock()
    resp = await s.api_set_user_mode(_Req(None))  # raises in json()
    assert resp.status == 400


@pytest.mark.asyncio
async def test_post_user_mode_missing_mode_field_returns_400() -> None:
    s = UIServer.__new__(UIServer)
    s.daemon = MagicMock()
    resp = await s.api_set_user_mode(_Req({}))
    assert resp.status == 400


@pytest.mark.asyncio
async def test_post_user_mode_non_string_returns_400() -> None:
    s = UIServer.__new__(UIServer)
    s.daemon = MagicMock()
    resp = await s.api_set_user_mode(_Req({"mode": 42}))
    assert resp.status == 400


@pytest.mark.asyncio
async def test_post_user_mode_setter_exception_returns_500() -> None:
    d = MagicMock()
    d.set_user_mode = MagicMock(side_effect=RuntimeError("simulated"))
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_set_user_mode(_Req({"mode": "paranoid"}))
    assert resp.status == 500


# ---------- GET /api/v1/coherence-field ----------


@pytest.mark.asyncio
async def test_coherence_field_no_obs_returns_unavailable() -> None:
    d = SimpleNamespace(_field_obs=None)
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_coherence_field(_Req())
    body = json.loads(resp.text)
    assert body["available"] is False
    assert body["peers"] == {}
    assert body["summary"]["count"] == 0


@pytest.mark.asyncio
async def test_coherence_field_returns_per_peer_tau_values() -> None:
    obs = MagicMock()
    tau_map = {"peer_fp_aaaaaaaa": 0.85, "peer_fp_bbbbbbbb": 0.65}
    obs.tau_for_peer = lambda fp: tau_map.get(fp)
    state = MagicMock()
    state.list_peers.return_value = [
        SimpleNamespace(fingerprint="peer_fp_aaaaaaaa"),
        SimpleNamespace(fingerprint="peer_fp_bbbbbbbb"),
    ]
    d = SimpleNamespace(_field_obs=obs, state=state)
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_coherence_field(_Req())
    body = json.loads(resp.text)
    assert body["available"] is True
    # First 16 chars of each fp as the key.
    assert body["peers"]["peer_fp_aaaaaaaa"] == 0.85
    assert body["peers"]["peer_fp_bbbbbbbb"] == 0.65


@pytest.mark.asyncio
async def test_coherence_field_summary_stats_computed() -> None:
    obs = MagicMock()
    tau_map = {"p1": 0.4, "p2": 0.6, "p3": 0.8}
    obs.tau_for_peer = lambda fp: tau_map.get(fp)
    state = MagicMock()
    state.list_peers.return_value = [
        SimpleNamespace(fingerprint="p1"),
        SimpleNamespace(fingerprint="p2"),
        SimpleNamespace(fingerprint="p3"),
    ]
    d = SimpleNamespace(_field_obs=obs, state=state)
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_coherence_field(_Req())
    body = json.loads(resp.text)
    summary = body["summary"]
    assert summary["count"] == 3
    assert summary["mean"] == pytest.approx(0.6)
    assert summary["min"] == 0.4
    assert summary["max"] == 0.8


@pytest.mark.asyncio
async def test_coherence_field_skips_peers_with_no_observation() -> None:
    obs = MagicMock()
    obs.tau_for_peer = lambda fp: None if fp == "p2" else 0.5
    state = MagicMock()
    state.list_peers.return_value = [
        SimpleNamespace(fingerprint="p1"),
        SimpleNamespace(fingerprint="p2"),
        SimpleNamespace(fingerprint="p3"),
    ]
    d = SimpleNamespace(_field_obs=obs, state=state)
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_coherence_field(_Req())
    body = json.loads(resp.text)
    # Only p1 + p3 land in the snapshot.
    assert body["summary"]["count"] == 2
    assert "p1"[:16] in body["peers"]


@pytest.mark.asyncio
async def test_coherence_field_survives_state_exception() -> None:
    obs = MagicMock()
    state = MagicMock()
    state.list_peers.side_effect = RuntimeError("simulated")
    d = SimpleNamespace(_field_obs=obs, state=state)
    s = UIServer.__new__(UIServer)
    s.daemon = d
    # Must not raise.
    resp = await s.api_coherence_field(_Req())
    body = json.loads(resp.text)
    assert body["available"] is True
    assert body["summary"]["count"] == 0


@pytest.mark.asyncio
async def test_coherence_field_survives_per_peer_exception() -> None:
    obs = MagicMock()
    # Half the peers raise, half return a value.
    def tau_or_raise(fp):
        if fp.startswith("bad"):
            raise RuntimeError("simulated")
        return 0.5
    obs.tau_for_peer = tau_or_raise
    state = MagicMock()
    state.list_peers.return_value = [
        SimpleNamespace(fingerprint="good_1"),
        SimpleNamespace(fingerprint="bad_1"),
        SimpleNamespace(fingerprint="good_2"),
    ]
    d = SimpleNamespace(_field_obs=obs, state=state)
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_coherence_field(_Req())
    body = json.loads(resp.text)
    # The two good peers landed; the bad one was skipped.
    assert body["summary"]["count"] == 2
