"""Tests for the REST surface of the F1 user_mode setting.

Verifies:
  - GET /api/settings returns the persisted user_mode (default normal)
  - POST /api/settings accepts known modes and persists them
  - POST /api/settings normalizes aliases (battery-save → battery_save)
  - POST /api/settings rejects unknown values with 400
  - POST /api/settings with null deletes the setting
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from one_link import server as server_module


def _mock_request(payload: dict):
    """A bare aiohttp.web.Request-shaped mock that returns ``payload``
    when .json() is awaited."""
    req = MagicMock()
    req.json = AsyncMock(return_value=payload)
    return req


def _ui_server_with_state():
    """A UIServer-shaped object with a MagicMock state, suitable for
    calling api_set_settings / api_get_settings against."""
    srv = server_module.UIServer.__new__(server_module.UIServer)
    daemon_mock = MagicMock()
    daemon_mock.state = MagicMock()
    daemon_mock.state.all_settings.return_value = {}
    daemon_mock.state.get_setting.return_value = None
    daemon_mock.state.set_setting = MagicMock()
    daemon_mock.state.delete_setting = MagicMock()
    daemon_mock.refresh_runtime_settings = MagicMock()
    srv.daemon = daemon_mock
    return srv


@pytest.mark.asyncio
async def test_set_settings_accepts_paranoid() -> None:
    srv = _ui_server_with_state()
    req = _mock_request({"user_mode": "paranoid"})
    resp = await srv.api_set_settings(req)
    assert resp.status == 200
    srv.daemon.state.set_setting.assert_any_call("user_mode", "paranoid")


@pytest.mark.asyncio
async def test_set_settings_normalizes_alias() -> None:
    srv = _ui_server_with_state()
    req = _mock_request({"user_mode": "battery-save"})
    resp = await srv.api_set_settings(req)
    assert resp.status == 200
    srv.daemon.state.set_setting.assert_any_call("user_mode", "battery_save")


@pytest.mark.asyncio
async def test_set_settings_rejects_unknown() -> None:
    srv = _ui_server_with_state()
    req = _mock_request({"user_mode": "supercritical"})
    resp = await srv.api_set_settings(req)
    assert resp.status == 400
    srv.daemon.state.set_setting.assert_not_called()


@pytest.mark.asyncio
async def test_set_settings_null_deletes() -> None:
    srv = _ui_server_with_state()
    req = _mock_request({"user_mode": None})
    resp = await srv.api_set_settings(req)
    assert resp.status == 200
    srv.daemon.state.delete_setting.assert_any_call("user_mode")


@pytest.mark.asyncio
async def test_set_settings_non_string_rejected() -> None:
    srv = _ui_server_with_state()
    req = _mock_request({"user_mode": 42})
    resp = await srv.api_set_settings(req)
    assert resp.status == 400


@pytest.mark.asyncio
async def test_set_settings_accepts_all_known_modes() -> None:
    for mode in ("normal", "paranoid", "battery_save", "latency_strict"):
        srv = _ui_server_with_state()
        req = _mock_request({"user_mode": mode})
        resp = await srv.api_set_settings(req)
        assert resp.status == 200, f"mode={mode}"


@pytest.mark.asyncio
async def test_get_settings_default_normal() -> None:
    srv = _ui_server_with_state()
    req = MagicMock()
    resp = await srv.api_get_settings(req)
    assert resp.status == 200
    # Body is web.json_response — body attr is bytes; decode + parse.
    import json
    body = json.loads(resp.body.decode("utf-8"))
    assert body["user_mode"] == "normal"


@pytest.mark.asyncio
async def test_get_settings_returns_persisted() -> None:
    srv = _ui_server_with_state()
    srv.daemon.state.all_settings.return_value = {"user_mode": "paranoid"}
    req = MagicMock()
    resp = await srv.api_get_settings(req)
    import json
    body = json.loads(resp.body.decode("utf-8"))
    assert body["user_mode"] == "paranoid"


@pytest.mark.asyncio
async def test_set_settings_refreshes_daemon_cache() -> None:
    srv = _ui_server_with_state()
    req = _mock_request({"user_mode": "paranoid"})
    resp = await srv.api_set_settings(req)
    assert resp.status == 200
    srv.daemon.refresh_runtime_settings.assert_called_once()
