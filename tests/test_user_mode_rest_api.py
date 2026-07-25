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
async def test_get_settings_returns_appearance_and_chat_defaults() -> None:
    srv = _ui_server_with_state()
    req = MagicMock()
    resp = await srv.api_get_settings(req)
    import json
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ui_density"] == "comfortable"
    assert body["message_bubble_style"] == "gradient"
    assert body["font_scale"] == "normal"
    assert body["motion_level"] == "full"
    assert body["accent_color"] == "#7c5cff"
    assert body["chat_wallpaper"] == "soft"
    assert body["enter_to_send"] is True
    assert body["auto_scroll_new_messages"] is True
    assert body["compact_message_list"] is False


@pytest.mark.asyncio
async def test_set_settings_persists_appearance_and_chat_controls() -> None:
    srv = _ui_server_with_state()
    req = _mock_request({
        "ui_density": "compact",
        "message_bubble_style": "solid",
        "font_scale": "large",
        "motion_level": "reduced",
        "accent_color": "#46D39A",
        "chat_wallpaper": "field",
        "enter_to_send": False,
        "auto_scroll_new_messages": True,
        "compact_message_list": True,
        "show_message_seconds": True,
        "send_link_previews": False,
    })
    resp = await srv.api_set_settings(req)
    assert resp.status == 200
    srv.daemon.state.set_setting.assert_any_call("ui_density", "compact")
    srv.daemon.state.set_setting.assert_any_call("message_bubble_style", "solid")
    srv.daemon.state.set_setting.assert_any_call("font_scale", "large")
    srv.daemon.state.set_setting.assert_any_call("motion_level", "reduced")
    srv.daemon.state.set_setting.assert_any_call("accent_color", "#46d39a")
    srv.daemon.state.set_setting.assert_any_call("chat_wallpaper", "field")
    srv.daemon.state.set_setting.assert_any_call("enter_to_send", "false")
    srv.daemon.state.set_setting.assert_any_call("compact_message_list", "true")
    srv.daemon.state.set_setting.assert_any_call("show_message_seconds", "true")
    srv.daemon.state.set_setting.assert_any_call("send_link_previews", "false")


@pytest.mark.asyncio
async def test_set_settings_rejects_bad_appearance_values() -> None:
    bad_payloads = [
        {"ui_density": "microscopic"},
        {"message_bubble_style": "random"},
        {"font_scale": "huge"},
        {"motion_level": "warp"},
        {"chat_wallpaper": "lava"},
        {"accent_color": "purple"},
    ]
    for payload in bad_payloads:
        srv = _ui_server_with_state()
        req = _mock_request(payload)
        resp = await srv.api_set_settings(req)
        assert resp.status == 400, payload


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [True, "true", "YES", "1"])
async def test_set_settings_rejects_enabling_in_place_update(value) -> None:
    srv = _ui_server_with_state()
    resp = await srv.api_set_settings(
        _mock_request({"auto_install_updates": value})
    )

    assert resp.status == 409
    srv.daemon.state.set_setting.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [False, "0", " no ", "false"])
async def test_set_settings_clears_historical_update_consent(value) -> None:
    srv = _ui_server_with_state()
    resp = await srv.api_set_settings(
        _mock_request({"auto_install_updates": value})
    )

    assert resp.status == 200
    srv.daemon.state.delete_setting.assert_any_call("auto_install_updates")


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [None, 1, 0, [], {}, "enabled", "truthy", ""])
async def test_set_settings_rejects_ambiguous_update_consent(value) -> None:
    srv = _ui_server_with_state()
    resp = await srv.api_set_settings(
        _mock_request({"auto_install_updates": value})
    )

    assert resp.status == 400
    srv.daemon.state.set_setting.assert_not_called()


@pytest.mark.asyncio
async def test_set_settings_refreshes_daemon_cache() -> None:
    srv = _ui_server_with_state()
    req = _mock_request({"user_mode": "paranoid"})
    resp = await srv.api_set_settings(req)
    assert resp.status == 200
    srv.daemon.refresh_runtime_settings.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "key",
    [
        "auto_accept_lan",
        "pair_default_allow_all",
        "sync_quiet_hours_enabled",
        "sync_pause_on_metered",
        "sync_pause_on_battery",
        "sync_paused",
        "onboarding_completed",
        "incoming_files_require_accept",
        "dnd_enabled",
        "notification_sound",
        "notification_preview",
        "notify_on_reactions",
        "send_read_receipts",
        "display_read_receipts",
        "send_typing_indicators",
        "display_typing_indicators",
        "enter_to_send",
        "compact_message_list",
        "show_message_seconds",
        "auto_scroll_new_messages",
        "send_link_previews",
    ],
)
async def test_set_settings_rejects_truthy_non_booleans(key: str) -> None:
    """The JSON string ``"false"`` must never turn a switch on."""
    srv = _ui_server_with_state()
    resp = await srv.api_set_settings(_mock_request({key: "false"}))

    assert resp.status == 400
    srv.daemon.state.set_setting.assert_not_called()
    srv.daemon.state.delete_setting.assert_not_called()


@pytest.mark.asyncio
async def test_set_settings_prevalidates_late_fields_before_any_write() -> None:
    srv = _ui_server_with_state()
    resp = await srv.api_set_settings(
        _mock_request({"theme": "light", "accent_color": "not-a-color"})
    )

    assert resp.status == 400
    srv.daemon.state.set_setting.assert_not_called()
    srv.daemon.state.delete_setting.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [[], ["theme"], "theme=light", 1, True, None])
async def test_set_settings_requires_json_object(payload) -> None:
    srv = _ui_server_with_state()
    resp = await srv.api_set_settings(_mock_request(payload))

    assert resp.status == 400
    srv.daemon.state.set_setting.assert_not_called()
    srv.daemon.state.delete_setting.assert_not_called()
