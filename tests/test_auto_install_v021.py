"""Fail-closed contracts for executable update handoff.

Background polling and the settings toggle must never replace the live
application. The distinct explicit owner-confirmed endpoint may hand off only
from a completely validated frozen bundle to the fixed external A/B helper.
"""
from __future__ import annotations

from pathlib import Path

import pytest


_SERVER = (
    Path(__file__).resolve().parents[1] / "src" / "one_link" / "server.py"
)
_DAEMON = (
    Path(__file__).resolve().parents[1] / "src" / "one_link" / "daemon.py"
)
_INDEX_HTML = (
    Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "index.html"
)


@pytest.fixture(scope="module")
def server_src() -> str:
    return _SERVER.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def daemon_src() -> str:
    return _DAEMON.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def index_html() -> str:
    return _INDEX_HTML.read_text(encoding="utf-8")


# ── server-side: gate flipped + setting respected ──────────────────


def test_api_update_install_requires_exact_confirmation_and_fixed_helper(server_src):
    idx = server_src.find("async def api_update_install(")
    assert idx > 0
    body = server_src[idx:idx + 15000]
    assert 'set(data) != {"confirmed_install"}' in body
    assert 'data.get("confirmed_install") is not True' in body
    assert '"code": "install_confirmation_required"' in body
    assert "status=409" in body
    assert "self._external_update_capability(fresh=True)" in body
    assert "if not capability.available:" in body
    assert "self._ui_update_handoff_blockers()" in body
    assert 'begin_handoff = getattr(self.daemon, "begin_update_handoff", None)' in body
    assert 'cancel_handoff = getattr(self.daemon, "cancel_update_handoff", None)' in body
    assert "blockers = begin_handoff()" in body
    assert "acquire_update_state_authority" in body
    assert "prepare_external_helper_launch" in body
    assert "spawn_external_update_helper" in body
    assert '"status": "handoff_started"' in body
    assert "status=202" in body
    for browser_controlled_field in (
        'data.get("tag")',
        'data.get("artifact")',
        'data.get("path")',
        'data.get("command")',
    ):
        assert browser_controlled_field not in body


def test_api_me_surfaces_autoinstall_unavailable(server_src):
    idx = server_src.find("async def api_me(")
    assert idx > 0
    body = server_src[idx:idx + 6000]
    assert "autoinstall_enabled" in body
    assert "autoinstall_enabled = False" in body
    assert '"update_install_available": bool(update_capability.available)' in body
    assert '"update_install_reason": update_capability.reason' in body
    assert 'get_setting("auto_install_updates")' not in body


def test_api_set_settings_rejects_enabling_auto_install(server_src):
    idx = server_src.find("async def api_set_settings(")
    assert idx > 0
    body = server_src[idx:idx + 4000]
    assert '"auto_install_updates" in data' in body
    assert 'if stored == "1":' in body
    assert "status=409" in body
    assert 'delete_setting("auto_install_updates")' in body


def test_api_get_settings_returns_auto_install_default_false(server_src):
    idx = server_src.find("async def api_get_settings(")
    assert idx > 0
    body = server_src[idx:idx + 4500]
    assert '"auto_install_updates": auto_install' in body
    assert "auto_install = False" in body


# ── daemon-side: silent install guard rails ────────────────────────


def test_daemon_auto_install_helper_has_no_legacy_substrate(daemon_src):
    assert "async def _maybe_auto_install(" in daemon_src, (
        "migration helper missing"
    )
    idx = daemon_src.find("async def _maybe_auto_install(")
    next_method = daemon_src.find("    def get_my_presence(", idx)
    body = daemon_src[idx:next_method]
    assert "auto-install unavailable" in body
    assert "build_install_plan" not in body
    assert "prepare_signed_update" not in body
    assert "spawn_detached" not in body
    assert "ONE_LINK_EXPERIMENTAL_AUTOINSTALL" not in body


def test_update_check_loop_is_notification_only(daemon_src):
    idx = daemon_src.find("async def _update_check_loop(")
    assert idx > 0
    body = daemon_src[idx:idx + 8000]
    assert "update installation must" in body
    assert "never begin in the background" in body
    assert "explicit owner-confirmed" in body
    assert "await self._maybe_auto_install(" not in body


# ── UI: Settings toggle wired + handler persists ───────────────────


def test_settings_about_marks_auto_install_unavailable(index_html):
    assert 'id="setting-auto-install-updates"' in index_html
    assert ">Updates<" in index_html
    assert "Automatic installation (not available)" in index_html
    toggle = index_html.find('id="setting-auto-install-updates"')
    assert 'disabled' in index_html[toggle:toggle + 300]
    assert "auto_install_updates" not in index_html
    assert "update_install_available" in index_html
    assert '"/api/update/install"' in index_html
    assert "{ confirmed_install: true }" in index_html
    assert "Install verified update" in index_html


def test_auto_install_toggle_default_state_is_false_in_ui(index_html):
    idx = index_html.find("function _refreshAutoInstallToggle(")
    assert idx > 0
    body = index_html[idx:idx + 1000]
    assert "v === undefined ? true" not in body
    assert "cb.checked = false" in body
    assert "cb.disabled = true" in body
    assert "transactional" in index_html
