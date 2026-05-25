"""v0.21.x: auto-install updates ON by default + silent background install.

Pre-v0.21.x, auto-install was gated behind
ONE_LINK_EXPERIMENTAL_AUTOINSTALL=1 - users had to set an env var
to get one-click updates. v0.21.x flips that:

  - Default user setting: 'auto_install_updates' = ON.
  - Settings -> About has a toggle to opt out.
  - The legacy env var is now a HARD OVERRIDE: setting it to '0'
    disables auto-install even when the user setting is ON
    (locked-down deployments where the operator manages updates).
  - _update_check_loop in the daemon AUTO-INSTALLS when it detects
    status='newer', user hasn't opted out, AND no voice/video call
    or active file transfer would be interrupted.

These tests pin all four contracts so a future refactor can't
silently revert any of them.
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


def test_api_update_install_no_longer_gated_off_by_default(server_src):
    """The legacy gate was 'if env var not in (1,true,yes) return
    disabled'. v0.21.x flips it: only DISABLE when the env var is
    explicitly set to 0/false/no, OR when the user's persisted
    setting says off. Default (env unset, setting unset) = ENABLED."""
    idx = server_src.find("async def api_update_install(")
    assert idx > 0
    body = server_src[idx:idx + 2500]
    # The old gate text must be gone.
    assert 'gate not in ("1", "true", "yes")' not in body, (
        "old 'must opt-in' gate still present; auto-install is "
        "still disabled by default"
    )
    # The new env-disable check must be present.
    assert 'env_gate in ("0", "false", "no")' in body, (
        "missing env-var hard-disable check"
    )
    # The user setting check must be present.
    assert 'get_setting("auto_install_updates")' in body, (
        "api_update_install doesn't check the user's "
        "auto_install_updates setting"
    )


def test_api_me_surfaces_autoinstall_enabled_from_user_setting(server_src):
    """The /api/me response carries `autoinstall_enabled` so the
    UI can render the toggle state correctly. v0.21.x: this value
    is derived from BOTH the env hard-disable AND the user
    setting, not just the env var."""
    idx = server_src.find("async def api_me(")
    assert idx > 0
    body = server_src[idx:idx + 6000]
    assert "autoinstall_enabled" in body
    # The user setting must influence the value.
    assert 'get_setting("auto_install_updates")' in body, (
        "/api/me doesn't read the user's auto_install_updates "
        "setting; the UI toggle would be wrong on first load"
    )


def test_api_set_settings_accepts_auto_install_updates(server_src):
    """The /api/settings POST handler must accept + persist the
    auto_install_updates key so the Settings -> About toggle
    actually writes to the database."""
    idx = server_src.find("async def api_set_settings(")
    assert idx > 0
    body = server_src[idx:idx + 4000]
    assert '"auto_install_updates" in data' in body, (
        "api_set_settings doesn't accept the auto_install_updates "
        "key; the toggle in Settings -> About has nothing to save to"
    )


def test_api_get_settings_returns_auto_install_default_true(server_src):
    """/api/settings GET must surface auto_install_updates with a
    DEFAULT of true (the sovereignty 'just works' default). The
    Settings UI checks this to render the toggle's initial state."""
    idx = server_src.find("async def api_get_settings(")
    assert idx > 0
    body = server_src[idx:idx + 4500]
    assert '"auto_install_updates": auto_install' in body
    # The default-true logic must be present.
    assert "auto_install_raw is None" in body, (
        "/api/settings must default auto_install_updates to True "
        "when the setting has never been written"
    )


# ── daemon-side: silent install guard rails ────────────────────────


def test_daemon_has_maybe_auto_install_method(daemon_src):
    """_update_check_loop must call into a guarded auto-install
    helper when status='newer'. Pin: the helper exists + has the
    safety guards (env override, user opt-out, active call, active
    transfer, in-flight installer)."""
    assert "async def _maybe_auto_install(" in daemon_src, (
        "_maybe_auto_install helper missing - silent auto-update "
        "wouldn't fire on newer-release detection"
    )
    idx = daemon_src.find("async def _maybe_auto_install(")
    body = daemon_src[idx:idx + 6000]
    # Operator hard-disable check.
    assert 'ONE_LINK_EXPERIMENTAL_AUTOINSTALL' in body
    assert 'env_gate in ("0"' in body
    # User opt-out check.
    assert 'get_setting("auto_install_updates")' in body
    # Active-call guard.
    assert "_call_registry.active_call_ids()" in body
    # Active-transfer guard.
    assert "list_transfers" in body
    # In-flight install guard.
    assert "_auto_install_in_flight" in body
    # SHA-256 verification before install.
    assert "sha256_file" in body
    # Refuse install without published hash.
    assert "refusing to install unverified" in body.lower()
    # Refuse install on hash mismatch.
    assert "SHA256 mismatch" in body or "sha256 mismatch" in body.lower()


def test_update_check_loop_calls_maybe_auto_install_on_newer(daemon_src):
    """The poll loop must trigger _maybe_auto_install when status
    transitions to 'newer'. Without this hook, the silent install
    never fires + we're back to manual click-to-update UX."""
    idx = daemon_src.find("async def _update_check_loop(")
    assert idx > 0
    body = daemon_src[idx:idx + 8000]
    assert 'if status == "newer":' in body, (
        "_update_check_loop doesn't branch on status=='newer'"
    )
    assert "_maybe_auto_install(" in body, (
        "_update_check_loop never calls _maybe_auto_install; "
        "the silent install path is reachable from nowhere"
    )


# ── UI: Settings toggle wired + handler persists ───────────────────


def test_settings_about_has_auto_install_toggle(index_html):
    """The Settings -> About 'Updates' section must surface a
    toggle the user can flip. Pin: input id + label + change
    handler that POSTs to /api/settings."""
    assert 'id="setting-auto-install-updates"' in index_html
    assert ">Updates<" in index_html
    assert "Auto-install updates" in index_html
    # The handler POSTs to /api/settings with the right key.
    assert '"/api/settings"' in index_html
    assert "auto_install_updates" in index_html


def test_auto_install_toggle_default_state_is_true_in_ui(index_html):
    """First time the user opens Settings, the toggle should
    render as ON (matches the daemon-side default). The UI must
    default to true when the setting is undefined in the response."""
    # The refresh helper handles the undefined case.
    idx = index_html.find("function _refreshAutoInstallToggle(")
    assert idx > 0
    body = index_html[idx:idx + 1000]
    assert "v === undefined ? true" in body, (
        "Auto-install toggle defaults to false when the setting "
        "is unset; should default to true to match the daemon's "
        "sovereignty 'just works' default"
    )
