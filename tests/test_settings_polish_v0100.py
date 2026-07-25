"""v0.10.0 — settings polish: theme + downloads + DND + sound + log level.

Five new settings, all persisted in state.settings, all surfaced in
the Settings modal:
  - theme: dark | light | auto (CSS variable swap, no JS repaint)
  - download_folder: custom inbox location (paths.set_inbox_override)
  - dnd_enabled / dnd_start / dnd_end: do-not-disturb window with
    midnight wrap-around support
  - notification_sound: master toggle for the Web Audio chime
  - log_level: error | warn | info | debug (applied live to the
    'one_link' logger)

Tests are split: state-layer + server-endpoint + UI-surface.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="settings-host",
    )


@pytest_asyncio.fixture
async def ctx(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client, daemon, state, server.token
    finally:
        await client.close()
        state.close()


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ───────── /api/settings GET defaults ─────────────────────────────────

@pytest.mark.asyncio
async def test_get_settings_defaults(ctx):
    """A never-touched daemon must return sane defaults for every
    new key — UI relies on these to render initial state."""
    client, _, _, token = ctx
    resp = await client.get("/api/settings", headers=_h(token))
    assert resp.status == 200
    j = await resp.json()
    assert j["theme"] == "dark"
    assert j["download_folder"] == ""
    assert j["dnd_enabled"] is False
    assert j["dnd_start"] == "22:00"
    assert j["dnd_end"] == "07:00"
    assert j["notification_sound"] is True
    assert j["log_level"] == "info"


# ───────── theme ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_theme_persists_and_reads_back(ctx):
    client, _, _, token = ctx
    resp = await client.post(
        "/api/settings", headers=_h(token), json={"theme": "light"},
    )
    assert resp.status == 200
    resp = await client.get("/api/settings", headers=_h(token))
    j = await resp.json()
    assert j["theme"] == "light"


@pytest.mark.asyncio
async def test_theme_rejects_invalid(ctx):
    client, _, _, token = ctx
    resp = await client.post(
        "/api/settings", headers=_h(token), json={"theme": "neon"},
    )
    assert resp.status == 400


# ───────── download_folder ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_download_folder_valid_dir_persists(ctx, tmp_path: Path):
    """A writable directory must persist + flip the inbox override."""
    client, _, _, token = ctx
    target = tmp_path / "downloads"
    target.mkdir()
    resp = await client.post(
        "/api/settings", headers=_h(token),
        json={"download_folder": str(target)},
    )
    assert resp.status == 200
    from one_link.paths import inbox_dir
    assert inbox_dir().resolve() == target.resolve()


@pytest.mark.asyncio
async def test_download_folder_nonexistent_rejected(ctx):
    client, _, _, token = ctx
    resp = await client.post(
        "/api/settings", headers=_h(token),
        json={"download_folder": "/this/path/does/not/exist/anywhere"},
    )
    assert resp.status == 400
    j = await resp.json()
    assert "not a directory" in j["error"].lower()


@pytest.mark.asyncio
async def test_download_folder_blank_clears_override(ctx, tmp_path: Path):
    """Empty string clears the custom folder + drops the override."""
    client, _, _, token = ctx
    target = tmp_path / "downloads2"
    target.mkdir()
    # Set, then clear.
    await client.post(
        "/api/settings", headers=_h(token),
        json={"download_folder": str(target)},
    )
    resp = await client.post(
        "/api/settings", headers=_h(token),
        json={"download_folder": ""},
    )
    assert resp.status == 200
    # Settings response should now show empty string for the folder.
    resp = await client.get("/api/settings", headers=_h(token))
    j = await resp.json()
    assert j["download_folder"] == ""


# ───────── DND ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dnd_round_trip(ctx):
    client, _, _, token = ctx
    resp = await client.post(
        "/api/settings", headers=_h(token),
        json={"dnd_enabled": True, "dnd_start": "23:30", "dnd_end": "06:15"},
    )
    assert resp.status == 200
    resp = await client.get("/api/settings", headers=_h(token))
    j = await resp.json()
    assert j["dnd_enabled"] is True
    assert j["dnd_start"] == "23:30"
    assert j["dnd_end"] == "06:15"


@pytest.mark.asyncio
async def test_dnd_canonicalizes_short_form(ctx):
    """'7:5' must be canonicalized to '07:05' on save so the time
    input round-trips cleanly."""
    client, _, _, token = ctx
    resp = await client.post(
        "/api/settings", headers=_h(token),
        json={"dnd_start": "7:5", "dnd_end": "9:0"},
    )
    assert resp.status == 200
    resp = await client.get("/api/settings", headers=_h(token))
    j = await resp.json()
    assert j["dnd_start"] == "07:05"
    assert j["dnd_end"] == "09:00"


@pytest.mark.asyncio
async def test_dnd_invalid_time_rejected(ctx):
    client, _, _, token = ctx
    for bad in ("25:00", "12:99", "abc", "1:2:3"):
        resp = await client.post(
            "/api/settings", headers=_h(token),
            json={"dnd_start": bad},
        )
        assert resp.status == 400, f"{bad!r} should be rejected"


# ───────── notification sound ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_notification_sound_round_trip(ctx):
    client, _, _, token = ctx
    resp = await client.post(
        "/api/settings", headers=_h(token),
        json={"notification_sound": False},
    )
    assert resp.status == 200
    resp = await client.get("/api/settings", headers=_h(token))
    assert (await resp.json())["notification_sound"] is False


# ───────── log level ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_log_level_applies_live(ctx):
    """Setting log_level must immediately affect the running logger,
    not require a restart."""
    client, _, _, token = ctx
    logger = logging.getLogger("one_link")
    original = logger.level
    try:
        resp = await client.post(
            "/api/settings", headers=_h(token), json={"log_level": "debug"},
        )
        assert resp.status == 200
        assert logger.level == logging.DEBUG
        resp = await client.post(
            "/api/settings", headers=_h(token), json={"log_level": "error"},
        )
        assert logger.level == logging.ERROR
    finally:
        logger.setLevel(original)


@pytest.mark.asyncio
async def test_log_level_invalid_rejected(ctx):
    client, _, _, token = ctx
    resp = await client.post(
        "/api/settings", headers=_h(token), json={"log_level": "yelling"},
    )
    assert resp.status == 400


# ───────── boot-time apply ────────────────────────────────────────────

def test_apply_settings_at_boot_loads_log_level(tmp_path: Path, monkeypatch):
    """A daemon restarting picks up the persisted log_level
    without going through /api/settings POST."""
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.set_setting("log_level", "debug")
    me = _identity()
    daemon = Daemon(me)
    daemon.state = state
    logger = logging.getLogger("one_link")
    original = logger.level
    try:
        daemon._apply_settings_at_boot()
        assert logger.level == logging.DEBUG
    finally:
        logger.setLevel(original)
        state.close()


def test_apply_settings_at_boot_loads_download_folder(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    target = tmp_path / "custom_downloads"
    target.mkdir()
    state = State(db_path=tmp_path / "state.db")
    state.set_setting("download_folder", str(target.resolve()))
    me = _identity()
    daemon = Daemon(me)
    daemon.state = state
    try:
        daemon._apply_settings_at_boot()
        from one_link.paths import inbox_dir
        assert inbox_dir().resolve() == target.resolve()
    finally:
        # Reset the global override so other tests aren't affected.
        from one_link.paths import set_inbox_override
        set_inbox_override(None)
        state.close()


def test_apply_settings_at_boot_skips_invalid_download_folder(
    tmp_path: Path, monkeypatch,
):
    """If the saved folder no longer exists at boot, fall back to
    default + don't crash."""
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    state.set_setting("download_folder", "/this/disappeared/since/last/run")
    me = _identity()
    daemon = Daemon(me)
    daemon.state = state
    try:
        # Should not raise.
        daemon._apply_settings_at_boot()
        from one_link.paths import inbox_dir
        # Falls back to default (under tmp_path because of ONE_LINK_HOME).
        assert "disappeared" not in str(inbox_dir())
    finally:
        from one_link.paths import set_inbox_override
        set_inbox_override(None)
        state.close()


# ───────── UI surface ─────────────────────────────────────────────────

@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


def test_settings_modal_has_new_controls(index_html: str):
    for ctrl_id in ("set-theme", "set-download-folder", "set-dnd-enabled",
                    "set-dnd-start", "set-dnd-end", "set-sound",
                    "set-log-level", "set-sound-test",
                    "set-ui-density", "set-message-bubble-style",
                    "set-font-scale", "set-motion-level",
                    "set-chat-wallpaper", "set-accent-color",
                    "set-enter-to-send", "set-auto-scroll",
                    "set-compact-message-list", "set-show-message-seconds",
                    "set-link-previews", "settings-copy-shortcuts",
                    "settings-open-shortcuts", "settings-advanced-support-grid"):
        assert f'id="{ctrl_id}"' in index_html, f"missing {ctrl_id}"


def test_light_theme_css_present(index_html: str):
    """Pin the light-theme variable overrides so a future palette
    refactor doesn't silently drop them."""
    assert 'html[data-theme="light"]' in index_html
    # Spot-check a couple of variable overrides flipped for light.
    assert "--bg-0:       #f6f7fb" in index_html
    assert "--text:       #1a1f2b" in index_html


def test_auto_theme_follows_system(index_html: str):
    """The 'auto' theme must follow prefers-color-scheme via a
    media query, not require manual JS polling."""
    assert "@media (prefers-color-scheme: light)" in index_html
    assert 'html[data-theme="auto"]' in index_html


def test_apply_theme_helper_present(index_html: str):
    assert "function applyTheme(" in index_html
    assert "function applyAppearanceSettings(" in index_html


def test_dnd_helper_handles_midnight_wrap(index_html: str):
    """Pin the wrap-around comment + logic so a refactor doesn't
    break 22:00 → 07:00 windows."""
    idx = index_html.find("function isQuietHoursActive(")
    assert idx > 0
    snippet = index_html[idx:idx + 1500]
    assert "Wrap-around" in snippet
    assert "minutes >= start || minutes < end" in snippet


def test_chime_uses_web_audio_api(index_html: str):
    """No vendored audio file — chime is synthesized in the browser."""
    assert "function playNotificationChime(" in index_html
    assert "AudioContext" in index_html
    assert "createOscillator" in index_html


def test_notify_incoming_respects_dnd(index_html: str):
    """notifyIncoming must call isQuietHoursActive BEFORE creating
    the desktop notification, otherwise DND would pop notifications
    that are then orphaned."""
    idx = index_html.find("function notifyIncoming(")
    snippet = index_html[idx:idx + 5000]
    assert "isQuietHoursActive()" in snippet


def test_settings_save_includes_new_keys(index_html: str):
    idx = index_html.find('"#settings-save"')
    snippet = index_html[idx:idx + 5000]
    for k in ("theme", "download_folder", "dnd_enabled", "dnd_start",
              "dnd_end", "notification_sound", "log_level",
              "ui_density", "message_bubble_style", "font_scale",
              "motion_level", "accent_color", "chat_wallpaper",
              "enter_to_send", "auto_scroll_new_messages",
              "compact_message_list", "show_message_seconds",
              "send_link_previews"):
        assert k in snippet, f"settings-save payload missing {k}"


def test_live_theme_preview_on_change(index_html: str):
    """Theme dropdown change event must call applyTheme so the user
    sees the preview before clicking Save."""
    # Find the addEventListener-on-change site, not the load-from-
    # settings site (which is also keyed off "#set-theme").
    idx = index_html.find(
        '$("#set-theme")?.addEventListener("change"'
    )
    assert idx > 0, "missing change listener on theme dropdown"
    snippet = index_html[idx:idx + 400]
    assert "applyTheme(" in snippet


def test_live_appearance_preview_on_change(index_html: str):
    """Appearance controls must be live-previewed, not just saved."""
    assert "collectAppearanceSettingsDraft" in index_html
    assert "applyAppearanceSettings(collectAppearanceSettingsDraft())" in index_html
    assert 'id="settings-accent-swatches"' in index_html


def test_chat_behavior_toggles_are_not_dead_switches(index_html: str):
    """New chat settings must feed real rendering/runtime branches."""
    assert 'html.dataset.compactMessages = settings.compact_message_list === true ? "1" : "0"' in index_html
    assert "const richPreviewsEnabled = state.runtimeSettings?.send_link_previews !== false;" in index_html
    assert "const previewKind = richPreviewsEnabled ? previewKindForName(msg.name) : null;" in index_html


def test_test_sound_button_bypasses_master_toggle(index_html: str):
    """Test-sound must call playNotificationChime directly so a user
    can preview the chime even with notification_sound off."""
    idx = index_html.find('"#set-sound-test"')
    snippet = index_html[idx:idx + 600]
    assert "playNotificationChime()" in snippet


def test_page_version_bumped(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
