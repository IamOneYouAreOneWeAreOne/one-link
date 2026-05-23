from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "src" / "one_link" / "web" / "index.html"
SERVER = ROOT / "src" / "one_link" / "server.py"


def _index() -> str:
    return INDEX.read_text(encoding="utf-8")


def _server() -> str:
    return SERVER.read_text(encoding="utf-8")


def _settings_shell(html: str) -> str:
    start = html.index('id="settings-backdrop"')
    end = html.index('id="device-backdrop"')
    return html[start:end]


def test_settings_setup_has_no_visible_mojibake() -> None:
    html = _index()
    setup_render = html[html.index("function renderOneSetup") : html.index("async function maybeShowOnboarding")]
    settings = _settings_shell(html)
    combined = settings + setup_render
    for bad in ("â", "Â", "Ã", "\ufffd", "âœ", "Â·"):
        assert bad not in combined


def test_html_shells_are_served_with_explicit_utf8_charset() -> None:
    server = _server()
    html_responses = re.findall(
        r"web\.Response\(\s*text=[^)]*?content_type=\"text/html\"[^)]*?\)",
        server,
        flags=re.DOTALL,
    )
    assert html_responses, "expected HTML web.Response calls"
    for response in html_responses:
        assert 'charset="utf-8"' in response, response


def test_live_status_strings_avoid_fragile_unicode_separators() -> None:
    html = _index()
    for fragile in (
        'parts.join(" · ")',
        'document.createTextNode(` · ',
        'document.createTextNode(" · ")',
        '`Queued · ${reasonHint}`',
        '`${txt} · `',
        '` · ${Math.round(peer.latency_ms)} ms`',
        '🔥 ${_humanTtl',
    ):
        assert fragile not in html


def test_settings_profile_identity_has_copy_action() -> None:
    settings = _settings_shell(_index())
    assert 'id="settings-identity-fp"' in settings
    assert 'id="settings-copy-identity"' in settings
    assert "Copy identity fingerprint" in settings
    assert 'copyToClipboard(txt, "identity fingerprint")' in _index()


def test_settings_devices_pane_is_real_device_management() -> None:
    html = _index()
    settings = _settings_shell(html)
    assert "We could've put" not in settings
    assert "We didn't" not in settings
    for required in (
        'id="settings-devices-list"',
        'id="settings-devices-refresh"',
        'id="settings-devices-pair"',
        'id="settings-devices-nearby"',
        "function renderSettingsDevices",
        "openDeviceDrawer(p.short_id)",
        "copyToClipboard(p.fingerprint || p.short_id || \"\", \"device ID\")",
        "loadActivityNearby({ force: true })",
    ):
        assert required in html


def test_settings_devices_controls_have_handlers() -> None:
    html = _index()
    for control_id in (
        "settings-copy-identity",
        "settings-devices-refresh",
        "settings-devices-pair",
        "settings-devices-nearby",
    ):
        assert re.search(
            rf'\$\("#{re.escape(control_id)}"\)\?\.addEventListener\("click"',
            html,
        ), control_id


def test_settings_save_feedback_is_visible_and_wired() -> None:
    html = _index()
    settings = _settings_shell(html)
    assert 'id="settings-save-status"' in settings
    assert "function markSettingsDirty" in html
    assert 'setSettingsSaveStatus("Saving..."' in html
    assert 'setSettingsSaveStatus("Save failed."' in html
    assert 'setSettingsSaveStatus("Rendezvous save failed."' in html
    assert 'settingsBackdrop?.querySelectorAll("input, select, textarea")' in html
