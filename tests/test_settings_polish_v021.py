from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "src" / "one_link" / "web" / "index.html"


def _index() -> str:
    return INDEX.read_text(encoding="utf-8")


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
