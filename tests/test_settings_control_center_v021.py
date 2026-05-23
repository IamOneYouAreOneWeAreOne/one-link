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


def test_settings_network_is_a_real_control_center() -> None:
    html = _index()
    settings = _settings_shell(html)
    for required in (
        'id="settings-network-health"',
        'id="settings-network-report"',
        'id="settings-network-refresh"',
        'id="settings-network-copy-report"',
        'id="settings-network-run-doctor"',
        "function renderSettingsNetwork",
        "function refreshSettingsNetwork",
        "function copySettingsNetworkReport",
        "await api.fabric()",
        "await api.noRouter()",
        "await api.mobileReach()",
    ):
        assert required in html if required.startswith("function") or "api." in required else required in settings


def test_settings_network_controls_have_handlers() -> None:
    html = _index()
    for control_id in (
        "settings-network-refresh",
        "settings-network-copy-report",
        "settings-network-run-doctor",
    ):
        assert re.search(
            rf'\$\("#{re.escape(control_id)}"\)\?\.addEventListener\("click"',
            html,
        ), control_id


def test_settings_privacy_has_identity_and_proof_actions() -> None:
    html = _index()
    settings = _settings_shell(html)
    for required in (
        'id="privacy-identity-short"',
        'id="privacy-sharing-summary"',
        'id="privacy-sharing-detail"',
        'id="settings-copy-identity-privacy"',
        'id="settings-open-privacy-proof"',
        "function renderSettingsPrivacySummary",
        "api.setupAction(\"privacy_proof_viewed\")",
    ):
        assert required in html if required.startswith("function") or "api." in required else required in settings


def test_settings_devices_report_and_summary_are_wired() -> None:
    html = _index()
    settings = _settings_shell(html)
    for required in (
        'id="settings-devices-summary"',
        'id="settings-devices-copy-roster"',
        "device fingerprint",
        "device export",
        "/api/peers/${fp}/export",
        "JSON.stringify({ generated_at: new Date().toISOString(), peers }, null, 2)",
    ):
        assert required in html if required.startswith("/") or "JSON.stringify" in required or "device " in required else required in settings


def test_settings_about_support_bundle_is_not_hidden_in_advanced() -> None:
    html = _index()
    settings = _settings_shell(html)
    assert 'id="settings-about-runtime"' in settings
    assert 'id="settings-about-runtime-detail"' in settings
    assert 'id="settings-about-copy-diagnostics"' in settings
    assert 'id="settings-about-download-diagnostics"' in settings
    assert '$("#settings-about-copy-diagnostics")?.addEventListener("click"' in html
    assert '$("#settings-about-download-diagnostics")?.addEventListener("click"' in html
