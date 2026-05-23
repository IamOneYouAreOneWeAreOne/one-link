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


def test_settings_profile_has_production_command_center() -> None:
    html = _index()
    settings = _settings_shell(html)
    for required in (
        'id="settings-command-center"',
        'id="settings-overview-health"',
        'id="settings-readiness-list"',
        'id="settings-overview-repair"',
        'id="settings-overview-copy"',
        'id="settings-overview-devices"',
        'id="settings-overview-privacy"',
        'id="settings-overview-storage"',
        "function _settingsOverviewSnapshot",
        "function renderSettingsOverview",
        "function copySettingsOverviewReport",
        "Live identity, device, network, privacy, storage, and diagnostic readiness",
    ):
        assert required in html if required.startswith("function") else required in settings


def test_settings_overview_actions_are_wired_to_real_panes() -> None:
    html = _index()
    assert '$("#settings-overview-repair")?.addEventListener("click"' in html
    assert '$("#settings-overview-copy")?.addEventListener("click"' in html
    assert '$("#settings-overview-devices")?.addEventListener("click", () => switchSettingsPane("devices"))' in html
    assert '$("#settings-overview-privacy")?.addEventListener("click", () => switchSettingsPane("privacy"))' in html
    assert '$("#settings-overview-storage")?.addEventListener("click", () => switchSettingsPane("storage"))' in html
    assert 'await refreshSettingsNetwork();' in html
    assert 'copySettingsOverviewReport().catch' in html


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


def test_settings_devices_have_real_management_actions() -> None:
    html = _index()
    for required in (
        "function _settingsDeviceHealth",
        "function _settingsRunDeviceAction",
        "Device path refreshed",
        "Device marked verified",
        "Verification removed",
        "Device muted",
        "Device unmuted",
        "Device blocked",
        "/api/peers/prune",
        "/resume",
        "/verify",
        "/mute",
        "/profile",
        "{ trust: \"rejected\" }",
        "settings-device-quick",
        "settings-device-advice",
    ):
        assert required in html


def test_runtime_peer_titles_use_ascii_separator_to_avoid_mojibake() -> None:
    html = _index()
    assert "row.title = `${p.display_name || p.hostname || p.short_id} - ${reachLabel(p)}`;" in html
    assert "` · ${reachLabel(p)}`" not in html


def test_settings_about_support_bundle_is_not_hidden_in_advanced() -> None:
    html = _index()
    settings = _settings_shell(html)
    assert 'id="settings-about-runtime"' in settings
    assert 'id="settings-about-runtime-detail"' in settings
    assert 'id="settings-about-copy-diagnostics"' in settings
    assert 'id="settings-about-download-diagnostics"' in settings
    assert '$("#settings-about-copy-diagnostics")?.addEventListener("click"' in html
    assert '$("#settings-about-download-diagnostics")?.addEventListener("click"' in html
