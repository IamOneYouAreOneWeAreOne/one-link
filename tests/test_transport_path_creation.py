from __future__ import annotations

import pytest

from one_link.hardware_inventory import HardwareInventory, HardwarePath
from one_link.transport_path_creation import (
    NativePathHelper,
    creation_summary,
    execute_native_creation_plan,
    launch_creation_plan,
    native_helpers_from_env,
    plans_from_inventory,
    plans_from_probe_dicts,
)


def test_creation_plans_rank_ready_ethernet_before_user_hotspot():
    inv = HardwareInventory(
        platform="windows",
        hostname="test",
        paths=(
            HardwarePath(
                kind="ethernet",
                adapter_id="ethernet.test",
                available=True,
                bulk_capable=True,
                estimated_bps=1_000_000_000,
            ),
            HardwarePath(
                kind="private_hotspot",
                adapter_id="windows.hotspot",
                available=True,
                bulk_capable=True,
                requires_user_action=True,
                estimated_bps=300_000_000,
            ),
        ),
    )

    plans = plans_from_inventory(inv, system="windows")

    assert plans[0].path_id == "direct_ethernet"
    assert plans[0].state == "ready"
    hotspot = next(p for p in plans if p.path_id == "private_hotspot")
    assert hotspot.state == "needs_user"
    assert hotspot.settings_uri == "ms-settings:network-mobilehotspot"
    assert hotspot.automatic is False
    assert "key-confirmed" in " ".join(hotspot.safeguards)


def test_creation_summary_is_readable_for_missing_capabilities():
    plans = plans_from_probe_dicts([
        {"kind": "qr_control", "available": True, "bulk_capable": False},
    ], system="linux")

    summary = creation_summary(plans)

    assert summary["unsupported"] >= 3
    assert summary["next_action"] == "connect_ethernet_or_same_switch"
    assert any(p["path_id"] == "ble_control" for p in summary["plans"])


def test_creation_plan_rejects_invalid_internal_state():
    from one_link.transport_path_creation import PathCreationPlan

    with pytest.raises(ValueError):
        PathCreationPlan(
            path_id="bad",
            label="Bad",
            state="maybe",
            action="none",
            automatic=False,
            requires_user_action=False,
            requires_admin=False,
            bulk_capable=False,
            control_capable=False,
            estimated_bps=0.0,
        )


def test_launch_creation_plan_only_opens_user_visible_ceremony():
    plans = plans_from_probe_dicts([
        {
            "kind": "private_hotspot",
            "available": True,
            "bulk_capable": True,
            "requires_user_action": True,
            "estimated_bps": 300_000_000,
        },
    ], system="windows")
    calls = []

    result = launch_creation_plan(
        "private_hotspot",
        plans,
        system="windows",
        launcher=lambda plan, system: calls.append((plan.path_id, system, plan.settings_uri)),
    )

    assert result["ok"] is True
    assert result["launched"] is True
    assert result["settings_uri"] == "ms-settings:network-mobilehotspot"
    assert calls == [("private_hotspot", "windows", "ms-settings:network-mobilehotspot")]


def test_launch_creation_plan_dry_run_does_not_call_launcher():
    plans = plans_from_probe_dicts([
        {
            "kind": "private_hotspot",
            "available": True,
            "bulk_capable": True,
            "requires_user_action": True,
        },
    ], system="windows")
    calls = []

    result = launch_creation_plan(
        "private_hotspot",
        plans,
        dry_run=True,
        system="windows",
        launcher=lambda plan, system: calls.append((plan.path_id, system)),
    )

    assert result["launched"] is False
    assert calls == []


def test_launch_creation_plan_rejects_unsupported_path():
    plans = plans_from_probe_dicts([], system="linux")

    with pytest.raises(ValueError, match="unsupported"):
        launch_creation_plan("wifi_direct", plans, dry_run=True, system="linux")


def test_native_hotspot_dry_run_redacts_passphrase():
    plans = plans_from_probe_dicts([
        {
            "kind": "private_hotspot",
            "available": True,
            "bulk_capable": True,
            "requires_user_action": True,
        },
    ], system="windows")

    result = execute_native_creation_plan(
        "private_hotspot",
        plans,
        system="windows",
        dry_run=True,
        ssid="OneLinkTest",
        passphrase="supersecret1",
    )

    assert result["ok"] is True
    assert result["state"] == "dry_run"
    rendered = " ".join(" ".join(cmd) for cmd in result["commands"])
    assert "supersecret1" not in rendered
    assert "key=********" in rendered


def test_native_hotspot_blocks_without_explicit_opt_in():
    plans = plans_from_probe_dicts([
        {
            "kind": "private_hotspot",
            "available": True,
            "bulk_capable": True,
            "requires_user_action": True,
        },
    ], system="windows")

    result = execute_native_creation_plan(
        "private_hotspot",
        plans,
        system="windows",
        ssid="OneLinkTest",
        passphrase="supersecret1",
    )

    assert result["ok"] is False
    assert result["state"] == "blocked"
    assert result["required_env"] == "ONE_LINK_ALLOW_NATIVE_PATH_CREATE=1"


def test_native_hotspot_executes_in_order_when_opted_in():
    plans = plans_from_probe_dicts([
        {
            "kind": "private_hotspot",
            "available": True,
            "bulk_capable": True,
            "requires_user_action": True,
        },
    ], system="windows")
    calls = []

    def runner(argv, timeout):
        calls.append((argv, timeout))
        return 0, "ok", ""

    result = execute_native_creation_plan(
        "private_hotspot",
        plans,
        system="windows",
        allow_native=True,
        ssid="OneLinkTest",
        passphrase="supersecret1",
        runner=runner,
    )

    assert result["ok"] is True
    assert result["state"] == "started"
    assert len(calls) == 2
    assert calls[0][0][:4] == ["netsh", "wlan", "set", "hostednetwork"]
    assert calls[1][0] == ["netsh", "wlan", "start", "hostednetwork"]
    assert "supersecret1" not in str(result)


def test_native_wifi_direct_reports_unsupported_silent_api():
    plans = plans_from_probe_dicts([
        {
            "kind": "wifi_direct",
            "available": True,
            "bulk_capable": True,
            "requires_user_action": True,
        },
    ], system="windows")

    with pytest.raises(ValueError, match="no safe silent native creation API"):
        execute_native_creation_plan(
            "wifi_direct",
            plans,
            system="windows",
            dry_run=True,
        )


def test_native_hotspot_validates_credentials_before_command_building():
    plans = plans_from_probe_dicts([
        {
            "kind": "private_hotspot",
            "available": True,
            "bulk_capable": True,
            "requires_user_action": True,
        },
    ], system="windows")

    with pytest.raises(ValueError, match="passphrase"):
        execute_native_creation_plan(
            "private_hotspot",
            plans,
            system="windows",
            dry_run=True,
            ssid="OneLinkTest",
            passphrase="short",
        )


def test_native_helper_dry_run_for_wifi_direct_uses_registered_absolute_helper():
    plans = plans_from_probe_dicts([
        {
            "kind": "wifi_direct",
            "available": True,
            "bulk_capable": True,
            "requires_user_action": True,
        },
    ], system="windows")
    helper = NativePathHelper(
        path_id="wifi_direct",
        command=("C:/OneLink/ol-wifi-direct-helper.exe", "--mode=safe"),
        supported_systems=("windows",),
        version="1.0",
    )

    result = execute_native_creation_plan(
        "wifi_direct",
        plans,
        system="windows",
        dry_run=True,
        helper_specs=(helper,),
    )

    assert result["ok"] is True
    assert result["state"] == "dry_run"
    assert result["helper"]["path_id"] == "wifi_direct"
    assert result["commands"][0][-4:] == [
        "--one-link-path-create",
        "wifi_direct",
        "--system",
        "windows",
    ]


def test_native_helper_executes_with_opt_in_and_redacts_secret_args():
    plans = plans_from_probe_dicts([
        {
            "kind": "ble_control",
            "available": True,
            "bulk_capable": False,
            "control_capable": True,
            "requires_user_action": True,
        },
    ], system="windows")
    helper = NativePathHelper(
        path_id="ble_control",
        command=("C:/OneLink/ol-ble-helper.exe", "--token", "super-secret"),
        supported_systems=("windows",),
    )
    calls = []

    result = execute_native_creation_plan(
        "ble_control",
        plans,
        system="windows",
        allow_native=True,
        helper_specs=(helper,),
        runner=lambda argv, timeout: calls.append((argv, timeout)) or (0, "ok", ""),
    )

    assert result["ok"] is True
    assert result["state"] == "started"
    assert calls and calls[0][0][0] == "C:/OneLink/ol-ble-helper.exe"
    assert "super-secret" not in str(result)
    assert "********" in str(result)


def test_native_helper_registry_from_env_validates_absolute_paths():
    helpers = native_helpers_from_env({
        "ONE_LINK_NATIVE_PATH_HELPERS": (
            '[{"path_id":"wifi_direct",'
            '"command":["C:/OneLink/helper.exe"],'
            '"supported_systems":["windows"],'
            '"version":"1"}]'
        ),
    })

    assert helpers[0].path_id == "wifi_direct"
    assert helpers[0].command == ("C:/OneLink/helper.exe",)


def test_native_helper_registry_rejects_relative_helper_paths():
    with pytest.raises(ValueError, match="absolute"):
        native_helpers_from_env({
            "ONE_LINK_NATIVE_PATH_HELPERS": (
                '[{"path_id":"wifi_direct","command":["helper.exe"]}]'
            ),
        })
