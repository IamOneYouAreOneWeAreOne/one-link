"""Local communication hardware and path inventory.

The Universal Comms Fabric starts by knowing what this device can physically
use. This module is intentionally conservative: it reports capabilities and
hints, but it does not create networks, request permissions, or transmit.
Higher layers can decide whether to ask the user or call a platform helper.
"""

from __future__ import annotations

import ipaddress
import os
import platform
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping

from one_link.bounded_resolver import resolve_bounded
from one_link.process_security import (
    hidden_creationflags,
    resolve_argv,
    resolve_system_executable,
    trusted_process_env,
)


ProbeRunner = Callable[[list[str], float], tuple[int, str, str]]


@dataclass(frozen=True)
class HardwarePath:
    """One local communication surface One Link may be able to use."""

    kind: str
    available: bool
    bulk_capable: bool = False
    control_capable: bool = True
    estimated_bps: float = 0.0
    privacy: str = "unknown"
    range_hint: str = "unknown"
    requires_user_action: bool = False
    requires_admin: bool = False
    safety_state: str = "ok"
    adapter_id: str | None = None
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "adapter_id": self.adapter_id or self.kind,
            "kind": self.kind,
            "available": self.available,
            "bulk_capable": self.bulk_capable,
            "control_capable": self.control_capable,
            "estimated_bps": self.estimated_bps,
            "privacy": self.privacy,
            "range": self.range_hint,
            "requires_user_action": self.requires_user_action,
            "requires_admin": self.requires_admin,
            "safety_state": self.safety_state,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class HardwareInventory:
    """Snapshot of this device's communication surfaces."""

    platform: str
    hostname: str
    paths: tuple[HardwarePath, ...] = field(default_factory=tuple)

    def available(self) -> tuple[HardwarePath, ...]:
        return tuple(p for p in self.paths if p.available)

    def by_kind(self, kind: str) -> tuple[HardwarePath, ...]:
        return tuple(p for p in self.paths if p.kind == kind)

    def strongest_bulk_path(self) -> HardwarePath | None:
        bulk = [p for p in self.available() if p.bulk_capable]
        if not bulk:
            return None
        return max(
            bulk,
            key=lambda p: (
                float(p.estimated_bps),
                p.privacy == "direct_local",
                not p.requires_user_action,
                p.kind,
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "platform": self.platform,
            "hostname": self.hostname,
            "paths": [p.to_dict() for p in self.paths],
        }


def collect_hardware_inventory(
    *,
    env: Mapping[str, str] | None = None,
    runner: ProbeRunner | None = None,
) -> HardwareInventory:
    """Collect a best-effort local hardware/path inventory.

    The function is side-effect-light. It reads OS state using binaries from
    fixed system directories; it does not trust PATH, start hotspot/Wi-Fi
    Direct/BLE scans, or touch RF transmit.
    Tests inject ``env`` and ``runner`` for deterministic behavior.
    """

    env = env or os.environ
    runner = runner or _run_command
    system = platform.system().lower() or "unknown"
    hostname = socket.gethostname()
    paths: list[HardwarePath] = []
    paths.extend(_lan_paths())
    paths.extend(_windows_wireless_paths(system, runner))
    paths.append(_bluetooth_path(system, env, runner))
    paths.append(_usb_storage_path(env))
    paths.append(_webrtc_path(env))
    paths.append(_qr_path(env))
    paths.append(_audio_path(env))
    paths.append(_onefield_path(env))
    return HardwareInventory(
        platform=system,
        hostname=hostname,
        paths=tuple(_dedupe_paths(paths)),
    )


def _lan_paths() -> tuple[HardwarePath, ...]:
    out: list[HardwarePath] = []
    addrs = _local_ip_addresses()
    has_non_loopback = any(not _is_loopback_ip(ip) for ip in addrs)
    link_local = tuple(ip for ip in addrs if _is_link_local_ip(ip))
    out.append(HardwarePath(
        kind="lan",
        adapter_id="lan.ip",
        available=has_non_loopback,
        bulk_capable=has_non_loopback,
        control_capable=True,
        estimated_bps=1_000_000_000.0 if has_non_loopback else 0.0,
        privacy="direct_local",
        range_hint="local_network",
        notes=tuple(addrs[:8]) if addrs else ("no local addresses detected",),
    ))
    out.append(HardwarePath(
        kind="ethernet",
        adapter_id="ethernet.link_local",
        available=bool(link_local),
        bulk_capable=bool(link_local),
        control_capable=True,
        estimated_bps=1_000_000_000.0 if link_local else 0.0,
        privacy="direct_local",
        range_hint="direct_cable_or_switch",
        notes=(
            tuple(f"link-local address {ip}" for ip in link_local[:8])
            if link_local else
            ("no IPv4/IPv6 link-local address detected",)
        ),
    ))
    out.append(HardwarePath(
        kind="loopback",
        adapter_id="loopback.local",
        available=True,
        bulk_capable=True,
        control_capable=True,
        estimated_bps=10_000_000_000.0,
        privacy="same_machine",
        range_hint="same_device",
        notes=("test/local daemon path",),
    ))
    return tuple(out)


def _windows_wireless_paths(system: str, runner: ProbeRunner) -> tuple[HardwarePath, ...]:
    if system != "windows":
        return (
            HardwarePath(
                kind="private_hotspot",
                adapter_id=f"{system}.hotspot",
                available=False,
                bulk_capable=True,
                control_capable=True,
                privacy="direct_local",
                range_hint="room_or_building",
                requires_user_action=True,
                notes=("platform helper required",),
            ),
            HardwarePath(
                kind="wifi_direct",
                adapter_id=f"{system}.wifi_direct",
                available=False,
                bulk_capable=True,
                control_capable=True,
                privacy="direct_local",
                range_hint="room_or_building",
                requires_user_action=True,
                notes=("platform helper required",),
            ),
        )
    rc, stdout, stderr = runner(["netsh", "wlan", "show", "drivers"], 4.0)
    text = f"{stdout}\n{stderr}".lower()
    wireless_present = rc == 0 and (
        "wireless" in text or "hosted network" in text or "wi-fi direct" in text
    )
    hosted_supported = "hosted network supported" in text and "yes" in text
    wifi_direct_hint = "wi-fi direct" in text or "wifi direct" in text
    return (
        HardwarePath(
            kind="private_hotspot",
            adapter_id="windows.hotspot",
            available=wireless_present,
            bulk_capable=True,
            control_capable=True,
            estimated_bps=300_000_000.0 if wireless_present else 0.0,
            privacy="direct_local",
            range_hint="room_or_building",
            requires_user_action=not hosted_supported,
            requires_admin=False,
            notes=(
                "hosted network supported"
                if hosted_supported else
                "wireless present; OS hotspot helper may be needed"
            ,),
        ),
        HardwarePath(
            kind="wifi_direct",
            adapter_id="windows.wifi_direct",
            available=wireless_present and wifi_direct_hint,
            bulk_capable=True,
            control_capable=True,
            estimated_bps=480_000_000.0 if wireless_present else 0.0,
            privacy="direct_local",
            range_hint="room_or_building",
            requires_user_action=not wifi_direct_hint,
            notes=(
                "Wi-Fi Direct hint present"
                if wifi_direct_hint else
                "probe-only; OS API integration required"
            ,),
        ),
    )


def _bluetooth_path(
    system: str,
    env: Mapping[str, str],
    runner: ProbeRunner,
) -> HardwarePath:
    forced = _env_bool(env, "ONE_LINK_ASSUME_BLE")
    available = bool(forced)
    notes: list[str] = []
    if system == "windows" and not available:
        rc, stdout, _ = runner([
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-PnpDevice -Class Bluetooth -PresentOnly | Select-Object -First 1 | ConvertTo-Json -Compress",
        ], 4.0)
        available = rc == 0 and bool(stdout.strip())
        if available:
            notes.append("Bluetooth device detected")
    elif not available:
        try:
            resolve_system_executable("bluetoothctl")
        except (OSError, ValueError):
            pass
        else:
            available = True
            notes.append("bluetoothctl available")
    if forced:
        notes.append("forced by ONE_LINK_ASSUME_BLE")
    return HardwarePath(
        kind="ble_control",
        adapter_id=f"{system}.ble",
        available=available,
        bulk_capable=False,
        control_capable=True,
        estimated_bps=200_000.0 if available else 0.0,
        privacy="proximity",
        range_hint="room",
        requires_user_action=True,
        notes=tuple(notes or ("BLE unavailable or permission not granted",)),
    )


def _usb_storage_path(env: Mapping[str, str]) -> HardwarePath:
    forced = _env_bool(env, "ONE_LINK_ASSUME_USB_COURIER")
    return HardwarePath(
        kind="storage_courier",
        adapter_id="storage.courier",
        available=True,
        bulk_capable=True,
        control_capable=True,
        estimated_bps=120_000_000.0,
        privacy="offline_physical",
        range_hint="hand_carried",
        requires_user_action=not forced,
        notes=("encrypted removable-drive courier path",),
    )


def _webrtc_path(env: Mapping[str, str]) -> HardwarePath:
    disabled = _env_bool(env, "ONE_LINK_DISABLE_WEBRTC")
    return HardwarePath(
        kind="webrtc",
        adapter_id="internet.webrtc",
        available=not disabled,
        bulk_capable=True,
        control_capable=True,
        estimated_bps=80_000_000.0 if not disabled else 0.0,
        privacy="direct_or_relayed_internet",
        range_hint="internet",
        notes=("NAT traversal / sealed relay candidate",),
    )


def _qr_path(env: Mapping[str, str]) -> HardwarePath:
    return HardwarePath(
        kind="qr_control",
        adapter_id="optical.qr",
        available=not _env_bool(env, "ONE_LINK_DISABLE_QR"),
        bulk_capable=False,
        control_capable=True,
        estimated_bps=4_000.0,
        privacy="in_person",
        range_hint="line_of_sight",
        requires_user_action=True,
        notes=("pairing, invite, route hints",),
    )


def _audio_path(env: Mapping[str, str]) -> HardwarePath:
    return HardwarePath(
        kind="audio_control",
        adapter_id="audio.chirp",
        available=_env_bool(env, "ONE_LINK_ENABLE_AUDIO_CONTROL"),
        bulk_capable=False,
        control_capable=True,
        estimated_bps=1_000.0 if _env_bool(env, "ONE_LINK_ENABLE_AUDIO_CONTROL") else 0.0,
        privacy="same_room",
        range_hint="room",
        requires_user_action=True,
        notes=("disabled by default; microphone/speaker permission required",),
    )


def _onefield_path(env: Mapping[str, str]) -> HardwarePath:
    root = env.get("ONEFIELD_MESH_ROOT") or r"$HOME\Projects\OneField Mesh"
    loopback = _env_bool(env, "ONE_LINK_ENABLE_ONEFIELD_LOOPBACK")
    available = os.path.exists(root)
    if loopback:
        return HardwarePath(
            kind="onefield",
            adapter_id="onefield.loopback",
            available=True,
            bulk_capable=True,
            control_capable=True,
            estimated_bps=5_000_000.0,
            privacy="same_machine",
            range_hint="software_loopback",
            requires_user_action=False,
            safety_state="ok",
            notes=("software loopback; RF transmit disabled", root),
        )
    return HardwarePath(
        kind="onefield",
        adapter_id="onefield.optional",
        available=available,
        bulk_capable=False,
        control_capable=True,
        estimated_bps=0.0,
        privacy="experimental_hardware",
        range_hint="hardware_dependent",
        requires_user_action=True,
        safety_state="rx_only_until_safety_gate",
        notes=(root if available else "set ONEFIELD_MESH_ROOT to enable probe",),
    )


def _local_ip_addresses() -> tuple[str, ...]:
    addrs: set[str] = set()
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            # Bounded: resolving this host's own name goes through mDNS for a
            # .local name and blocks for a minute on a degraded network. An
            # inventory entry is never worth stalling its caller.
            infos = resolve_bounded(
                socket.getaddrinfo,
                socket.gethostname(),
                None,
                family,
                socket.SOCK_DGRAM,
                default=[],
                label="hardware inventory local-address enumeration",
            )
        except OSError:
            continue
        for info in infos:
            # ``getaddrinfo`` is OS-controlled, but defensive shape checks
            # keep a malformed provider result from hiding behind a broad
            # per-entry exception boundary.
            if len(info) < 5:
                continue
            sockaddr = info[4]
            if not isinstance(sockaddr, tuple) or not sockaddr:
                continue
            address = sockaddr[0]
            if isinstance(address, str) and address:
                addrs.add(address)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            addrs.add(s.getsockname()[0])
    except OSError:
        pass
    return tuple(sorted(addrs))


def _is_loopback_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%", 1)[0]).is_loopback
    except ValueError:
        return ip.startswith("127.") or ip == "::1" or ip.lower() == "localhost"


def _is_link_local_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%", 1)[0]).is_link_local
    except ValueError:
        return False


def _dedupe_paths(paths: Iterable[HardwarePath]) -> tuple[HardwarePath, ...]:
    out: dict[str, HardwarePath] = {}
    for p in paths:
        out[p.adapter_id or p.kind] = p
    return tuple(out[k] for k in sorted(out))


def _env_bool(env: Mapping[str, str], key: str) -> bool:
    return str(env.get(key, "")).strip().lower() in {"1", "true", "yes", "on"}


def _run_command(argv: list[str], timeout_s: float) -> tuple[int, str, str]:
    # CREATE_NO_WINDOW (0x08000000) on Windows so the periodic hardware
    # inventory probes (wmic / powershell / PnPUtil) don't flash a
    # console window every refresh cycle. The UI polls /api/fabric
    # every 30s, which triggers this; without the flag the user sees
    # a black box pop up on the desktop every 30 seconds.
    if not 0.0 < float(timeout_s) <= 30.0:
        return 127, "", "invalid probe timeout"
    try:
        safe_argv = resolve_argv(argv, system_tool=True)
        r = subprocess.run(
            safe_argv,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
            creationflags=hidden_creationflags(),
            cwd=str(Path(safe_argv[0]).parent),
            env=trusted_process_env(),
            shell=False,
        )
    except (subprocess.SubprocessError, OSError, ValueError) as exc:
        return 127, "", str(exc)
    return int(r.returncode), (r.stdout or "")[:262_144], (r.stderr or "")[:65_536]
