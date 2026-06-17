"""Safety-gated local path creation plans.

This module is deliberately about *plans*, not blind OS mutation. The comms
fabric can tell the UI or a future native helper exactly what ceremony is
needed to create a no-router path, while keeping automatic execution locked
behind explicit safety gates.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, cast

from .hardware_inventory import HardwareInventory, HardwarePath


CREATE_STATES = {"ready", "needs_user", "blocked", "unsupported"}


@dataclass(frozen=True)
class PathCreationPlan:
    path_id: str
    label: str
    state: str
    action: str
    automatic: bool
    requires_user_action: bool
    requires_admin: bool
    bulk_capable: bool
    control_capable: bool
    estimated_bps: float
    command: tuple[str, ...] = ()
    settings_uri: str | None = None
    reason: str = ""
    guide_steps: tuple[str, ...] = ()
    safeguards: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.state not in CREATE_STATES:
            raise ValueError(f"invalid path creation state: {self.state}")

    def to_dict(self) -> dict[str, object]:
        return {
            "path_id": self.path_id,
            "label": self.label,
            "state": self.state,
            "action": self.action,
            "automatic": self.automatic,
            "requires_user_action": self.requires_user_action,
            "requires_admin": self.requires_admin,
            "bulk_capable": self.bulk_capable,
            "control_capable": self.control_capable,
            "estimated_bps": self.estimated_bps,
            "command": list(self.command),
            "settings_uri": self.settings_uri,
            "reason": self.reason,
            "guide_steps": list(self.guide_steps),
            "safeguards": list(self.safeguards),
        }


LaunchFn = Callable[[PathCreationPlan, str], None]
NativeRunner = Callable[[list[str], float], tuple[int, str, str]]


@dataclass(frozen=True)
class NativePathHelper:
    path_id: str
    command: tuple[str, ...]
    label: str = ""
    version: str = ""
    supported_systems: tuple[str, ...] = ()
    requires_admin: bool = False

    def __post_init__(self) -> None:
        if not self.path_id or not self.path_id.replace("_", "").isalnum():
            raise ValueError("native helper path_id must be alphanumeric/underscore")
        if not self.command:
            raise ValueError("native helper command is required")
        # 2026-06-04: a native helper is platform-specific (e.g. a
        # Windows ".exe" registered for supported_systems=("windows",)),
        # so its path must be validated with the TARGET platform's
        # rules, not the host's. Path(...).is_absolute() uses the host
        # pathlib, so a legitimate Windows path like "C:/OneLink/x.exe"
        # was rejected as "not absolute" when the check ran on a POSIX
        # box (CI / a Linux peer). Accept a command path that is
        # absolute under EITHER Windows or POSIX semantics — the real
        # intent is to reject RELATIVE paths (PATH-hijacking risk),
        # which are non-absolute under both.
        import ntpath
        import posixpath

        cmd0 = str(self.command[0])
        if not (ntpath.isabs(cmd0) or posixpath.isabs(cmd0)):
            raise ValueError("native helper executable path must be absolute")

    def applies_to(self, path_id: str, system: str) -> bool:
        systems = {s.lower() for s in self.supported_systems}
        return self.path_id == path_id and (not systems or system.lower() in systems)

    def to_dict(self) -> dict[str, object]:
        return {
            "path_id": self.path_id,
            "label": self.label or self.path_id,
            "version": self.version,
            "command": [self.command[0], *["<arg>" for _ in self.command[1:]]],
            "supported_systems": list(self.supported_systems),
            "requires_admin": self.requires_admin,
        }


def plans_from_inventory(
    inventory: HardwareInventory,
    *,
    system: str | None = None,
) -> tuple[PathCreationPlan, ...]:
    """Build deterministic creation plans from a hardware inventory."""

    system = (system or inventory.platform or platform.system()).lower()
    paths = tuple(inventory.paths)
    return plans_from_paths(paths, system=system)


def plans_from_probe_dicts(
    probes: Iterable[Mapping[str, object]],
    *,
    system: str | None = None,
) -> tuple[PathCreationPlan, ...]:
    paths = tuple(_path_from_probe(p) for p in probes)
    return plans_from_paths(paths, system=(system or platform.system()).lower())


def plans_from_paths(
    paths: Iterable[HardwarePath],
    *,
    system: str,
) -> tuple[PathCreationPlan, ...]:
    by_kind = {p.kind: p for p in paths}
    plans = [
        _ethernet_plan(by_kind.get("ethernet")),
        _hotspot_plan(by_kind.get("private_hotspot"), system=system),
        _wifi_direct_plan(by_kind.get("wifi_direct"), system=system),
        _ble_plan(by_kind.get("ble_control"), system=system),
    ]
    return tuple(sorted(plans, key=_plan_sort_key))


def creation_summary(plans: Iterable[PathCreationPlan]) -> dict[str, object]:
    items = tuple(plans)
    ready = sum(1 for p in items if p.state == "ready")
    needs_user = sum(1 for p in items if p.state == "needs_user")
    blocked = sum(1 for p in items if p.state == "blocked")
    unsupported = sum(1 for p in items if p.state == "unsupported")
    next_plan = next(
        (
            p for p in items
            if p.state in {"ready", "needs_user"}
        ),
        items[0] if items else None,
    )
    return {
        "ready": ready,
        "needs_user": needs_user,
        "blocked": blocked,
        "unsupported": unsupported,
        "next_action": next_plan.action if next_plan else "wait_for_path",
        "plans": [p.to_dict() for p in items],
    }


def launch_creation_plan(
    path_id: str,
    plans: Iterable[PathCreationPlan],
    *,
    dry_run: bool = False,
    system: str | None = None,
    launcher: LaunchFn | None = None,
) -> dict[str, object]:
    """Launch a user-visible OS ceremony for a creation plan.

    This never toggles radios or creates networks silently. It only opens the
    operating system surface described by a plan that is already marked
    ``needs_user`` or ``ready``.
    """

    plan = next((p for p in plans if p.path_id == path_id), None)
    if plan is None:
        raise ValueError("unknown path creation plan")
    if plan.state not in {"ready", "needs_user"}:
        raise ValueError(f"path creation plan is {plan.state}")
    if plan.automatic:
        raise ValueError("automatic path creation is not exposed by this launcher")
    if not plan.settings_uri and not plan.command:
        raise ValueError("path creation plan has no launchable OS ceremony")
    system = (system or platform.system()).lower()
    if not dry_run:
        (launcher or _default_launcher)(plan, system)
    return {
        "ok": True,
        "launched": not dry_run,
        "dry_run": dry_run,
        "path_id": plan.path_id,
        "action": plan.action,
        "settings_uri": plan.settings_uri,
        "command": list(plan.command),
        "safeguards": list(plan.safeguards),
    }


def execute_native_creation_plan(
    path_id: str,
    plans: Iterable[PathCreationPlan],
    *,
    system: str | None = None,
    allow_native: bool = False,
    dry_run: bool = False,
    ssid: str | None = None,
    passphrase: str | None = None,
    runner: NativeRunner | None = None,
    helper_specs: Iterable[NativePathHelper] = (),
) -> dict[str, object]:
    """Execute a supported native path-creation command.

    Only a tiny set of OS command surfaces qualify here. Unsupported surfaces
    return structured evidence instead of pretending a platform can silently
    create a radio path.
    """

    plan = next((p for p in plans if p.path_id == path_id), None)
    if plan is None:
        raise ValueError("unknown path creation plan")
    system = (system or platform.system()).lower()
    if path_id == "direct_ethernet":
        return {
            "ok": True,
            "state": "no_op",
            "path_id": path_id,
            "dry_run": dry_run,
            "commands": [],
            "message": "direct Ethernet is created by attaching the cable or switch",
            "safeguards": list(plan.safeguards),
        }
    if path_id == "private_hotspot" and system == "windows":
        return _execute_windows_hosted_network(
            plan,
            allow_native=allow_native,
            dry_run=dry_run,
            ssid=ssid,
            passphrase=passphrase,
            runner=runner,
        )
    helper = next(
        (h for h in helper_specs if h.applies_to(path_id, system)),
        None,
    )
    if helper is not None:
        return _execute_native_helper(
            plan,
            helper,
            system=system,
            allow_native=allow_native,
            dry_run=dry_run,
            runner=runner,
        )
    if path_id in {"wifi_direct", "ble_control"}:
        raise ValueError(f"{path_id} has no safe silent native creation API on {system}")
    raise ValueError(f"{path_id} native creation is unsupported on {system}")


def native_helpers_from_env(
    env: Mapping[str, str] | None = None,
) -> tuple[NativePathHelper, ...]:
    """Load explicit native helper registrations from environment JSON.

    ONE_LINK_NATIVE_PATH_HELPERS is a JSON list of objects:
    {"path_id":"wifi_direct","command":["C:/.../helper.exe"],"supported_systems":["windows"]}
    """

    env = env or os.environ
    raw = str(env.get("ONE_LINK_NATIVE_PATH_HELPERS") or "").strip()
    if not raw:
        return ()
    try:
        data = json.loads(raw)
    except Exception as exc:
        raise ValueError(f"invalid ONE_LINK_NATIVE_PATH_HELPERS JSON: {exc}") from exc
    if not isinstance(data, list) or len(data) > 16:
        raise ValueError("native helper registry must be a list of at most 16 helpers")
    out: list[NativePathHelper] = []
    for item in data:
        if not isinstance(item, dict):
            raise ValueError("native helper registry entries must be objects")
        command = item.get("command")
        if not isinstance(command, list) or not all(isinstance(x, str) for x in command):
            raise ValueError("native helper command must be a string list")
        systems = item.get("supported_systems")
        if systems is None:
            systems = []
        if not isinstance(systems, list) or not all(isinstance(x, str) for x in systems):
            raise ValueError("native helper supported_systems must be a string list")
        out.append(NativePathHelper(
            path_id=str(item.get("path_id") or ""),
            label=str(item.get("label") or ""),
            version=str(item.get("version") or ""),
            command=tuple(command),
            supported_systems=tuple(systems),
            requires_admin=bool(item.get("requires_admin")),
        ))
    return tuple(out)


def _ethernet_plan(path: HardwarePath | None) -> PathCreationPlan:
    available = bool(path and path.available)
    return PathCreationPlan(
        path_id="direct_ethernet",
        label="Direct Ethernet",
        state="ready" if available else "needs_user",
        action="exchange_route_token" if available else "connect_ethernet_or_same_switch",
        automatic=available,
        requires_user_action=not available,
        requires_admin=False,
        bulk_capable=True,
        control_capable=True,
        estimated_bps=float(path.estimated_bps if path else 1_000_000_000.0),
        reason=(
            "link-local Ethernet is already visible"
            if available else
            "connect both devices with Ethernet or the same unmanaged switch"
        ),
        guide_steps=(
            "connect cable or switch",
            "wait for link-local address",
            "exchange route token",
            "verify pinned peer key",
        ),
        safeguards=_base_safeguards() + ("no OS network creation required",),
    )


def _hotspot_plan(path: HardwarePath | None, *, system: str) -> PathCreationPlan:
    available = bool(path and path.available)
    if not available:
        return _unsupported(
            "private_hotspot",
            "Private hotspot",
            "private hotspot capability was not detected",
            bulk=True,
        )
    if system == "windows":
        return PathCreationPlan(
            path_id="private_hotspot",
            label="Private hotspot",
            state="needs_user",
            action="open_windows_hotspot_settings",
            automatic=False,
            requires_user_action=True,
            requires_admin=bool(getattr(path, "requires_admin", False)),
            bulk_capable=True,
            control_capable=True,
            estimated_bps=float(getattr(path, "estimated_bps", None) or 300_000_000.0),
            command=("start", "ms-settings:network-mobilehotspot"),
            settings_uri="ms-settings:network-mobilehotspot",
            reason="Windows hotspot must be confirmed in OS settings",
            guide_steps=(
                "open mobile hotspot settings",
                "turn on hotspot",
                "join the other device to it",
                "exchange route token",
            ),
            safeguards=_base_safeguards() + (
                "hotspot creation is user-visible",
                "credentials are never published to rendezvous",
            ),
        )
    return PathCreationPlan(
        path_id="private_hotspot",
        label="Private hotspot",
        state="needs_user",
        action="open_os_hotspot_settings",
        automatic=False,
        requires_user_action=True,
        requires_admin=bool(getattr(path, "requires_admin", False)),
        bulk_capable=True,
        control_capable=True,
        estimated_bps=float(getattr(path, "estimated_bps", None) or 180_000_000.0),
        reason=f"{system or 'this platform'} requires a user-visible hotspot ceremony",
        guide_steps=(
            "open OS hotspot settings",
            "turn on hotspot",
            "join the other device to it",
            "exchange route token",
        ),
        safeguards=_base_safeguards() + ("hotspot creation is explicit",),
    )


def _wifi_direct_plan(path: HardwarePath | None, *, system: str) -> PathCreationPlan:
    available = bool(path and path.available)
    if not available:
        return _unsupported(
            "wifi_direct",
            "Wi-Fi Direct",
            "Wi-Fi Direct capability was not detected",
            bulk=True,
        )
    return PathCreationPlan(
        path_id="wifi_direct",
        label="Wi-Fi Direct",
        state="needs_user",
        action="open_wifi_direct_ceremony",
        automatic=False,
        requires_user_action=True,
        requires_admin=bool(getattr(path, "requires_admin", False)),
        bulk_capable=True,
        control_capable=True,
        estimated_bps=float(getattr(path, "estimated_bps", None) or 480_000_000.0),
        reason=f"{system or 'platform'} Wi-Fi Direct needs a visible pairing ceremony",
        settings_uri="ms-settings:network-wifi" if system == "windows" else None,
        command=("start", "ms-settings:network-wifi") if system == "windows" else (),
        guide_steps=(
            "open Wi-Fi Direct device ceremony",
            "pair the devices",
            "exchange route token",
            "verify pinned peer key",
        ),
        safeguards=_base_safeguards() + (
            "Wi-Fi Direct is never auto-started",
            "bulk data remains encrypted above the transport",
        ),
    )


def _ble_plan(path: HardwarePath | None, *, system: str) -> PathCreationPlan:
    available = bool(path and path.available)
    if not available:
        return _unsupported(
            "ble_control",
            "BLE control",
            "BLE control capability was not detected or permission is missing",
            bulk=False,
        )
    return PathCreationPlan(
        path_id="ble_control",
        label="BLE control",
        state="needs_user",
        action="open_ble_control_ceremony",
        automatic=False,
        requires_user_action=True,
        requires_admin=bool(getattr(path, "requires_admin", False)),
        bulk_capable=False,
        control_capable=True,
        estimated_bps=float(getattr(path, "estimated_bps", None) or 80_000.0),
        reason=f"{system or 'platform'} BLE is control-only and permission-gated",
        settings_uri="ms-settings:bluetooth" if system == "windows" else None,
        command=("start", "ms-settings:bluetooth") if system == "windows" else (),
        guide_steps=(
            "grant Bluetooth permission",
            "advertise or scan route token",
            "promote a faster local path",
        ),
        safeguards=_base_safeguards() + (
            "BLE carries control hints only",
            "bulk payloads are never forced through BLE",
        ),
    )


def _unsupported(
    path_id: str,
    label: str,
    reason: str,
    *,
    bulk: bool,
) -> PathCreationPlan:
    return PathCreationPlan(
        path_id=path_id,
        label=label,
        state="unsupported",
        action="wait_for_capability",
        automatic=False,
        requires_user_action=False,
        requires_admin=False,
        bulk_capable=bulk,
        control_capable=True,
        estimated_bps=0.0,
        reason=reason,
        guide_steps=("use Ethernet, same LAN, route token, or courier fallback",),
        safeguards=_base_safeguards(),
    )


def _base_safeguards() -> tuple[str, ...]:
    return (
        "creation plans never bypass pairing",
        "route tokens carry endpoint hints only",
        "local endpoints require key-confirmed promotion",
    )


def _default_launcher(plan: PathCreationPlan, system: str) -> None:
    target = plan.settings_uri
    if target and system == "windows":
        import os

        os.startfile(target)  # type: ignore[attr-defined]
        return
    if target and system == "darwin":
        subprocess.Popen(["open", target])
        return
    if target:
        subprocess.Popen(["xdg-open", target])
        return
    if plan.command:
        subprocess.Popen(list(plan.command))
        return
    raise ValueError("path creation plan has no launchable OS ceremony")


def _execute_windows_hosted_network(
    plan: PathCreationPlan,
    *,
    allow_native: bool,
    dry_run: bool,
    ssid: str | None,
    passphrase: str | None,
    runner: NativeRunner | None,
) -> dict[str, object]:
    clean_ssid = _validate_hotspot_ssid(ssid)
    clean_key = _validate_hotspot_passphrase(passphrase)
    commands = [
        [
            "netsh",
            "wlan",
            "set",
            "hostednetwork",
            "mode=allow",
            f"ssid={clean_ssid}",
            f"key={clean_key}",
        ],
        ["netsh", "wlan", "start", "hostednetwork"],
    ]
    redacted = [
        [part if not part.startswith("key=") else "key=********" for part in cmd]
        for cmd in commands
    ]
    if not allow_native and not dry_run:
        return {
            "ok": False,
            "state": "blocked",
            "path_id": plan.path_id,
            "dry_run": False,
            "commands": redacted,
            "message": "native hotspot creation requires explicit operator opt-in",
            "required_env": "ONE_LINK_ALLOW_NATIVE_PATH_CREATE=1",
            "safeguards": list(plan.safeguards) + [
                "native hotspot execution is opt-in",
                "hotspot passphrase is redacted from API responses",
            ],
        }
    if dry_run:
        return {
            "ok": True,
            "state": "dry_run",
            "path_id": plan.path_id,
            "dry_run": True,
            "commands": redacted,
            "message": "native hotspot commands validated but not executed",
            "safeguards": list(plan.safeguards),
        }
    runner = runner or _run_native_command
    evidence = []
    for cmd in commands:
        rc, stdout, stderr = runner(cmd, 15.0)
        evidence.append({
            "command": [
                part if not part.startswith("key=") else "key=********"
                for part in cmd
            ],
            "returncode": int(rc),
            "stdout": stdout[-2048:],
            "stderr": stderr[-2048:],
        })
        if rc != 0:
            return {
                "ok": False,
                "state": "failed",
                "path_id": plan.path_id,
                "dry_run": False,
                "commands": redacted,
                "evidence": evidence,
                "message": "native hotspot command failed",
                "safeguards": list(plan.safeguards),
            }
    return {
        "ok": True,
        "state": "started",
        "path_id": plan.path_id,
        "dry_run": False,
        "commands": redacted,
        "evidence": evidence,
        "message": "native hotspot command sequence completed",
        "safeguards": list(plan.safeguards),
    }


def _execute_native_helper(
    plan: PathCreationPlan,
    helper: NativePathHelper,
    *,
    system: str,
    allow_native: bool,
    dry_run: bool,
    runner: NativeRunner | None,
) -> dict[str, object]:
    cmd = [
        *helper.command,
        "--one-link-path-create",
        plan.path_id,
        "--system",
        system,
    ]
    redacted = _redact_helper_command(cmd)
    if not allow_native and not dry_run:
        return {
            "ok": False,
            "state": "blocked",
            "path_id": plan.path_id,
            "dry_run": False,
            "helper": helper.to_dict(),
            "commands": [redacted],
            "message": "native helper execution requires explicit operator opt-in",
            "required_env": "ONE_LINK_ALLOW_NATIVE_PATH_CREATE=1",
            "safeguards": list(plan.safeguards) + [
                "native helper execution is opt-in",
                "helper command details are redacted",
            ],
        }
    if dry_run:
        return {
            "ok": True,
            "state": "dry_run",
            "path_id": plan.path_id,
            "dry_run": True,
            "helper": helper.to_dict(),
            "commands": [redacted],
            "message": "native helper command validated but not executed",
            "safeguards": list(plan.safeguards),
        }
    runner = runner or _run_native_command
    rc, stdout, stderr = runner(cmd, 20.0)
    evidence = {
        "command": redacted,
        "returncode": int(rc),
        "stdout": stdout[-2048:],
        "stderr": stderr[-2048:],
    }
    return {
        "ok": rc == 0,
        "state": "started" if rc == 0 else "failed",
        "path_id": plan.path_id,
        "dry_run": False,
        "helper": helper.to_dict(),
        "commands": [redacted],
        "evidence": [evidence],
        "message": (
            "native helper command completed"
            if rc == 0 else
            "native helper command failed"
        ),
        "safeguards": list(plan.safeguards),
    }


def _redact_helper_command(argv: list[str]) -> list[str]:
    redacted: list[str] = []
    hide_next = False
    secret_flags = {"--password", "--passphrase", "--key", "--secret", "--token"}
    for part in argv:
        if hide_next:
            redacted.append("********")
            hide_next = False
            continue
        key, sep, _value = part.partition("=")
        if key.lower() in secret_flags:
            redacted.append(f"{key}=********" if sep else key)
            hide_next = not sep
        else:
            redacted.append(part)
    return redacted


def _validate_hotspot_ssid(value: str | None) -> str:
    clean = str(value or "").strip()
    if not 1 <= len(clean) <= 32:
        raise ValueError("hotspot ssid must be 1..32 characters")
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in clean):
        raise ValueError("hotspot ssid must be printable ASCII")
    return clean


def _validate_hotspot_passphrase(value: str | None) -> str:
    clean = str(value or "")
    if not 8 <= len(clean) <= 63:
        raise ValueError("hotspot passphrase must be 8..63 characters")
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in clean):
        raise ValueError("hotspot passphrase must be printable ASCII")
    return clean


def _run_native_command(argv: list[str], timeout: float) -> tuple[int, str, str]:
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return int(proc.returncode), proc.stdout or "", proc.stderr or ""


def _path_from_probe(probe: Mapping[str, object]) -> HardwarePath:
    return HardwarePath(
        kind=str(probe.get("kind") or "unknown"),
        adapter_id=str(probe.get("adapter_id") or probe.get("kind") or "unknown"),
        available=bool(probe.get("available")),
        bulk_capable=bool(probe.get("bulk_capable")),
        control_capable=bool(probe.get("control_capable", True)),
        estimated_bps=float(cast("float | int | str | None", probe.get("estimated_bps")) or 0.0),
        privacy=str(probe.get("privacy") or "unknown"),
        range_hint=str(probe.get("range") or probe.get("range_hint") or "unknown"),
        requires_user_action=bool(probe.get("requires_user_action")),
        requires_admin=bool(probe.get("requires_admin")),
        safety_state=str(probe.get("safety_state") or "ok"),
    )


def _plan_sort_key(plan: PathCreationPlan) -> tuple[int, int, str]:
    state_rank = {
        "ready": 0,
        "needs_user": 1,
        "blocked": 2,
        "unsupported": 3,
    }.get(plan.state, 4)
    kind_rank = {
        "direct_ethernet": 0,
        "private_hotspot": 1,
        "wifi_direct": 2,
        "ble_control": 3,
    }.get(plan.path_id, 9)
    return (state_rank, kind_rank, plan.path_id)
