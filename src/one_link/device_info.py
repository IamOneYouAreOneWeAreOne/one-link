"""Cross-platform device-type detection for One Link.

Each daemon advertises a stable, human-meaningful device kind in
its mDNS TXT record (and richer detail in its CAPS frame), so the
pair-a-new-device list can show "Alex's MacBook Pro" instead of
"30f968ee · 192.168.1.142".

Detection is best-effort and never raises — every probe is wrapped
so a missing tool / permission denial / quirky platform falls back
to a sensible default. The output is a `DeviceInfo` dataclass with:

  os:        windows | macos | linux | bsd | ios | android | other
  kind:      desktop | laptop | server | mobile | tablet | embedded | unknown
  vendor:    e.g. "Apple", "Lenovo", "Dell" — empty if unknown
  model:     e.g. "MacBookPro18,1", "ThinkPad X1" — empty if unknown
  arch:      x86_64 | arm64 | armv7 | unknown
  display:   pretty short label, e.g. "MacBook Pro" / "Windows laptop"

The compact form for the mDNS TXT record is `<os>-<kind>` (e.g.
`macos-laptop`); the full DeviceInfo travels post-handshake in the
CAPS frame so a peer can render the rich label.
"""
from __future__ import annotations

import contextlib
import os
import platform
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from one_link.platform_guard import install_windows_platform_fastpath

install_windows_platform_fastpath()


@dataclass
class DeviceInfo:
    os: str = "other"            # windows | macos | linux | bsd | ios | android | other
    kind: str = "unknown"        # desktop | laptop | server | mobile | tablet | embedded | unknown
    vendor: str = ""
    model: str = ""
    arch: str = "unknown"
    display: str = ""            # pretty short label

    def to_dict(self) -> dict[str, str]:
        return {
            "os": self.os,
            "kind": self.kind,
            "vendor": self.vendor,
            "model": self.model,
            "arch": self.arch,
            "display": self.display,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "DeviceInfo":
        if not d:
            return cls()
        return cls(
            os=str(d.get("os", "other")),
            kind=str(d.get("kind", "unknown")),
            vendor=str(d.get("vendor", "")),
            model=str(d.get("model", "")),
            arch=str(d.get("arch", "unknown")),
            display=str(d.get("display", "")),
        )

    def compact(self) -> str:
        """Compact `<os>-<kind>` for the mDNS TXT record. Bounded
        length, no special chars — safe across mDNS implementations."""
        return f"{self.os}-{self.kind}"


# ─── platform-specific probes ──────────────────────────────────────

def _normalize_arch() -> str:
    m = (platform.machine() or "").lower()
    if m in ("amd64", "x86_64", "x64"):
        return "x86_64"
    if m in ("arm64", "aarch64"):
        return "arm64"
    if m.startswith("armv7") or m.startswith("armv6"):
        return "armv7"
    if m in ("i386", "i686", "x86"):
        return "x86"
    return m or "unknown"


def _safe_run(cmd: list[str], *, timeout: float = 1.5) -> str:
    """Run a small command, return stdout or empty string on any
    error. Bounded; never blocks the daemon startup if a tool hangs."""
    try:
        out = subprocess.run(
            cmd,
            capture_output=True, text=True, check=False,
            timeout=timeout,
        )
        return (out.stdout or "").strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, Exception):
        return ""


# ─── Windows ───────────────────────────────────────────────────────

# DMI / WMI Win32_ComputerSystem.PCSystemType:
#   0 = Unspecified, 1 = Desktop, 2 = Mobile (laptop),
#   3 = Workstation, 4 = Enterprise Server, 5 = SOHO Server,
#   6 = Appliance PC, 7 = Performance Server, 8 = Maximum
_WIN_PC_TYPE = {
    1: "desktop",
    2: "laptop",
    3: "desktop",     # Workstation = beefy desktop
    4: "server",
    5: "server",
    6: "embedded",
    7: "server",
}


def _detect_windows() -> DeviceInfo:
    info = DeviceInfo(os="windows", arch=_normalize_arch())
    # Battery presence is the most reliable laptop signal on Windows
    # without elevation. Try psutil first; fall back to powershell.
    has_battery = False
    try:
        import psutil  # types-psutil stub package supplies the type info
        b = psutil.sensors_battery()
        has_battery = b is not None
    except Exception:
        # Fall back to a tiny powershell call.
        out = _safe_run([
            "powershell", "-NoProfile", "-Command",
            "(Get-CimInstance Win32_Battery).Status",
        ])
        has_battery = bool(out and out.lower() != "null")
    info.kind = "laptop" if has_battery else "desktop"

    # Vendor / model / canonical PCSystemType.
    out = _safe_run([
        "powershell", "-NoProfile", "-Command",
        "(Get-CimInstance Win32_ComputerSystem"
        " | Select-Object -Property Manufacturer,Model,PCSystemType"
        " | ConvertTo-Csv -NoTypeInformation"
        " | Select-Object -Skip 1)",
    ])
    if out:
        # Single CSV row: "Manufacturer","Model","PCSystemType"
        try:
            import csv
            import io
            row = next(csv.reader(io.StringIO(out)))
            if len(row) >= 1:
                info.vendor = row[0].strip()
            if len(row) >= 2:
                info.model = row[1].strip()
            if len(row) >= 3:
                try:
                    pc_type = int(row[2].strip())
                    info.kind = _WIN_PC_TYPE.get(pc_type, info.kind)
                except (ValueError, TypeError):
                    pass
        except Exception:
            pass

    info.display = _windows_display_label(info)
    return info


def _windows_display_label(info: DeviceInfo) -> str:
    if info.vendor and info.model:
        return f"{info.vendor} {info.model}"
    if info.model:
        return info.model
    return f"Windows {info.kind}".strip()


# ─── macOS ─────────────────────────────────────────────────────────

# Apple model identifiers we care about. The full prefix uniquely
# identifies the line. `iMacPro` is included separately because it
# isn't a regular iMac for kind purposes.
_MAC_LAPTOP_PREFIXES = ("MacBook",)
_MAC_DESKTOP_PREFIXES = (
    "iMac", "iMacPro", "Macmini", "MacPro", "Mac",
)

_MAC_PRETTY = {
    "MacBookPro": "MacBook Pro",
    "MacBookAir": "MacBook Air",
    "MacBook": "MacBook",
    "iMacPro": "iMac Pro",
    "iMac": "iMac",
    "Macmini": "Mac mini",
    "MacPro": "Mac Pro",
    "Mac": "Mac",         # Apple silicon Studio shows as Mac<N>,<M>
}


def _detect_macos() -> DeviceInfo:
    info = DeviceInfo(os="macos", vendor="Apple", arch=_normalize_arch())
    raw = _safe_run(["sysctl", "-n", "hw.model"])
    info.model = raw or ""
    # Pretty prefix is the longest match — "MacBookPro18,1" should
    # match "MacBookPro" before "MacBook".
    pretty = "Mac"
    for prefix in sorted(_MAC_PRETTY, key=len, reverse=True):
        if raw.startswith(prefix):
            pretty = _MAC_PRETTY[prefix]
            break
    if any(raw.startswith(p) for p in _MAC_LAPTOP_PREFIXES):
        info.kind = "laptop"
    elif any(raw.startswith(p) for p in _MAC_DESKTOP_PREFIXES):
        info.kind = "desktop"
    else:
        # Apple silicon Mac Studio shows as Mac14,13 etc — desktop.
        info.kind = "desktop" if raw.startswith("Mac") else "unknown"
    info.display = pretty
    return info


# ─── Linux ─────────────────────────────────────────────────────────

# DMI chassis_type codes per SMBIOS spec.
#   3 Desktop, 4 Low-profile Desktop, 5 Pizza Box, 6 Mini Tower,
#   7 Tower, 8 Portable, 9 Laptop, 10 Notebook, 11 Hand Held,
#   12 Docking Station, 13 All-in-One, 14 Sub Notebook,
#   15 Space-saving, 16 Lunch Box, 17 Main Server Chassis,
#   18 Expansion Chassis, 19 SubChassis, 20 Bus Expansion,
#   21 Peripheral, 22 RAID, 23 Rack Mount, 24 Sealed Case PC,
#   30 Tablet, 31 Convertible, 32 Detachable
_DMI_CHASSIS = {
    3: "desktop", 4: "desktop", 5: "desktop", 6: "desktop", 7: "desktop",
    8: "laptop", 9: "laptop", 10: "laptop", 14: "laptop",
    11: "mobile",
    13: "desktop",
    17: "server", 23: "server",
    30: "tablet", 31: "laptop", 32: "tablet",
    24: "embedded",
}


def _read_dmi(name: str) -> str:
    p = Path(f"/sys/class/dmi/id/{name}")
    try:
        return p.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _detect_linux() -> DeviceInfo:
    info = DeviceInfo(os="linux", arch=_normalize_arch())
    # Battery → laptop is a strong default before DMI.
    bat_glob = list(Path("/sys/class/power_supply").glob("BAT*")) \
        if Path("/sys/class/power_supply").is_dir() else []
    info.kind = "laptop" if bat_glob else "desktop"
    # DMI overrides if present + parseable.
    chassis_raw = _read_dmi("chassis_type")
    try:
        chassis_int = int(chassis_raw)
        kind = _DMI_CHASSIS.get(chassis_int)
        if kind:
            info.kind = kind
    except (ValueError, TypeError):
        pass
    info.vendor = _read_dmi("sys_vendor") or _read_dmi("chassis_vendor")
    product = _read_dmi("product_name") or _read_dmi("board_name")
    info.model = product
    # Heuristic: if hostname contains "server" or "rpi" / "raspi"
    # signals; respect the DMI answer first, fall back to hostname.
    hn = (platform.node() or "").lower()
    if info.kind == "desktop" and ("server" in hn or "kube" in hn or "k8s" in hn):
        info.kind = "server"
    if "raspberrypi" in hn or "raspi" in hn or info.model.lower().startswith("raspberry"):
        info.kind = "embedded"
        info.vendor = info.vendor or "Raspberry Pi"
    info.display = _linux_display_label(info)
    return info


def _linux_display_label(info: DeviceInfo) -> str:
    if info.vendor and info.model:
        return f"{info.vendor} {info.model}".strip()
    if info.model:
        return info.model
    return f"Linux {info.kind}".strip()


# ─── BSD / others (best-effort) ────────────────────────────────────

def _detect_bsd() -> DeviceInfo:
    info = DeviceInfo(os="bsd", arch=_normalize_arch())
    info.model = platform.platform() or ""
    info.kind = "desktop"  # no easy laptop probe; user can override
    info.display = info.model or "BSD"
    return info


def _detect_other() -> DeviceInfo:
    return DeviceInfo(
        os="other", arch=_normalize_arch(),
        kind="unknown", display=platform.platform() or "Unknown device",
    )


# ─── public entry point ───────────────────────────────────────────

_CACHED: DeviceInfo | None = None


def detect(*, force: bool = False) -> DeviceInfo:
    """Return DeviceInfo for the local machine. Cached after first
    call (detection probes are mildly expensive on Windows + Linux).
    Pass `force=True` to re-probe."""
    global _CACHED
    if _CACHED is not None and not force:
        return _CACHED
    sys_name = (sys.platform or "").lower()
    try:
        if sys_name.startswith("win"):
            info = _detect_windows()
        elif sys_name == "darwin":
            info = _detect_macos()
        elif sys_name.startswith("linux"):
            info = _detect_linux()
        elif sys_name.endswith("bsd") or sys_name == "freebsd":
            info = _detect_bsd()
        else:
            info = _detect_other()
    except Exception:
        info = DeviceInfo()
    if not info.display:
        info.display = f"{info.os} {info.kind}".strip()
    _CACHED = info
    return info


__all__ = ["DeviceInfo", "detect"]
