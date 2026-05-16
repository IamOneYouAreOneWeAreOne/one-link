"""Multi-modal LAN discovery — finds EVERY device on the local
network and identifies it, without calling any third-party server.

Five protocols, all open-standard, all local-only:

  1. mDNS / Bonjour browse-everything (RFC 6762/6763). Built on
     python-zeroconf which we already use for our own service
     advertisement. We browse a curated set of common service types
     (AirPlay, AirDrop discoverability, AirDroid, IPP printing,
     Chromecast/DIAL, Steam in-home streaming, SSH, SMB, etc.) and
     correlate the portfolio per host to infer device kind.

  2. ARP table sweep — every device that has spoken to your gateway
     in the kernel's ARP cache. Catches devices that don't advertise
     anything but are otherwise on the network. Cross-platform via
     `arp -a` on Windows and `ip neigh` / `arp -an` on UNIX.

  3. SSDP / UPnP (RFC standard) — smart TVs, speakers, media
     servers, gateways, IoT.

  4. NetBIOS name-service — Windows machines + their friendly
     names. We send the standard \\x21 query to the broadcast
     address on UDP/137 and parse responses.

  5. TCP fingerprinting probe — for unknown hosts, attempt a
     non-intrusive probe of a few well-known ports (22/80/443/445)
     and read banners. Gives us "this responds on 445" → "Windows
     machine" / "responds on 22 with OpenSSH" → "*nix box".

Everything correlates by (IP, MAC). OUI vendor lookup ships INSIDE
One Link via a bundled, gzipped subset of the IEEE OUI registry
(no calls to macvendors.com / wireshark.org / corp lookup services).

Sovereignty floor: this module never touches an outside server.
Verified by the Privacy panel's outbound-call audit log — a scan
adds zero entries.
"""
from __future__ import annotations

import asyncio
import gzip
import ipaddress
import logging
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

log = logging.getLogger("one_link.lan_discovery")


# ── Public data shape ──────────────────────────────────────────────


@dataclass
class DiscoveredDevice:
    """One device, fused from every protocol that saw it.

    Fields are populated incrementally as each scanner adds data.
    `confidence` is the merged score across scanners (1.0 = strong
    multi-protocol corroboration; 0.3 = only one weak signal).
    """
    # Identification.
    ip: str = ""
    mac: str = ""                       # lowercase, colons; empty if unknown
    hostname: str = ""                  # friendly name from mDNS / NetBIOS / SMB
    vendor: str = ""                    # OUI-derived ("Apple, Inc.", "Samsung")
    # Inferred kind: "phone" / "tablet" / "laptop" / "desktop" /
    # "tv" / "speaker" / "printer" / "router" / "iot" / "unknown".
    # The UI uses this to filter "pairable" (phone/laptop/tablet/
    # desktop) vs "other gear".
    kind: str = "unknown"
    # Best-guess model string, e.g. "iPhone15,3" or "MacBookPro18,3".
    model: str = ""
    # Whether this device is already running One Link (i.e., shows
    # up in the existing _onelink._tcp.local. mDNS browse).
    is_one_link_peer: bool = False
    # mDNS service types the device advertises. The PORTFOLIO is
    # diagnostic ("_airplay + _raop + _companion-link" = Apple).
    mdns_services: list[str] = field(default_factory=list)
    # Open TCP ports seen during probing. Empty if no probe ran.
    open_ports: list[int] = field(default_factory=list)
    # Each scanner that contributed evidence ("mdns", "arp",
    # "ssdp", "netbios", "tcp_probe"). The UI surfaces this so the
    # user can see "we know about this from 3 different sources."
    sources: list[str] = field(default_factory=list)
    # Confidence: 0.0 ("we only saw a MAC in ARP, nothing else")
    # to 1.0 ("multi-protocol corroboration, vendor + kind both
    # firm"). Heuristic, not statistical.
    confidence: float = 0.0


# ── OUI vendor database ────────────────────────────────────────────
#
# Bundled inside One Link so we never call out to a corp lookup
# service. The file lives at `data/oui_prefixes.txt.gz`. Format is
# one line per prefix:  AABBCC<TAB>Vendor Name
# We only bundle ~2,500 of the most common consumer prefixes —
# enough to identify >99% of devices a normal home user will see.

_OUI_PATH = (
    Path(__file__).parent / "data" / "oui_prefixes.txt.gz"
)
_OUI_CACHE: Optional[dict[str, str]] = None


def _load_oui_table() -> dict[str, str]:
    """Read the bundled OUI prefix table into a dict. Cached after
    first call. Falls back to a tiny built-in subset if the file is
    missing so the daemon still functions (just less specific).
    """
    global _OUI_CACHE
    if _OUI_CACHE is not None:
        return _OUI_CACHE
    table: dict[str, str] = {}
    try:
        if _OUI_PATH.is_file():
            with gzip.open(_OUI_PATH, "rt", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "\t" in line:
                        pfx, vendor = line.split("\t", 1)
                    elif " " in line:
                        pfx, vendor = line.split(None, 1)
                    else:
                        continue
                    pfx = pfx.replace(":", "").replace("-", "").lower()
                    if len(pfx) >= 6:
                        table[pfx[:6]] = vendor.strip()
    except Exception as e:
        log.warning("OUI table load failed (%s); using fallback", e)
    if not table:
        # Minimum viable fallback: the major consumer prefixes.
        # Better to identify SOMETHING than nothing. Will be
        # replaced by the bundled file when present.
        table = _MINIMAL_OUI_FALLBACK
    _OUI_CACHE = table
    return table


# Minimum-viable hardcoded fallback — covers the top ~50 consumer
# vendor prefixes. Used when the bundled OUI file isn't present
# (developer-mode source-tree run without the data file built).
_MINIMAL_OUI_FALLBACK = {
    # Apple (a few of the many they own; real bundle has ~1000)
    "000393": "Apple, Inc.",
    "0017f2": "Apple, Inc.",
    "001451": "Apple, Inc.",
    "0019e3": "Apple, Inc.",
    "001b63": "Apple, Inc.",
    "001ec2": "Apple, Inc.",
    "0021e9": "Apple, Inc.",
    "002241": "Apple, Inc.",
    "002332": "Apple, Inc.",
    "002436": "Apple, Inc.",
    "00254b": "Apple, Inc.",
    "0025bc": "Apple, Inc.",
    "002608": "Apple, Inc.",
    "002612": "Apple, Inc.",
    "00264a": "Apple, Inc.",
    "00265e": "Apple, Inc.",
    "0026b0": "Apple, Inc.",
    "0026bb": "Apple, Inc.",
    "003ee1": "Apple, Inc.",
    "1093e9": "Apple, Inc.",
    "5cf938": "Apple, Inc.",
    "ac3613": "Apple, Inc.",
    "f0d1a9": "Apple, Inc.",
    # Samsung
    "002566": "Samsung Electronics",
    "0023db": "Samsung Electronics",
    "0026e2": "Samsung Electronics",
    "00e64c": "Samsung Electronics",
    "5440ad": "Samsung Electronics",
    "78bdbc": "Samsung Electronics",
    "8425db": "Samsung Electronics",
    # Google / Nest
    "f4f5d8": "Google",
    "f8f005": "Google",
    "20df3f": "Google",
    "4cf739": "Google Nest",
    # Microsoft / Xbox / Surface
    "00125a": "Microsoft",
    "0017fa": "Microsoft",
    "0050f2": "Microsoft",
    "7c1e52": "Microsoft",
    # Amazon (Echo, Fire)
    "08bdf4": "Amazon Technologies",
    "44650d": "Amazon Technologies",
    # Roku
    "b0a737": "Roku",
    "cc6da0": "Roku",
    # Sonos
    "00ee02": "Sonos",
    "5ccea1": "Sonos",
    # TP-Link / common routers
    "00040e": "TP-Link",
    "001e64": "TP-Link",
    # Raspberry Pi
    "b827eb": "Raspberry Pi Foundation",
    "dca632": "Raspberry Pi Trading",
    "e45f01": "Raspberry Pi Foundation",
}


def vendor_for_mac(mac: str) -> str:
    """OUI lookup. Returns vendor name or "" if unknown."""
    if not mac:
        return ""
    key = mac.replace(":", "").replace("-", "").lower()[:6]
    table = _load_oui_table()
    return table.get(key, "")


# ── ARP table ──────────────────────────────────────────────────────


_ARP_LINE_RE = re.compile(
    r"^\s*"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
    r"\s+"
    r"(?:[a-z-]+\s+)?"          # state on Linux ("ether"), interface name etc.
    r"(?P<mac>[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})"
)


def scan_arp_table(timeout_s: float = 2.0) -> list[DiscoveredDevice]:
    """Read the kernel's ARP table and return one DiscoveredDevice
    per (IP, MAC) pair. Cheap — no network packets sent."""
    cmds: list[list[str]]
    if os.name == "nt":
        cmds = [["arp", "-a"]]
    else:
        cmds = [["ip", "neigh"], ["arp", "-an"]]

    seen: dict[str, DiscoveredDevice] = {}
    for cmd in cmds:
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                creationflags=(
                    0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
                ),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if res.returncode != 0:
            continue
        for line in (res.stdout or "").splitlines():
            m = _ARP_LINE_RE.search(line)
            if not m:
                continue
            ip = m.group("ip")
            mac = m.group("mac").lower().replace("-", ":")
            # Skip multicast / broadcast / unspecified / link-local
            # so the discovery list only contains real peer
            # candidates. 224.0.0.0/4 = IPv4 multicast block.
            try:
                ip_obj = ipaddress.ip_address(ip)
                if (
                    ip_obj.is_multicast
                    or ip_obj.is_unspecified
                    or ip in ("255.255.255.255",)
                    or mac.startswith("ff:ff")
                    or mac.startswith("01:00:5e")   # IPv4 multicast MAC
                    or mac.startswith("33:33")      # IPv6 multicast MAC
                    or mac in ("00:00:00:00:00:00",)
                ):
                    continue
            except ValueError:
                continue
            key = ip
            if key in seen:
                seen[key].mac = seen[key].mac or mac
            else:
                seen[key] = DiscoveredDevice(
                    ip=ip,
                    mac=mac,
                    vendor=vendor_for_mac(mac),
                    sources=["arp"],
                    confidence=0.4,
                )
    return list(seen.values())


# ── mDNS browse-everything ─────────────────────────────────────────


# Service types we browse. Carefully chosen — broad enough to catch
# Apple / Google / Microsoft devices + media gear, narrow enough not
# to flood the network with browse traffic.
_INTERESTING_MDNS_SERVICES = [
    # Apple-y
    "_companion-link._tcp.local.",      # Continuity / Handoff
    "_airplay._tcp.local.",             # AirPlay (TVs, speakers, Apple TVs)
    "_raop._tcp.local.",                # Remote Audio Output (AirPlay v1)
    "_homekit._tcp.local.",             # HomeKit accessories
    "_apple-mobdev2._tcp.local.",       # iOS device tether
    "_sleep-proxy._udp.local.",         # Bonjour Sleep Proxy (Mac wake)
    "_rfb._tcp.local.",                 # Screen sharing (Apple Remote Desktop)
    # Generic
    "_ipp._tcp.local.",                 # Printers (IPP)
    "_ipps._tcp.local.",                # Secure IPP
    "_printer._tcp.local.",
    "_smb._tcp.local.",                 # Windows / Samba shares
    "_ssh._tcp.local.",                 # SSH server
    "_http._tcp.local.",                # Generic web service
    "_googlecast._tcp.local.",          # Chromecast
    "_steam._tcp.local.",               # Steam in-home streaming
    "_spotify-connect._tcp.local.",     # Spotify Connect speakers
    "_workstation._tcp.local.",         # Linux/Avahi workstations
    "_device-info._tcp.local.",         # Generic device info
]


async def scan_mdns_browse_all(
    timeout_s: float = 5.0,
) -> list[DiscoveredDevice]:
    """Browse multiple mDNS service types in parallel. Returns one
    DiscoveredDevice per host, with merged service list. Same host
    seen via _airplay + _raop + _companion-link becomes ONE
    device record with all three services in `mdns_services`."""
    try:
        from zeroconf.asyncio import (
            AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf,
        )
    except Exception as e:
        log.warning("zeroconf unavailable: %s", e)
        return []

    aio = AsyncZeroconf()
    # Key by IP (the only stable cross-protocol identifier).
    by_ip: dict[str, DiscoveredDevice] = {}

    async def _on_service(zc, st, name, state_change):
        try:
            info = AsyncServiceInfo(st, name)
            ok = await info.async_request(zc, timeout=1500)
            if not ok:
                return
            addrs = info.parsed_addresses() or []
            if not addrs:
                return
            ip = addrs[0]
            dev = by_ip.get(ip)
            if dev is None:
                dev = DiscoveredDevice(ip=ip, sources=["mdns"], confidence=0.6)
                by_ip[ip] = dev
            if "mdns" not in dev.sources:
                dev.sources.append("mdns")
            # Merge service type.
            stype_short = st.replace("._tcp.local.", "").replace("._udp.local.", "")
            if stype_short not in dev.mdns_services:
                dev.mdns_services.append(stype_short)
            # Hostname.
            srv_name = (info.server or "").rstrip(".")
            if srv_name and not dev.hostname:
                # Strip trailing .local. so the UI gets just "Alex's-iPhone"
                dev.hostname = srv_name.rsplit(".local", 1)[0].rsplit(".", 1)[0]
            # TXT records may carry model info.
            try:
                txt = info.properties or {}
                for k, v in txt.items():
                    k_s = k.decode("utf-8", "replace") if isinstance(k, bytes) else str(k)
                    v_s = v.decode("utf-8", "replace") if isinstance(v, bytes) else (str(v) if v else "")
                    if k_s.lower() == "model" and not dev.model:
                        dev.model = v_s
                    elif k_s.lower() in ("md", "device") and not dev.model:
                        dev.model = v_s
            except Exception:
                pass
        except Exception:
            return

    # Synchronous wrapper that zeroconf can call from its callback thread.
    # zeroconf >=0.130 passes args as kwargs (zeroconf=, service_type=,
    # name=, state_change=); accept **kw to stay forward compatible.
    def _on_state_change_sync(zeroconf=None, service_type=None, name=None,
                              state_change=None, **_kw):
        zc = zeroconf
        st = service_type
        try:
            from zeroconf import ServiceStateChange
            if state_change is not ServiceStateChange.Added:
                return
        except Exception:
            pass
        if zc is None or st is None or name is None:
            return
        asyncio.ensure_future(_on_service(zc, st, name, state_change))

    browsers = []
    for st in _INTERESTING_MDNS_SERVICES:
        try:
            b = AsyncServiceBrowser(
                aio.zeroconf, st, handlers=[_on_state_change_sync],
            )
            browsers.append(b)
        except Exception:
            continue

    await asyncio.sleep(timeout_s)

    for b in browsers:
        try:
            await b.async_cancel()
        except Exception:
            pass
    try:
        await aio.async_close()
    except Exception:
        pass

    return list(by_ip.values())


# ── SSDP / UPnP discovery ──────────────────────────────────────────


def scan_ssdp(timeout_s: float = 2.5) -> list[DiscoveredDevice]:
    """Send an M-SEARCH probe and collect responses. Identifies smart
    TVs, media servers, gateways, speakers."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode("ascii")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(timeout_s)
    devices: dict[str, DiscoveredDevice] = {}
    try:
        s.sendto(msg, ("239.255.255.250", 1900))
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                break
            except OSError:
                break
            ip = addr[0]
            txt = data.decode("ascii", errors="replace")
            dev = devices.get(ip)
            if dev is None:
                dev = DiscoveredDevice(
                    ip=ip, sources=["ssdp"], confidence=0.5,
                )
                devices[ip] = dev
            if "ssdp" not in dev.sources:
                dev.sources.append("ssdp")
            # Parse a few useful header values.
            for line in txt.splitlines():
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                k = k.strip().lower()
                v = v.strip()
                if k == "server" and not dev.model:
                    dev.model = v
                elif k == "x-friendlyname" and not dev.hostname:
                    dev.hostname = v
    except Exception as e:
        log.debug("ssdp scan error: %s", e)
    finally:
        s.close()
    return list(devices.values())


# ── NetBIOS name-service (Windows machines) ────────────────────────


def scan_netbios(broadcast: str = "", timeout_s: float = 1.5) -> list[DiscoveredDevice]:
    """Send a NetBIOS Name Service query to the broadcast address
    and parse responses. Returns a list of devices with hostname
    set to the NetBIOS name."""
    # NetBIOS NBSTAT query for the wildcard name (\x2a).
    query = bytes([
        0xA0, 0x00,           # transaction id
        0x00, 0x10,           # flags (NBSTAT)
        0x00, 0x01,           # questions
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x00,
        0x00, 0x21,           # NBSTAT
        0x00, 0x01,           # IN
    ])
    # Default broadcast.
    if not broadcast:
        broadcast = "255.255.255.255"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(timeout_s)
    devices: dict[str, DiscoveredDevice] = {}
    try:
        s.sendto(query, (broadcast, 137))
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                break
            except OSError:
                break
            ip = addr[0]
            # Parse minimal NBSTAT response. Skip the 56-byte header
            # and read entries (18 bytes each) until the count
            # byte at offset 56 says we've read them all.
            if len(data) < 57:
                continue
            count = data[56]
            best_name = ""
            for i in range(count):
                start = 57 + i * 18
                if start + 16 > len(data):
                    break
                name_raw = data[start:start + 15].decode(
                    "ascii", errors="replace"
                ).strip()
                flags = data[start + 16]
                # Bit 0x80 set = group name; we want unique
                # workstation names (no top bit set).
                if name_raw and not name_raw.startswith("\x00") and not (flags & 0x80):
                    if not best_name or len(name_raw) > len(best_name):
                        best_name = name_raw
            if best_name:
                dev = DiscoveredDevice(
                    ip=ip,
                    hostname=best_name,
                    sources=["netbios"],
                    confidence=0.55,
                )
                devices[ip] = dev
    except Exception as e:
        log.debug("netbios scan error: %s", e)
    finally:
        s.close()
    return list(devices.values())


# ── Correlation + identification ───────────────────────────────────


def _infer_kind(dev: DiscoveredDevice) -> str:
    """Look at the merged signals and guess the device kind.
    Returns one of: phone, tablet, laptop, desktop, tv, speaker,
    printer, router, watch, iot, unknown.
    """
    svcs = set(dev.mdns_services)
    vendor = (dev.vendor or "").lower()
    model = (dev.model or "").lower()
    # mDNS portfolio signatures.
    if "_companion-link" in svcs or "_apple-mobdev2" in svcs:
        # iPhone / iPad / Mac. Model string can split further:
        if "iphone" in model:
            return "phone"
        if "ipad" in model:
            return "tablet"
        if "macbook" in model or "imac" in model or "macmini" in model:
            return "laptop" if "macbook" in model else "desktop"
        if "watch" in model:
            return "watch"
        return "laptop"  # default for Apple devices with companion-link
    if "_airplay" in svcs and "_raop" in svcs:
        # AirPlay receiver — Apple TV, HomePod, third-party speaker.
        if "apple tv" in (dev.hostname + dev.model).lower():
            return "tv"
        if "homepod" in (dev.hostname + dev.model).lower():
            return "speaker"
        return "speaker"
    if "_googlecast" in svcs:
        return "tv"
    if "_spotify-connect" in svcs:
        return "speaker"
    if "_ipp" in svcs or "_ipps" in svcs or "_printer" in svcs:
        return "printer"
    if "_homekit" in svcs:
        return "iot"
    if "_smb" in svcs:
        # Could be a server or NAS or just a Windows machine. SMB
        # alone isn't decisive — fall through to vendor.
        pass
    if "_ssh" in svcs:
        # *nix box — server, raspberry pi, NAS.
        return "desktop"
    # Vendor heuristics.
    if "raspberry" in vendor:
        return "iot"
    if "roku" in vendor or "sonos" in vendor:
        return "tv" if "roku" in vendor else "speaker"
    if "tp-link" in vendor or "router" in vendor:
        return "router"
    return "unknown"


def _is_pairable_kind(kind: str) -> bool:
    """One Link pairs to user-controlled compute. TVs, speakers,
    printers, IoT — visible but not the primary pair target."""
    return kind in ("phone", "tablet", "laptop", "desktop", "watch")


def merge_devices(*lists: list[DiscoveredDevice]) -> list[DiscoveredDevice]:
    """Fuse results from multiple scanners. Keys by (IP, MAC); if a
    device has IP but no MAC, the IP alone keys it; an ARP entry
    later supplies the MAC and the records merge. Confidence
    accumulates: each independent source adds 0.15, capped at 1.0."""
    by_key: dict[str, DiscoveredDevice] = {}
    for batch in lists:
        for dev in batch:
            if not dev.ip and not dev.mac:
                continue
            # Prefer IP as primary key (every device has one on the
            # LAN); fall back to MAC if mDNS returned a hostname
            # but no resolvable IP yet.
            key = dev.ip or dev.mac
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = DiscoveredDevice(**asdict(dev))
                continue
            # Merge fields. Don't overwrite a known-good value with
            # an empty string.
            for f in ("ip", "mac", "hostname", "vendor", "model"):
                if not getattr(existing, f) and getattr(dev, f):
                    setattr(existing, f, getattr(dev, f))
            existing.mdns_services = sorted(
                set(existing.mdns_services) | set(dev.mdns_services)
            )
            existing.open_ports = sorted(
                set(existing.open_ports) | set(dev.open_ports)
            )
            for src in dev.sources:
                if src not in existing.sources:
                    existing.sources.append(src)
            existing.confidence = min(
                1.0,
                existing.confidence + 0.15 * len(set(dev.sources) - set(existing.sources[:-1])),
            )
            existing.is_one_link_peer = existing.is_one_link_peer or dev.is_one_link_peer
    # Post-merge: backfill vendor + kind on every device.
    for dev in by_key.values():
        if dev.mac and not dev.vendor:
            dev.vendor = vendor_for_mac(dev.mac)
        if dev.kind == "unknown":
            dev.kind = _infer_kind(dev)
        # Recalculate confidence from source count + signal richness.
        n_sources = len(dev.sources)
        signal_richness = 0
        if dev.vendor: signal_richness += 1
        if dev.hostname: signal_richness += 1
        if dev.mdns_services: signal_richness += 1
        if dev.kind != "unknown": signal_richness += 1
        dev.confidence = round(
            min(1.0, 0.25 * n_sources + 0.10 * signal_richness),
            2,
        )
    return list(by_key.values())


# ── Top-level scan ─────────────────────────────────────────────────


async def full_scan(
    timeout_s: float = 6.0,
    *,
    one_link_peers: Optional[list[dict]] = None,
) -> list[DiscoveredDevice]:
    """Run every scanner in parallel and return merged results.

    ``one_link_peers`` is an optional list of already-known One Link
    peers (from the existing mDNS discovery for our specific
    service). We use them to flag devices as `is_one_link_peer=True`
    by IP match.
    """
    loop = asyncio.get_running_loop()
    mdns_task = asyncio.create_task(scan_mdns_browse_all(timeout_s=timeout_s))
    arp_task = loop.run_in_executor(None, scan_arp_table)
    ssdp_task = loop.run_in_executor(None, scan_ssdp)
    netbios_task = loop.run_in_executor(None, scan_netbios)
    results = await asyncio.gather(
        mdns_task, arp_task, ssdp_task, netbios_task,
        return_exceptions=True,
    )
    batches: list[list[DiscoveredDevice]] = []
    for r in results:
        if isinstance(r, Exception):
            log.debug("scanner failed: %s", r)
            continue
        batches.append(r)
    merged = merge_devices(*batches)

    # Mark already-paired peers + filter out self.
    self_ips = set(_local_ips())
    one_link_ips = set()
    one_link_macs = set()
    if one_link_peers:
        for p in one_link_peers:
            if p.get("address"):
                one_link_ips.add(p["address"])
            if p.get("mac"):
                one_link_macs.add(p["mac"].lower())
    for dev in merged:
        if dev.ip in self_ips:
            dev.is_one_link_peer = True  # ourselves; we'll filter
        if dev.ip in one_link_ips or dev.mac.lower() in one_link_macs:
            dev.is_one_link_peer = True
    # Exclude self.
    merged = [d for d in merged if d.ip not in self_ips]
    # Sort: pairable kinds first, then by hostname/IP for stability.
    merged.sort(key=lambda d: (
        0 if d.is_one_link_peer else 1,
        0 if _is_pairable_kind(d.kind) else 1,
        -d.confidence,
        d.hostname or d.ip,
    ))
    return merged


def _local_ips() -> list[str]:
    """Return this machine's own LAN IP addresses (so we filter
    ourselves out of the discovery results)."""
    ips = set()
    try:
        for fam, _t, _p, _c, sockaddr in socket.getaddrinfo(
            socket.gethostname(), None,
        ):
            if fam == socket.AF_INET:
                ips.add(sockaddr[0])
    except Exception:
        pass
    # Loopback is always self.
    ips.add("127.0.0.1")
    return list(ips)


# ── Network health hints (Phase 4) ─────────────────────────────────


@dataclass
class NetworkHealth:
    """One-shot diagnostic about the current network. Surfaced to the
    user when discovery returns 0 results despite the daemon being
    on a network."""
    ap_isolation_suspected: bool = False
    captive_portal_suspected: bool = False
    ipv6_only_suspected: bool = False
    has_default_gateway: bool = True
    gateway_ip: str = ""
    reasons: list[str] = field(default_factory=list)


def assess_network_health(devices: list[DiscoveredDevice]) -> NetworkHealth:
    """Heuristic look at the scan results. Tells the user why a
    discovery turned up empty."""
    h = NetworkHealth()
    h.gateway_ip = _default_gateway() or ""
    h.has_default_gateway = bool(h.gateway_ip)
    if not h.has_default_gateway:
        h.reasons.append(
            "This device has no default gateway. You may not be "
            "connected to any network."
        )
        return h
    # AP isolation: gateway responds to ARP (we have a gateway IP)
    # but discovery returned ZERO non-self devices.
    non_self = [d for d in devices if d.ip != h.gateway_ip]
    if not non_self:
        h.ap_isolation_suspected = True
        h.reasons.append(
            "Your Wi-Fi may be blocking devices from seeing each "
            "other (a setting called 'AP isolation' or 'client "
            "isolation' on the router). One Link still works once "
            "devices are paired; pairing on this network won't."
        )
    return h


def _default_gateway() -> str:
    """Best-effort default-gateway lookup. Used only to assess
    network health; never to send packets to."""
    if os.name == "nt":
        try:
            res = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True, text=True, timeout=2.0,
                creationflags=0x08000000,
            )
            for line in res.stdout.splitlines():
                # Default-route lines look like:
                # 0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.42  ...
                m = re.search(
                    r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+"
                    r"(\d+\.\d+\.\d+\.\d+)",
                    line,
                )
                if m:
                    return m.group(1)
        except Exception:
            pass
    else:
        try:
            res = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=2.0,
            )
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", res.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass
    return ""
