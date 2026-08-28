"""Reachability Doctor: why can't this device talk to the other one?

`peers` answers that question with "(no peers discovered yet - give it a few
seconds)". That one sentence is printed for every cause, and most of the causes
never resolve by waiting:

  * the network is classified Public, so Windows denies unsolicited inbound;
  * no firewall rule matches the RUNNING executable -- a reinstall to a new
    path leaves the old path-based rule behind while the app keeps announcing
    as if healthy, so discovery works and transfers do not;
  * an explicit Block rule exists, which no added Allow rule can override;
  * the peer simply is not on this network;
  * multicast reaches nobody, so nothing can be discovered in either direction;
  * the daemon is not listening at all.

Each needs a DIFFERENT action, and the app was telling the user to wait for all
five. This module turns observable facts into one named cause, the specific
remedy, and any secondary findings that will bite later.

Design mirrors transfer_doctor: `diagnose()` is pure and side-effect free, so
every branch is reachable in a test without a firewall, a network, or a peer.
The impure half (`collect_facts`) is isolated and does the OS probing.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

# Diagnosis vocabulary. Stable strings: CLI, UI and tests key off these, so
# adding a cause is additive and renaming one is a breaking change.
CAUSE_OK = "ok"
CAUSE_DAEMON_DOWN = "daemon_not_listening"
CAUSE_INBOUND_BLOCKED = "inbound_blocked_by_firewall"
CAUSE_FIREWALL_RULE_STALE = "firewall_rule_does_not_match_executable"
CAUSE_MULTICAST_DEAF = "multicast_not_received"
CAUSE_NOT_ANNOUNCING = "not_announcing"
CAUSE_PEER_ABSENT = "peer_not_on_this_network"

SEVERITY_OK = "ok"
SEVERITY_WARN = "warning"
SEVERITY_BLOCKED = "blocked"

DEFAULT_SERVICE_TYPE = "_onelink._tcp.local."


@dataclass(frozen=True)
class ReachabilityFacts:
    """Everything the diagnosis is allowed to reason about.

    Deliberately plain data so a test constructs it directly. ``None`` means
    "not determined on this platform" and must never be read as a negative
    finding -- reporting a firewall problem on a machine whose firewall could
    not be read would be a guess wearing a verdict's clothes.
    """

    platform: str = "unknown"
    daemon_running: bool = False
    peer_port: int | None = None
    peer_port_listening: bool = False
    mdns_self_visible: bool = False
    mdns_peers_visible: int = 0
    # Hosts announcing ANY mDNS service. This third number is what separates
    # "nobody is there" from "we cannot hear anyone".
    mdns_other_hosts: int = 0
    network_profile: str | None = None          # Public / Private / Domain
    firewall_enabled: bool | None = None
    executable_path: str | None = None
    firewall_allow_matches_executable: bool | None = None
    firewall_block_matches_executable: bool | None = None
    stale_block_rules: int = 0
    lan_addresses: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReachabilityDiagnosis:
    cause: str
    severity: str
    headline: str
    detail: str
    remedy: tuple[str, ...] = ()
    facts: Mapping[str, Any] = field(default_factory=dict)
    # Real problems that are NOT why communication is failing right now. Kept
    # separate so an urgent cause never swallows a latent one: while the peer is
    # away a missing firewall rule explains nothing, and the moment the peer
    # returns it explains everything.
    also: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.cause == CAUSE_OK

    def render(self) -> str:
        mark = {SEVERITY_OK: "OK", SEVERITY_WARN: "WARN", SEVERITY_BLOCKED: "BLOCKED"}
        lines = [f"[{mark[self.severity]}] {self.headline}", "", self.detail]
        if self.remedy:
            lines.append("")
            lines.append("What to do:")
            lines.extend(f"  {i}. {step}" for i, step in enumerate(self.remedy, 1))
        if self.also:
            lines.append("")
            lines.append("Also worth fixing (not why it is failing now):")
            lines.extend(f"  - {item}" for item in self.also)
        return "\n".join(lines)


def _public_profile(facts: ReachabilityFacts) -> bool:
    return (facts.network_profile or "").strip().lower() == "public"


def _inbound_unallowed(facts: ReachabilityFacts) -> bool:
    """True only when we positively READ the firewall and found no Allow rule.

    ``firewall_allow_matches_executable is False`` is a measurement; ``None`` is
    an unread instrument, and the two must not collapse together.
    """

    return bool(facts.firewall_enabled) and facts.firewall_allow_matches_executable is False


def _secondary_findings(facts: ReachabilityFacts, primary: str) -> tuple[str, ...]:
    out: list[str] = []
    if primary != CAUSE_FIREWALL_RULE_STALE and _inbound_unallowed(facts):
        out.append(
            "No firewall rule allows inbound to the program One Link runs as "
            f"({facts.executable_path}). Outgoing connections still work, so it "
            "presents as 'sometimes connects' -- it fails only when the OTHER "
            "device is the one dialling."
        )
    if primary != CAUSE_OK and _public_profile(facts):
        out.append(
            "This network is classified Public, the strictest firewall profile. "
            "Private is the correct setting for your own home network."
        )
    if facts.stale_block_rules:
        out.append(
            f"{facts.stale_block_rules} firewall Block rule(s) name One Link "
            "executables that no longer exist. Harmless today, but they will "
            "shadow a future install that lands on the same path."
        )
    return tuple(out)


def diagnose(facts: ReachabilityFacts) -> ReachabilityDiagnosis:
    """Return ONE primary cause plus secondary findings. Pure.

    Ordered by what actually stops traffic, not by what is easiest to detect. In
    particular a missing firewall rule is NOT the cause while no peer is even
    advertising: mDNS is multicast and independent of the TCP rule, so a present
    peer would still be visible. Blaming the firewall there sends the user to
    fix something real but unrelated and leaves the actual problem untouched.
    """

    payload = {
        "platform": facts.platform,
        "peer_port": facts.peer_port,
        "network_profile": facts.network_profile,
        "mdns_self_visible": facts.mdns_self_visible,
        "mdns_peers_visible": facts.mdns_peers_visible,
        "mdns_other_hosts": facts.mdns_other_hosts,
        "firewall_allow_matches_executable": facts.firewall_allow_matches_executable,
        "executable_path": facts.executable_path,
    }

    def finish(cause, severity, headline, detail, remedy=()):
        return ReachabilityDiagnosis(
            cause, severity, headline, detail, tuple(remedy), payload,
            _secondary_findings(facts, cause),
        )

    # 1. Nothing else matters if we are not listening.
    if not facts.daemon_running or not facts.peer_port_listening:
        return finish(
            CAUSE_DAEMON_DOWN, SEVERITY_BLOCKED,
            "One Link is not listening for peers on this device.",
            "The daemon is not running, or never bound its peer port, so no other "
            "device can reach this one however the network is configured.",
            ("Start the daemon: one-link daemon (or reopen the One Link app).",
             "If it exits immediately, run it with -v and read the last lines."),
        )

    # 2. A Block rule beats every Allow rule in Windows Firewall, so it comes
    #    before anything else network-shaped: this is the one case where the
    #    obvious remedy (add an Allow rule) is the WRONG one.
    if facts.firewall_block_matches_executable:
        return finish(
            CAUSE_INBOUND_BLOCKED, SEVERITY_BLOCKED,
            "A firewall BLOCK rule names this exact program.",
            "Windows Firewall applies Block before Allow, so adding an Allow rule "
            "changes nothing while this exists. It is usually created by "
            "dismissing the 'Allow this app to communicate?' prompt.",
            ("Open 'Windows Defender Firewall with Advanced Security'.",
             "Inbound Rules -> find the rules naming this program -> delete the "
             "Block entries.",
             "Then allow it once: New Rule -> Program -> this executable."),
        )

    # 3. We hear nothing at all -- not a router, not a printer. Local receive
    #    problem; fixing the other machine cannot help.
    if facts.mdns_other_hosts == 0 and facts.mdns_peers_visible == 0:
        return finish(
            CAUSE_MULTICAST_DEAF, SEVERITY_BLOCKED,
            "This device is not receiving any multicast traffic.",
            "Not one other device on this network is visible -- no router, no "
            "printer, nothing. Discovery is multicast, so this points at the "
            "local network path rather than the other computer: a VPN holding the "
            "interface, client isolation on the access point, or multicast "
            "disabled for this adapter.",
            ("Disconnect any VPN and re-check.",
             "Confirm this is the normal Wi-Fi, not a Guest network -- guest "
             "networks isolate devices from each other by design.",
             "If the two devices are on different adapters (Ethernet vs Wi-Fi), "
             "confirm they share a subnet."),
        )

    # 4. We can hear, but we are not being heard.
    if not facts.mdns_self_visible:
        return finish(
            CAUSE_NOT_ANNOUNCING, SEVERITY_BLOCKED,
            "This device is not announcing itself on the network.",
            "Other devices are visible, so reception works, but One Link's own "
            "service advertisement is not going out. The other computer cannot "
            "discover this one.",
            ("Restart the daemon so it re-registers its mDNS service.",
             "With several adapters (Wi-Fi plus a VM or WSL bridge) the "
             "announcement can leave on the wrong one."),
        )

    # 5. Peers ARE visible, so nothing is 'blocked' -- but a missing inbound rule
    #    still predicts one-way failure, and staying silent until it bites is
    #    what made this class of bug invisible in the first place.
    if facts.mdns_peers_visible > 0:
        if _inbound_unallowed(facts) and _public_profile(facts):
            return finish(
                CAUSE_FIREWALL_RULE_STALE, SEVERITY_WARN,
                f"{facts.mdns_peers_visible} peer(s) visible, but nothing may "
                "connect TO this device.",
                "Discovery works because it is multicast. Transfers are TCP, and "
                "no firewall rule allows inbound to:\n"
                f"    {facts.executable_path}\n"
                "On a Public network that is denied by default. Connections this "
                "device starts still succeed, which is exactly why it reads as "
                "'works sometimes'. Firewall rules name an exact path, so "
                "reinstalling to a different location leaves the old rule behind "
                "pointing at a program that no longer runs.",
                ("Allow it inbound, as Administrator:\n"
                 '     New-NetFirewallRule -DisplayName "One Link peer" '
                 "-Direction Inbound -Action Allow -Program "
                 f'"{facts.executable_path}" -Profile Private,Public',
                 "On your own network, prefer Private:\n"
                 "     Set-NetConnectionProfile -InterfaceAlias 'Wi-Fi' "
                 "-NetworkCategory Private"),
            )
        return finish(
            CAUSE_OK, SEVERITY_OK,
            f"Reachable. {facts.mdns_peers_visible} One Link peer(s) visible.",
            "Listening, announcing, receiving multicast, and peers are visible.",
        )

    # 6. Everything local is healthy and the LAN is alive, so the peer is the one
    #    that is missing. This is the case the old message hid.
    return finish(
        CAUSE_PEER_ABSENT, SEVERITY_WARN,
        "This device is healthy; the other computer is not on this network.",
        "One Link is running, listening, announcing, and receiving multicast "
        f"({facts.mdns_other_hosts} other device(s) visible). No other One Link "
        "is advertising here, so waiting will not help -- the other machine is "
        "off, not running One Link, or on a different network.",
        ("On the other computer: is One Link actually running?",
         "Is it on the SAME Wi-Fi name -- not the guest network, and not a band "
         "with client isolation?",
         "Its address should share this device's subnet "
         f"({', '.join(facts.lan_addresses) or 'unknown'}).",
         "If it is running and on the same network, run this same check there."),
    )


# --------------------------------------------------------------------------
# Impure half: observe the machine. Isolated so diagnose() stays testable.
# --------------------------------------------------------------------------

def _powershell(script: str, timeout: float = 15.0) -> str:
    """Run one PowerShell probe. Returns "" on any failure.

    A probe that cannot run must leave its fact unknown (None), never a false
    negative -- that distinction is what keeps this from inventing firewall
    problems on machines it could not inspect.
    """

    import subprocess

    try:
        out = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        return out.stdout if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def normalized_program_path(path: str) -> str:
    """The form a firewall rule must be compared against.

    Windows matches a rule against the RESOLVED image path of the running
    process, so the comparison has to resolve links first. This is not a
    detail: uv publishes its interpreter as a junction, so

        ...\\uv\\python\\cpython-3.12-windows-x86_64-none\\python.exe

    resolves to

        ...\\uv\\python\\cpython-3.12.13-windows-x86_64-none\\python.exe

    Comparing the unresolved form finds no matching rule and reports a firewall
    problem that does not exist -- a false alarm that sends the user to add a
    duplicate rule and to distrust a working firewall. Case is normalised too,
    because rules store the path exactly as it was typed.
    """

    return os.path.normcase(os.path.realpath(path))


def _windows_firewall_facts(executable: str | None) -> dict[str, Any]:
    if os.name != "nt" or not executable:
        return {}
    profile = _powershell(
        "(Get-NetConnectionProfile | Select-Object -First 1).NetworkCategory"
    ).strip()
    enabled = _powershell(
        "[string](((Get-NetFirewallProfile | Where-Object Enabled -eq $true).Name) -join ',')"
    ).strip()
    # Compare on the resolved, case-normalised path: rules store the path as it
    # was typed, which differs in case and short-name form from ours.
    target = normalized_program_path(executable).replace("'", "''")
    # Filter by PATH first, then resolve only the few matching rules. Walking
    # every inbound rule and invoking Get-NetFirewallApplicationFilter on each
    # takes longer than any sane timeout on a machine with hundreds of rules --
    # it returned nothing at all, which the diagnosis then had to report as
    # "unknown" rather than risk inventing a verdict.
    counts = _powershell(
        "$t = '" + target + "'; $a=0; $b=0; "
        "Get-NetFirewallApplicationFilter -All -EA SilentlyContinue | "
        "Where-Object { $_.Program -and $_.Program.ToLower() -eq $t } | "
        "ForEach-Object { $r = $_ | Get-NetFirewallRule -EA SilentlyContinue; "
        "if ($r -and $r.Enabled -eq 'True' -and $r.Direction -eq 'Inbound') { "
        "if ($r.Action -eq 'Allow') { $a++ } else { $b++ } } }; "
        '"$a,$b"',
        timeout=25.0,
    ).strip()
    allow: bool | None = None
    block: bool | None = None
    if "," in counts:
        head, _, tail = counts.partition(",")
        try:
            allow, block = int(head) > 0, int(tail) > 0
        except ValueError:
            allow = block = None
    stale = _powershell(
        "$n=0; Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True "
        "-EA SilentlyContinue | ForEach-Object { "
        "$p = ($_ | Get-NetFirewallApplicationFilter -EA SilentlyContinue).Program; "
        "if ($p -and $p -match 'one.?link' -and -not (Test-Path $p)) { $n++ } }; $n"
    ).strip()
    return {
        "network_profile": profile or None,
        "firewall_enabled": True if enabled else None,
        "firewall_allow_matches_executable": allow,
        "firewall_block_matches_executable": block,
        "stale_block_rules": int(stale) if stale.isdigit() else 0,
    }


def _mdns_facts(
    self_short_id: str | None,
    service_type: str = DEFAULT_SERVICE_TYPE,
    seconds: float = 6.0,
) -> dict[str, Any]:
    """Browse the LAN, counting self, One Link peers, and everyone else."""

    try:
        import time

        from zeroconf import (
            ServiceBrowser,
            ServiceListener,
            Zeroconf,
            ZeroconfServiceTypes,
        )
    except ImportError:
        return {}

    seen_onelink: set[str] = set()
    other_hosts: set[str] = set()
    self_port: dict[str, int] = {}

    class _Listener(ServiceListener):
        def add_service(self, zc: Any, type_: str, name: str) -> None:
            try:
                info = zc.get_service_info(type_, name, timeout=1500)
            except Exception:
                return
            if info is None:
                return
            if type_ == service_type:
                seen_onelink.add(name)
                # Our own announcement is the authoritative source for the peer
                # port: the control API's `me` record does not carry one, and
                # guessing a field name there produced a confidently wrong
                # "daemon not listening" verdict on a daemon that was listening.
                if self_short_id and self_short_id in name and info.port:
                    self_port["port"] = int(info.port)
                return
            for addr in info.addresses or ():
                other_hosts.add(".".join(str(b) for b in addr))

        def update_service(self, *_a: Any) -> None: ...

        def remove_service(self, *_a: Any) -> None: ...

    zc = None
    try:
        zc = Zeroconf()
        listener = _Listener()
        ServiceBrowser(zc, service_type, listener)
        try:
            for other in list(ZeroconfServiceTypes.find(zc=zc, timeout=2))[:8]:
                if other != service_type:
                    ServiceBrowser(zc, other, listener)
        except Exception:
            pass
        time.sleep(seconds)
    except Exception:
        return {}
    finally:
        if zc is not None:
            try:
                zc.close()
            except Exception:
                pass

    sid = self_short_id or ""
    self_visible = bool(sid) and any(sid in n for n in seen_onelink)
    peers = len(seen_onelink) - (1 if self_visible else 0)
    out: dict[str, Any] = {
        "mdns_self_visible": self_visible,
        "mdns_peers_visible": max(0, peers),
        "mdns_other_hosts": len(other_hosts),
    }
    if "port" in self_port:
        out["announced_port"] = self_port["port"]
    return out


def _port_accepts_locally(port: int | None) -> bool:
    """Can anything actually connect to the announced port on this machine?

    Loopback only: this proves the daemon is listening, and deliberately does
    NOT prove the firewall permits a remote peer -- Windows does not filter
    loopback, so a success here says nothing about inbound from the LAN. Those
    are separate facts and conflating them would manufacture a false all-clear.
    """

    if not port:
        return False
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(1.5)
            return probe.connect_ex(("127.0.0.1", int(port))) == 0
    except OSError:
        return False


def _listener_executable(port: int | None) -> str | None:
    """The image path of whatever is actually listening on the peer port.

    The firewall question is about the DAEMON, not about whichever interpreter
    happens to be running this diagnostic. Those differ in normal use -- the
    CLI runs from .venv while the daemon runs from uv's managed Python -- and
    checking the wrong one produces a remedy that tells the user to allow a
    binary that never listens for peers.
    """

    if os.name != "nt" or not port:
        return None
    out = _powershell(
        f"$c = Get-NetTCPConnection -State Listen -LocalPort {int(port)} -EA SilentlyContinue | "
        "Select-Object -First 1; "
        "if ($c) { (Get-Process -Id $c.OwningProcess -EA SilentlyContinue).Path }"
    ).strip()
    return out or None


def _lan_addresses() -> tuple[str, ...]:
    """This device's LAN address, resolved WITHOUT any name lookup.

    The obvious implementation -- getaddrinfo(gethostname()) -- is banned in
    this package for a reason documented at length in
    tests/test_no_unbounded_resolution_v0210.py: the C resolver takes no
    timeout, a host's own name is often answered over mDNS, and on a degraded
    network the call blocks for a minute or more. One Link shipped that defect
    twice already, and putting it HERE would be the worst copy yet -- a network
    doctor that hangs for a minute precisely when the network is broken is the
    one moment it has to answer.

    A UDP socket needs no packets and no DNS: connecting a datagram socket only
    selects a route, and getsockname() then reports the address the kernel
    would send from. TEST-NET-1 (RFC 5737) is used as the target because it is
    guaranteed never to be routed anywhere real. It also yields a better answer
    than enumerating adapters did -- the address actually used for LAN traffic,
    rather than a list including WSL and VM bridges the peer will never be on.
    """

    import socket

    out: set[str] = set()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.settimeout(0.5)
            probe.connect(("192.0.2.1", 9))  # RFC 5737 TEST-NET-1; no traffic
            ip = probe.getsockname()[0]
        if isinstance(ip, str) and not ip.startswith(("127.", "169.254.")):
            out.add(ip)
    except OSError:
        pass
    return tuple(sorted(out))


def collect_facts(
    *,
    daemon_running: bool,
    peer_port: int | None,
    peer_port_listening: bool,
    self_short_id: str | None = None,
    service_type: str = DEFAULT_SERVICE_TYPE,
    executable: str | None = None,
    mdns_seconds: float = 6.0,
) -> ReachabilityFacts:
    """Observe this machine. Callers pass what they already know about the
    daemon so this never has to guess at process state."""

    data: dict[str, Any] = {
        "platform": sys.platform,
        "daemon_running": daemon_running,
        "peer_port": peer_port,
        "peer_port_listening": peer_port_listening,
        "lan_addresses": _lan_addresses(),
    }
    mdns = _mdns_facts(self_short_id, service_type, mdns_seconds)
    data.update(mdns)

    # Prefer the port this device is actually ANNOUNCING over anything the
    # caller believed. If we advertise a port, that is the one a peer will dial.
    announced = mdns.pop("announced_port", None)
    resolved_port = announced or peer_port
    if resolved_port:
        data["peer_port"] = resolved_port
        if not peer_port_listening:
            data["peer_port_listening"] = _port_accepts_locally(resolved_port)

    # Ask the firewall about the process that is actually listening, falling
    # back to this interpreter only when the listener cannot be identified.
    exe = executable or _listener_executable(resolved_port) or sys.executable
    data["executable_path"] = exe
    data.update(_windows_firewall_facts(exe))

    known = set(ReachabilityFacts.__dataclass_fields__)
    return ReachabilityFacts(**{k: v for k, v in data.items() if k in known})


def summarize(facts: ReachabilityFacts) -> str:
    """Evidence block printed under the verdict, so the user can see WHAT was
    observed instead of being asked to trust a conclusion."""

    def mark(value: Any) -> str:
        if value is None:
            return "?"
        return "yes" if value else "NO"

    rows: Iterable[tuple[str, str]] = (
        ("daemon listening", mark(facts.daemon_running and facts.peer_port_listening)),
        ("peer port", str(facts.peer_port or "unknown")),
        ("announcing itself", mark(facts.mdns_self_visible)),
        ("One Link peers seen", str(facts.mdns_peers_visible)),
        ("other LAN devices seen", str(facts.mdns_other_hosts)),
        ("network profile", facts.network_profile or "n/a"),
        ("firewall allows this program", mark(facts.firewall_allow_matches_executable)),
        ("firewall blocks this program", mark(facts.firewall_block_matches_executable)),
    )
    return "\n".join(f"  {k:<30} {v}" for k, v in rows)
