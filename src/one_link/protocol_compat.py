"""Protocol compatibility and capability negotiation.

This module turns a peer's version and advertised capabilities into an
explicit decision so send paths can degrade cleanly instead of surprising the
user with a hard version wall.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable

from .capabilities import (
    CHAT,
    FILES,
    FILE_CDC,
    FILE_COMPRESSION,
    FILE_RESUMABLE,
    FILE_SWARM,
    normalize_caps,
)


SEMVER_RE = re.compile(r"^\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?")
# Wire-protocol versions are stamped like "OL1.2" — a non-digit prefix
# then a dotted number. We search (not match) for the first numeric run
# so the prefix is ignored.
WIRE_VER_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")
BASELINE_CAPABILITIES = (CHAT, FILES)


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int = 0
    patch: int = 0

    @classmethod
    def parse(cls, value: str | None) -> "Version | None":
        if not value:
            return None
        m = SEMVER_RE.match(str(value))
        if not m:
            return None
        return cls(*(int(part or 0) for part in m.groups()))

    @classmethod
    def parse_wire(cls, value: str | None) -> "Version | None":
        """Parse a WIRE protocol version like ``OL1.2`` (or a bare
        ``1.2``). Unlike :meth:`parse`, tolerates a leading non-digit
        prefix so the wire tag and the app semver can be parsed by the
        same type. Returns None if no numeric run is present."""
        if not value:
            return None
        m = WIRE_VER_RE.search(str(value))
        if not m:
            return None
        return cls(*(int(part or 0) for part in m.groups()))


@dataclass(frozen=True)
class CompatibilityResult:
    compatible: bool
    mode: str
    local_version: Version | None
    peer_version: Version | None
    common_capabilities: tuple[str, ...]
    missing_required: tuple[str, ...]
    reasons: tuple[str, ...] = ()

    def supports(self, capability: str) -> bool:
        return capability in self.common_capabilities

    @property
    def transfer_mode(self) -> str:
        if FILE_SWARM in self.common_capabilities and FILE_CDC in self.common_capabilities:
            return "swarm_cdc"
        if FILE_RESUMABLE in self.common_capabilities and FILE_CDC in self.common_capabilities:
            return "resumable_cdc"
        if FILE_CDC in self.common_capabilities:
            return "cdc"
        if FILES in self.common_capabilities:
            return "baseline_file"
        return "none"


def negotiate(
    *,
    local_version: str | None,
    peer_version: str | None,
    local_capabilities: Iterable[str],
    peer_capabilities: Iterable[str],
    required: Iterable[str] = (),
    local_wire_version: str | None = None,
    peer_wire_version: str | None = None,
) -> CompatibilityResult:
    """Decide how two One Link builds should talk.

    Core principle (2026-06-04): **different versions ALWAYS work as
    long as they share a baseline capability.** Compatibility is driven
    by shared CAPABILITIES, never by a version number alone. A version
    difference can only DOWNGRADE the negotiated mode (disable advanced
    framing), never sever the connection outright.

    The "major boundary" check that gates advanced modes prefers the
    WIRE protocol version (``local_wire_version`` / ``peer_wire_version``,
    e.g. ``OL1.2``) — the thing that actually governs frame shape — and
    falls back to the app semver only when a (legacy) peer doesn't
    advertise a wire version. This decoupling means a routine app major
    bump (e.g. 0.x -> 1.0) with an UNCHANGED wire no longer breaks
    interop: same wire major -> full negotiation regardless of app
    version. Only a genuine wire-major boundary conservatively drops
    the pair to the universal CHAT/FILES baseline until both upgrade.
    """
    local_v = Version.parse(local_version)
    peer_v = Version.parse(peer_version)
    local_caps = set(normalize_caps(local_capabilities))
    peer_caps = set(normalize_caps(peer_capabilities))
    common = tuple(sorted(local_caps & peer_caps))
    required_caps = tuple(normalize_caps(required))
    missing = tuple(c for c in required_caps if c not in common)
    reasons: list[str] = []

    # Is this a major boundary? Prefer the wire protocol version; fall
    # back to the app semver only when wire versions aren't advertised.
    local_wire_v = Version.parse_wire(local_wire_version)
    peer_wire_v = Version.parse_wire(peer_wire_version)
    if local_wire_v is not None and peer_wire_v is not None:
        cross_major = local_wire_v.major != peer_wire_v.major
    elif local_v is not None and peer_v is not None:
        cross_major = local_v.major != peer_v.major
    else:
        cross_major = False

    if cross_major:
        # DEGRADE, do not refuse. Across a major boundary the advanced
        # framing (CDC / swarm / resumable / compression) may have
        # changed shape, so we trust ONLY the universal baseline
        # (CHAT / FILES). Chat + basic file transfer keep working; the
        # fancy modes re-enable once both sides share a major. This is
        # what makes "different versions always work" true instead of
        # aspirational. The previous code returned compatible=False
        # here, which turned a marketing-version bump into a hard
        # interop wall.
        reasons.append("major_version_boundary")
        common = tuple(c for c in common if c in BASELINE_CAPABILITIES)
        missing = tuple(c for c in required_caps if c not in common)

    if missing:
        reasons.append("missing_required_capability")
        return CompatibilityResult(
            compatible=False,
            mode="missing_required",
            local_version=local_v,
            peer_version=peer_v,
            common_capabilities=common,
            missing_required=missing,
            reasons=tuple(reasons),
        )

    if cross_major and any(c in common for c in BASELINE_CAPABILITIES):
        # Distinct label so the UI / logs can say "talking in safe
        # cross-version mode" rather than a plain baseline.
        mode = "baseline_cross_major"
    elif FILE_SWARM in common and FILE_CDC in common:
        mode = "swarm_advanced"
    elif FILE_RESUMABLE in common and FILE_CDC in common:
        mode = "resumable_advanced"
    elif FILE_CDC in common:
        mode = "advanced"
    elif any(c in common for c in BASELINE_CAPABILITIES):
        mode = "baseline"
    elif peer_v is None:
        mode = "legacy_unknown"
        reasons.append("peer_version_unknown")
    else:
        mode = "no_shared_user_capability"
        reasons.append(mode)

    return CompatibilityResult(
        compatible=mode != "no_shared_user_capability",
        mode=mode,
        local_version=local_v,
        peer_version=peer_v,
        common_capabilities=common,
        missing_required=missing,
        reasons=tuple(reasons),
    )


def fallback_order(result: CompatibilityResult) -> tuple[str, ...]:
    """Return strongest-to-weakest transfer methods for this peer."""
    order: list[str] = []
    if FILE_SWARM in result.common_capabilities and FILE_CDC in result.common_capabilities:
        order.append("file_swarm_cdc")
    if FILE_RESUMABLE in result.common_capabilities and FILE_CDC in result.common_capabilities:
        order.append("file_resumable_cdc")
    if FILE_CDC in result.common_capabilities:
        order.append("file_cdc")
    if FILES in result.common_capabilities:
        order.append("file_baseline")
    if CHAT in result.common_capabilities:
        order.append("chat_text")
    return tuple(order)
