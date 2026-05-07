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
) -> CompatibilityResult:
    local_v = Version.parse(local_version)
    peer_v = Version.parse(peer_version)
    local_caps = set(normalize_caps(local_capabilities))
    peer_caps = set(normalize_caps(peer_capabilities))
    common = tuple(sorted(local_caps & peer_caps))
    required_caps = tuple(normalize_caps(required))
    missing = tuple(c for c in required_caps if c not in common)
    reasons: list[str] = []

    if local_v is not None and peer_v is not None and local_v.major != peer_v.major:
        reasons.append("major_version_mismatch")
        return CompatibilityResult(
            compatible=False,
            mode="incompatible_major",
            local_version=local_v,
            peer_version=peer_v,
            common_capabilities=common,
            missing_required=missing,
            reasons=tuple(reasons),
        )

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

    if FILE_SWARM in common and FILE_CDC in common:
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
