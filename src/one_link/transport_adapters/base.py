"""Common transport adapter contract.

Adapters are intentionally below One Link identity, capability, encryption,
and chunk verification. They move bytes; they do not decide who is trusted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Protocol


@dataclass(frozen=True)
class AdapterProbe:
    adapter_id: str
    kind: str
    available: bool
    bulk_capable: bool = False
    control_capable: bool = True
    estimated_bps: float = 0.0
    latency_ms: float | None = None
    loss: float = 0.0
    privacy: str = "unknown"
    range_hint: str = "unknown"
    requires_user_action: bool = False
    requires_admin: bool = False
    safety_state: str = "ok"
    notes: tuple[str, ...] = ()

    @property
    def route_name(self) -> str:
        if self.kind in {"lan", "loopback", "ethernet"}:
            return "lan"
        if self.kind in {"webrtc", "sealed_relay"}:
            return "relay"
        if self.kind in {"wifi_direct", "private_hotspot"}:
            return "lan"
        if self.kind in {"storage_courier"}:
            return "courier"
        if self.kind in {"onefield"}:
            return "onefield"
        return self.kind

    def to_dict(self) -> dict[str, object]:
        return {
            "adapter_id": self.adapter_id,
            "kind": self.kind,
            "route_name": self.route_name,
            "available": self.available,
            "bulk_capable": self.bulk_capable,
            "control_capable": self.control_capable,
            "estimated_bps": self.estimated_bps,
            "latency_ms": self.latency_ms,
            "loss": self.loss,
            "privacy": self.privacy,
            "range": self.range_hint,
            "requires_user_action": self.requires_user_action,
            "requires_admin": self.requires_admin,
            "safety_state": self.safety_state,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class RouteScore:
    adapter_id: str
    route_name: str
    score: float
    estimated_bps: float
    latency_ms: float | None
    reliability: float
    privacy: str
    reason: str
    usable_for_bulk: bool = False
    usable_for_control: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "adapter_id": self.adapter_id,
            "route_name": self.route_name,
            "score": round(self.score, 6),
            "estimated_bps": self.estimated_bps,
            "latency_ms": self.latency_ms,
            "reliability": round(self.reliability, 6),
            "privacy": self.privacy,
            "reason": self.reason,
            "usable_for_bulk": self.usable_for_bulk,
            "usable_for_control": self.usable_for_control,
        }


@dataclass(frozen=True)
class PreparedRoute:
    adapter_id: str
    route_name: str
    endpoint: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class SessionStats:
    bytes_sent: int = 0
    bytes_received: int = 0
    frames_sent: int = 0
    frames_received: int = 0
    rtt_ms: float | None = None
    measured_bps: float = 0.0
    loss: float = 0.0


@dataclass(frozen=True)
class RepairResult:
    repaired: bool
    action: str
    retry_after_s: float = 0.0
    reason: str = ""


class TransportSession(Protocol):
    mtu: int
    ordered: bool
    reliable: bool
    bulk_capable: bool
    control_capable: bool

    async def send_frame(self, frame: bytes) -> None: ...

    async def recv_frame(self) -> bytes: ...

    async def stats(self) -> SessionStats: ...

    async def repair(self, reason: str) -> RepairResult: ...


class ScorableAdapter(Protocol):
    """The probe/score surface the routing *fabric* needs — a strict
    subset of `TransportAdapter`. Some adapters (static-path hints,
    loopback) are scoring-only and don't implement the full connect
    lifecycle, so the fabric (which only calls probe/score) is typed
    against this narrower protocol.

    `adapter_id`/`kind` are read-only properties (not plain attributes):
    every concrete adapter exposes them via @property, and a *settable*
    Protocol attribute is NOT satisfied by a read-only property.
    """

    @property
    def adapter_id(self) -> str: ...

    @property
    def kind(self) -> str: ...

    def probe(self) -> AdapterProbe: ...

    def score(self, *, intent: object | None = None, peer: object | None = None) -> RouteScore: ...


class TransportAdapter(ScorableAdapter, Protocol):
    """Full adapter: scoring + the async connect lifecycle."""

    async def prepare(
        self,
        *,
        peer: object | None = None,
        intent: object | None = None,
    ) -> PreparedRoute: ...

    async def open(self, route: PreparedRoute) -> TransportSession: ...

