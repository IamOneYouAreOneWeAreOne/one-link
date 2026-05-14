"""OneField software-loopback transport adapter.

This is the safe OneField bridge: it proves One Link encrypted frames can pass
through a OneField-shaped transport without enabling RF transmit. Hardware
helpers can later attach beneath this adapter contract once their safety gates
are proven.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from time import perf_counter

from one_link.hardware_inventory import HardwarePath

from .base import AdapterProbe, PreparedRoute, RepairResult, RouteScore, SessionStats
from .static import score_probe


ONEFIELD_LOOPBACK_MTU = 64 * 1024


@dataclass
class OneFieldLoopbackSession:
    mtu: int = ONEFIELD_LOOPBACK_MTU
    ordered: bool = True
    reliable: bool = True
    bulk_capable: bool = True
    control_capable: bool = True
    max_queued_frames: int = 1024
    _queue: asyncio.Queue[bytes] = field(init=False, repr=False)
    _created: float = field(default_factory=perf_counter, init=False)
    _bytes_sent: int = 0
    _bytes_received: int = 0
    _frames_sent: int = 0
    _frames_received: int = 0

    def __post_init__(self) -> None:
        self._queue = asyncio.Queue(maxsize=self.max_queued_frames)

    async def send_frame(self, frame: bytes) -> None:
        data = bytes(frame)
        if not data:
            raise ValueError("onefield loopback frame cannot be empty")
        if len(data) > self.mtu:
            raise ValueError("onefield loopback frame exceeds mtu")
        await self._queue.put(data)
        self._bytes_sent += len(data)
        self._frames_sent += 1

    async def recv_frame(self) -> bytes:
        data = await self._queue.get()
        self._bytes_received += len(data)
        self._frames_received += 1
        return data

    async def stats(self) -> SessionStats:
        elapsed = max(0.001, perf_counter() - self._created)
        return SessionStats(
            bytes_sent=self._bytes_sent,
            bytes_received=self._bytes_received,
            frames_sent=self._frames_sent,
            frames_received=self._frames_received,
            rtt_ms=1.0,
            measured_bps=(self._bytes_sent + self._bytes_received) / elapsed,
            loss=0.0,
        )

    async def repair(self, reason: str) -> RepairResult:
        return RepairResult(
            repaired=True,
            action="onefield_loopback_queue_preserved",
            reason=str(reason or "operator_requested_repair"),
        )


@dataclass(frozen=True)
class OneFieldLoopbackAdapter:
    path: HardwarePath

    @property
    def adapter_id(self) -> str:
        return self.path.adapter_id or "onefield.loopback"

    @property
    def kind(self) -> str:
        return "onefield"

    def probe(self) -> AdapterProbe:
        loopback_only = "software loopback" in " ".join(self.path.notes).lower()
        return AdapterProbe(
            adapter_id=self.adapter_id,
            kind="onefield",
            available=bool(self.path.available and loopback_only),
            bulk_capable=bool(self.path.bulk_capable and loopback_only),
            control_capable=bool(self.path.control_capable),
            estimated_bps=float(self.path.estimated_bps or 5_000_000.0),
            latency_ms=1.0 if loopback_only else 250.0,
            loss=0.0,
            privacy="same_machine" if loopback_only else "experimental_hardware",
            range_hint="software_loopback" if loopback_only else self.path.range_hint,
            requires_user_action=not loopback_only,
            requires_admin=False,
            safety_state="ok" if loopback_only else "rx_only_until_safety_gate",
            notes=(
                "software loopback; RF transmit disabled",
                "frames remain encrypted above the adapter",
                *tuple(n for n in self.path.notes if n),
            ),
        )

    def score(self, *, intent: object | None = None, peer: object | None = None) -> RouteScore:
        return score_probe(self.probe(), intent=intent, peer=peer)

    def score_from_probe(
        self,
        probe: AdapterProbe,
        *,
        intent: object | None = None,
        peer: object | None = None,
    ) -> RouteScore:
        return score_probe(probe, intent=intent, peer=peer)

    async def prepare(
        self,
        *,
        peer: object | None = None,
        intent: object | None = None,
    ) -> PreparedRoute:
        probe = self.probe()
        if not probe.available:
            raise RuntimeError("onefield loopback is not enabled")
        return PreparedRoute(
            adapter_id=self.adapter_id,
            route_name=probe.route_name,
            metadata={
                "mode": "software_loopback",
                "rf_transmit": False,
                "safety_state": probe.safety_state,
            },
        )

    async def open(self, route: PreparedRoute) -> OneFieldLoopbackSession:
        if route.adapter_id != self.adapter_id:
            raise RuntimeError("prepared route belongs to another adapter")
        if route.metadata.get("rf_transmit") is not False:
            raise RuntimeError("onefield loopback refuses RF transmit routes")
        return OneFieldLoopbackSession()


def onefield_adapters_from_paths(paths: tuple[HardwarePath, ...] | list[HardwarePath]) -> tuple[OneFieldLoopbackAdapter, ...]:
    return tuple(OneFieldLoopbackAdapter(p) for p in paths if p.kind == "onefield")
