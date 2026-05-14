"""Durable route-memory adapters for the Universal Comms Fabric.

Route candidates are concrete, key-confirmed ways we have learned to reach a
peer: host/port/transport plus success/failure history. This adapter lets the
fabric route brain rank those remembered paths as real transport evidence
instead of showing them only as diagnostics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .base import AdapterProbe, PreparedRoute, RouteScore, TransportSession
from .static import score_probe


@dataclass(frozen=True)
class DurableRouteCandidateAdapter:
    candidate: Mapping[str, object]

    @property
    def adapter_id(self) -> str:
        peer = str(self.candidate.get("peer_fp") or "")[:8] or "unknown"
        route = self.kind
        transport = str(self.candidate.get("transport") or "tcp")
        host = str(self.candidate.get("host") or "unknown")
        port = int(self.candidate.get("port") or 0)
        return f"remembered.{peer}.{route}.{transport}.{host}.{port}"

    @property
    def kind(self) -> str:
        route = str(self.candidate.get("route") or "lan").lower()
        if route == "internet":
            return "webrtc"
        if route == "sealed_relay":
            return "sealed_relay"
        if route == "relay":
            return "sealed_relay"
        return route or "lan"

    def probe(self) -> AdapterProbe:
        attempts = max(0, int(self.candidate.get("attempts") or 0))
        successes = max(0, int(self.candidate.get("successes") or 0))
        failures = max(0, int(self.candidate.get("failures") or 0))
        verified = bool(self.candidate.get("verified"))
        reliability = (
            successes / max(1, attempts)
            if attempts
            else (0.98 if verified else 0.50)
        )
        reliability = max(0.05, min(0.995, float(reliability)))
        bps = float(self.candidate.get("bandwidth_bps") or _default_bps(self.kind))
        latency = self.candidate.get("latency_ms")
        latency_ms = float(latency) if isinstance(latency, (int, float)) else _default_latency_ms(self.kind)
        return AdapterProbe(
            adapter_id=self.adapter_id,
            kind=self.kind,
            available=verified,
            bulk_capable=self.kind not in {"qr_control", "audio_control", "ble_control"},
            control_capable=True,
            estimated_bps=max(0.0, bps),
            latency_ms=latency_ms,
            loss=max(0.0, min(0.95, 1.0 - reliability)),
            privacy=_privacy_for_route(self.kind),
            range_hint="remembered",
            safety_state="ok" if verified else "needs_verification",
            notes=(
                f"remembered route from {self.candidate.get('source') or 'runtime'}",
                f"{successes} success, {failures} failure",
            ),
        )

    def score(self, *, intent: object | None = None, peer: object | None = None) -> RouteScore:
        probe = self.probe()
        return self.score_from_probe(probe, intent=intent, peer=peer)

    def score_from_probe(
        self,
        probe: AdapterProbe,
        *,
        intent: object | None = None,
        peer: object | None = None,
    ) -> RouteScore:
        score = score_probe(probe, intent=intent, peer=peer)
        verified_bonus = 0.10 if bool(self.candidate.get("verified")) else 0.0
        success_bonus = min(0.10, 0.025 * int(self.candidate.get("successes") or 0))
        failure_penalty = min(0.20, 0.04 * int(self.candidate.get("failures") or 0))
        return RouteScore(
            adapter_id=score.adapter_id,
            route_name=score.route_name,
            score=max(0.0, min(1.0, score.score + verified_bonus + success_bonus - failure_penalty)),
            estimated_bps=score.estimated_bps,
            latency_ms=score.latency_ms,
            reliability=score.reliability,
            privacy=score.privacy,
            reason=(
                "verified remembered route"
                if bool(self.candidate.get("verified"))
                else "remembered route awaiting verification"
            ),
            usable_for_bulk=score.usable_for_bulk,
            usable_for_control=score.usable_for_control,
        )

    async def prepare(
        self,
        *,
        peer: object | None = None,
        intent: object | None = None,
    ) -> PreparedRoute:
        return PreparedRoute(
            adapter_id=self.adapter_id,
            route_name=self.probe().route_name,
            endpoint=f"{self.candidate.get('host')}:{self.candidate.get('port')}",
            metadata={
                "candidate": {
                    "peer": str(self.candidate.get("peer_fp") or "")[:8],
                    "route": self.candidate.get("route"),
                    "transport": self.candidate.get("transport"),
                    "source": self.candidate.get("source"),
                    "verified": bool(self.candidate.get("verified")),
                }
            },
        )

    async def open(self, route: PreparedRoute) -> TransportSession:
        if str(self.candidate.get("transport") or "tcp").lower() != "tcp":
            raise RuntimeError("only tcp remembered routes can be opened today")
        from .tcp import open_tcp_route

        return await open_tcp_route(route)


def adapters_from_route_candidates(
    candidates: list[Mapping[str, object]] | tuple[Mapping[str, object], ...],
) -> tuple[DurableRouteCandidateAdapter, ...]:
    return tuple(DurableRouteCandidateAdapter(c) for c in candidates)


def _privacy_for_route(route: str) -> str:
    if route in {"lan", "loopback", "ethernet", "wifi_direct", "private_hotspot"}:
        return "direct_local"
    if route in {"sealed_relay", "relay", "webrtc"}:
        return "direct_or_relayed_internet"
    if route in {"onefield", "lora", "sdr", "rf"}:
        return "experimental_hardware"
    return "unknown"


def _default_bps(route: str) -> float:
    return {
        "loopback": 8_000_000_000.0,
        "lan": 500_000_000.0,
        "ethernet": 1_000_000_000.0,
        "wifi_direct": 350_000_000.0,
        "private_hotspot": 180_000_000.0,
        "webrtc": 80_000_000.0,
        "sealed_relay": 40_000_000.0,
        "onefield": 2_000_000.0,
    }.get(route, 25_000_000.0)


def _default_latency_ms(route: str) -> float:
    return {
        "loopback": 1.0,
        "lan": 6.0,
        "ethernet": 2.0,
        "wifi_direct": 8.0,
        "private_hotspot": 12.0,
        "webrtc": 70.0,
        "sealed_relay": 120.0,
        "onefield": 250.0,
    }.get(route, 100.0)
