"""Adaptive transfer planning inspired by Coherence NPE.

This module is deliberately deterministic and dependency-light. It ports the
parts of Coherence that matter for One Link transfers:

* calibration tiers from adaptive cost models;
* Pareto-frontier strategy selection;
* an autonomic health regulator for route degradation;
* route memory that learns from observed latency/bandwidth/failure.

The daemon can use it incrementally without changing the wire protocol. The
first production value is simple: avoid expensive planning work unless it is
likely to save more than it costs.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping


MiB = 1024 * 1024


class CalibrationTier(str, Enum):
    COLD = "cold"
    WARMING = "warming"
    WARM = "warm"
    HOT = "hot"
    VERIFIED = "verified"


class TransferMode(str, Enum):
    HASH_STREAM = "hash_stream"
    FIXED_MANIFEST = "fixed_manifest"
    CDC_MANIFEST = "cdc_manifest"
    SWARM_CDC = "swarm_cdc"
    WAIT = "wait"


class HealthState(str, Enum):
    HEALTHY = "healthy"
    OBSERVING = "observing"
    CONSTRAINED = "constrained"
    REPAIR = "repair"


@dataclass(frozen=True)
class TransferRouteObservation:
    route: str
    ok: bool
    latency_ms: float | None = None
    bandwidth_bps: float | None = None
    energy_cost: float = 1.0


@dataclass(frozen=True)
class RouteStats:
    route: str
    observations: int = 0
    successes: int = 0
    failures: int = 0
    latency_ema_ms: float | None = None
    bandwidth_ema_bps: float | None = None
    energy_ema: float = 1.0

    @property
    def reliability(self) -> float:
        # Jeffreys-style smoothing prevents cold routes from looking perfect.
        return (self.successes + 0.5) / max(1.0, self.observations + 1.0)

    @property
    def tier(self) -> CalibrationTier:
        if self.observations < 4:
            return CalibrationTier.COLD
        if self.observations < 12:
            return CalibrationTier.WARMING
        if self.observations < 32:
            return CalibrationTier.WARM
        if self.failures == 0 and self.observations >= 64:
            return CalibrationTier.VERIFIED
        return CalibrationTier.HOT

    @property
    def confidence(self) -> float:
        base = {
            CalibrationTier.COLD: 0.25,
            CalibrationTier.WARMING: 0.45,
            CalibrationTier.WARM: 0.65,
            CalibrationTier.HOT: 0.82,
            CalibrationTier.VERIFIED: 0.95,
        }[self.tier]
        return round(base * self.reliability, 4)

    def observe(self, obs: TransferRouteObservation, *, alpha: float = 0.25) -> "RouteStats":
        latency = self.latency_ema_ms
        bandwidth = self.bandwidth_ema_bps
        energy = self.energy_ema
        if obs.ok and obs.latency_ms is not None:
            latency = obs.latency_ms if latency is None else latency * (1 - alpha) + obs.latency_ms * alpha
        if obs.ok and obs.bandwidth_bps is not None:
            bandwidth = obs.bandwidth_bps if bandwidth is None else bandwidth * (1 - alpha) + obs.bandwidth_bps * alpha
        energy = energy * (1 - alpha) + max(0.01, float(obs.energy_cost)) * alpha
        return RouteStats(
            route=obs.route,
            observations=self.observations + 1,
            successes=self.successes + (1 if obs.ok else 0),
            failures=self.failures + (0 if obs.ok else 1),
            latency_ema_ms=latency,
            bandwidth_ema_bps=bandwidth,
            energy_ema=energy,
        )


@dataclass(frozen=True)
class TransferCandidate:
    mode: TransferMode
    route: str
    estimated_ms: float
    estimated_wire_bytes: int
    manifest_cpu_ms: float
    reliability: float
    energy_score: float
    confidence: float
    reasons: tuple[str, ...] = ()

    def dominates(self, other: "TransferCandidate") -> bool:
        return (
            self.estimated_ms <= other.estimated_ms
            and self.estimated_wire_bytes <= other.estimated_wire_bytes
            and self.manifest_cpu_ms <= other.manifest_cpu_ms
            and self.energy_score <= other.energy_score
            and self.reliability >= other.reliability
            and (
                self.estimated_ms < other.estimated_ms
                or self.estimated_wire_bytes < other.estimated_wire_bytes
                or self.reliability > other.reliability
            )
        )


@dataclass(frozen=True)
class TransferBrainDecision:
    selected: TransferCandidate
    frontier: tuple[TransferCandidate, ...]
    health: HealthState
    action: str

    def to_dict(self) -> dict:
        return {
            "selected": self.selected.mode.value,
            "route": self.selected.route,
            "estimated_ms": round(self.selected.estimated_ms, 3),
            "estimated_wire_bytes": self.selected.estimated_wire_bytes,
            "manifest_cpu_ms": round(self.selected.manifest_cpu_ms, 3),
            "reliability": round(self.selected.reliability, 4),
            "confidence": round(self.selected.confidence, 4),
            "health": self.health.value,
            "action": self.action,
            "frontier": [c.mode.value for c in self.frontier],
            "reasons": list(self.selected.reasons),
        }


def pareto_frontier(candidates: Iterable[TransferCandidate]) -> tuple[TransferCandidate, ...]:
    items = tuple(candidates)
    frontier = [
        c for c in items
        if not any(other is not c and other.dominates(c) for other in items)
    ]
    return tuple(sorted(
        frontier,
        key=lambda c: (
            c.estimated_ms,
            c.estimated_wire_bytes,
            c.energy_score,
            -c.reliability,
            c.mode.value,
            c.route,
        ),
    ))


class AdaptiveTransferBrain:
    """Learns route cost and chooses a transfer strategy."""

    DEFAULT_HASH_MIB_S = 1500.0
    DEFAULT_FIXED_MIB_S = 1100.0
    DEFAULT_CDC_MIB_S = 8.0
    DEFAULT_ROUTE_BPS = 80_000_000.0

    def __init__(self) -> None:
        self._routes: dict[str, RouteStats] = {}

    def observe(self, obs: TransferRouteObservation) -> None:
        current = self._routes.get(obs.route, RouteStats(route=obs.route))
        self._routes[obs.route] = current.observe(obs)

    def route_stats(self) -> tuple[RouteStats, ...]:
        return tuple(sorted(
            self._routes.values(),
            key=lambda s: (-s.reliability, -(s.bandwidth_ema_bps or 0.0), s.route),
        ))

    def decide(
        self,
        *,
        size_bytes: int,
        supports_cdc: bool,
        supports_swarm: bool = False,
        prior_hit_rate: float | None = None,
        routes: Iterable[str] | None = None,
        observed_hash_mib_s: float | None = None,
        observed_fixed_mib_s: float | None = None,
        observed_cdc_mib_s: float | None = None,
    ) -> TransferBrainDecision:
        size = max(0, int(size_bytes))
        hit_rate = min(1.0, max(0.0, float(prior_hit_rate or 0.0)))
        candidate_routes = tuple(routes or (s.route for s in self.route_stats()) or ("lan",))
        candidates: list[TransferCandidate] = []
        for route in candidate_routes:
            stats = self._routes.get(route, RouteStats(route=route))
            candidates.extend(self._candidates_for_route(
                route=route,
                stats=stats,
                size_bytes=size,
                supports_cdc=supports_cdc,
                supports_swarm=supports_swarm,
                prior_hit_rate=hit_rate,
                hash_mib_s=observed_hash_mib_s or self.DEFAULT_HASH_MIB_S,
                fixed_mib_s=observed_fixed_mib_s or self.DEFAULT_FIXED_MIB_S,
                cdc_mib_s=observed_cdc_mib_s or self.DEFAULT_CDC_MIB_S,
            ))
        frontier = pareto_frontier(candidates)
        selected = min(
            frontier or tuple(candidates),
            key=lambda c: (
                c.estimated_ms / max(0.05, c.reliability),
                c.estimated_wire_bytes,
                c.manifest_cpu_ms,
                c.mode.value,
            ),
        )
        health, action = self._regulate(selected)
        return TransferBrainDecision(
            selected=selected,
            frontier=frontier,
            health=health,
            action=action,
        )

    def _candidates_for_route(
        self,
        *,
        route: str,
        stats: RouteStats,
        size_bytes: int,
        supports_cdc: bool,
        supports_swarm: bool,
        prior_hit_rate: float,
        hash_mib_s: float,
        fixed_mib_s: float,
        cdc_mib_s: float,
    ) -> tuple[TransferCandidate, ...]:
        route_bps = stats.bandwidth_ema_bps or self.DEFAULT_ROUTE_BPS
        route_ms = (size_bytes * 8.0 / max(1.0, route_bps)) * 1000.0
        latency = stats.latency_ema_ms or 10.0
        reliability = stats.reliability
        confidence = stats.confidence

        def cpu_ms(speed_mib_s: float) -> float:
            return (size_bytes / MiB) / max(0.001, speed_mib_s) * 1000.0

        out = [
            TransferCandidate(
                mode=TransferMode.HASH_STREAM,
                route=route,
                estimated_ms=latency + route_ms + cpu_ms(hash_mib_s),
                estimated_wire_bytes=size_bytes,
                manifest_cpu_ms=cpu_ms(hash_mib_s),
                reliability=reliability,
                energy_score=stats.energy_ema,
                confidence=confidence,
                reasons=("fastest compatible baseline",),
            ),
            TransferCandidate(
                mode=TransferMode.FIXED_MANIFEST,
                route=route,
                estimated_ms=latency + route_ms + cpu_ms(fixed_mib_s),
                estimated_wire_bytes=size_bytes,
                manifest_cpu_ms=cpu_ms(fixed_mib_s),
                reliability=reliability,
                energy_score=stats.energy_ema * 0.92,
                confidence=confidence,
                reasons=("aligned-block high-throughput manifest",),
            ),
        ]
        if supports_cdc:
            wire_bytes = int(size_bytes * (1.0 - prior_hit_rate))
            cdc_route_ms = (wire_bytes * 8.0 / max(1.0, route_bps)) * 1000.0
            out.append(TransferCandidate(
                mode=TransferMode.CDC_MANIFEST,
                route=route,
                estimated_ms=latency + cdc_route_ms + cpu_ms(cdc_mib_s),
                estimated_wire_bytes=wire_bytes,
                manifest_cpu_ms=cpu_ms(cdc_mib_s),
                reliability=reliability,
                energy_score=stats.energy_ema * (1.0 - prior_hit_rate * 0.7),
                confidence=confidence,
                reasons=(f"prior hit estimate {prior_hit_rate:.1%}",),
            ))
            if supports_swarm:
                out.append(TransferCandidate(
                    mode=TransferMode.SWARM_CDC,
                    route=route,
                    estimated_ms=latency + cdc_route_ms * 0.55 + cpu_ms(cdc_mib_s),
                    estimated_wire_bytes=wire_bytes,
                    manifest_cpu_ms=cpu_ms(cdc_mib_s),
                    reliability=min(0.995, reliability + 0.08),
                    energy_score=stats.energy_ema * (1.0 - prior_hit_rate * 0.8),
                    confidence=confidence * 0.95,
                    reasons=("multiple trusted sources can split missing chunks",),
                ))
        return tuple(out)

    def _regulate(self, selected: TransferCandidate) -> tuple[HealthState, str]:
        if selected.reliability < 0.35:
            return HealthState.REPAIR, "refresh_route_and_reopen_session"
        if selected.reliability < 0.60:
            return HealthState.CONSTRAINED, "prefer_simplest_verified_protocol"
        if selected.confidence < 0.35:
            return HealthState.OBSERVING, "collect_more_route_evidence"
        return HealthState.HEALTHY, "send"


def decision_from_observations(
    *,
    size_bytes: int,
    supports_cdc: bool,
    supports_swarm: bool,
    prior_hit_rate: float | None,
    observations: Iterable[TransferRouteObservation],
    routes: Iterable[str] | None = None,
    speeds: Mapping[str, float] | None = None,
) -> TransferBrainDecision:
    brain = AdaptiveTransferBrain()
    for obs in observations:
        brain.observe(obs)
    speeds = speeds or {}
    return brain.decide(
        size_bytes=size_bytes,
        supports_cdc=supports_cdc,
        supports_swarm=supports_swarm,
        prior_hit_rate=prior_hit_rate,
        routes=routes,
        observed_hash_mib_s=speeds.get("hash_mib_s"),
        observed_fixed_mib_s=speeds.get("fixed_mib_s"),
        observed_cdc_mib_s=speeds.get("cdc_mib_s"),
    )
