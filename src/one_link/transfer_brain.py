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
class MeshNodeSignal:
    """Live evidence for a trusted node in the personal mesh.

    This is the practical form of the Coherence/Tau idea for One Link:
    the score is not mystical, it is earned from trust, route quality,
    chunk overlap, freshness, and local cost. Higher coherence means this
    node should be used earlier for routing, chunk claims, and verification.
    """

    peer_fp: str
    trust_score: float = 0.5
    reliability: float = 0.5
    latency_ms: float | None = None
    bandwidth_bps: float | None = None
    chunk_hit_rate: float = 0.0
    freshness: float = 1.0
    energy_cost: float = 1.0
    route_kind: str = "unknown"

    @property
    def coherence(self) -> float:
        latency = self.latency_ms if self.latency_ms is not None else 250.0
        latency_score = 1.0 / (1.0 + max(0.0, latency) / 50.0)
        bandwidth = self.bandwidth_bps if self.bandwidth_bps is not None else 0.0
        bandwidth_score = min(1.0, max(0.0, bandwidth) / 1_000_000_000.0)
        energy_score = 1.0 / (1.0 + max(0.0, self.energy_cost - 1.0))
        value = (
            0.28 * _clamp01(self.trust_score)
            + 0.24 * _clamp01(self.reliability)
            + 0.18 * bandwidth_score
            + 0.12 * latency_score
            + 0.12 * _clamp01(self.chunk_hit_rate)
            + 0.04 * _clamp01(self.freshness)
            + 0.02 * energy_score
        )
        return round(_clamp01(value), 6)


@dataclass(frozen=True)
class VerificationTask:
    index: int
    chunk_hash: str
    priority: float
    reason: str


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
    coherence_score: float = 0.0
    parallelism: int = 1
    verification_head: tuple[int, ...] = ()
    reasons: tuple[str, ...] = ()

    def dominates(self, other: "TransferCandidate") -> bool:
        return (
            self.estimated_ms <= other.estimated_ms
            and self.estimated_wire_bytes <= other.estimated_wire_bytes
            and self.manifest_cpu_ms <= other.manifest_cpu_ms
            and self.energy_score <= other.energy_score
            and self.reliability >= other.reliability
            and self.coherence_score >= other.coherence_score
            and (
                self.estimated_ms < other.estimated_ms
                or self.estimated_wire_bytes < other.estimated_wire_bytes
                or self.reliability > other.reliability
                or self.coherence_score > other.coherence_score
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
            "coherence_score": round(self.selected.coherence_score, 4),
            "parallelism": self.selected.parallelism,
            "verification_head": list(self.selected.verification_head),
            "health": self.health.value,
            "action": self.action,
            "frontier": [c.mode.value for c in self.frontier],
            "reasons": list(self.selected.reasons),
        }


def adapt_pipeline_profile(
    profile: Mapping[str, int],
    decision: Mapping[str, object] | TransferBrainDecision,
    *,
    max_window_chunks: int = 32,
    max_window_bytes: int = 64 * MiB,
) -> dict[str, int | float | str]:
    """Tune chunk pipeline depth from the current brain decision.

    This is intentionally bounded. A strong LAN/mesh path gets enough
    in-flight work to fill the pipe; an observing/constrained/repair path
    backs off so a flaky session does less damage before the auto-healer
    refreshes it.
    """

    if isinstance(decision, TransferBrainDecision):
        d = decision.to_dict()
    else:
        d = dict(decision)
    chunk_size = max(1, int(profile.get("chunk_size") or MiB))
    base_chunks = max(1, int(profile.get("window_chunks") or 1))
    base_bytes = max(chunk_size, int(profile.get("window_bytes") or base_chunks * chunk_size))
    health = str(d.get("health") or "observing")
    coherence = float(d.get("coherence_score") or 0.0)
    reliability = float(d.get("reliability") or 0.0)
    parallelism = max(1, int(d.get("parallelism") or 1))

    multiplier = 1.0
    reason = "steady"
    if health == HealthState.REPAIR.value:
        multiplier = 0.35
        reason = "repair_backoff"
    elif health == HealthState.CONSTRAINED.value:
        multiplier = 0.55
        reason = "constrained_backoff"
    elif health == HealthState.OBSERVING.value:
        multiplier = 0.80
        reason = "observing_probe"
    elif coherence >= 0.88 and reliability >= 0.90:
        multiplier = 2.0
        reason = "coherent_fast_lane"
    elif coherence >= 0.72 and reliability >= 0.80:
        multiplier = 1.5
        reason = "coherent_lane"

    if parallelism > 1 and health == HealthState.HEALTHY.value:
        multiplier *= min(1.75, 1.0 + (parallelism - 1) * 0.18)
        reason = "mesh_parallel_lane" if reason == "steady" else reason

    tuned_chunks = max(1, min(max_window_chunks, int(round(base_chunks * multiplier))))
    tuned_bytes = min(max_window_bytes, max(chunk_size, tuned_chunks * chunk_size, int(base_bytes * multiplier)))
    tuned_chunks = max(1, min(max_window_chunks, tuned_bytes // chunk_size))
    return {
        "chunk_size": chunk_size,
        "window_chunks": int(tuned_chunks),
        "window_bytes": int(tuned_chunks * chunk_size),
        "multiplier": round(multiplier, 4),
        "reason": reason,
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
            -c.coherence_score,
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
        mesh_nodes: Iterable[MeshNodeSignal] | None = None,
        verification_head: Iterable[int] | None = None,
        observed_hash_mib_s: float | None = None,
        observed_fixed_mib_s: float | None = None,
        observed_cdc_mib_s: float | None = None,
    ) -> TransferBrainDecision:
        size = max(0, int(size_bytes))
        hit_rate = min(1.0, max(0.0, float(prior_hit_rate or 0.0)))
        candidate_routes = tuple(routes or (s.route for s in self.route_stats()) or ("lan",))
        mesh = tuple(mesh_nodes or ())
        mesh_coherence = max((n.coherence for n in mesh), default=0.5)
        mesh_parallelism = max(1, min(8, sum(1 for n in mesh if n.coherence >= 0.55)))
        verification = tuple(int(i) for i in (verification_head or ()))[:8]
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
                mesh_coherence=mesh_coherence,
                mesh_parallelism=mesh_parallelism,
                verification_head=verification,
            ))
        frontier = pareto_frontier(candidates)
        selected = min(
            frontier or tuple(candidates),
            key=lambda c: (
                c.estimated_ms / max(0.05, c.reliability),
                c.estimated_wire_bytes,
                c.manifest_cpu_ms,
                -c.coherence_score,
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
        mesh_coherence: float,
        mesh_parallelism: int,
        verification_head: tuple[int, ...],
    ) -> tuple[TransferCandidate, ...]:
        route_bps = stats.bandwidth_ema_bps or self.DEFAULT_ROUTE_BPS
        route_ms = (size_bytes * 8.0 / max(1.0, route_bps)) * 1000.0
        latency = stats.latency_ema_ms or 10.0
        reliability = stats.reliability
        confidence = stats.confidence
        route_coherence = route_coherence_score(stats)
        coherence = round((route_coherence * 0.70) + (mesh_coherence * 0.30), 6)

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
                coherence_score=coherence,
                verification_head=verification_head,
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
                coherence_score=coherence,
                verification_head=verification_head,
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
                coherence_score=round(min(1.0, coherence + prior_hit_rate * 0.15), 6),
                parallelism=1,
                verification_head=verification_head,
                reasons=(f"prior hit estimate {prior_hit_rate:.1%}",),
            ))
            if supports_swarm:
                out.append(TransferCandidate(
                    mode=TransferMode.SWARM_CDC,
                    route=route,
                    estimated_ms=latency + cdc_route_ms * max(0.22, 0.75 / mesh_parallelism) + cpu_ms(cdc_mib_s),
                    estimated_wire_bytes=wire_bytes,
                    manifest_cpu_ms=cpu_ms(cdc_mib_s),
                    reliability=min(0.995, reliability + 0.08),
                    energy_score=stats.energy_ema * (1.0 - prior_hit_rate * 0.8),
                    confidence=confidence * 0.95,
                    coherence_score=round(min(1.0, coherence + 0.10 + prior_hit_rate * 0.18), 6),
                    parallelism=mesh_parallelism,
                    verification_head=verification_head,
                    reasons=("multiple trusted sources can split missing chunks",),
                ))
        return tuple(out)

    def _regulate(self, selected: TransferCandidate) -> tuple[HealthState, str]:
        if selected.reliability < 0.35:
            return HealthState.REPAIR, "refresh_route_and_reopen_session"
        if selected.coherence_score < 0.30:
            return HealthState.REPAIR, "seek_better_mesh_route"
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
    mesh_nodes: Iterable[MeshNodeSignal] | None = None,
    verification_head: Iterable[int] | None = None,
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
        mesh_nodes=mesh_nodes,
        verification_head=verification_head,
        observed_hash_mib_s=speeds.get("hash_mib_s"),
        observed_fixed_mib_s=speeds.get("fixed_mib_s"),
        observed_cdc_mib_s=speeds.get("cdc_mib_s"),
    )


def _clamp01(value: float) -> float:
    return min(1.0, max(0.0, float(value)))


def route_coherence_score(stats: RouteStats) -> float:
    latency = stats.latency_ema_ms if stats.latency_ema_ms is not None else 250.0
    latency_score = 1.0 / (1.0 + max(0.0, latency) / 50.0)
    bandwidth = stats.bandwidth_ema_bps if stats.bandwidth_ema_bps is not None else 0.0
    bandwidth_score = min(1.0, max(0.0, bandwidth) / 1_000_000_000.0)
    energy_score = 1.0 / (1.0 + max(0.0, stats.energy_ema - 1.0))
    value = (
        0.45 * stats.reliability
        + 0.25 * bandwidth_score
        + 0.18 * latency_score
        + 0.08 * stats.confidence
        + 0.04 * energy_score
    )
    return round(_clamp01(value), 6)


def verification_priority_order(
    chunks: Iterable[object],
    *,
    claim_counts: Mapping[str, int] | None = None,
    source_coherence: Mapping[str, float] | None = None,
    max_items: int = 16,
) -> tuple[VerificationTask, ...]:
    """Order chunk verification suspicious-first.

    Rare chunks, chunks with weak source coherence, and edge chunks get checked
    first. This borrows the forge shootout's "verify where failure is likeliest"
    idea without weakening cryptographic verification: every chunk still must
    hash correctly, we simply surface the most valuable early checks first.
    """
    claim_counts = claim_counts or {}
    source_coherence = source_coherence or {}
    rows = list(chunks)
    if not rows:
        return ()
    last_index = max(int(getattr(c, "index", 0)) for c in rows)
    tasks: list[VerificationTask] = []
    for c in rows:
        idx = int(getattr(c, "index", 0))
        h = str(getattr(c, "hash", ""))
        claims = max(0, int(claim_counts.get(h, 0)))
        coherence = _clamp01(source_coherence.get(h, 0.5))
        rarity = 1.0 / (1.0 + claims)
        edge = 1.0 if idx in (0, last_index) else 0.0
        priority = 0.58 * rarity + 0.32 * (1.0 - coherence) + 0.10 * edge
        reason = "rare_or_unclaimed" if claims <= 1 else "weak_source" if coherence < 0.45 else "edge_guard"
        tasks.append(VerificationTask(idx, h, round(priority, 6), reason))
    return tuple(sorted(tasks, key=lambda t: (-t.priority, t.index))[:max_items])
