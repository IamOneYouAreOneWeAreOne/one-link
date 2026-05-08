"""Trust-aware chunk source planning for swarm transfer.

This is deliberately local and deterministic: given a file manifest and a set
of peers that claim chunks, pick the best source for each missing chunk.

The planner uses three ideas that matter for very large files:

* rarest-first scheduling so fragile / scarce chunks are fetched before common
  chunks;
* trust-aware route scoring so verified local devices beat fast-but-weaker
  paths;
* byte-load balancing so equal sources are used in parallel instead of one
  device doing all the work.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .transfer_intent import FileManifest


@dataclass(frozen=True)
class ChunkSource:
    peer_fp: str
    chunk_hashes: frozenset[str]
    trust_score: float = 0.0
    latency_ms: float | None = None
    bandwidth_bps: float | None = None
    reliability: float = 1.0
    energy_cost: float = 1.0
    route_kind: str = "unknown"
    available: bool = True
    coherence_score: float | None = None

    def score_for(self, chunk_hash: str) -> tuple[int, float, float]:
        has_chunk = 1 if chunk_hash in self.chunk_hashes else 0
        latency = self.latency_ms if self.latency_ms is not None else 10_000.0
        return (has_chunk, self.trust_score, -latency)

    def route_score(self) -> tuple[float, float, float, float, float, str]:
        """Deterministic strength score for this source.

        Higher is better. Trust remains first because chunk data is always
        hash-verified, but wasting time with weak or flaky peers still hurts
        the user experience.
        """

        latency = self.latency_ms if self.latency_ms is not None else 10_000.0
        bandwidth = self.bandwidth_bps if self.bandwidth_bps is not None else 0.0
        reliability = min(1.0, max(0.0, float(self.reliability)))
        energy = max(0.0, float(self.energy_cost))
        coherence = (
            min(1.0, max(0.0, float(self.coherence_score)))
            if self.coherence_score is not None
            else (
                0.40 * min(1.0, max(0.0, float(self.trust_score)))
                + 0.32 * reliability
                + 0.18 * min(1.0, max(0.0, float(bandwidth)) / 1_000_000_000.0)
                + 0.10 * (1.0 / (1.0 + max(0.0, latency) / 50.0))
            )
        )
        return (
            float(self.trust_score),
            coherence,
            reliability,
            float(bandwidth),
            -float(latency),
            -energy,
            self.peer_fp,
        )

    def route_score_without_tiebreaker(self) -> tuple[float, float, float, float, float, float]:
        score = self.route_score()
        return score[:5]


@dataclass(frozen=True)
class ChunkAssignment:
    index: int
    chunk_hash: str
    source_peer_fp: str | None
    status: str
    size: int = 0
    candidate_count: int = 0
    priority: int = 0


@dataclass(frozen=True)
class SwarmPlan:
    assignments: tuple[ChunkAssignment, ...]

    @property
    def complete(self) -> bool:
        return all(a.status == "assigned" for a in self.assignments)

    @property
    def missing_indexes(self) -> tuple[int, ...]:
        return tuple(a.index for a in self.assignments if a.status == "missing")

    @property
    def sources(self) -> tuple[str, ...]:
        seen: list[str] = []
        for a in self.assignments:
            if a.source_peer_fp and a.source_peer_fp not in seen:
                seen.append(a.source_peer_fp)
        return tuple(seen)

    def per_source_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for a in self.assignments:
            if a.source_peer_fp:
                counts[a.source_peer_fp] = counts.get(a.source_peer_fp, 0) + 1
        return counts

    def per_source_bytes(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for a in self.assignments:
            if a.source_peer_fp:
                counts[a.source_peer_fp] = counts.get(a.source_peer_fp, 0) + int(a.size)
        return counts

    @property
    def assigned_bytes(self) -> int:
        return sum(a.size for a in self.assignments if a.status == "assigned")

    @property
    def missing_bytes(self) -> int:
        return sum(a.size for a in self.assignments if a.status == "missing")

    @property
    def rarest_first_indexes(self) -> tuple[int, ...]:
        return tuple(a.index for a in self.assignments)


def plan_swarm_sources(
    *,
    manifest: FileManifest,
    needed_indexes: Iterable[int] | None,
    sources: Iterable[ChunkSource],
) -> SwarmPlan:
    needed = set(needed_indexes) if needed_indexes is not None else {
        c.index for c in manifest.chunks
    }
    usable = [s for s in sources if s.available]
    source_load_bytes: dict[str, int] = {s.peer_fp: 0 for s in usable}
    candidates_by_hash = {
        c.hash: [s for s in usable if c.hash in s.chunk_hashes]
        for c in manifest.chunks
        if c.index in needed
    }
    chunks = sorted(
        (c for c in manifest.chunks if c.index in needed),
        key=lambda c: (len(candidates_by_hash.get(c.hash, ())), c.index),
    )

    assignments: list[ChunkAssignment] = []
    for priority, c in enumerate(chunks):
        if c.index not in needed:
            continue
        candidates = candidates_by_hash.get(c.hash, [])
        if not candidates:
            assignments.append(ChunkAssignment(
                c.index,
                c.hash,
                None,
                "missing",
                size=c.size,
                candidate_count=0,
                priority=priority,
            ))
            continue
        # Highest route score wins; equal routes are spread by current byte
        # load so multiple local devices work as a parallel fabric.
        best = max(
            candidates,
            key=lambda s: (
                *s.route_score_without_tiebreaker(),
                -source_load_bytes.get(s.peer_fp, 0),
                s.peer_fp,
            ),
        )
        source_load_bytes[best.peer_fp] = source_load_bytes.get(best.peer_fp, 0) + c.size
        assignments.append(ChunkAssignment(
            c.index,
            c.hash,
            best.peer_fp,
            "assigned",
            size=c.size,
            candidate_count=len(candidates),
            priority=priority,
        ))
    return SwarmPlan(tuple(assignments))


def source_from_hashes(
    peer_fp: str,
    hashes: Iterable[str],
    *,
    trust_score: float = 0.0,
    latency_ms: float | None = None,
    bandwidth_bps: float | None = None,
    reliability: float = 1.0,
    energy_cost: float = 1.0,
    route_kind: str = "unknown",
    available: bool = True,
    coherence_score: float | None = None,
) -> ChunkSource:
    return ChunkSource(
        peer_fp=peer_fp,
        chunk_hashes=frozenset(str(h) for h in hashes),
        trust_score=float(trust_score),
        latency_ms=latency_ms,
        bandwidth_bps=bandwidth_bps,
        reliability=reliability,
        energy_cost=energy_cost,
        route_kind=route_kind,
        available=available,
        coherence_score=coherence_score,
    )


def source_index_from_claims(
    claims: Mapping[str, Iterable[str]],
    *,
    trust_scores: Mapping[str, float] | None = None,
    latencies_ms: Mapping[str, float] | None = None,
    bandwidth_bps: Mapping[str, float] | None = None,
    reliabilities: Mapping[str, float] | None = None,
) -> tuple[ChunkSource, ...]:
    trust_scores = trust_scores or {}
    latencies_ms = latencies_ms or {}
    bandwidth_bps = bandwidth_bps or {}
    reliabilities = reliabilities or {}
    return tuple(
        source_from_hashes(
            fp,
            hashes,
            trust_score=trust_scores.get(fp, 0.0),
            latency_ms=latencies_ms.get(fp),
            bandwidth_bps=bandwidth_bps.get(fp),
            reliability=reliabilities.get(fp, 1.0),
        )
        for fp, hashes in claims.items()
    )
