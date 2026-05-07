"""Trust-aware chunk source planning for future swarm transfer.

This is deliberately local and deterministic: given a file manifest and a set
of peers that claim chunks, pick the best source for each missing chunk. The
live transport can later execute this plan over LAN, relay, or courier paths.
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
    available: bool = True

    def score_for(self, chunk_hash: str) -> tuple[int, float, float]:
        has_chunk = 1 if chunk_hash in self.chunk_hashes else 0
        latency = self.latency_ms if self.latency_ms is not None else 10_000.0
        return (has_chunk, self.trust_score, -latency)


@dataclass(frozen=True)
class ChunkAssignment:
    index: int
    chunk_hash: str
    source_peer_fp: str | None
    status: str


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
    assignments: list[ChunkAssignment] = []
    for c in manifest.chunks:
        if c.index not in needed:
            continue
        candidates = [s for s in usable if c.hash in s.chunk_hashes]
        if not candidates:
            assignments.append(ChunkAssignment(c.index, c.hash, None, "missing"))
            continue
        # Highest trust wins, then lower latency. Sorting by tuple keeps the
        # decision deterministic and easy to test.
        best = max(candidates, key=lambda s: s.score_for(c.hash))
        assignments.append(ChunkAssignment(c.index, c.hash, best.peer_fp, "assigned"))
    return SwarmPlan(tuple(assignments))


def source_from_hashes(
    peer_fp: str,
    hashes: Iterable[str],
    *,
    trust_score: float = 0.0,
    latency_ms: float | None = None,
    available: bool = True,
) -> ChunkSource:
    return ChunkSource(
        peer_fp=peer_fp,
        chunk_hashes=frozenset(str(h) for h in hashes),
        trust_score=float(trust_score),
        latency_ms=latency_ms,
        available=available,
    )


def source_index_from_claims(
    claims: Mapping[str, Iterable[str]],
    *,
    trust_scores: Mapping[str, float] | None = None,
    latencies_ms: Mapping[str, float] | None = None,
) -> tuple[ChunkSource, ...]:
    trust_scores = trust_scores or {}
    latencies_ms = latencies_ms or {}
    return tuple(
        source_from_hashes(
            fp,
            hashes,
            trust_score=trust_scores.get(fp, 0.0),
            latency_ms=latencies_ms.get(fp),
        )
        for fp, hashes in claims.items()
    )
