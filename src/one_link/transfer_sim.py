"""Deterministic never-lose transfer torture simulator.

The simulator uses synthetic manifests, so it can model multi-gigabyte sends
without writing multi-gigabyte files. It exercises the same planning ideas as
the live engine: rarest-first chunk scheduling, route memory, transient
failures, corruption retry, offline waits, and legacy fallback.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from typing import Iterable

from .swarm_plan import ChunkSource, plan_swarm_sources, source_from_hashes
from .transfer_doctor import RouteMemory, RouteObservation, diagnose_transfer
from .transfer_intent import FileChunkManifest, FileManifest


@dataclass(frozen=True)
class SimSource:
    peer_fp: str
    route: str
    chunk_indexes: frozenset[int]
    trust_score: float = 1.0
    latency_ms: float = 10.0
    bandwidth_bps: float = 100_000_000.0
    reliability: float = 0.99
    old_version: bool = False


@dataclass(frozen=True)
class TortureReport:
    seed: int
    file_size: int
    chunks_total: int
    chunks_done: int
    delivered: bool
    attempts: int
    retries: int
    corruptions: int
    offline_waits: int
    fallback_events: int
    bytes_sent: int
    bytes_saved: int
    doctor_states: tuple[str, ...]
    best_route: str
    route_scores: tuple[dict, ...]

    def to_dict(self) -> dict:
        return {
            "seed": self.seed,
            "file_size": self.file_size,
            "chunks_total": self.chunks_total,
            "chunks_done": self.chunks_done,
            "delivered": self.delivered,
            "attempts": self.attempts,
            "retries": self.retries,
            "corruptions": self.corruptions,
            "offline_waits": self.offline_waits,
            "fallback_events": self.fallback_events,
            "bytes_sent": self.bytes_sent,
            "bytes_saved": self.bytes_saved,
            "doctor_states": list(self.doctor_states),
            "best_route": self.best_route,
            "route_scores": list(self.route_scores),
        }


def synthetic_manifest(
    *,
    name: str = "huge-video.bin",
    size: int,
    chunk_size: int = 1024 * 1024,
) -> FileManifest:
    if size < 0:
        raise ValueError("size must be non-negative")
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    chunks: list[FileChunkManifest] = []
    offset = 0
    index = 0
    while offset < size or (size == 0 and not chunks):
        end = min(size, offset + chunk_size)
        if size == 0:
            end = 0
        h = hashlib.blake2s(
            f"{name}:{size}:{index}:{offset}:{end}".encode("utf-8"),
            digest_size=32,
        ).hexdigest()
        chunks.append(FileChunkManifest(
            index=index,
            start=offset,
            end=end,
            size=end - offset,
            hash=h,
        ))
        if size == 0:
            break
        offset = end
        index += 1
    blob = hashlib.blake2s(
        f"{name}:{size}:{len(chunks)}".encode("utf-8"),
        digest_size=32,
    ).hexdigest()
    return FileManifest(name=name, size=size, blob_hash=blob, chunks=tuple(chunks))


def _default_sources(manifest: FileManifest) -> tuple[SimSource, ...]:
    indexes = [c.index for c in manifest.chunks]
    even = frozenset(i for i in indexes if i % 2 == 0)
    odd = frozenset(i for i in indexes if i % 2 == 1)
    all_chunks = frozenset(indexes)
    return (
        SimSource("a" * 64, "lan", even, trust_score=2.0, latency_ms=4, bandwidth_bps=250_000_000, reliability=0.97),
        SimSource("b" * 64, "relay", odd, trust_score=1.5, latency_ms=80, bandwidth_bps=80_000_000, reliability=0.93),
        SimSource("c" * 64, "prior", all_chunks, trust_score=2.0, latency_ms=1, bandwidth_bps=1_000_000_000, reliability=0.88),
    )


def _source_to_plan_source(source: SimSource, manifest: FileManifest) -> ChunkSource:
    hashes = [c.hash for c in manifest.chunks if c.index in source.chunk_indexes]
    return source_from_hashes(
        source.peer_fp,
        hashes,
        trust_score=source.trust_score,
        latency_ms=source.latency_ms,
        bandwidth_bps=source.bandwidth_bps,
        reliability=source.reliability,
        route_kind=source.route,
    )


def simulate_never_lose_transfer(
    *,
    size: int = 10 * 1024 * 1024 * 1024,
    chunk_size: int = 16 * 1024 * 1024,
    seed: int = 20260507,
    sources: Iterable[SimSource] | None = None,
    drop_rate: float = 0.03,
    corruption_rate: float = 0.01,
    max_rounds: int = 50_000,
) -> TortureReport:
    rng = random.Random(seed)
    manifest = synthetic_manifest(size=size, chunk_size=chunk_size)
    sim_sources = tuple(sources) if sources is not None else _default_sources(manifest)
    by_hash = {c.hash: c for c in manifest.chunks}
    delivered: set[int] = set()
    needed = {c.index for c in manifest.chunks}
    route_memory = RouteMemory()
    attempts = retries = corruptions = offline_waits = fallback_events = 0
    bytes_sent = 0
    bytes_saved = 0
    doctor_codes: list[str] = []

    for round_no in range(max_rounds):
        if not needed:
            break
        active_sources: list[SimSource] = []
        for src in sim_sources:
            # Devices may sleep or routes may disappear for a round.
            if rng.random() < drop_rate:
                offline_waits += 1
                route_memory.observe(RouteObservation(
                    route=src.route, ok=False, error_code="offline", at_ms=round_no,
                ))
                diag = diagnose_transfer({
                    "status": "paused",
                    "direction": "out",
                    "metadata": {
                        "delivery_state": "waiting_for_device",
                        "error_class": "PeerOffline",
                    },
                })
                doctor_codes.append(diag.code)
                continue
            active_sources.append(src)
        if not active_sources:
            continue

        plan = plan_swarm_sources(
            manifest=manifest,
            needed_indexes=needed,
            sources=[_source_to_plan_source(s, manifest) for s in active_sources],
        )
        if not plan.assignments:
            continue

        for assignment in plan.assignments:
            if assignment.status != "assigned" or assignment.source_peer_fp is None:
                continue
            src = next(s for s in active_sources if s.peer_fp == assignment.source_peer_fp)
            attempts += 1
            chunk = by_hash[assignment.chunk_hash]
            if src.old_version and rng.random() < 0.5:
                fallback_events += 1
                route_memory.observe(RouteObservation(
                    route=src.route, ok=False, error_code="legacy_fallback", at_ms=round_no,
                ))
                doctor_codes.append(diagnose_transfer({
                    "status": "paused",
                    "direction": "out",
                    "metadata": {
                        "delivery_state": "resuming",
                        "error_class": "ProtocolVersionMismatch",
                    },
                }).code)
                retries += 1
                continue
            if rng.random() < corruption_rate:
                corruptions += 1
                retries += 1
                route_memory.observe(RouteObservation(
                    route=src.route, ok=False, error_code="chunk_integrity", at_ms=round_no,
                ))
                doctor_codes.append(diagnose_transfer({
                    "status": "paused",
                    "direction": "out",
                    "metadata": {
                        "delivery_state": "resuming",
                        "error_class": "ChunkIntegrityError",
                    },
                }).code)
                continue
            delivered.add(chunk.index)
            needed.discard(chunk.index)
            if src.route == "prior":
                bytes_saved += chunk.size
            else:
                bytes_sent += chunk.size
            route_memory.observe(RouteObservation(
                route=src.route,
                ok=True,
                latency_ms=src.latency_ms,
                bandwidth_bps=src.bandwidth_bps,
                at_ms=round_no,
            ))
            if not needed:
                break

    delivered_ok = len(delivered) == len(manifest.chunks)
    if delivered_ok:
        doctor_codes.append("done")
    route_scores = tuple(c.__dict__ for c in route_memory.candidates())
    return TortureReport(
        seed=seed,
        file_size=size,
        chunks_total=len(manifest.chunks),
        chunks_done=len(delivered),
        delivered=delivered_ok,
        attempts=attempts,
        retries=retries,
        corruptions=corruptions,
        offline_waits=offline_waits,
        fallback_events=fallback_events,
        bytes_sent=bytes_sent,
        bytes_saved=bytes_saved,
        doctor_states=tuple(dict.fromkeys(doctor_codes)),
        best_route=route_memory.best_route(),
        route_scores=route_scores,
    )


def simulate_autopilot_torture_matrix(
    *,
    size: int = 2 * 1024 * 1024 * 1024,
    chunk_size: int = 16 * 1024 * 1024,
    seeds: Iterable[int] = (3, 7, 11, 19),
) -> dict[str, object]:
    """Run a small deterministic matrix of hard transfer conditions.

    This is the benchmark harness for the product promise: big sends should
    finish under drops, corruption, sleep/reconnect, and version fallback.
    It stays synthetic so CI can model multi-GB videos without disk I/O.
    """

    scenarios = {
        "clean_lan": {"drop_rate": 0.0, "corruption_rate": 0.0},
        "sleepy_wifi": {"drop_rate": 0.22, "corruption_rate": 0.01},
        "hostile_wifi": {"drop_rate": 0.35, "corruption_rate": 0.06},
        "prior_knowledge": {"drop_rate": 0.05, "corruption_rate": 0.01},
    }
    reports = []
    for name, params in scenarios.items():
        for seed in seeds:
            manifest = synthetic_manifest(size=size, chunk_size=chunk_size)
            sources = None
            if name == "prior_knowledge":
                all_indexes = frozenset(c.index for c in manifest.chunks)
                sources = (
                    SimSource(
                        "p" * 64,
                        "prior",
                        all_indexes,
                        trust_score=2.0,
                        latency_ms=1.0,
                        bandwidth_bps=2_000_000_000,
                        reliability=0.97,
                    ),
                    SimSource(
                        "l" * 64,
                        "lan",
                        frozenset(i for i in all_indexes if i % 3 == 0),
                        trust_score=1.5,
                        latency_ms=5.0,
                        bandwidth_bps=700_000_000,
                        reliability=0.98,
                    ),
                )
            report = simulate_never_lose_transfer(
                size=size,
                chunk_size=chunk_size,
                seed=int(seed),
                sources=sources,
                max_rounds=80_000,
                **params,
            )
            row = report.to_dict()
            row["scenario"] = name
            row["efficiency_multiplier"] = round(
                report.file_size / max(1, report.bytes_sent),
                3,
            )
            reports.append(row)
    delivered = sum(1 for r in reports if r["delivered"])
    retries = sum(int(r["retries"]) for r in reports)
    offline_waits = sum(int(r["offline_waits"]) for r in reports)
    avg_efficiency = (
        sum(float(r["efficiency_multiplier"]) for r in reports) / max(1, len(reports))
    )
    return {
        "runs": len(reports),
        "delivered": delivered,
        "delivery_rate": round(delivered / max(1, len(reports)), 6),
        "retries": retries,
        "offline_waits": offline_waits,
        "avg_efficiency_multiplier": round(avg_efficiency, 3),
        "reports": reports,
    }


def main() -> int:
    report = simulate_never_lose_transfer()
    print("One Link never-lose transfer torture simulator")
    for key, value in report.to_dict().items():
        print(f"  {key}: {value}")
    return 0 if report.delivered else 1


if __name__ == "__main__":
    raise SystemExit(main())
