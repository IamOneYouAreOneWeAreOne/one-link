from __future__ import annotations

import random
import time
from pathlib import Path

from one_link.swarm_plan import plan_swarm_sources, source_from_hashes, source_index_from_claims
from one_link.transfer_intent import FileChunkManifest, FileManifest, build_file_manifest


def _manifest(tmp_path: Path):
    src = tmp_path / "large.bin"
    rng = random.Random(1337)
    src.write_bytes(bytes(rng.randrange(0, 256) for _ in range(900_000)))
    return build_file_manifest(src)


def test_swarm_plan_assigns_chunks_across_multiple_sources(tmp_path: Path):
    manifest = _manifest(tmp_path)
    hashes = [c.hash for c in manifest.chunks]
    a = source_from_hashes("aa" * 32, hashes[:1], trust_score=0.8, latency_ms=5)
    b = source_from_hashes("bb" * 32, hashes[1:], trust_score=0.8, latency_ms=5)
    plan = plan_swarm_sources(manifest=manifest, needed_indexes=None, sources=[a, b])
    assert plan.complete
    assert set(plan.sources) == {"aa" * 32, "bb" * 32}
    assert sum(plan.per_source_counts().values()) == manifest.chunk_count


def test_swarm_plan_prefers_higher_trust_over_latency(tmp_path: Path):
    manifest = _manifest(tmp_path)
    h = manifest.chunks[0].hash
    trusted = source_from_hashes("aa" * 32, [h], trust_score=0.9, latency_ms=50)
    fast_untrusted = source_from_hashes("bb" * 32, [h], trust_score=0.2, latency_ms=1)
    plan = plan_swarm_sources(
        manifest=manifest,
        needed_indexes=[manifest.chunks[0].index],
        sources=[fast_untrusted, trusted],
    )
    assert plan.assignments[0].source_peer_fp == "aa" * 32


def test_swarm_plan_reports_missing_chunks(tmp_path: Path):
    manifest = _manifest(tmp_path)
    first = manifest.chunks[0]
    source = source_from_hashes("aa" * 32, [first.hash], trust_score=1.0)
    plan = plan_swarm_sources(manifest=manifest, needed_indexes=None, sources=[source])
    assert plan.complete is False
    assert first.index not in plan.missing_indexes
    assert set(plan.missing_indexes) == {c.index for c in manifest.chunks[1:]}


def test_source_index_from_claims_builds_deterministic_sources():
    claims = {"b": ["2"], "a": ["1"]}
    sources = source_index_from_claims(
        claims,
        trust_scores={"a": 0.8, "b": 0.4},
        latencies_ms={"a": 10, "b": 20},
        bandwidth_bps={"a": 1_000_000},
        reliabilities={"a": 0.99},
    )
    by_fp = {s.peer_fp: s for s in sources}
    assert by_fp["a"].trust_score == 0.8
    assert by_fp["b"].latency_ms == 20
    assert by_fp["a"].bandwidth_bps == 1_000_000
    assert by_fp["a"].reliability == 0.99


def test_swarm_plan_schedules_rarest_chunks_first(tmp_path: Path):
    manifest = _manifest(tmp_path)
    common = manifest.chunks[0]
    rare = manifest.chunks[1]
    a = source_from_hashes("aa" * 32, [common.hash, rare.hash], trust_score=1.0)
    b = source_from_hashes("bb" * 32, [common.hash], trust_score=1.0)

    plan = plan_swarm_sources(
        manifest=manifest,
        needed_indexes=[common.index, rare.index],
        sources=[a, b],
    )

    assert plan.assignments[0].index == rare.index
    assert plan.assignments[0].candidate_count == 1
    assert plan.rarest_first_indexes == (rare.index, common.index)


def test_swarm_plan_balances_equal_sources_by_bytes(tmp_path: Path):
    manifest = _manifest(tmp_path)
    hashes = [c.hash for c in manifest.chunks[:4]]
    a = source_from_hashes("aa" * 32, hashes, trust_score=1.0, latency_ms=5)
    b = source_from_hashes("bb" * 32, hashes, trust_score=1.0, latency_ms=5)

    plan = plan_swarm_sources(
        manifest=manifest,
        needed_indexes=[c.index for c in manifest.chunks[:4]],
        sources=[a, b],
    )

    assert set(plan.sources) == {"aa" * 32, "bb" * 32}
    assert sum(plan.per_source_bytes().values()) == plan.assigned_bytes


def test_swarm_plan_splits_by_predicted_finish_time_not_just_fastest_label(tmp_path: Path):
    manifest = _manifest(tmp_path)
    chunks = manifest.chunks[:12]
    hashes = [c.hash for c in chunks]
    fast = source_from_hashes(
        "aa" * 32,
        hashes,
        trust_score=1.0,
        latency_ms=3,
        bandwidth_bps=800_000_000,
        reliability=0.99,
    )
    helper = source_from_hashes(
        "bb" * 32,
        hashes,
        trust_score=1.0,
        latency_ms=4,
        bandwidth_bps=250_000_000,
        reliability=0.99,
    )

    plan = plan_swarm_sources(
        manifest=manifest,
        needed_indexes=[c.index for c in chunks],
        sources=[fast, helper],
    )

    counts = plan.per_source_counts()
    assert counts["aa" * 32] > counts["bb" * 32]
    assert counts["bb" * 32] > 0
    assert sum(counts.values()) == len(chunks)


def test_swarm_plan_prefers_reliable_high_bandwidth_route_after_trust(tmp_path: Path):
    manifest = _manifest(tmp_path)
    h = manifest.chunks[0].hash
    flaky_fast = source_from_hashes(
        "aa" * 32,
        [h],
        trust_score=1.0,
        latency_ms=1,
        bandwidth_bps=500_000_000,
        reliability=0.20,
    )
    steady = source_from_hashes(
        "bb" * 32,
        [h],
        trust_score=1.0,
        latency_ms=20,
        bandwidth_bps=50_000_000,
        reliability=0.99,
    )

    plan = plan_swarm_sources(
        manifest=manifest,
        needed_indexes=[manifest.chunks[0].index],
        sources=[flaky_fast, steady],
    )

    assert plan.assignments[0].source_peer_fp == "bb" * 32


def test_swarm_plan_uses_coherence_after_trust(tmp_path: Path):
    manifest = _manifest(tmp_path)
    h = manifest.chunks[0].hash
    ordinary = source_from_hashes(
        "aa" * 32,
        [h],
        trust_score=1.0,
        latency_ms=3,
        bandwidth_bps=800_000_000,
        reliability=0.90,
        coherence_score=0.45,
    )
    coherent = source_from_hashes(
        "bb" * 32,
        [h],
        trust_score=1.0,
        latency_ms=10,
        bandwidth_bps=500_000_000,
        reliability=0.90,
        coherence_score=0.95,
    )

    plan = plan_swarm_sources(
        manifest=manifest,
        needed_indexes=[manifest.chunks[0].index],
        sources=[ordinary, coherent],
    )

    assert plan.assignments[0].source_peer_fp == "bb" * 32


def _timed_sparse_plan(chunk_count: int) -> tuple[float, object]:
    chunks = [
        FileChunkManifest(
            index=i,
            start=i * 2048,
            end=(i + 1) * 2048,
            size=2048,
            hash=f"{i:064x}",
        )
        for i in range(chunk_count)
    ]
    manifest = FileManifest(
        name="large-sparse.bin",
        size=sum(c.size for c in chunks),
        blob_hash="f" * 64,
        chunks=tuple(chunks),
    )
    sources = []
    for source_idx in range(16):
        owned = [
            chunk.hash for chunk in chunks
            if chunk.index % 16 == source_idx or chunk.index % 97 == source_idx
        ]
        sources.append(
            source_from_hashes(
                f"{source_idx:064x}",
                owned,
                trust_score=1.0,
                latency_ms=2.0 + source_idx,
                bandwidth_bps=900_000_000 - source_idx * 10_000_000,
                reliability=0.99,
            )
        )

    start = time.perf_counter()
    plan = plan_swarm_sources(
        manifest=manifest,
        needed_indexes=[chunk.index for chunk in chunks],
        sources=sources,
    )
    return time.perf_counter() - start, plan


def test_swarm_plan_handles_large_sparse_claims_quickly(tmp_path: Path):
    """Planning must scale ~linearly in chunk count.

    A fixed 1-second wall cap gated shared-runner load, not the algorithm:
    a loaded CI box ran the same healthy planner in 2.4 s where a dev box
    runs it in ~0.2 s. The regression this test exists to catch is an
    accidental O(n^2) in plan_swarm_sources, and that is machine-invariant
    in the SCALING ratio: linear planning makes the 4096-chunk run ~8x the
    512-chunk run, quadratic makes it ~64x. The loose absolute backstop
    still catches a pathological constant factor."""
    small_elapsed, _small_plan = _timed_sparse_plan(512)
    elapsed, plan = _timed_sparse_plan(4096)

    assert plan.complete
    assert len(plan.assignments) == 4096
    assert sum(plan.per_source_counts().values()) == 4096
    assert len(plan.sources) > 8
    # Clamp the small-run denominator so timer noise cannot inflate the
    # ratio on machines where 512 chunks plan in microseconds.
    ratio = elapsed / max(small_elapsed, 0.005)
    assert ratio < 24.0, (
        f"4096-chunk plan took {ratio:.1f}x the 512-chunk plan "
        f"({elapsed:.3f}s vs {small_elapsed:.3f}s); linear scaling is ~8x, "
        "quadratic is ~64x. plan_swarm_sources likely regressed."
    )
    assert elapsed < 15.0, (
        f"4096-chunk plan took {elapsed:.3f}s; even a heavily loaded runner "
        "should finish well inside 15s unless the constant factor exploded."
    )
