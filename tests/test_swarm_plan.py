from __future__ import annotations

import random
from pathlib import Path

from one_link.swarm_plan import plan_swarm_sources, source_from_hashes, source_index_from_claims
from one_link.transfer_intent import build_file_manifest


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
