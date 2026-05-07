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
    )
    by_fp = {s.peer_fp: s for s in sources}
    assert by_fp["a"].trust_score == 0.8
    assert by_fp["b"].latency_ms == 20
