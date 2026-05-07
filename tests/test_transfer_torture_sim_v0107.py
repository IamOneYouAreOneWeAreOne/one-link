from __future__ import annotations

from one_link.transfer_sim import (
    SimSource,
    simulate_never_lose_transfer,
    synthetic_manifest,
)


def test_synthetic_manifest_models_huge_file_without_disk_io():
    manifest = synthetic_manifest(size=10 * 1024 * 1024 * 1024, chunk_size=64 * 1024 * 1024)

    assert manifest.size == 10 * 1024 * 1024 * 1024
    assert manifest.chunk_count == 160
    assert len({c.hash for c in manifest.chunks}) == manifest.chunk_count
    assert manifest.chunks[0].start == 0


def test_torture_sim_delivers_under_drops_and_corruption():
    report = simulate_never_lose_transfer(
        size=512 * 1024 * 1024,
        chunk_size=8 * 1024 * 1024,
        seed=7,
        drop_rate=0.35,
        corruption_rate=0.05,
        max_rounds=10_000,
    )

    assert report.delivered is True
    assert report.chunks_done == report.chunks_total
    assert report.bytes_sent + report.bytes_saved == report.file_size
    assert report.retries >= report.corruptions
    assert report.offline_waits > 0
    assert "done" in report.doctor_states
    assert report.best_route in {"lan", "relay", "prior"}


def test_torture_sim_exercises_legacy_protocol_fallback():
    manifest = synthetic_manifest(size=96 * 1024 * 1024, chunk_size=8 * 1024 * 1024)
    indexes = frozenset(c.index for c in manifest.chunks)
    sources = [
        SimSource(
            "a" * 64,
            "legacy-peer",
            indexes,
            trust_score=2.0,
            latency_ms=1.0,
            bandwidth_bps=500_000_000,
            reliability=1.0,
            old_version=True,
        ),
        SimSource(
            "b" * 64,
            "modern-peer",
            indexes,
            reliability=1.0,
            old_version=False,
        ),
    ]

    report = simulate_never_lose_transfer(
        size=manifest.size,
        chunk_size=8 * 1024 * 1024,
        seed=11,
        sources=sources,
        drop_rate=0.0,
        corruption_rate=0.0,
    )

    assert report.delivered is True
    assert report.fallback_events > 0
    assert "protocol_fallback" in report.doctor_states
