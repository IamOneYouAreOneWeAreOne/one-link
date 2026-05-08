from one_link.transfer_brain import (
    AdaptiveTransferScheduler,
    AdaptiveTransferBrain,
    CalibrationTier,
    HealthState,
    MeshNodeSignal,
    TransferPerformanceOracle,
    TransferMode,
    TransferRouteObservation,
    adapt_pipeline_profile,
    decision_from_observations,
    transfer_result_report,
    verification_priority_order,
)
from one_link.transfer_intent import FileChunkManifest


def test_route_stats_calibrate_from_observations():
    brain = AdaptiveTransferBrain()
    for _ in range(16):
        brain.observe(TransferRouteObservation(
            route="lan",
            ok=True,
            latency_ms=4.0,
            bandwidth_bps=900_000_000,
        ))

    stats = brain.route_stats()[0]

    assert stats.route == "lan"
    assert stats.tier in {CalibrationTier.WARM, CalibrationTier.HOT, CalibrationTier.VERIFIED}
    assert stats.reliability > 0.9
    assert stats.confidence > 0.5


def test_brain_avoids_cdc_when_prior_knowledge_is_low():
    decision = decision_from_observations(
        size_bytes=4 * 1024 * 1024 * 1024,
        supports_cdc=True,
        supports_swarm=True,
        prior_hit_rate=0.0,
        observations=[
            TransferRouteObservation("lan", True, latency_ms=5, bandwidth_bps=800_000_000)
            for _ in range(20)
        ],
        routes=["lan"],
        speeds={"hash_mib_s": 1600.0, "fixed_mib_s": 1200.0, "cdc_mib_s": 8.0},
    )

    assert decision.selected.mode in {TransferMode.HASH_STREAM, TransferMode.FIXED_MANIFEST}
    assert decision.health == HealthState.HEALTHY


def test_brain_chooses_cdc_or_swarm_when_prior_knowledge_is_high_and_cdc_is_accelerated():
    decision = decision_from_observations(
        size_bytes=20 * 1024 * 1024 * 1024,
        supports_cdc=True,
        supports_swarm=True,
        prior_hit_rate=0.985,
        observations=[
            TransferRouteObservation("lan", True, latency_ms=3, bandwidth_bps=500_000_000)
            for _ in range(40)
        ],
        routes=["lan"],
        speeds={"hash_mib_s": 1600.0, "fixed_mib_s": 1200.0, "cdc_mib_s": 1200.0},
    )

    assert decision.selected.mode in {TransferMode.CDC_MANIFEST, TransferMode.SWARM_CDC}
    assert decision.selected.estimated_wire_bytes < 400 * 1024 * 1024


def test_brain_enters_repair_for_bad_routes():
    brain = AdaptiveTransferBrain()
    for _ in range(6):
        brain.observe(TransferRouteObservation("relay", False))

    decision = brain.decide(
        size_bytes=1024 * 1024,
        supports_cdc=False,
        routes=["relay"],
    )

    assert decision.health == HealthState.REPAIR
    assert decision.action == "refresh_route_and_reopen_session"


def test_mesh_coherence_pushes_high_prior_sends_to_swarm():
    decision = decision_from_observations(
        size_bytes=40 * 1024 * 1024 * 1024,
        supports_cdc=True,
        supports_swarm=True,
        prior_hit_rate=0.97,
        observations=[
            TransferRouteObservation("lan", True, latency_ms=4, bandwidth_bps=700_000_000)
            for _ in range(32)
        ],
        routes=["lan"],
        mesh_nodes=[
            MeshNodeSignal(
                peer_fp="a" * 64,
                trust_score=1.0,
                reliability=0.99,
                latency_ms=3,
                bandwidth_bps=900_000_000,
                chunk_hit_rate=0.99,
            ),
            MeshNodeSignal(
                peer_fp="b" * 64,
                trust_score=0.95,
                reliability=0.97,
                latency_ms=8,
                bandwidth_bps=500_000_000,
                chunk_hit_rate=0.90,
            ),
        ],
        verification_head=[12, 4, 99],
        speeds={"cdc_mib_s": 1200.0},
    )

    assert decision.selected.mode == TransferMode.SWARM_CDC
    assert decision.selected.parallelism == 2
    assert decision.selected.coherence_score > 0.75
    assert decision.to_dict()["verification_head"] == [12, 4, 99]


def test_verification_priority_checks_rare_weak_chunks_first():
    chunks = (
        FileChunkManifest(0, 0, 10, 10, "edge"),
        FileChunkManifest(1, 10, 20, 10, "common"),
        FileChunkManifest(2, 20, 30, 10, "rare"),
    )

    order = verification_priority_order(
        chunks,
        claim_counts={"edge": 3, "common": 6, "rare": 0},
        source_coherence={"edge": 0.9, "common": 0.9, "rare": 0.2},
    )

    assert order[0].index == 2
    assert order[0].reason == "rare_or_unclaimed"


def test_pipeline_profile_expands_only_for_coherent_healthy_routes():
    profile = {"chunk_size": 1024 * 1024, "window_chunks": 8, "window_bytes": 8 * 1024 * 1024}
    fast = adapt_pipeline_profile(profile, {
        "health": "healthy",
        "coherence_score": 0.91,
        "reliability": 0.94,
        "parallelism": 3,
    })
    repair = adapt_pipeline_profile(profile, {
        "health": "repair",
        "coherence_score": 0.2,
        "reliability": 0.2,
        "parallelism": 1,
    })

    assert fast["window_chunks"] > profile["window_chunks"]
    assert fast["window_chunks"] <= 32
    assert repair["window_chunks"] < profile["window_chunks"]
    assert repair["reason"] == "repair_backoff"


def test_pipeline_profile_uses_bandwidth_delay_product_for_fast_links():
    profile = {"chunk_size": 1024 * 1024, "window_chunks": 2, "window_bytes": 2 * 1024 * 1024}
    tuned = adapt_pipeline_profile(profile, {
        "health": "healthy",
        "coherence_score": 0.7,
        "reliability": 0.95,
        "parallelism": 1,
        "route_latency_ms": 90.0,
        "route_bandwidth_bps": 1_200_000_000.0,
    })

    assert tuned["window_chunks"] > profile["window_chunks"]
    assert tuned["window_bytes"] <= 64 * 1024 * 1024
    assert tuned["reason"] == "bdp_fast_lane"


def test_decision_exports_route_quality_for_runtime_tuning():
    decision = decision_from_observations(
        size_bytes=128 * 1024 * 1024,
        supports_cdc=True,
        supports_swarm=False,
        prior_hit_rate=0.0,
        observations=[
            TransferRouteObservation("lan", True, latency_ms=7, bandwidth_bps=900_000_000)
            for _ in range(8)
        ],
    ).to_dict()

    assert decision["route"] == "lan"
    assert decision["route_latency_ms"] == 7
    assert decision["route_bandwidth_bps"] == 900_000_000


def test_transfer_result_report_counts_skipped_bytes_as_effective_delivery():
    report = transfer_result_report(
        raw_bytes=10 * 1024 * 1024,
        wire_bytes=6 * 1024 * 1024,
        skipped_bytes=90 * 1024 * 1024,
        elapsed_s=2.0,
    )

    assert report["effective_payload_bytes"] == 100 * 1024 * 1024
    assert report["saved_bytes"] == 94 * 1024 * 1024
    assert report["bandwidth_savings_ratio"] == 0.94
    assert report["effective_throughput_bps"] > report["wire_throughput_bps"]


def test_transfer_performance_oracle_learns_cdc_engine_speed():
    oracle = TransferPerformanceOracle()
    defaults = oracle.speeds(native_cdc=True)
    report = transfer_result_report(
        raw_bytes=5 * 1024 * 1024,
        wire_bytes=1 * 1024 * 1024,
        skipped_bytes=95 * 1024 * 1024,
        elapsed_s=0.05,
    )

    oracle.observe(method="file_cdc", report=report)
    oracle.observe(method="file_cdc", report=report)
    speeds = oracle.speeds(native_cdc=True)
    snap = oracle.snapshot()

    assert speeds["cdc_mib_s"] > defaults["cdc_mib_s"]
    assert snap["cdc"]["samples"] == 2
    assert snap["cdc"]["savings_ratio"] > 0.90


def test_transfer_performance_oracle_penalizes_failed_engine():
    oracle = TransferPerformanceOracle()
    report = transfer_result_report(
        raw_bytes=32 * 1024 * 1024,
        wire_bytes=32 * 1024 * 1024,
        elapsed_s=1.0,
    )
    oracle.observe(method="file_binary_frame", report=report)
    oracle.observe(method="file_binary_frame", report=report)
    oracle.observe_failure(method="file_binary_frame")

    snap = oracle.snapshot()
    assert snap["stream"]["samples"] == 3
    assert snap["stream"]["reliability"] < 1.0


def test_adaptive_scheduler_opens_window_on_fast_acks():
    scheduler = AdaptiveTransferScheduler({
        "chunk_size": 1024,
        "window_chunks": 2,
        "reason": "test",
        "target_ack_ms": 20,
    }, max_window_chunks=5)

    for _ in range(4):
        scheduler.observe_ack(
            ack_ms=8,
            raw_bytes=1024,
            wire_bytes=1024,
            in_flight_chunks=1,
        )

    snap = scheduler.snapshot()
    assert snap["window_chunks"] > 2
    assert any(e["event"] == "window_up" for e in snap["timeline"])


def test_adaptive_scheduler_closes_window_on_slow_ack():
    scheduler = AdaptiveTransferScheduler({
        "chunk_size": 1024,
        "window_chunks": 8,
        "reason": "test",
        "target_ack_ms": 20,
    }, max_window_chunks=8)

    scheduler.observe_ack(
        ack_ms=250,
        raw_bytes=1024,
        wire_bytes=1024,
        in_flight_chunks=7,
    )

    snap = scheduler.snapshot()
    assert snap["window_chunks"] == 4
    assert any(e["event"] == "window_down" for e in snap["timeline"])


def test_adaptive_scheduler_records_retry_or_reopen():
    scheduler = AdaptiveTransferScheduler({
        "chunk_size": 1024,
        "window_chunks": 6,
        "reason": "test",
    }, max_window_chunks=8)

    scheduler.observe_retry(reason="TimeoutError", in_flight_chunks=5)
    snap = scheduler.snapshot()

    assert snap["window_chunks"] == 3
    assert snap["timeline"][-1]["event"] == "retry_or_reopen"
    assert snap["timeline"][-1]["reason"] == "TimeoutError"
