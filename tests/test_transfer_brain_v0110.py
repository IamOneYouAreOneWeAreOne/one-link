from one_link.transfer_brain import (
    AdaptiveTransferBrain,
    CalibrationTier,
    HealthState,
    TransferMode,
    TransferRouteObservation,
    decision_from_observations,
)


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
