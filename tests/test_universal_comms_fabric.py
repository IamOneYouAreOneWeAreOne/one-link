from one_link.hardware_inventory import (
    HardwareInventory,
    HardwarePath,
    collect_hardware_inventory,
)
from one_link.transport_adapters.static import StaticPathAdapter, adapters_from_paths, score_probe
from one_link.transport_activation import (
    ActivationIntent,
    ActivationState,
    activation_plan_for,
    activation_plans_for,
)
from one_link.transport_fabric import UniversalCommsFabric, observations_from_scores


def test_hardware_inventory_can_be_collected_with_deterministic_runner():
    def runner(argv, timeout):
        if argv[:3] == ["netsh", "wlan", "show"]:
            return 0, "Hosted network supported  : Yes\nWi-Fi Direct", ""
        return 1, "", "not available"

    inv = collect_hardware_inventory(
        env={
            "ONE_LINK_ASSUME_BLE": "1",
            "ONE_LINK_ENABLE_AUDIO_CONTROL": "1",
            "ONEFIELD_MESH_ROOT": "Z:\\does-not-exist",
        },
        runner=runner,
    )

    kinds = {p.kind for p in inv.paths}
    assert "lan" in kinds
    assert "loopback" in kinds
    assert "ble_control" in kinds
    assert "qr_control" in kinds
    assert any(p.kind == "storage_courier" and p.available for p in inv.paths)


def test_strongest_bulk_path_prefers_fast_available_direct_path():
    inv = HardwareInventory(
        platform="test",
        hostname="unit",
        paths=(
            HardwarePath(
                kind="webrtc",
                available=True,
                bulk_capable=True,
                estimated_bps=80_000_000,
                privacy="direct_or_relayed_internet",
            ),
            HardwarePath(
                kind="wifi_direct",
                available=True,
                bulk_capable=True,
                estimated_bps=480_000_000,
                privacy="direct_local",
            ),
            HardwarePath(
                kind="ble_control",
                available=True,
                bulk_capable=False,
                estimated_bps=200_000,
                privacy="proximity",
            ),
        ),
    )

    best = inv.strongest_bulk_path()
    assert best is not None
    assert best.kind == "wifi_direct"


def test_static_adapter_scores_unavailable_as_zero():
    adapter = StaticPathAdapter(HardwarePath(
        kind="wifi_direct",
        available=False,
        bulk_capable=True,
        estimated_bps=480_000_000,
        privacy="direct_local",
    ))

    score = adapter.score()

    assert score.score == 0.0
    assert not score.usable_for_bulk
    assert score.reason == "adapter unavailable"


def test_score_probe_keeps_control_only_paths_but_below_bulk():
    ble = StaticPathAdapter(HardwarePath(
        kind="ble_control",
        available=True,
        bulk_capable=False,
        estimated_bps=200_000,
        privacy="proximity",
    )).score()
    lan = StaticPathAdapter(HardwarePath(
        kind="lan",
        available=True,
        bulk_capable=True,
        estimated_bps=900_000_000,
        privacy="direct_local",
    )).score()

    assert ble.usable_for_control
    assert not ble.usable_for_bulk
    assert lan.score > ble.score


def test_fabric_feeds_existing_transfer_brain_with_adapter_observations():
    inv = HardwareInventory(
        platform="test",
        hostname="unit",
        paths=(
            HardwarePath(
                kind="lan",
                adapter_id="lan.test",
                available=True,
                bulk_capable=True,
                estimated_bps=900_000_000,
                privacy="direct_local",
            ),
            HardwarePath(
                kind="webrtc",
                adapter_id="webrtc.test",
                available=True,
                bulk_capable=True,
                estimated_bps=80_000_000,
                privacy="direct_or_relayed_internet",
            ),
            HardwarePath(
                kind="storage_courier",
                adapter_id="courier.test",
                available=True,
                bulk_capable=True,
                estimated_bps=120_000_000,
                privacy="offline_physical",
                requires_user_action=True,
            ),
        ),
    )
    fabric = UniversalCommsFabric(adapters_from_paths(inv.paths))

    plan = fabric.plan(
        size_bytes=8 * 1024 * 1024,
        supports_cdc=True,
        supports_swarm=False,
        prior_hit_rate=0.25,
        speeds={"cdc_mib_s": 900.0},
    )
    truth = plan.route_truth()

    assert plan.best_score is not None
    assert plan.best_score.route_name == "lan"
    assert truth["kind"] == "Local network"
    assert truth["transfer"]["route"] == "lan"
    assert truth["activation_state"] in {"ready", "ask_user"}
    assert any(o.route == "lan" and o.ok for o in plan.observations)


def test_fabric_ranks_verified_remembered_route_as_real_path():
    inv = HardwareInventory(
        platform="test",
        hostname="unit",
        paths=(
            HardwarePath(
                kind="webrtc",
                adapter_id="webrtc.slow",
                available=True,
                bulk_capable=True,
                estimated_bps=45_000_000,
                privacy="direct_or_relayed_internet",
            ),
        ),
    )
    fabric = UniversalCommsFabric.from_inventory_and_candidates(
        inv,
        (
            {
                "peer_fp": "a" * 64,
                "route": "lan",
                "transport": "tcp",
                "host": "192.168.1.42",
                "port": 17117,
                "source": "session_open",
                "verified": True,
                "attempts": 3,
                "successes": 3,
                "failures": 0,
                "latency_ms": 4,
                "bandwidth_bps": 900_000_000,
            },
        ),
    )

    plan = fabric.plan(size_bytes=128 * 1024 * 1024, supports_cdc=True)
    truth = plan.route_truth()

    assert plan.best_score is not None
    assert plan.best_score.adapter_id.startswith("remembered.aaaaaaaa.lan.tcp")
    assert plan.best_score.route_name == "lan"
    assert truth["kind"] == "Local network"
    assert truth["estimated_bps"] == 900_000_000
    assert truth["reason"] == "verified remembered route"
    assert any(p.adapter_id.startswith("remembered.") and p.available for p in plan.probes)


def test_fabric_keeps_unverified_remembered_route_out_of_bulk_path():
    fabric = UniversalCommsFabric.from_inventory_and_candidates(
        HardwareInventory(platform="test", hostname="unit", paths=()),
        (
            {
                "peer_fp": "b" * 64,
                "route": "lan",
                "transport": "tcp",
                "host": "192.168.1.55",
                "port": 17117,
                "source": "qr_bootstrap",
                "verified": False,
                "attempts": 0,
                "successes": 0,
                "failures": 0,
            },
        ),
    )

    plan = fabric.plan(size_bytes=1024 * 1024, supports_cdc=False)

    assert plan.best_score is not None
    assert plan.best_score.score == 0.0
    assert plan.best_score.reason == "remembered route awaiting verification"
    assert not plan.best_score.usable_for_bulk
    assert plan.probes[0].safety_state == "needs_verification"


def test_observations_from_scores_penalizes_control_only_routes():
    scores = (
        score_probe(StaticPathAdapter(HardwarePath(
            kind="ble_control",
            available=True,
            bulk_capable=False,
            estimated_bps=200_000,
            privacy="proximity",
        )).probe()),
    )

    obs = observations_from_scores(scores)

    assert obs[0].route == "ble_control"
    assert obs[0].ok
    assert obs[0].energy_cost > 1.0


def test_activation_blocks_bulk_over_control_only_path():
    score = score_probe(StaticPathAdapter(HardwarePath(
        kind="ble_control",
        adapter_id="ble.test",
        available=True,
        bulk_capable=False,
        estimated_bps=200_000,
        privacy="proximity",
    )).probe())

    plan = activation_plan_for(score, intent=ActivationIntent(needs_bulk=True))

    assert plan.state == ActivationState.ASK_USER
    assert not plan.automatic
    assert plan.needs_user
    assert "control-only" in plan.reason


def test_activation_auto_opens_low_risk_verified_trusted_path():
    probe = StaticPathAdapter(HardwarePath(
        kind="wifi_direct",
        adapter_id="wifi.test",
        available=True,
        bulk_capable=True,
        estimated_bps=480_000_000,
        privacy="direct_local",
    )).probe()
    score = score_probe(probe)

    plan = activation_plan_for(
        score,
        probe,
        intent=ActivationIntent(trusted_peer=True, verified_peer=True),
    )

    assert plan.state == ActivationState.ACTIVE
    assert plan.automatic
    assert not plan.needs_user
    assert "local paths never require cloud storage" in plan.safeguards


def test_activation_requires_user_for_admin_path():
    probe = StaticPathAdapter(HardwarePath(
        kind="private_hotspot",
        adapter_id="admin.hotspot",
        available=True,
        bulk_capable=True,
        estimated_bps=300_000_000,
        privacy="direct_local",
        requires_admin=True,
    )).probe()
    score = score_probe(probe)

    plan = activation_plan_for(
        score,
        probe,
        intent=ActivationIntent(trusted_peer=True, verified_peer=True),
    )

    assert plan.state == ActivationState.ASK_USER
    assert not plan.automatic
    assert plan.next_action == "ask_user_for_permission"


def test_activation_summary_sorts_safe_ready_paths_first():
    probes = (
        StaticPathAdapter(HardwarePath(
            kind="webrtc",
            adapter_id="relayish",
            available=True,
            bulk_capable=True,
            estimated_bps=80_000_000,
            privacy="direct_or_relayed_internet",
        )).probe(),
        StaticPathAdapter(HardwarePath(
            kind="lan",
            adapter_id="lan",
            available=True,
            bulk_capable=True,
            estimated_bps=900_000_000,
            privacy="direct_local",
        )).probe(),
    )
    scores = tuple(score_probe(p) for p in probes)

    plans = activation_plans_for(
        scores,
        probes,
        intent=ActivationIntent(trusted_peer=True, verified_peer=True),
    )

    assert plans[0].route_name == "lan"
    assert plans[0].automatic
