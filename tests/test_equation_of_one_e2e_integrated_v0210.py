"""End-to-end integrated-flow tests exercising the FULL equation-of-ONE
stack — selector + cover-traffic + dedupe + forecast + adaptive-transport
all firing together on one daemon instance.

These tests verify the wires hold under realistic combined load. Each
test is a scenario that walks one (or more) flows through the daemon's
public surface AND inspects telemetry counters to confirm the right
things fired.
"""

from __future__ import annotations

from collections import OrderedDict
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from one_link import daemon as daemon_module
from one_link import dedupe_sites as dedupe_sites_module
from one_link.capabilities import BLOB_REQUEST_V1


def _build_e2e_daemon():
    """Build a daemon instance with every equation-of-one subsystem
    wired but no live network. The result is a Daemon whose public
    methods can be called sequentially to walk a full event flow."""
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d.me = MagicMock()
    d.me.short_id = "selfid"
    d.me.public_bytes = b"\x00" * 32
    # Selector state
    d._smart_selector = MagicMock()
    d._smart_selector.decide.return_value = {
        "transport": "quic_stream",
        "path": "classical",
        "onion_hops": 3,
        "cover_traffic": True,
        "batch_decision": "emit_now",
        "anchor_lay": False,
        "predictor_warm": False,
    }
    d._smart_selector.safe_default = MagicMock(return_value=d._smart_selector.decide.return_value)
    d._smart_selector.observe = MagicMock()
    d._smart_selector.name = MagicMock(return_value="UnifiedMin")
    d._smart_selector.__class__.__name__ = "OnlineLearner"
    d._selector_kind = "online_learner"
    d._selector_mode = "1"
    d._selector_enforce = True
    d._user_mode_value = "paranoid"
    # Observation stash + decision counters
    d._pending_selector_observations = OrderedDict()
    d._pending_selector_observations_cap = 4096
    d._selector_decision_counters = {
        "total": 0,
        "transport": {"quic_stream": 0, "quic_datagram": 0, "webrtc": 0, "relay": 0},
        "path": {"classical": 0, "coherence": 0},
        "onion_hops": {1: 0, 3: 0, 5: 0},
        "cover_traffic_on": 0, "cover_traffic_off": 0,
        "batch_decision": {"emit_now": 0, "batch": 0, "urgent_bypass": 0},
        "anchor_lay_on": 0, "anchor_lay_off": 0,
        "predictor_warm_on": 0, "predictor_warm_off": 0,
        "f4_violations": 0,
    }
    d._selector_regret_ewma = {
        "normal": 0.0, "paranoid": 0.0,
        "battery_save": 0.0, "latency_strict": 0.0,
    }
    d._selector_regret_ewma_alpha = 0.1
    d._alignment_trust_histogram = [0, 0, 0, 0, 0]
    d._capability_denial_counters = {
        "total": 0,
        "by_reason": {
            "seed_tamper": 0, "policy_denied": 0,
            "low_trust_blocked": 0, "scope_mismatch": 0,
        },
        "by_capability": {},
    }
    # Cover traffic
    d._cover_traffic = None
    d._cover_traffic_env_gate = False
    d._cover_packets_sent = 0
    d._cover_packets_received = 0
    d._cover_dispatch_rr_idx = 0
    # Dedupe sites
    d._dedupe_sites = dedupe_sites_module.DedupeSiteIndex()
    # Wave forecast
    d._wave_forecast = None
    d._wave_forecast_enabled = False
    d._wave_forecast_steps = 0
    d._wave_forecast_warnings = 0
    d._wave_predicted_disturbance = {}
    d._wave_forecast_dt = 0.5
    d._cascade_warning_count = 0
    d._cascade_warning_threshold = 0.5
    # Adaptive transport
    d._capability_fail_open_count = 0
    d._reconnect_stability_ewma_ms = {}
    d._discovery_interval_s = daemon_module.DISCOVERY_BASELINE_S
    d._discovery_churn_count = 0
    # Field obs
    d._field_obs = None
    # Misc state needed by helpers
    d._is_pinned = MagicMock(return_value=True)
    d.state.get_peer.return_value = MagicMock(trust="pinned")
    d.state.list_peers.return_value = []
    d.predict_next_files_for_peer = MagicMock(return_value=[])
    return d


# ─── Scenario 1: selector + observe loop integrated ───


def test_full_transfer_decision_to_observe_cycle() -> None:
    """A transfer goes: selector.decide -> stash -> transfer
    completes -> selector.observe fires with correct regret."""
    d = _build_e2e_daemon()
    # Simulate the selector call at send time.
    d._log_selector_decision_for_file(
        peer=MagicMock(), peer_fp="peerA", size=10_000,
        transfer_id="t1",
    )
    # Decision was stashed under transfer_id.
    assert "t1" in d._pending_selector_observations
    # Counters updated.
    assert d._selector_decision_counters["total"] == 1
    assert d._selector_decision_counters["cover_traffic_on"] == 1
    assert d._selector_decision_counters["onion_hops"][3] == 1
    # Simulate transfer completing.
    d._maybe_feed_selector_observation("t1", "completed")
    # Observe was called with regret=0 (completed).
    d._smart_selector.observe.assert_called_once()
    obs_kwargs = d._smart_selector.observe.call_args.kwargs
    assert obs_kwargs["regret"] == 0.0
    # Regret EWMA updated for paranoid mode.
    assert d._selector_regret_ewma["paranoid"] == pytest.approx(0.0)
    # Stash drained.
    assert "t1" not in d._pending_selector_observations


def test_failed_transfer_drives_high_regret() -> None:
    """A failed transfer should produce regret=1.0 + bump EWMA."""
    d = _build_e2e_daemon()
    d._log_selector_decision_for_file(
        peer=MagicMock(), peer_fp="peerA", size=10_000,
        transfer_id="t1",
    )
    d._maybe_feed_selector_observation("t1", "failed")
    obs_kwargs = d._smart_selector.observe.call_args.kwargs
    assert obs_kwargs["regret"] == 1.0
    # EWMA: 0.9 * 0 + 0.1 * 1 = 0.1
    assert d._selector_regret_ewma["paranoid"] == pytest.approx(0.1)


# ─── Scenario 2: dedupe + BLOB_REQUEST + fallback orchestrator ───


@pytest.mark.asyncio
async def test_dedupe_fallback_uses_recorded_sources() -> None:
    """When primary fails + dedupe index has alternates with
    BLOB_REQUEST_V1, fallback to the freshest alternate."""
    d = _build_e2e_daemon()
    # Populate dedupe index from prior BLOB_OFFER events. Use explicit
    # millisecond-distinct fresh timestamps so the TTL filter sees
    # them live AND the newest-first sort is unambiguous.
    import time
    now = int(time.time() * 1000)
    d._dedupe_sites.record_have("blob_h", "peerA", now_ms=now - 1000)
    d._dedupe_sites.record_have("blob_h", "peerB", now_ms=now - 500)
    # Both peers advertise the cap.
    d.state.get_peer_capabilities = lambda fp: [BLOB_REQUEST_V1]
    # First request_blob_from_peer (primary) fails; second succeeds.
    d.request_blob_from_peer = AsyncMock(side_effect=[
        {"status": "no_session"},      # primary fails
        {"status": "requested"},        # first alt succeeds
    ])
    out = await d.request_blob_with_dedupe_fallback(
        "blob_h", primary="primary_peer",
    )
    assert out["status"] == "requested"
    # Freshest alternate (peerB at t=200) was chosen.
    assert out["succeeded_via"] == "peerB"


# ─── Scenario 3: wave forecast → selector observed_loss bump ───


def test_forecast_bumps_selector_observed_loss() -> None:
    """High predicted disturbance bumps observed_loss + nudges the
    selector toward a more conservative decision."""
    d = _build_e2e_daemon()
    # Pre-load the forecast cache with a high disturbance for peerA.
    d._wave_predicted_disturbance = {"peerA": 0.4}
    d._log_selector_decision_for_file(
        peer=MagicMock(), peer_fp="peerA", size=10_000,
        transfer_id="t1",
    )
    # Decide was called with observed_loss bumped.
    call_kwargs = d._smart_selector.decide.call_args.kwargs
    assert "observed_loss" in call_kwargs
    # Map: 0.4 - 0.05 = 0.35 → capped at 0.3.
    assert call_kwargs["observed_loss"] == pytest.approx(0.3)


# ─── Scenario 4: adaptive heartbeat reacts to forecast ───


def test_adaptive_heartbeat_shortens_under_predicted_cascade() -> None:
    """When the forecaster predicts cascade at a peer, the heartbeat
    interval shrinks to probe more aggressively."""
    d = _build_e2e_daemon()
    d._peer_trust_score = MagicMock(return_value=1.0)  # max base
    # Baseline (no disturbance).
    d._wave_predicted_disturbance = {}
    baseline = d.adaptive_heartbeat_interval("peerA")
    assert baseline == pytest.approx(
        daemon_module.HEARTBEAT_MAX_INTERVAL_S, abs=0.5,
    )
    # Now inject a full-magnitude disturbance.
    d._wave_predicted_disturbance = {"peerA": 1.0}
    under_cascade = d.adaptive_heartbeat_interval("peerA")
    # Half-rate reduction.
    assert under_cascade < baseline
    assert under_cascade == pytest.approx(60.0, abs=1.0)


# ─── Scenario 5: capability fail-open + denial counter ───


def test_capability_verifier_error_fails_closed() -> None:
    """A verifier exception fails CLOSED + bumps the continuity metric."""
    d = _build_e2e_daemon()
    d.state.get_peer_capability_policy = MagicMock(
        side_effect=RuntimeError("simulated"),
    )
    d.detect_seed_file_tamper = MagicMock(return_value=False)
    d._cap_store = None
    d._peer_pub_for_fp = MagicMock(return_value=None)
    result = d._capability_allowed("peerA", "files")
    assert result is False
    assert d._capability_fail_open_count == 1
    assert d._capability_denial_counters["total"] == 1


def test_capability_denial_counter_records_policy_deny() -> None:
    """A genuine policy denial bumps the by_reason counter."""
    d = _build_e2e_daemon()
    d.state.get_peer_capability_policy = MagicMock(return_value=["chat"])
    d.detect_seed_file_tamper = MagicMock(return_value=False)
    d._cap_store = None
    d._peer_pub_for_fp = MagicMock(return_value=None)
    result = d._capability_allowed("peerA", "files")
    assert result is False
    assert d._capability_denial_counters["total"] == 1
    assert d._capability_denial_counters["by_reason"]["policy_denied"] == 1


# ─── Scenario 6: dashboard endpoint aggregates everything ───


@pytest.mark.asyncio
async def test_dashboard_endpoint_includes_all_subsystems() -> None:
    """The /api/v1/equation-of-one/stats endpoint returns all the
    subsystem snapshots in one envelope."""
    from one_link.server import UIServer
    d = _build_e2e_daemon()
    # Add enough activity to populate counters.
    d._log_selector_decision_for_file(
        peer=MagicMock(), peer_fp="peerA", size=10_000,
        transfer_id="t1",
    )
    d._record_capability_denial(reason="policy_denied", capability="files")
    d._record_alignment_trust_score(0.6)
    # Fuse + cover traffic + dedupe stats accessible.
    d.fuse_capabilities = MagicMock(return_value={
        "platform": "windows_unsupported", "ready": False,
        "message": "WinFSP needed", "native_loaded": True,
    })
    s = UIServer.__new__(UIServer)
    s.daemon = d
    resp = await s.api_equation_of_one_stats(MagicMock())
    import json
    body = json.loads(resp.text)
    # Every subsystem present.
    for key in (
        "user_mode", "selector", "cover_traffic", "dedupe_sites",
        "fuse", "capability_denials", "alignment_trust",
        "cascade_warnings", "wave_forecast", "adaptive_transport",
    ):
        assert key in body, f"missing dashboard key: {key}"
    # Selector envelope rich.
    assert body["selector"]["decisions"]["total"] == 1
    assert body["selector"]["decisions"]["cover_traffic_on"] == 1
    assert body["capability_denials"]["total"] == 1
    assert body["alignment_trust"]["total"] == 1


# ─── Scenario 7: F4 contract enforcement across modes ───


def test_paranoid_mode_drives_cover_on_decisions() -> None:
    """In paranoid mode, the selector ALWAYS sets cover_traffic=True;
    the decision-counter cover_ratio reflects this."""
    d = _build_e2e_daemon()
    d._user_mode_value = "paranoid"
    # Selector returns cover_traffic=True (already the default mock).
    for i in range(10):
        d._log_selector_decision_for_file(
            peer=MagicMock(), peer_fp="peerA", size=1000,
            transfer_id=f"t{i}",
        )
    stats = d.selector_decision_stats()
    assert stats["total"] == 10
    assert stats["cover_ratio"] == 1.0


def test_battery_save_drives_cover_off_decisions() -> None:
    """In battery_save mode, the selector returns cover_traffic=False
    so cover_ratio stays at zero."""
    d = _build_e2e_daemon()
    d._user_mode_value = "battery_save"
    # Override the mock to return cover_traffic=False.
    d._smart_selector.decide.return_value = dict(
        d._smart_selector.decide.return_value, cover_traffic=False,
    )
    for i in range(10):
        d._log_selector_decision_for_file(
            peer=MagicMock(), peer_fp="peerA", size=1000,
            transfer_id=f"t{i}",
        )
    stats = d.selector_decision_stats()
    assert stats["cover_ratio"] == 0.0


# ─── Scenario 8: adaptive cover-traffic rate driven by cover_ratio ───


def test_adaptive_cover_rate_responds_to_cover_ratio() -> None:
    """High cover_ratio bumps the cover-traffic emitter's multiplier;
    low cover_ratio backs off toward the baseline floor."""
    d = _build_e2e_daemon()
    d._user_mode_value = "normal"  # not paranoid (which would force 1.0)
    fake_emitter = MagicMock()
    d._cover_traffic = fake_emitter
    # Drive cover_ratio = 0.8 via 8/10 cover-on decisions.
    d._selector_decision_counters["total"] = 10
    d._selector_decision_counters["cover_traffic_on"] = 8
    d._selector_decision_counters["cover_traffic_off"] = 2
    multiplier = d.update_cover_traffic_rate_from_selector()
    assert multiplier == pytest.approx(0.8)
    fake_emitter.set_rate_multiplier.assert_called_with(0.8)


def test_paranoid_forces_full_cover_rate() -> None:
    """Paranoid mode forces multiplier=1.0 regardless of cover_ratio."""
    d = _build_e2e_daemon()
    d._user_mode_value = "paranoid"
    fake_emitter = MagicMock()
    d._cover_traffic = fake_emitter
    # cover_ratio = 0 — but paranoid takes precedence.
    d._selector_decision_counters["total"] = 10
    d._selector_decision_counters["cover_traffic_on"] = 0
    multiplier = d.update_cover_traffic_rate_from_selector()
    assert multiplier == 1.0


# ─── Scenario 9: dedupe site index lifecycle ───


def test_dedupe_lifecycle_record_then_forget_on_revoke() -> None:
    """BLOB_OFFER → record_have → peer revoke → forget_peer → site
    no longer nominated."""
    d = _build_e2e_daemon()
    d._dedupe_sites.record_have("blob_h", "peerA")
    d._dedupe_sites.record_have("blob_h", "peerB")
    assert "peerA" in d._dedupe_sites.sites_for("blob_h")
    # Revoke peerA.
    d._dedupe_sites.forget_peer("peerA")
    sites = d._dedupe_sites.sites_for("blob_h")
    assert "peerA" not in sites
    assert "peerB" in sites


# ─── Scenario 10: wave forecast + cascade warning + telemetry ───


def test_full_forecast_telemetry_chain() -> None:
    """Forecast tick advances counters + populates per-peer
    disturbance + flows through stats() snapshot."""
    d = _build_e2e_daemon()
    d._wave_forecast_enabled = True
    fake_stepper = MagicMock()
    fake_stepper.step.return_value = 2  # 2 warnings
    fake_stepper.snapshot.return_value = {"peerA": 0.7, "peerB": 0.4}
    d._wave_forecast = fake_stepper
    d._wave_forecast_steps = 1  # past seed
    d.state.list_peers.return_value = [
        SimpleNamespace(fingerprint="peerA", trust="pinned"),
        SimpleNamespace(fingerprint="peerB", trust="pinned"),
    ]
    obs = MagicMock()
    obs.tau_at = lambda fp: 0.5
    d._field_obs = obs
    warnings = d._wave_forecast_tick()
    assert warnings == 2
    assert d._wave_forecast_warnings == 2
    # Per-peer disturbance recorded.
    assert d._wave_predicted_disturbance["peerA"] == pytest.approx(0.2)
    # Stats snapshot reflects.
    stats = d.wave_forecast_stats()
    assert stats["warnings"] == 2
    assert stats["steps"] == 2
