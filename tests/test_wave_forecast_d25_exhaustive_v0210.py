"""Exhaustive Python-side tests for the D25 wave-equation forecast
loop.

Covers:
  - wave_forecast_native adapter (HAS_NATIVE, wave_stepper builder,
    _require_native guard)
  - _ensure_wave_forecaster lazy construction + env gating
  - _build_field_neighbor_graph full-mesh-over-paired correctness
  - _snapshot_field_state pulls live τ_c
  - _wave_forecast_tick: gate-off no-op, first-call seed, subsequent
    propagation, error recovery, warning count
  - predicted_disturbance_for accessor + default None
  - wave_forecast_stats envelope shape + config readout
  - Selector wiring: predicted_disturbance bumps observed_loss
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from one_link import daemon as daemon_module
from one_link import wave_forecast_native


# ---------- module-level adapter ----------


def test_module_constants_exposed() -> None:
    assert isinstance(wave_forecast_native.HAS_NATIVE, bool)


def test_has_native_function() -> None:
    assert wave_forecast_native.has_native() == wave_forecast_native.HAS_NATIVE


def test_require_native_raises_when_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(wave_forecast_native, "HAS_NATIVE", False)
    with pytest.raises(RuntimeError, match="WaveStepper required"):
        wave_forecast_native._require_native()


def test_wave_stepper_factory_returns_instance() -> None:
    # Re-probe HAS_NATIVE at runtime via the native module directly
    # rather than the cached wave_forecast_native.HAS_NATIVE flag.
    # The flag is set once at module-import time; a wheel rebuild
    # that lands AFTER pytest collection won't flip the cached
    # value to True without a reload. Re-probing the native module
    # gives the true current state.
    try:
        from one_link_native import coherence_field as _cf
        if not hasattr(_cf, "WaveStepper"):
            pytest.skip("native WaveStepper not exposed by installed wheel")
    except ImportError:
        pytest.skip("one_link_native.coherence_field not importable")
    # Force a refresh of HAS_NATIVE so the factory works.
    import importlib
    importlib.reload(wave_forecast_native)
    w = wave_forecast_native.wave_stepper()
    assert w is not None
    # Has the documented method surface.
    for method in (
        "set_wave_speed", "set_damping", "set_threshold",
        "set_clamp_range", "set_cfl_enforce",
        "seed", "step", "psi_at", "snapshot",
        "courant_number", "max_stable_dt", "total_energy",
        "reset_warnings",
    ):
        assert hasattr(w, method), f"missing method: {method}"


# ---------- _bare_daemon ----------


def _bare_daemon():
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d._field_obs = None
    d._wave_forecast = None
    d._wave_forecast_enabled = False
    d._wave_forecast_steps = 0
    d._wave_forecast_warnings = 0
    d._wave_predicted_disturbance = {}
    d._wave_forecast_dt = 0.5
    return d


# ---------- _ensure_wave_forecaster ----------


def test_ensure_forecaster_returns_none_when_disabled() -> None:
    d = _bare_daemon()
    d._wave_forecast_enabled = False
    assert d._ensure_wave_forecaster() is None


def test_ensure_forecaster_returns_none_when_native_missing(monkeypatch) -> None:
    d = _bare_daemon()
    d._wave_forecast_enabled = True
    monkeypatch.setattr(wave_forecast_native, "HAS_NATIVE", False)
    assert d._ensure_wave_forecaster() is None


def test_ensure_forecaster_caches_instance(monkeypatch) -> None:
    d = _bare_daemon()
    d._wave_forecast_enabled = True
    monkeypatch.setattr(wave_forecast_native, "HAS_NATIVE", True)
    fake_stepper = MagicMock()
    monkeypatch.setattr(
        wave_forecast_native, "wave_stepper",
        MagicMock(return_value=fake_stepper),
    )
    w1 = d._ensure_wave_forecaster()
    w2 = d._ensure_wave_forecaster()
    assert w1 is w2
    # Constructor called only once.
    wave_forecast_native.wave_stepper.assert_called_once()


def test_ensure_forecaster_configures_defaults(monkeypatch) -> None:
    d = _bare_daemon()
    d._wave_forecast_enabled = True
    monkeypatch.setattr(wave_forecast_native, "HAS_NATIVE", True)
    fake = MagicMock()
    monkeypatch.setattr(
        wave_forecast_native, "wave_stepper",
        MagicMock(return_value=fake),
    )
    d._ensure_wave_forecaster()
    fake.set_wave_speed.assert_called_once_with(0.5)
    fake.set_damping.assert_called_once_with(0.05)
    fake.set_threshold.assert_called_once_with(0.15)
    fake.set_clamp_range.assert_called_once_with(0.0, 1.0)


def test_ensure_forecaster_survives_construction_exception(monkeypatch) -> None:
    d = _bare_daemon()
    d._wave_forecast_enabled = True
    monkeypatch.setattr(wave_forecast_native, "HAS_NATIVE", True)
    monkeypatch.setattr(
        wave_forecast_native, "wave_stepper",
        MagicMock(side_effect=RuntimeError("simulated")),
    )
    # Must not raise.
    assert d._ensure_wave_forecaster() is None


# ---------- _build_field_neighbor_graph ----------


def test_neighbor_graph_empty_when_state_missing() -> None:
    d = _bare_daemon()
    d.state = None
    assert d._build_field_neighbor_graph() == {}


def test_neighbor_graph_empty_when_no_paired() -> None:
    d = _bare_daemon()
    d.state.list_peers.return_value = []
    assert d._build_field_neighbor_graph() == {}


def test_neighbor_graph_full_mesh_over_paired() -> None:
    d = _bare_daemon()
    d.state.list_peers.return_value = [
        SimpleNamespace(fingerprint="peerA", trust="pinned"),
        SimpleNamespace(fingerprint="peerB", trust="pinned"),
        SimpleNamespace(fingerprint="peerC", trust="pinned"),
        # Non-paired should be excluded.
        SimpleNamespace(fingerprint="peerD", trust="pending"),
    ]
    graph = d._build_field_neighbor_graph()
    assert set(graph.keys()) == {"peerA", "peerB", "peerC"}
    assert set(graph["peerA"]) == {"peerB", "peerC"}
    assert set(graph["peerB"]) == {"peerA", "peerC"}
    assert set(graph["peerC"]) == {"peerA", "peerB"}
    # peerD excluded entirely.
    assert "peerD" not in graph


def test_neighbor_graph_no_self_loops() -> None:
    """Each peer's neighbor list must NOT include itself — would break
    the Laplacian assumption + cause numerical artifacts."""
    d = _bare_daemon()
    d.state.list_peers.return_value = [
        SimpleNamespace(fingerprint="peerA", trust="pinned"),
        SimpleNamespace(fingerprint="peerB", trust="pinned"),
    ]
    graph = d._build_field_neighbor_graph()
    for peer, neighbors in graph.items():
        assert peer not in neighbors, (
            f"self-loop at {peer}: neighbors={neighbors}"
        )


def test_neighbor_graph_survives_state_exception() -> None:
    d = _bare_daemon()
    d.state.list_peers.side_effect = RuntimeError("simulated")
    # Must not raise.
    assert d._build_field_neighbor_graph() == {}


# ---------- _snapshot_field_state ----------


def test_snapshot_empty_when_no_field_obs() -> None:
    d = _bare_daemon()
    d._field_obs = None
    assert d._snapshot_field_state() == {}


def test_snapshot_empty_when_no_state() -> None:
    d = _bare_daemon()
    d._field_obs = MagicMock()
    d.state = None
    assert d._snapshot_field_state() == {}


def test_snapshot_collects_per_peer_tau() -> None:
    d = _bare_daemon()
    obs = MagicMock()
    tau_map = {"peerA": 0.7, "peerB": 0.4}
    obs.tau_at = lambda fp: tau_map.get(fp)
    d._field_obs = obs
    d.state.list_peers.return_value = [
        SimpleNamespace(fingerprint="peerA"),
        SimpleNamespace(fingerprint="peerB"),
    ]
    s = d._snapshot_field_state()
    assert s == {"peerA": 0.7, "peerB": 0.4}


def test_snapshot_skips_peers_with_no_observation() -> None:
    d = _bare_daemon()
    obs = MagicMock()
    obs.tau_at = lambda fp: 0.5 if fp == "peerA" else None
    d._field_obs = obs
    d.state.list_peers.return_value = [
        SimpleNamespace(fingerprint="peerA"),
        SimpleNamespace(fingerprint="peerB"),
    ]
    assert d._snapshot_field_state() == {"peerA": 0.5}


def test_snapshot_survives_per_peer_exception() -> None:
    d = _bare_daemon()
    obs = MagicMock()

    def tau_or_raise(fp):
        if fp == "bad":
            raise RuntimeError("simulated")
        return 0.5

    obs.tau_at = tau_or_raise
    d._field_obs = obs
    d.state.list_peers.return_value = [
        SimpleNamespace(fingerprint="good"),
        SimpleNamespace(fingerprint="bad"),
    ]
    s = d._snapshot_field_state()
    assert s == {"good": 0.5}


# ---------- _wave_forecast_tick ----------


def test_tick_no_op_when_forecaster_disabled() -> None:
    d = _bare_daemon()
    d._wave_forecast_enabled = False
    assert d._wave_forecast_tick() == 0
    assert d._wave_forecast_steps == 0


def test_tick_no_op_when_no_neighbors() -> None:
    d = _bare_daemon()
    d._wave_forecast_enabled = True
    d._wave_forecast = MagicMock()
    d.state.list_peers.return_value = []
    assert d._wave_forecast_tick() == 0


def test_tick_seeds_on_first_call() -> None:
    d = _bare_daemon()
    d._wave_forecast_enabled = True
    fake_stepper = MagicMock()
    fake_stepper.step.return_value = 0
    fake_stepper.snapshot.return_value = {"peerA": 0.6}
    d._wave_forecast = fake_stepper
    d._wave_forecast_steps = 0
    # Set up neighbor graph + field state.
    d.state.list_peers.return_value = [
        SimpleNamespace(fingerprint="peerA", trust="pinned"),
        SimpleNamespace(fingerprint="peerB", trust="pinned"),
    ]
    obs = MagicMock()
    obs.tau_at = lambda fp: 0.5
    d._field_obs = obs
    d._wave_forecast_tick()
    # seed() was called with the field-state snapshot.
    fake_stepper.seed.assert_called_once()
    seed_arg = fake_stepper.seed.call_args.args[0]
    assert seed_arg == {"peerA": 0.5, "peerB": 0.5}


def test_tick_does_not_reseed_after_first_call() -> None:
    d = _bare_daemon()
    d._wave_forecast_enabled = True
    fake_stepper = MagicMock()
    fake_stepper.step.return_value = 0
    fake_stepper.snapshot.return_value = {"peerA": 0.5}
    d._wave_forecast = fake_stepper
    d._wave_forecast_steps = 5  # already-stepping
    d.state.list_peers.return_value = [
        SimpleNamespace(fingerprint="peerA", trust="pinned"),
        SimpleNamespace(fingerprint="peerB", trust="pinned"),
    ]
    obs = MagicMock()
    obs.tau_at = lambda fp: 0.5
    d._field_obs = obs
    d._wave_forecast_tick()
    # No re-seed after the first step.
    fake_stepper.seed.assert_not_called()


def test_tick_increments_counters() -> None:
    d = _bare_daemon()
    d._wave_forecast_enabled = True
    fake_stepper = MagicMock()
    fake_stepper.step.return_value = 3  # 3 warnings
    fake_stepper.snapshot.return_value = {}
    d._wave_forecast = fake_stepper
    d._wave_forecast_steps = 1  # past initial seed
    d.state.list_peers.return_value = [
        SimpleNamespace(fingerprint="peerA", trust="pinned"),
        SimpleNamespace(fingerprint="peerB", trust="pinned"),
    ]
    obs = MagicMock()
    obs.tau_at = lambda fp: 0.5
    d._field_obs = obs
    warnings = d._wave_forecast_tick()
    assert warnings == 3
    assert d._wave_forecast_steps == 2
    assert d._wave_forecast_warnings == 3


def test_tick_recovers_from_step_exception() -> None:
    d = _bare_daemon()
    d._wave_forecast_enabled = True
    fake_stepper = MagicMock()
    fake_stepper.step.side_effect = RuntimeError("simulated")
    d._wave_forecast = fake_stepper
    d._wave_forecast_steps = 5
    d.state.list_peers.return_value = [
        SimpleNamespace(fingerprint="peerA", trust="pinned"),
        SimpleNamespace(fingerprint="peerB", trust="pinned"),
    ]
    obs = MagicMock()
    obs.tau_at = lambda fp: 0.5
    d._field_obs = obs
    # Must not raise.
    result = d._wave_forecast_tick()
    assert result == 0
    # Stepper got dropped so next tick re-seeds.
    assert d._wave_forecast is None
    assert d._wave_forecast_steps == 0


def test_tick_refreshes_predicted_disturbance_cache() -> None:
    d = _bare_daemon()
    d._wave_forecast_enabled = True
    fake_stepper = MagicMock()
    fake_stepper.step.return_value = 0
    fake_stepper.snapshot.return_value = {"peerA": 0.7, "peerB": 0.4}
    d._wave_forecast = fake_stepper
    d._wave_forecast_steps = 1
    d.state.list_peers.return_value = [
        SimpleNamespace(fingerprint="peerA", trust="pinned"),
        SimpleNamespace(fingerprint="peerB", trust="pinned"),
    ]
    obs = MagicMock()
    # Initial value 0.5 per peer; forecaster says 0.7 / 0.4 →
    # disturbance is +0.2 / -0.1.
    obs.tau_at = lambda fp: 0.5
    d._field_obs = obs
    d._wave_forecast_tick()
    assert d._wave_predicted_disturbance["peerA"] == pytest.approx(0.2)
    assert d._wave_predicted_disturbance["peerB"] == pytest.approx(-0.1)


# ---------- predicted_disturbance_for ----------


def test_predicted_disturbance_for_unknown_peer_returns_none() -> None:
    d = _bare_daemon()
    assert d.predicted_disturbance_for("unknown") is None


def test_predicted_disturbance_for_empty_returns_none() -> None:
    d = _bare_daemon()
    assert d.predicted_disturbance_for("") is None


def test_predicted_disturbance_for_known_peer() -> None:
    d = _bare_daemon()
    d._wave_predicted_disturbance = {"peerA": 0.25}
    assert d.predicted_disturbance_for("peerA") == 0.25


# ---------- wave_forecast_stats ----------


def test_stats_envelope_shape() -> None:
    d = _bare_daemon()
    d._wave_forecast_enabled = True
    d._wave_forecast_steps = 7
    d._wave_forecast_warnings = 2
    s = d.wave_forecast_stats()
    for key in (
        "enabled", "available", "steps", "warnings", "dt",
        "predicted_disturbance",
    ):
        assert key in s


def test_stats_reflects_counters() -> None:
    d = _bare_daemon()
    d._wave_forecast_steps = 42
    d._wave_forecast_warnings = 17
    s = d.wave_forecast_stats()
    assert s["steps"] == 42
    assert s["warnings"] == 17


def test_stats_bounds_predicted_disturbance_keys() -> None:
    """Predicted disturbance is keyed by 16-char fingerprint prefix +
    capped at 32 entries to keep response size bounded."""
    d = _bare_daemon()
    # Build 50 unique 64-char fingerprints by hashing a counter so
    # the first 16 chars differ across keys.
    import hashlib
    d._wave_predicted_disturbance = {
        hashlib.sha256(f"peer{i}".encode()).hexdigest(): 0.1
        for i in range(50)
    }
    s = d.wave_forecast_stats()
    assert len(s["predicted_disturbance"]) == 32
    for k in s["predicted_disturbance"]:
        assert len(k) == 16


def test_stats_includes_stepper_config_when_available() -> None:
    d = _bare_daemon()
    fake_stepper = MagicMock()
    fake_stepper.wave_speed = 0.5
    fake_stepper.damping = 0.05
    fake_stepper.cascade_threshold = 0.15
    fake_stepper.max_stable_dt = MagicMock(return_value=1.0)
    fake_stepper.courant_number = MagicMock(return_value=0.5)
    d._wave_forecast = fake_stepper
    s = d.wave_forecast_stats()
    assert s["wave_speed"] == 0.5
    assert s["damping"] == 0.05
    assert s["cascade_threshold"] == 0.15
    assert s["max_stable_dt"] == 1.0
    assert s["courant_number"] == 0.5


def test_stats_defensive_when_attrs_missing() -> None:
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    # No attrs set.
    s = d.wave_forecast_stats()
    assert s["enabled"] is False
    assert s["steps"] == 0
    assert s["warnings"] == 0


# ---------- selector wiring: predicted_disturbance → observed_loss ---


def _selector_daemon():
    """Build a bare daemon with selector pre-wired so we can assert
    on the kwargs the selector sees."""
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d._user_mode_value = "normal"
    d._field_obs = None
    d._radio_batcher = None
    d._smart_selector = MagicMock()
    d._smart_selector.decide.return_value = {
        "transport": "quic_stream",
        "path": "classical",
        "onion_hops": 3,
        "cover_traffic": False,
        "batch_decision": "emit_now",
        "anchor_lay": False,
        "predictor_warm": False,
    }
    d._selector_mode = "log"
    d._selector_enforce = False
    d._selector_kind = "smart_rules"
    d._wave_predicted_disturbance = {}
    d._pending_selector_observations = __import__(
        "collections",
    ).OrderedDict()
    d._pending_selector_observations_cap = 100
    d._selector_decision_counters = {
        "total": 0,
        "transport": {},
        "path": {},
        "onion_hops": {},
        "cover_traffic_on": 0,
        "cover_traffic_off": 0,
        "batch_decision": {},
        "anchor_lay_on": 0,
        "anchor_lay_off": 0,
        "predictor_warm_on": 0,
        "predictor_warm_off": 0,
        "f4_violations": 0,
    }
    d.predict_next_files_for_peer = MagicMock(return_value=[])
    d.state.get_peer.return_value = MagicMock(trust="pinned")
    return d


def test_observability_path_no_disturbance_no_bump() -> None:
    """When no disturbance is predicted, observed_loss is NOT set in
    decide_kwargs (the selector uses its own default)."""
    d = _selector_daemon()
    d._wave_predicted_disturbance = {}
    d._log_selector_decision_for_file(
        peer=MagicMock(), peer_fp="peerA", size=1000,
    )
    call_kwargs = d._smart_selector.decide.call_args.kwargs
    assert "observed_loss" not in call_kwargs


def test_observability_path_low_disturbance_no_bump() -> None:
    """Disturbance below the 0.05 threshold doesn't bump."""
    d = _selector_daemon()
    d._wave_predicted_disturbance = {"peerA": 0.03}
    d._log_selector_decision_for_file(
        peer=MagicMock(), peer_fp="peerA", size=1000,
    )
    call_kwargs = d._smart_selector.decide.call_args.kwargs
    assert "observed_loss" not in call_kwargs


def test_observability_path_high_disturbance_bumps_observed_loss() -> None:
    """Disturbance above the 0.05 threshold maps to an observed_loss
    bump in [0.0, 0.3]."""
    d = _selector_daemon()
    d._wave_predicted_disturbance = {"peerA": 0.25}
    d._log_selector_decision_for_file(
        peer=MagicMock(), peer_fp="peerA", size=1000,
    )
    call_kwargs = d._smart_selector.decide.call_args.kwargs
    # Expected: min(0.3, max(0.0, 0.25 - 0.05)) = 0.2
    assert call_kwargs["observed_loss"] == pytest.approx(0.2)


def test_observability_path_huge_disturbance_capped_at_0_3() -> None:
    """Disturbance >> 0.35 caps at 0.3 (privacy: never feed selector
    a synthetic value outside the [0, 1] expected range)."""
    d = _selector_daemon()
    d._wave_predicted_disturbance = {"peerA": 0.99}
    d._log_selector_decision_for_file(
        peer=MagicMock(), peer_fp="peerA", size=1000,
    )
    call_kwargs = d._smart_selector.decide.call_args.kwargs
    assert call_kwargs["observed_loss"] == 0.3


def test_observability_path_negative_disturbance_uses_abs() -> None:
    """A negative disturbance still bumps observed_loss — magnitude
    is what matters, not direction."""
    d = _selector_daemon()
    d._wave_predicted_disturbance = {"peerA": -0.25}
    d._log_selector_decision_for_file(
        peer=MagicMock(), peer_fp="peerA", size=1000,
    )
    call_kwargs = d._smart_selector.decide.call_args.kwargs
    assert call_kwargs["observed_loss"] == pytest.approx(0.2)


def test_enforce_path_also_consumes_disturbance() -> None:
    """The enforce path also reads predicted_disturbance and bumps
    observed_loss for parity with the observability path."""
    d = _selector_daemon()
    d._wave_predicted_disturbance = {"peerA": 0.30}
    out = d._selector_decision_for_file(peer_fp="peerA", size=1000)
    assert out is not None
    call_kwargs = d._smart_selector.decide.call_args.kwargs
    # Expected: 0.30 - 0.05 = 0.25 < 0.3 cap → 0.25
    assert call_kwargs["observed_loss"] == pytest.approx(0.25)


def test_disturbance_for_different_peer_does_not_leak() -> None:
    """Disturbance recorded for peer B must NOT bump peer A's
    selector call."""
    d = _selector_daemon()
    d._wave_predicted_disturbance = {"peerB": 0.5}
    d._log_selector_decision_for_file(
        peer=MagicMock(), peer_fp="peerA", size=1000,
    )
    call_kwargs = d._smart_selector.decide.call_args.kwargs
    assert "observed_loss" not in call_kwargs
