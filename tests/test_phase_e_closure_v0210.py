"""Integration map Phase E closure — Tests for the final PARTIAL
items (D10 fail-open, D11 adaptive discovery, D12 reconnect EWMA,
D13 adaptive heartbeat).

Each item closes a specific gap the map's §0.6 flagged as still
needing work. Together they bring Phase E to full ship.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from one_link import daemon as daemon_module


# ─── shared helpers ───


def _bare_daemon():
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d.state.get_peer.return_value = None
    d._capability_fail_open_count = 0
    d._reconnect_stability_ewma_ms = {}
    d._discovery_interval_s = daemon_module.DISCOVERY_BASELINE_S
    d._discovery_churn_count = 0
    d._wave_predicted_disturbance = {}
    return d


# ─── D13 adaptive_heartbeat_interval ───


def test_heartbeat_baseline_when_no_signal() -> None:
    """Unknown peer (no trust score, no disturbance) → baseline.
    Wait — the helper defaults trust=0.5 when unknown, so the
    interval lands in the middle of [MIN, MAX]."""
    d = _bare_daemon()
    d._peer_trust_score = MagicMock(return_value=None)
    interval = d.adaptive_heartbeat_interval("peerA")
    # trust=0.5 → midpoint of [10, 120] = 65s
    assert (
        daemon_module.HEARTBEAT_MIN_INTERVAL_S
        <= interval
        <= daemon_module.HEARTBEAT_MAX_INTERVAL_S
    )
    assert interval == pytest.approx(65.0, abs=1.0)


def test_heartbeat_high_trust_long_interval() -> None:
    """trust = 1.0 → interval near MAX."""
    d = _bare_daemon()
    d._peer_trust_score = MagicMock(return_value=1.0)
    interval = d.adaptive_heartbeat_interval("peerA")
    assert interval == pytest.approx(
        daemon_module.HEARTBEAT_MAX_INTERVAL_S, abs=0.1,
    )


def test_heartbeat_zero_trust_short_interval() -> None:
    """trust = 0.0 → interval = MIN."""
    d = _bare_daemon()
    d._peer_trust_score = MagicMock(return_value=0.0)
    interval = d.adaptive_heartbeat_interval("peerA")
    assert interval == pytest.approx(
        daemon_module.HEARTBEAT_MIN_INTERVAL_S, abs=0.1,
    )


def test_heartbeat_disturbance_shortens_interval() -> None:
    """High predicted disturbance pulls the interval toward MIN."""
    d = _bare_daemon()
    d._peer_trust_score = MagicMock(return_value=1.0)  # max base
    d._wave_predicted_disturbance = {"peerA": 1.0}  # max disturbance
    interval = d.adaptive_heartbeat_interval("peerA")
    # With full disturbance, base * 0.5 → 60s (was 120s).
    assert interval == pytest.approx(60.0, abs=1.0)


def test_heartbeat_empty_peer_returns_baseline() -> None:
    d = _bare_daemon()
    assert d.adaptive_heartbeat_interval("") == daemon_module.HEARTBEAT_BASELINE_S


def test_heartbeat_survives_trust_score_exception() -> None:
    d = _bare_daemon()
    d._peer_trust_score = MagicMock(side_effect=RuntimeError("simulated"))
    # Must not raise.
    interval = d.adaptive_heartbeat_interval("peerA")
    assert (
        daemon_module.HEARTBEAT_MIN_INTERVAL_S
        <= interval
        <= daemon_module.HEARTBEAT_MAX_INTERVAL_S
    )


def test_heartbeat_clamped_to_bounds() -> None:
    """Even with adversarial inputs, the result is bounded."""
    d = _bare_daemon()
    # Mock trust > 1 (shouldn't happen but defensive).
    d._peer_trust_score = MagicMock(return_value=2.5)
    interval = d.adaptive_heartbeat_interval("peerA")
    assert interval <= daemon_module.HEARTBEAT_MAX_INTERVAL_S


# ─── D12 reconnect_backoff_ms ───


def test_reconnect_backoff_no_history_returns_midpoint() -> None:
    d = _bare_daemon()
    backoff = d.adaptive_reconnect_backoff_ms("peerA")
    expected = (
        daemon_module.RECONNECT_BACKOFF_MIN_MS
        + daemon_module.RECONNECT_BACKOFF_MAX_MS
    ) // 2
    assert backoff == expected


def test_reconnect_backoff_long_stability_short_backoff() -> None:
    """Long observed stability → short backoff."""
    d = _bare_daemon()
    # Record several long-lived sessions.
    for _ in range(5):
        d.record_reconnect_outcome("peerA", 60_000.0)
    backoff = d.adaptive_reconnect_backoff_ms("peerA")
    # EWMA should be near 60_000 → backoff near MIN.
    assert backoff <= 5_000  # well below midpoint


def test_reconnect_backoff_short_stability_long_backoff() -> None:
    """Short observed stability → long backoff."""
    d = _bare_daemon()
    for _ in range(5):
        d.record_reconnect_outcome("peerA", 500.0)
    backoff = d.adaptive_reconnect_backoff_ms("peerA")
    # EWMA near 500 → backoff near MAX.
    assert backoff >= 50_000


def test_reconnect_record_ignores_negative() -> None:
    d = _bare_daemon()
    d.record_reconnect_outcome("peerA", -100.0)
    assert "peerA" not in d._reconnect_stability_ewma_ms


def test_reconnect_record_ignores_nan() -> None:
    d = _bare_daemon()
    d.record_reconnect_outcome("peerA", float("nan"))
    assert "peerA" not in d._reconnect_stability_ewma_ms


def test_reconnect_record_ignores_empty_peer() -> None:
    d = _bare_daemon()
    d.record_reconnect_outcome("", 1000.0)
    assert d._reconnect_stability_ewma_ms == {}


def test_reconnect_record_ignores_non_numeric() -> None:
    d = _bare_daemon()
    d.record_reconnect_outcome("peerA", "not-a-number")  # type: ignore[arg-type]
    assert "peerA" not in d._reconnect_stability_ewma_ms


def test_reconnect_ewma_converges() -> None:
    """EWMA should converge toward repeated input."""
    d = _bare_daemon()
    for _ in range(50):
        d.record_reconnect_outcome("peerA", 10_000.0)
    assert d._reconnect_stability_ewma_ms["peerA"] == pytest.approx(10_000.0, abs=1.0)


def test_reconnect_backoff_bounded() -> None:
    """Even pathological inputs produce a value in [MIN, MAX]."""
    d = _bare_daemon()
    d._reconnect_stability_ewma_ms["peerA"] = -1000.0  # nonsense
    backoff = d.adaptive_reconnect_backoff_ms("peerA")
    assert (
        daemon_module.RECONNECT_BACKOFF_MIN_MS
        <= backoff
        <= daemon_module.RECONNECT_BACKOFF_MAX_MS
    )


# ─── D11 adaptive_discovery_interval ───


def test_discovery_no_churn_backs_off() -> None:
    """No recent churn → interval grows toward MAX."""
    d = _bare_daemon()
    d._discovery_interval_s = daemon_module.DISCOVERY_BASELINE_S
    interval = d.adaptive_discovery_interval()
    # baseline * 1.5 = 15s
    assert interval == pytest.approx(
        daemon_module.DISCOVERY_BASELINE_S * 1.5, abs=0.1,
    )


def test_discovery_single_churn_half_baseline() -> None:
    d = _bare_daemon()
    d.record_peer_churn()  # one event
    interval = d.adaptive_discovery_interval()
    assert interval == pytest.approx(
        daemon_module.DISCOVERY_BASELINE_S / 2, abs=0.1,
    )


def test_discovery_high_churn_pulls_to_min() -> None:
    """3+ churn events in window → interval = MIN."""
    d = _bare_daemon()
    for _ in range(5):
        d.record_peer_churn()
    interval = d.adaptive_discovery_interval()
    assert interval == daemon_module.DISCOVERY_MIN_INTERVAL_S


def test_discovery_churn_counter_resets_per_call() -> None:
    """The churn counter resets each call so the next interval
    reflects the next window."""
    d = _bare_daemon()
    d.record_peer_churn()
    d.adaptive_discovery_interval()  # consumes 1
    assert d._discovery_churn_count == 0


def test_discovery_caps_at_max() -> None:
    """Repeated no-churn calls cap at MAX, don't grow unboundedly."""
    d = _bare_daemon()
    d._discovery_interval_s = daemon_module.DISCOVERY_BASELINE_S
    for _ in range(20):
        d.adaptive_discovery_interval()
    assert d._discovery_interval_s == pytest.approx(
        daemon_module.DISCOVERY_MAX_INTERVAL_S, abs=0.1,
    )


# ─── D10 capability verifier error continuity metric ───


def test_capability_fails_closed_on_state_exception() -> None:
    """When state.get_peer_capability_policy raises, _capability_allowed
    must fail CLOSED + bump the legacy continuity counter."""
    d = _bare_daemon()
    d.state.get_peer.return_value = MagicMock(trust="pinned")
    d.state.get_peer_capability_policy = MagicMock(
        side_effect=RuntimeError("simulated state corruption"),
    )
    # Need the seed-tamper check to pass.
    d.detect_seed_file_tamper = MagicMock(return_value=False)
    # No cap_store grant path needed; pass through.
    d._cap_store = None
    d.me = MagicMock()
    d.me.public_bytes = b"\x00" * 32
    d._peer_pub_for_fp = MagicMock(return_value=None)
    out = d._capability_allowed("peerA", "files")
    assert out is False
    assert d._capability_fail_open_count == 1


def test_capability_fail_open_counter_accumulates() -> None:
    d = _bare_daemon()
    d.state.get_peer.return_value = MagicMock(trust="pinned")
    d.state.get_peer_capability_policy = MagicMock(
        side_effect=RuntimeError("simulated"),
    )
    d.detect_seed_file_tamper = MagicMock(return_value=False)
    d._cap_store = None
    d.me = MagicMock()
    d.me.public_bytes = b"\x00" * 32
    d._peer_pub_for_fp = MagicMock(return_value=None)
    for _ in range(5):
        d._capability_allowed("peerA", "files")
    assert d._capability_fail_open_count == 5


def test_capability_normal_path_does_not_bump_fail_open() -> None:
    """Healthy capability check must NOT bump the fail-open counter."""
    d = _bare_daemon()
    d.state.get_peer.return_value = MagicMock(trust="pinned")
    d.state.get_peer_capability_policy = MagicMock(return_value=["files"])
    d.detect_seed_file_tamper = MagicMock(return_value=False)
    d._cap_store = None
    d.me = MagicMock()
    d.me.public_bytes = b"\x00" * 32
    d._peer_pub_for_fp = MagicMock(return_value=None)
    d._peer_trust_score = MagicMock(return_value=0.8)
    d._record_alignment_trust_score = MagicMock()
    out = d._capability_allowed("peerA", "files")
    assert out is True
    assert d._capability_fail_open_count == 0


# ─── adaptive_transport_stats ───


def test_adaptive_transport_stats_shape() -> None:
    d = _bare_daemon()
    s = d.adaptive_transport_stats()
    for key in (
        "heartbeat_baseline_s", "heartbeat_min_s", "heartbeat_max_s",
        "reconnect_backoff_min_ms", "reconnect_backoff_max_ms",
        "reconnect_ewma_alpha", "reconnect_ewma_peers",
        "discovery_interval_s", "discovery_churn_pending",
        "capability_fail_open_count",
    ):
        assert key in s


def test_adaptive_transport_stats_includes_ewma_preview() -> None:
    d = _bare_daemon()
    d.record_reconnect_outcome("peerA_long_fingerprint_12345678", 10_000.0)
    s = d.adaptive_transport_stats()
    # Key truncated to 16 chars.
    keys = list(s["reconnect_ewma_peers"].keys())
    assert len(keys) == 1
    assert len(keys[0]) == 16


def test_adaptive_transport_stats_bounds_ewma_preview_to_32() -> None:
    d = _bare_daemon()
    import hashlib
    for i in range(50):
        fp = hashlib.sha256(f"peer{i}".encode()).hexdigest()
        d.record_reconnect_outcome(fp, 5_000.0)
    s = d.adaptive_transport_stats()
    assert len(s["reconnect_ewma_peers"]) == 32


def test_adaptive_transport_stats_reflects_fail_open_count() -> None:
    d = _bare_daemon()
    d._capability_fail_open_count = 42
    s = d.adaptive_transport_stats()
    assert s["capability_fail_open_count"] == 42
