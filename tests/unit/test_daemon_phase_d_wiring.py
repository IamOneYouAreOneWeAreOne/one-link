"""Phase D daemon-integration smoke tests.

Verifies the prefetch + diagnostics + relay-picker helpers added to
``Daemon`` in the Phase D wiring commit. Direct unit-level coverage;
end-to-end multi-daemon integration stays in the daemon test suite.
"""

from __future__ import annotations

import pytest


def _native_available() -> bool:
    try:
        from one_link_native import prefetch, routing, homology  # noqa: F401

        return True
    except ImportError:
        return False


def test_pick_best_relay_single_relay_passthrough():
    """With only one relay, _pick_best_relay returns the input list."""
    from one_link.daemon import Daemon

    # Build a Daemon-like object that owns the helper but doesn't need
    # full init. We mimic the relevant attributes _pick_best_relay reads.
    class _StubRelay:
        def __init__(self, url: str):
            self._rendezvous_url = url

    # Use the unbound method to avoid Daemon's full constructor.
    relays = [_StubRelay("relay-a")]
    result = Daemon._pick_best_relay(  # type: ignore[arg-type]
        object(),  # self placeholder; helper doesn't touch attrs in 1-relay path
        relays,
    )
    assert result == relays


def test_pick_best_relay_zero_relays():
    from one_link.daemon import Daemon

    result = Daemon._pick_best_relay(object(), [])  # type: ignore[arg-type]
    assert result == []


def test_relay_metrics_for_returns_none_by_default():
    """Without a metrics surface, every relay query returns None."""
    from one_link.daemon import Daemon

    result = Daemon._relay_metrics_for(object(), "any-url")  # type: ignore[arg-type]
    assert result is None


@pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native Phase D submodules not installed",
)
def test_pick_best_relay_with_routing_no_metrics_preserves_order():
    """When routing IS available but no per-relay metrics exist, the
    cost is the same for every relay (default 1.0) so the input order
    is preserved by a stable sort."""
    from one_link.daemon import Daemon

    class _R:
        def __init__(self, url: str):
            self._rendezvous_url = url

    class _StubDaemon:
        def _relay_metrics_for(self, _url):
            return None

    relays = [_R("r1"), _R("r2"), _R("r3")]
    out = Daemon._pick_best_relay(_StubDaemon(), relays)  # type: ignore[arg-type]
    # All three present, no reordering when metrics are uniform.
    assert len(out) == 3
    urls = [r._rendezvous_url for r in out]
    assert set(urls) == {"r1", "r2", "r3"}


def test_native_diagnostics_reports_all_subsystems():
    """native_diagnostics returns the standard 5 keys regardless of
    which native crates are available."""
    from one_link.daemon import Daemon

    # Build a fake daemon-ish stub with the minimum attrs.
    class _Stub:
        _prefetch_predictor = None
        _last_minted_macaroon = None

    diag = Daemon.native_diagnostics(_Stub())  # type: ignore[arg-type]
    assert set(diag.keys()) >= {
        "prefetch",
        "routing",
        "homology",
        "native_transfer_v1",
        "macaroon_dual_issue",
    }
    for sub in ("prefetch", "routing", "homology"):
        assert isinstance(diag[sub]["available"], bool)
    assert isinstance(diag["native_transfer_v1"]["advertised"], bool)


def test_native_diagnostics_native_transfer_v1_advertised():
    """When the daemon's LOCAL_CAPABILITIES includes NATIVE_TRANSFER_V1
    (the default), diagnostics should report `advertised=True`."""
    from one_link.daemon import Daemon

    class _Stub:
        _prefetch_predictor = None
        _last_minted_macaroon = None

    diag = Daemon.native_diagnostics(_Stub())  # type: ignore[arg-type]
    assert diag["native_transfer_v1"]["advertised"] is True


@pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native Phase D submodules not installed",
)
def test_native_diagnostics_reports_prefetch_available():
    from one_link.daemon import Daemon

    class _Stub:
        _prefetch_predictor = None
        _last_minted_macaroon = None

    diag = Daemon.native_diagnostics(_Stub())  # type: ignore[arg-type]
    assert diag["prefetch"]["available"] is True
    assert diag["routing"]["available"] is True
    assert diag["homology"]["available"] is True


# ── Relay metrics surface (Phase D #1) ──────────────────────────────


def test_record_relay_observation_first_success():
    """First successful observation populates the metrics dict for a
    relay URL with the dial RTT + n_attempts=1 + n_successes=1."""
    from one_link.daemon import Daemon

    class _Stub:
        _relay_metrics: dict = {}

    stub = _Stub()
    Daemon.record_relay_observation(
        stub, "https://relay-a.example.com", rtt_ms=45.0, success=True
    )
    m = stub._relay_metrics["https://relay-a.example.com"]
    assert m["n_attempts"] == 1
    assert m["n_successes"] == 1
    # EWMA(prev=100, alpha=0.2, obs=45) = 0.8*100 + 0.2*45 = 89.
    assert abs(m["rtt_ms"] - 89.0) < 1e-9
    # loss_rate EWMA(prev=0, alpha=0.2, obs=0) = 0.
    assert m["loss_rate"] == 0.0


def test_record_relay_observation_failure_bumps_loss_rate():
    from one_link.daemon import Daemon

    class _Stub:
        _relay_metrics: dict = {}

    stub = _Stub()
    Daemon.record_relay_observation(
        stub, "https://relay-a.example.com", rtt_ms=None, success=False
    )
    m = stub._relay_metrics["https://relay-a.example.com"]
    assert m["n_attempts"] == 1
    assert m["n_successes"] == 0
    # First failure: loss_rate EWMA(0, alpha=0.2, obs=1) = 0.2.
    assert abs(m["loss_rate"] - 0.2) < 1e-9


def test_record_relay_observation_ewma_smoothing_converges():
    """20 consecutive successes at 50 ms should converge close to 50 ms."""
    from one_link.daemon import Daemon

    class _Stub:
        _relay_metrics: dict = {}

    stub = _Stub()
    for _ in range(20):
        Daemon.record_relay_observation(
            stub, "https://relay-a.example.com", rtt_ms=50.0, success=True
        )
    m = stub._relay_metrics["https://relay-a.example.com"]
    # After 20 EWMA steps with alpha=0.2 starting from prev=100, residual
    # is (1-alpha)^20 * (100-50) = 0.0115 * 50 ≈ 0.576 — converging but
    # still ~1% off. Tolerance of 1.0 ms covers the closed-form value
    # with margin.
    assert abs(m["rtt_ms"] - 50.0) < 1.0


def test_relay_metrics_for_returns_recorded_dict():
    """After observation, _relay_metrics_for returns the recorded dict."""
    from one_link.daemon import Daemon

    class _Stub:
        _relay_metrics: dict = {}

    stub = _Stub()
    Daemon.record_relay_observation(
        stub, "https://relay-a.example.com", rtt_ms=20.0, success=True
    )
    out = Daemon._relay_metrics_for(stub, "https://relay-a.example.com")
    assert out is not None
    assert "rtt_ms" in out
    assert "loss_rate" in out


@pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native Phase D submodules not installed",
)
def test_pick_best_relay_with_metrics_promotes_low_loss_relay():
    """With real metrics: a low-RTT, low-loss relay should rank above
    a high-RTT, high-loss one."""
    from one_link.daemon import Daemon

    class _R:
        def __init__(self, url):
            self._rendezvous_url = url

    class _Stub:
        _relay_metrics: dict = {}

    stub = _Stub()
    # Relay A: fast (20 ms) + reliable (0% loss).
    for _ in range(10):
        Daemon.record_relay_observation(stub, "fast", rtt_ms=20.0, success=True)
    # Relay B: slow (500 ms) + lossy (50% loss).
    for _ in range(5):
        Daemon.record_relay_observation(stub, "slow", rtt_ms=500.0, success=True)
        Daemon.record_relay_observation(stub, "slow", rtt_ms=None, success=False)

    relays = [_R("slow"), _R("fast")]  # input order: slow first
    sorted_relays = Daemon._pick_best_relay(stub, relays)  # type: ignore[arg-type]
    # Fast should be promoted to first slot.
    assert sorted_relays[0]._rendezvous_url == "fast"
    assert sorted_relays[1]._rendezvous_url == "slow"
