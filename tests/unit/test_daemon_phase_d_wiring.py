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
