"""Tests for the Phase A2 QUIC dual-stack transport wiring."""

from __future__ import annotations

import pytest


def _quic_available() -> bool:
    try:
        from one_link_native import quic  # noqa: F401

        return True
    except ImportError:
        return False


def test_quic_capability_advertised():
    """Daemons must advertise QUIC_TRANSPORT_V1 so peers know to
    negotiate. The cap is what gates the entire feature."""
    from one_link.capabilities import LOCAL_CAPABILITIES, QUIC_TRANSPORT_V1

    assert QUIC_TRANSPORT_V1 in LOCAL_CAPABILITIES


def test_should_prefer_quic_requires_both_sides_advertising():
    from one_link.capabilities import QUIC_TRANSPORT_V1
    from one_link.peer_quic import should_prefer_quic_for_peer

    # Both advertise → prefer QUIC.
    assert should_prefer_quic_for_peer(
        (QUIC_TRANSPORT_V1,), (QUIC_TRANSPORT_V1,)
    ) is True
    # Local advertises but peer doesn't → no QUIC.
    assert should_prefer_quic_for_peer((QUIC_TRANSPORT_V1,), ()) is False
    # Peer advertises but local doesn't → no QUIC.
    assert should_prefer_quic_for_peer((), (QUIC_TRANSPORT_V1,)) is False
    # Neither → no QUIC.
    assert should_prefer_quic_for_peer((), ()) is False


def test_transport_choice_for_peer_defaults_to_webrtc_without_caps():
    """The daemon's transport_choice_for_peer must return 'webrtc'
    when the peer has no caps (v0.20.x peers, browser-as-peer, etc.)
    — backward-compat guarantee."""
    from one_link.daemon import Daemon

    class _PeerNoCaps:
        capabilities = None
        advertised_caps = None

    # Unbound-method invocation against a stub that has the attributes
    # transport_choice_for_peer reads.
    class _Stub:
        _quic_endpoint = None

        def _ensure_quic_endpoint(self):
            return None

    choice = Daemon.transport_choice_for_peer(_Stub(), _PeerNoCaps())  # type: ignore[arg-type]
    assert choice == "webrtc"


def test_transport_choice_returns_webrtc_when_peer_lacks_quic_cap():
    from one_link.daemon import Daemon

    class _PeerWebRTCOnly:
        capabilities = ("chat", "files")

    class _Stub:
        _quic_endpoint = None

        def _ensure_quic_endpoint(self):
            return None

    choice = Daemon.transport_choice_for_peer(_Stub(), _PeerWebRTCOnly())  # type: ignore[arg-type]
    assert choice == "webrtc"


@pytest.mark.skipif(
    not _quic_available(),
    reason="one_link_native.quic not installed",
)
def test_quic_endpoint_construction_returns_object_or_none_cleanly():
    """make_endpoint either returns a usable endpoint OR cleanly
    returns None — never raises."""
    from one_link.peer_quic import make_endpoint

    ep = make_endpoint()
    # We don't assert on the type — the binding may not yet support
    # full server construction on this platform. The contract is:
    # no exception, returns either an object with close() or None.
    if ep is not None:
        assert hasattr(ep, "close")
        try:
            ep.close()
        except Exception:
            pass


def test_native_diagnostics_exposes_bloom_init_block():
    """The status response must include bloom_init availability info
    so operators + integration tests can verify Phase B is wired."""
    from one_link.daemon import Daemon

    class _Stub:
        _prefetch_predictor = None
        _last_minted_macaroon = None

    diag = Daemon.native_diagnostics(_Stub())  # type: ignore[arg-type]
    assert "bloom_init" in diag
    assert isinstance(diag["bloom_init"]["available"], bool)
    assert isinstance(diag["bloom_init"]["advertised"], bool)
    # The cap is unconditionally advertised by the daemon build.
    assert diag["bloom_init"]["advertised"] is True


def test_native_diagnostics_exposes_quic_transport_block():
    from one_link.daemon import Daemon

    class _Stub:
        _prefetch_predictor = None
        _last_minted_macaroon = None

    diag = Daemon.native_diagnostics(_Stub())  # type: ignore[arg-type]
    assert "quic_transport" in diag
    assert isinstance(diag["quic_transport"]["available"], bool)
    assert isinstance(diag["quic_transport"]["advertised"], bool)
    assert diag["quic_transport"]["advertised"] is True


def test_daemon_build_local_bloom_advertisement():
    """When called with a list of chunk IDs, the daemon returns wire
    bytes the receiver can send to a sender. Returns None gracefully
    if the native crate is missing."""
    from one_link.daemon import Daemon

    class _Stub:
        pass

    ids = [b"\x00" * 32, b"\x01" * 32, b"\x02" * 32]
    result = Daemon.build_local_bloom_advertisement(_Stub(), ids)  # type: ignore[arg-type]
    # Either: native installed → returns bytes with content; or not
    # installed → returns None cleanly. No exception either way.
    assert result is None or (isinstance(result, bytes) and len(result) > 4)


def test_daemon_filter_manifest_with_receiver_bloom_round_trip():
    """End-to-end Daemon-method-level test: build a Bloom on one
    side, filter a manifest on the other, verify only missing chunks
    appear."""
    from one_link.daemon import Daemon

    try:
        from one_link import bloom_init

        if not bloom_init.HAS_NATIVE:
            pytest.skip("one_link_native.bloom not installed")
    except ImportError:
        pytest.skip("one_link_native.bloom not installed")

    class _Stub:
        pass

    stub = _Stub()
    receiver_ids = [b"r" + bytes([i]) + b"\x00" * 30 for i in range(50)]
    advertisement = Daemon.build_local_bloom_advertisement(stub, receiver_ids)  # type: ignore[arg-type]
    assert advertisement is not None

    sender_manifest = receiver_ids + [b"NEW" + bytes([i]) + b"\x00" * 28 for i in range(10)]
    missing = Daemon.filter_manifest_with_receiver_bloom(
        stub,  # type: ignore[arg-type]
        sender_manifest,
        advertisement,
    )
    assert missing is not None
    # At least 8 of the 10 new chunks must show up as missing (allowing
    # ~2 false positives at 5% FP × 10 new chunks).
    new_set = {b"NEW" + bytes([i]) + b"\x00" * 28 for i in range(10)}
    flagged_new = sum(1 for cid in missing if cid in new_set)
    assert flagged_new >= 8
