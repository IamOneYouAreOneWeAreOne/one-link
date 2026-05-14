"""Tests for the PeerTransport facade — the uniform abstraction
between channel-layer send/recv and the actual transport (WebRTC or
QUIC)."""

from __future__ import annotations

import pytest


def test_webrtc_transport_sends_through_channel():
    from one_link.peer_transport import WebRTCTransport

    captured: list[bytes] = []

    class _FakeChannel:
        _closed = False

        def send(self, payload):
            # Sync return — matches the test-stub channel surface.
            captured.append(payload)
            return None

    t = WebRTCTransport(channel=_FakeChannel())
    assert t.kind == "webrtc"
    assert t.is_open() is True
    t.send_bytes(b"hello")
    assert captured == [b"hello"]
    assert t.stats.bytes_sent == 5
    assert t.stats.sends == 1


def test_webrtc_transport_reports_closed_channel():
    from one_link.peer_transport import TransportSendError, WebRTCTransport

    class _ClosedChannel:
        _closed = True

        def send(self, payload):
            pass

    t = WebRTCTransport(channel=_ClosedChannel())
    assert t.is_open() is False
    with pytest.raises(TransportSendError, match="closed"):
        t.send_bytes(b"x")
    assert t.stats.send_failures == 1


def test_webrtc_transport_propagates_send_errors():
    from one_link.peer_transport import TransportSendError, WebRTCTransport

    class _ErrChannel:
        _closed = False

        def send(self, payload):
            raise OSError("network down")

    t = WebRTCTransport(channel=_ErrChannel())
    with pytest.raises(TransportSendError, match="network down"):
        t.send_bytes(b"data")
    assert t.stats.send_failures == 1
    assert t.stats.bytes_sent == 0


def test_quic_transport_sends_through_session():
    from one_link.peer_transport import QuicTransport
    from one_link.peer_quic import HAS_NATIVE, FRAME_CHUNK_REQUEST

    if not HAS_NATIVE or FRAME_CHUNK_REQUEST is None:
        pytest.skip(
            "one_link_native.quic not importable here (likely Smart "
            "App Control blocked the freshly-built DLL); the QUIC "
            "send-frame test needs the native frame-type constant"
        )

    captured: list[tuple[int, bytes]] = []

    class _FakeSession:
        def is_connected(self):
            return True

        def rtt_ms(self):
            return 12.5

        def send_frame(self, frame_type, payload):
            captured.append((frame_type, bytes(payload)))
            return b""

    t = QuicTransport(session=_FakeSession())
    assert t.kind == "quic"
    assert t.is_open() is True
    t.send_bytes(b"payload")
    assert len(captured) == 1
    # Frame type is the generic carrier — exact value depends on the
    # native crate, but it should be an int.
    assert isinstance(captured[0][0], int)
    assert captured[0][1] == b"payload"
    assert t.stats.bytes_sent == 7
    assert t.rtt_ms() == 12.5


def test_quic_transport_reports_closed_session():
    from one_link.peer_transport import QuicTransport, TransportSendError

    class _ClosedSession:
        def is_connected(self):
            return False

    t = QuicTransport(session=_ClosedSession())
    assert t.is_open() is False
    with pytest.raises(TransportSendError, match="closed"):
        t.send_bytes(b"x")


def test_make_transport_for_peer_dispatches_correctly():
    from one_link.peer_transport import (
        QuicTransport,
        WebRTCTransport,
        make_transport_for_peer,
    )

    class _Channel:
        _closed = False

        def send(self, p):
            pass

    class _Session:
        def is_connected(self):
            return True

    webrtc = make_transport_for_peer("webrtc", channel=_Channel())
    assert isinstance(webrtc, WebRTCTransport)

    quic = make_transport_for_peer("quic", quic_session=_Session())
    assert isinstance(quic, QuicTransport)


def test_make_transport_for_peer_rejects_missing_underlying():
    from one_link.peer_transport import make_transport_for_peer

    with pytest.raises(ValueError, match="WebRTC transport requires"):
        make_transport_for_peer("webrtc")

    with pytest.raises(ValueError, match="QUIC transport requires"):
        make_transport_for_peer("quic")


def test_make_transport_for_peer_rejects_unknown_kind():
    from one_link.peer_transport import make_transport_for_peer

    with pytest.raises(ValueError, match="unknown transport kind"):
        make_transport_for_peer("morse-code")


def test_transport_stats_carries_kind():
    from one_link.peer_transport import QuicTransport, WebRTCTransport

    class _Channel:
        _closed = False

        def send(self, p):
            pass

    class _Session:
        def is_connected(self):
            return True

        def send_frame(self, t, p):
            return b""

    assert WebRTCTransport(channel=_Channel()).stats.transport_kind == "webrtc"
    assert QuicTransport(session=_Session()).stats.transport_kind == "quic"


def test_quic_transport_rtt_returns_none_when_session_closed():
    from one_link.peer_transport import QuicTransport

    class _ClosedSession:
        def is_connected(self):
            return False

    t = QuicTransport(session=_ClosedSession())
    assert t.rtt_ms() is None


def test_webrtc_close_is_noop_for_facade():
    """The facade's close() must not tear down the underlying channel
    — the daemon owns channel lifecycle. Facade close is a marker."""
    from one_link.peer_transport import WebRTCTransport

    closed_calls = []

    class _Channel:
        _closed = False

        def send(self, p):
            pass

        def close(self):
            closed_calls.append(True)

    t = WebRTCTransport(channel=_Channel())
    t.close()
    # Facade close must NOT have called channel.close().
    assert closed_calls == []
