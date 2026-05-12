"""Tests for the Bloom-init honor env flag + async-flavoured
PeerTransport facade."""

from __future__ import annotations

import asyncio
import os
from contextlib import contextmanager

import pytest


@contextmanager
def env(var: str, value: str | None):
    """Temporarily set ``var`` to ``value`` (or unset if None)."""
    prev = os.environ.get(var)
    if value is None:
        os.environ.pop(var, None)
    else:
        os.environ[var] = value
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop(var, None)
        else:
            os.environ[var] = prev


def _native_available() -> bool:
    try:
        from one_link_native import bloom  # noqa: F401

        return True
    except ImportError:
        return False


# ──────────────────────────────── bloom_honor_enabled() ────────────


def test_bloom_honor_disabled_by_default():
    from one_link.bloom_init import bloom_honor_enabled

    with env("ONE_LINK_BLOOM_HONOR", None):
        assert bloom_honor_enabled() is False


def test_bloom_honor_enabled_with_env_flag():
    from one_link.bloom_init import bloom_honor_enabled

    for v in ("1", "true", "yes"):
        with env("ONE_LINK_BLOOM_HONOR", v):
            assert bloom_honor_enabled() is True


def test_bloom_honor_rejects_unknown_values():
    from one_link.bloom_init import bloom_honor_enabled

    for v in ("", "0", "false", "no", "off"):
        with env("ONE_LINK_BLOOM_HONOR", v):
            assert bloom_honor_enabled() is False


# ────────────────────────────────── _resolve_fp_rate ───────────────


@pytest.mark.skipif(not _native_available(), reason="ol_bloom not installed")
def test_production_fp_rate_default():
    from one_link.bloom_init import PRODUCTION_FP_RATE, _resolve_fp_rate

    # No env, no override → production default.
    with env("ONE_LINK_BLOOM_FP_RATE", None):
        assert _resolve_fp_rate(None) == PRODUCTION_FP_RATE


def test_production_fp_rate_env_override():
    from one_link.bloom_init import _resolve_fp_rate

    with env("ONE_LINK_BLOOM_FP_RATE", "0.001"):
        assert _resolve_fp_rate(None) == 0.001
    with env("ONE_LINK_BLOOM_FP_RATE", "0.05"):
        assert _resolve_fp_rate(None) == 0.05


def test_production_fp_rate_explicit_override_beats_env():
    """When the caller passes target_fp_rate, env is ignored."""
    from one_link.bloom_init import _resolve_fp_rate

    with env("ONE_LINK_BLOOM_FP_RATE", "0.05"):
        assert _resolve_fp_rate(0.001) == 0.001


def test_production_fp_rate_rejects_invalid_env():
    from one_link.bloom_init import PRODUCTION_FP_RATE, _resolve_fp_rate

    # Out-of-range or non-numeric env values fall back to production.
    for bad in ("1.5", "-0.1", "abc", ""):
        with env("ONE_LINK_BLOOM_FP_RATE", bad):
            assert _resolve_fp_rate(None) == PRODUCTION_FP_RATE


# ──────────────────────────── _bloom_only_for_peer ─────────────────


def test_bloom_only_for_peer_false_without_env_flag():
    from one_link.daemon import Daemon

    class _Stub:
        _outbound_sessions = {}

        def _peer_advertised_caps(self, fp):
            from one_link.capabilities import BLOOM_INIT_V1

            return frozenset({BLOOM_INIT_V1})

        def _locally_held_chunk_ids_for_blob(self, _blob):
            return [b"\x00" * 32]  # not empty

    stub = _Stub()
    with env("ONE_LINK_BLOOM_HONOR", None):
        assert Daemon._bloom_only_for_peer(stub, "anyone") is False  # type: ignore[arg-type]


def test_bloom_only_for_peer_false_without_peer_cap():
    from one_link.daemon import Daemon

    class _Stub:
        _outbound_sessions = {}

        def _peer_advertised_caps(self, fp):
            return frozenset()  # peer doesn't advertise

        def _locally_held_chunk_ids_for_blob(self, _blob):
            return [b"\x00" * 32]

    stub = _Stub()
    with env("ONE_LINK_BLOOM_HONOR", "1"):
        assert Daemon._bloom_only_for_peer(stub, "anyone") is False  # type: ignore[arg-type]


def test_bloom_only_for_peer_false_when_no_local_chunks():
    """Empty receiver inventory → no Bloom-only advantage."""
    from one_link.daemon import Daemon

    class _Stub:
        _outbound_sessions = {}

        def _peer_advertised_caps(self, fp):
            from one_link.capabilities import BLOOM_INIT_V1

            return frozenset({BLOOM_INIT_V1})

        def _locally_held_chunk_ids_for_blob(self, _blob):
            return []  # empty

    stub = _Stub()
    with env("ONE_LINK_BLOOM_HONOR", "1"):
        assert Daemon._bloom_only_for_peer(stub, "anyone") is False  # type: ignore[arg-type]


@pytest.mark.skipif(not _native_available(), reason="ol_bloom not installed")
def test_bloom_only_for_peer_true_when_all_conditions_met():
    from one_link.daemon import Daemon

    class _Stub:
        _outbound_sessions = {}

        def _peer_advertised_caps(self, fp):
            from one_link.capabilities import BLOOM_INIT_V1

            return frozenset({BLOOM_INIT_V1})

        def _locally_held_chunk_ids_for_blob(self, _blob):
            return [b"\x00" * 32, b"\x01" * 32]

    stub = _Stub()
    with env("ONE_LINK_BLOOM_HONOR", "1"):
        assert Daemon._bloom_only_for_peer(stub, "anyone") is True  # type: ignore[arg-type]


# ────────────────────────── async PeerTransport facade ────────────


def test_webrtc_async_send_awaits_coroutine_channel():
    """The async send must await coroutine channels, not raise."""
    from one_link.peer_transport import WebRTCTransport

    captured: list[bytes] = []

    class _AsyncChannel:
        _closed = False

        async def send(self, payload):
            await asyncio.sleep(0)
            captured.append(payload)

    t = WebRTCTransport(channel=_AsyncChannel())
    asyncio.run(t.send_bytes_async(b"async-payload"))
    assert captured == [b"async-payload"]
    assert t.stats.sends == 1
    assert t.stats.bytes_sent == len(b"async-payload")


def test_webrtc_async_send_propagates_channel_errors():
    from one_link.peer_transport import TransportSendError, WebRTCTransport

    class _ErrChannel:
        _closed = False

        async def send(self, payload):
            raise OSError("disconnected")

    t = WebRTCTransport(channel=_ErrChannel())
    with pytest.raises(TransportSendError, match="disconnected"):
        asyncio.run(t.send_bytes_async(b"x"))
    assert t.stats.send_failures == 1


def test_quic_async_send_via_thread_pool():
    """QuicTransport.send_bytes_async offloads to executor to avoid
    blocking the event loop on the underlying QUIC send."""
    from one_link.peer_transport import QuicTransport

    captured = []

    class _SyncSession:
        def is_connected(self):
            return True

        def send_frame(self, frame_type, payload):
            # Simulate a slow native call.
            captured.append((frame_type, bytes(payload)))
            return b""

    t = QuicTransport(session=_SyncSession())
    asyncio.run(t.send_bytes_async(b"quic-async"))
    assert len(captured) == 1
    assert captured[0][1] == b"quic-async"
