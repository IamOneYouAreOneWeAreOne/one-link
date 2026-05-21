"""D05 wire-up — Tests for real COVER_PACKET dispatch + receive path.

Exercises:
  - COVER_TRAFFIC_V1 capability is advertised + in TRANSPORT_LAYER_CAPS
  - _pick_cover_traffic_peers filters by (pinned + cap + active session)
  - _emit_cover_packet_callback picks via round-robin
  - _handle_cover_packet drops unpinned senders + counts pinned ones
  - cover_traffic_stats includes packets_sent + packets_received
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from one_link import daemon as daemon_module
from one_link.capabilities import (
    COVER_TRAFFIC_V1,
    LOCAL_CAPABILITIES,
    TRANSPORT_LAYER_CAPS,
)


# ---------- capability ----------


def test_cover_traffic_cap_in_local_capabilities() -> None:
    assert COVER_TRAFFIC_V1 in LOCAL_CAPABILITIES


def test_cover_traffic_cap_in_transport_layer() -> None:
    """COVER_TRAFFIC_V1 doesn't grant any new user-facing permission;
    it's a protocol-level privacy primitive. Must be in
    TRANSPORT_LAYER_CAPS so deny-by-default tests don't expect it in
    DEFAULT_ALLOW or PROMPT_REQUIRED."""
    assert COVER_TRAFFIC_V1 in TRANSPORT_LAYER_CAPS


def test_cover_traffic_cap_string_value() -> None:
    """Wire-stability check — don't accidentally rename."""
    assert COVER_TRAFFIC_V1 == "cover_traffic_v1"


# ---------- _pick_cover_traffic_peers ----------


def _bare_daemon():
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d.me = MagicMock()
    d.me.short_id = "selfid"
    d._is_pinned = MagicMock(return_value=True)
    d._outbound_sessions = {}
    d._cover_packets_sent = 0
    d._cover_packets_received = 0
    d._cover_dispatch_rr_idx = 0
    return d


def test_pick_returns_empty_when_no_sessions() -> None:
    d = _bare_daemon()
    d._outbound_sessions = {}
    assert d._pick_cover_traffic_peers() == []


def test_pick_filters_unpinned_peers() -> None:
    d = _bare_daemon()
    d._is_pinned = lambda fp: fp == "peerA"
    sess_a = MagicMock()
    sess_b = MagicMock()
    d._outbound_sessions = {"peerA": sess_a, "peerB": sess_b}
    d.state.get_peer_capabilities = lambda fp: [COVER_TRAFFIC_V1]
    peers = d._pick_cover_traffic_peers()
    assert len(peers) == 1
    assert peers[0][0] == "peerA"


def test_pick_filters_peers_without_cap() -> None:
    d = _bare_daemon()
    sess_a = MagicMock()
    sess_b = MagicMock()
    d._outbound_sessions = {"peerA": sess_a, "peerB": sess_b}
    caps_map = {
        "peerA": [COVER_TRAFFIC_V1],
        "peerB": [],  # no cap
    }
    d.state.get_peer_capabilities = lambda fp: caps_map.get(fp, [])
    peers = d._pick_cover_traffic_peers()
    assert len(peers) == 1
    assert peers[0][0] == "peerA"


def test_pick_filters_peers_with_no_channel() -> None:
    d = _bare_daemon()
    sess_a = MagicMock()
    sess_b = MagicMock()
    sess_b.channel = None
    d._outbound_sessions = {"peerA": sess_a, "peerB": sess_b}
    d.state.get_peer_capabilities = lambda fp: [COVER_TRAFFIC_V1]
    peers = d._pick_cover_traffic_peers()
    assert len(peers) == 1
    assert peers[0][0] == "peerA"


def test_pick_survives_state_exception() -> None:
    d = _bare_daemon()
    sess = MagicMock()
    d._outbound_sessions = {"peerA": sess}
    d.state.get_peer_capabilities = MagicMock(side_effect=RuntimeError("simulated"))
    # Exception per-peer is caught — peer is just skipped.
    peers = d._pick_cover_traffic_peers()
    assert peers == []


# ---------- _emit_cover_packet_callback ----------


def test_emit_no_op_when_no_peers() -> None:
    d = _bare_daemon()
    d._pick_cover_traffic_peers = MagicMock(return_value=[])
    # Must not raise.
    d._emit_cover_packet_callback()
    assert d._cover_packets_sent == 0


def test_emit_round_robin_idx_advances() -> None:
    d = _bare_daemon()
    sess1 = MagicMock()
    sess1.channel = MagicMock()
    sess2 = MagicMock()
    sess2.channel = MagicMock()
    d._pick_cover_traffic_peers = MagicMock(
        return_value=[("peerA", sess1), ("peerB", sess2)],
    )
    # Patch asyncio bits so we don't actually run a coroutine.
    import asyncio
    d._main_loop = asyncio.new_event_loop()
    try:
        # Replace asyncio.run_coroutine_threadsafe with a mock that
        # captures + completes synchronously.
        from unittest.mock import patch
        fut_mock = MagicMock()
        fut_mock.result.return_value = None
        with patch("asyncio.run_coroutine_threadsafe", return_value=fut_mock):
            d._emit_cover_packet_callback()
            # idx 0 was used; next call should use idx 1.
            assert d._cover_dispatch_rr_idx == 1
            d._emit_cover_packet_callback()
            # Wrapped back to idx 0.
            assert d._cover_dispatch_rr_idx == 0
        assert d._cover_packets_sent == 2
    finally:
        d._main_loop.close()


def test_emit_survives_send_exception() -> None:
    d = _bare_daemon()
    sess = MagicMock()
    sess.channel = MagicMock()
    d._pick_cover_traffic_peers = MagicMock(return_value=[("peerA", sess)])
    import asyncio
    d._main_loop = asyncio.new_event_loop()
    try:
        from unittest.mock import patch
        fut_mock = MagicMock()
        fut_mock.result.side_effect = RuntimeError("simulated")
        with patch("asyncio.run_coroutine_threadsafe", return_value=fut_mock):
            # Must not raise.
            d._emit_cover_packet_callback()
            # Counter stays at 0 since send failed.
            assert d._cover_packets_sent == 0
    finally:
        d._main_loop.close()


# ---------- _handle_cover_packet ----------


def test_handle_cover_packet_drops_unpinned_sender() -> None:
    d = _bare_daemon()
    d._is_pinned = lambda fp: False
    d._handle_cover_packet(MagicMock(), {"payload": "AAA="}, "peerX")
    assert d._cover_packets_received == 0


def test_handle_cover_packet_increments_counter() -> None:
    d = _bare_daemon()
    d._is_pinned = lambda fp: True
    d._handle_cover_packet(MagicMock(), {"payload": "AAA="}, "peerA")
    assert d._cover_packets_received == 1


def test_handle_cover_packet_drops_silently_no_response() -> None:
    """The handler must not call channel.send — cover packets have no
    reply (the whole point is they're indistinguishable from one-way
    real traffic)."""
    d = _bare_daemon()
    d._is_pinned = lambda fp: True
    channel = MagicMock()
    channel.send = AsyncMock()
    d._handle_cover_packet(channel, {"payload": "AAA="}, "peerA")
    channel.send.assert_not_called()


# ---------- cover_traffic_stats includes wire counters ----------


def test_stats_includes_packets_sent_received_when_emitter_missing() -> None:
    d = _bare_daemon()
    d._cover_traffic = None
    d._user_mode_value = "normal"
    d._cover_traffic_env_gate = False
    d._cover_packets_sent = 7
    d._cover_packets_received = 3
    from one_link import cover_traffic as ct
    import unittest.mock as um
    with um.patch.object(ct, "HAS_NATIVE", False):
        stats = d.cover_traffic_stats()
    assert stats["packets_sent"] == 7
    assert stats["packets_received"] == 3


def test_stats_includes_packets_when_emitter_present() -> None:
    d = _bare_daemon()
    d._user_mode_value = "paranoid"
    d._cover_traffic_env_gate = True
    d._cover_packets_sent = 12
    d._cover_packets_received = 5
    emitter = MagicMock()
    emitter.stats.return_value = {
        "running": True, "emitted": 12, "errors": 0,
        "user_mode": "paranoid", "rate_hz": 0.5,
    }
    d._cover_traffic = emitter
    stats = d.cover_traffic_stats()
    assert stats["packets_sent"] == 12
    assert stats["packets_received"] == 5
    assert stats["running"] is True
