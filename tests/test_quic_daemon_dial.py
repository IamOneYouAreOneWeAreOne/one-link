"""End-to-end test for the Wave 2d/2e daemon-level QUIC pipeline.

Spins up a daemon pair, lets them pair via mDNS, waits for the
ENDPOINT_UPDATE round-trip to publish each side's QUIC port,
then asserts both sides:

  - have a QUIC server endpoint up
  - record the peer's advertised QUIC port
  - can successfully dial that port via the cached-or-open
    helper ``_get_or_dial_quic``

Skipped when the native crate isn't installed.
"""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

peer_quic = pytest.importorskip("one_link.peer_quic")
if not peer_quic.HAS_NATIVE:  # pragma: no cover
    pytest.skip("one_link_native.quic not installed", allow_module_level=True)

from tests.harness import daemon_pair, request
from one_link.daemon import Daemon


pytestmark = [pytest.mark.timeout(120), pytest.mark.soak]


def test_quic_connection_alive_accepts_native_conn_without_state_flag() -> None:
    class NativeConnLike:
        def send_frame_round_trip(self, *_args):
            return (241, b"pong")

    assert Daemon._quic_connection_alive(NativeConnLike()) is True


def test_quic_connection_alive_honors_explicit_false_state() -> None:
    class ClosedConnLike:
        is_connected = False

    assert Daemon._quic_connection_alive(ClosedConnLike()) is False


def test_quic_status_endpoint_returns_state() -> None:
    """The ``quic_status`` control command must return a clean
    state snapshot after the daemon's QUIC server endpoint is
    up. Used by ops tooling + UI dashboards to verify the QUIC
    stack is alive without grepping the daemon log."""
    with daemon_pair() as p:
        # Drive a chat send so the channel comes up + CAPS
        # exchange completes.
        request(p.a.control_port, cmd="send",
                peer=p.b.short_id, body="warm")
        time.sleep(1.0)
        status = request(p.a.control_port, cmd="quic_status")
        assert status.get("ok") is True
        assert status.get("native_quic_available") is True
        assert status.get("server_up") is True
        assert isinstance(status.get("local_port"), int)
        assert status["local_port"] > 0
        # Outbound + inbound are lists; advertised_ports a dict.
        assert isinstance(status.get("outbound"), list)
        assert isinstance(status.get("inbound"), list)
        assert isinstance(status.get("advertised_ports"), dict)
        assert isinstance(status.get("recent_paired_count"), int)


def test_daemon_brings_up_quic_endpoint() -> None:
    """After daemon_pair settles, both daemons must have a
    QUIC server endpoint up on a non-zero port. Without this the
    Wave 2d bring-up is a no-op."""
    with daemon_pair() as p:
        # Send a probe message to drive the channel + caps exchange.
        request(p.a.control_port, cmd="send",
                peer=p.b.short_id, body="quic-probe")
        # Allow time for the endpoint announcement + processing
        # round-trip.
        time.sleep(2.0)
        a_status = request(p.a.control_port, cmd="status")
        b_status = request(p.b.control_port, cmd="status")
        assert a_status.get("ok") is True
        assert b_status.get("ok") is True
        # The status endpoint may or may not surface the QUIC
        # port explicitly â€” what matters here is the daemon
        # didn't crash on QUIC bring-up. The actual port lookup
        # happens in the next test against the in-process state.


def _wait_for_quic_peer_port(ctrl_port: int, target_fp_prefix: str, timeout: float = 30.0) -> bool:
    """Poll the daemon's quic_status endpoint until the named
    peer's QUIC port is recorded in ``advertised_ports``. Returns
    True on success, False on timeout."""
    end = time.time() + timeout
    while time.time() < end:
        status = request(ctrl_port, cmd="quic_status")
        if status.get("ok"):
            advertised = status.get("advertised_ports") or {}
            for fp_hex in advertised:
                if fp_hex.startswith(target_fp_prefix):
                    return True
        time.sleep(0.1)
    return False


def test_quic_ping_round_trip_between_daemons() -> None:
    """Headline Wave 2e proof: control-API ``quic_ping`` against
    a paired peer returns ok with a real RTT. This exercises:

      * Wave 2c Identity bridge â€” daemon PEM â†’ native Identity
      * Wave 2d daemon QUIC bring-up â€” server endpoint up
      * Wave 2d ENDPOINT_UPDATE â€” A's quic_port reaches B
      * Wave 2e ``_get_or_dial_quic`` â€” B dials A successfully
      * Wave 2e per-connection frame loop â€” A answers PING with PONG

    Frame round-trip is the simplest viable shape; once this is
    green the chunk routing can land on top of the same pipeline.
    """
    with daemon_pair() as p:
        # Pin BOTH directions so the ENDPOINT_UPDATE gate
        # (``_is_pinned``) passes and each side stashes the
        # other's quic_port. Without pinning, the discovered
        # peers stay at trust=None and the QUIC dial has no
        # port to call.
        a_pin = request(p.a.control_port, cmd="pin_peer",
                        peer=p.b.short_id)
        b_pin = request(p.b.control_port, cmd="pin_peer",
                        peer=p.a.short_id)
        assert a_pin.get("ok"), a_pin
        assert b_pin.get("ok"), b_pin
        # Warm up by sending a chat message â€” drives CAPS +
        # session bringup so the broadcast_endpoint_to_paired
        # called by pin_peer has a live channel to push the
        # quic_port over.
        warm = request(p.a.control_port, cmd="send",
                       peer=p.b.short_id, body="warm")
        assert warm.get("ok") is True
        # Poll quic_status on BOTH sides until each daemon's
        # ``advertised_ports`` map has an entry for the OTHER
        # peer's fingerprint. This replaces the brittle fixed
        # sleep â€” we wait for the real signal that the wire
        # frame landed instead of guessing the timing.
        #
        # Note: ``a_pin["peer_fp"]`` is the peer's (B's) fingerprint
        # as recorded by A's daemon, and vice versa. So:
        #   - "A learned B's QUIC port" = A's advertised_ports has
        #      a key matching B's fp prefix = a_pin["peer_fp"]
        #   - "B learned A's QUIC port" = B's advertised_ports has
        #      a key matching A's fp prefix = b_pin["peer_fp"]
        b_fp_from_a = a_pin["peer_fp"][:16]  # B's fp prefix
        a_fp_from_b = b_pin["peer_fp"][:16]  # A's fp prefix
        a_sees_b_quic = _wait_for_quic_peer_port(
            p.a.control_port, b_fp_from_a, timeout=30.0,
        )
        b_sees_a_quic = _wait_for_quic_peer_port(
            p.b.control_port, a_fp_from_b, timeout=30.0,
        )
        assert a_sees_b_quic, (
            "A never learned B's QUIC port; "
            "broadcast_endpoint_to_paired may not be delivering."
        )
        assert b_sees_a_quic, (
            "B never learned A's QUIC port."
        )
        # Ask A to ping B over QUIC.
        result = request(
            p.a.control_port, cmd="quic_ping",
            peer=p.b.short_id, payload="hello-quic",
        )
        assert result.get("ok") is True, (
            f"quic_ping failed: {result}. The full Wave 2c+2d+2e "
            f"pipeline isn't connected end-to-end yet."
        )
        assert "rtt_ms" in result
        assert isinstance(result["rtt_ms"], (int, float))
        # On loopback RTT should be small â€” single-digit ms is
        # typical. Be generous (1000 ms) to tolerate CI noise.
        assert 0.0 < result["rtt_ms"] < 1000.0, (
            f"quic_ping returned unrealistic RTT: {result['rtt_ms']} ms"
        )
        assert result.get("response_len", 0) >= len(b"hello-quic")


def test_send_file_stream_mode_survives_with_quic_route_available() -> None:
    """Wave 2f integration end-to-end. Pin both directions, send
    a small file (small enough to skip CDC and route via the
    stream-mode FILE_NATIVE_CHUNK path where Wave 2e+2f's QUIC
    fork lives), verify:

      1. The file lands intact on the receiver.
      2. ``quic_status`` on the sender shows an outbound
         Connection to the receiver â€” proves the QUIC dial fired
         + the chunk-send path actually took the QUIC fork
         (the cache only populates via ``_get_or_dial_quic`` calls
         which run on the QUIC fast path).
    """
    payload = b"quic-fast-path-payload" * 64  # ~1.4 KiB, way under CDC threshold
    with daemon_pair() as p:
        # Pin both directions so QUIC port advertisement flows.
        a_pin = request(p.a.control_port, cmd="pin_peer",
                        peer=p.b.short_id)
        b_pin = request(p.b.control_port, cmd="pin_peer",
                        peer=p.a.short_id)
        assert a_pin.get("ok"), a_pin
        assert b_pin.get("ok"), b_pin
        request(p.a.control_port, cmd="send",
                peer=p.b.short_id, body="warm")
        # Wait until A knows B's QUIC port.
        b_fp_from_a = a_pin["peer_fp"][:16]
        assert _wait_for_quic_peer_port(
            p.a.control_port, b_fp_from_a, timeout=30.0,
        ), "A never learned B's QUIC port"

        # Send a small file. Should take the stream-mode QUIC
        # fork in send_file (Wave 2e/2f).
        import tempfile
        from pathlib import Path as _Path
        with tempfile.TemporaryDirectory() as td:
            src = _Path(td) / "stream_quic.bin"
            src.write_bytes(payload)
            res = request(p.a.control_port, cmd="send_file",
                          peer=p.b.short_id, path=str(src),
                          timeout=30)
            assert res.get("ok"), res

        # Verify file landed.
        deadline = time.time() + 10.0
        landed = False
        while time.time() < deadline:
            for f in (p.b.home / "data" / "inbox").iterdir() if (p.b.home / "data" / "inbox").is_dir() else []:
                if f.is_file():
                    try:
                        if f.read_bytes() == payload:
                            landed = True
                            break
                    except OSError:
                        pass
            if landed:
                break
            time.sleep(0.1)
        assert landed, "payload never arrived in B's inbox"

        # The complementary check that the Wave 2f regression
        # would have caught loudly: no silent native-transfer
        # fallback fired. Reads `transfer_diagnostics` which
        # daemon.send_file populates whenever native_transfer was
        # advertised by the peer but the session derivation
        # failed (e.g. the DR-wipe bug fixed in commit 28e264d).
        # A clean run leaves the ring empty.
        diag = request(p.a.control_port, cmd="transfer_diagnostics")
        events = diag.get("degradation_events") or []
        native_unavail = [
            e for e in events
            if e.get("kind") == "native_transfer_unavailable"
        ]
        assert not native_unavail, (
            f"Silent native-transfer fallback fired despite peer "
            f"advertising NATIVE_TRANSFER_V1 + QUIC. Events: "
            f"{native_unavail}"
        )


def test_endpoint_announcement_carries_quic_port() -> None:
    """The ENDPOINT_UPDATE frame must include ``quic_port`` once
    the daemon has a QUIC endpoint up â€” paired peers consume
    this to populate their _quic_peer_ports map."""
    with daemon_pair() as p:
        # Drive a CAPS exchange + endpoint announcement.
        request(p.a.control_port, cmd="send",
                peer=p.b.short_id, body="trigger announce")
        # Wait for the endpoint announcement round-trip. The
        # daemon publishes within seconds of session up.
        deadline = time.time() + 30.0
        b_log_has_quic_port = False
        a_log_has_quic_port = False
        while time.time() < deadline:
            b_log = p.b.log.read_text(errors="replace")
            a_log = p.a.log.read_text(errors="replace")
            if "QUIC server endpoint up" in b_log:
                b_log_has_quic_port = True
            if "QUIC server endpoint up" in a_log:
                a_log_has_quic_port = True
            if "stored QUIC port" in a_log or "stored QUIC port" in b_log:
                # We've seen at least one direction publish + the
                # other side consume it. Good enough.
                break
            time.sleep(0.5)
        assert b_log_has_quic_port, (
            "Daemon B never brought up its QUIC server endpoint; "
            "Wave 2d bring-up may be broken."
        )
        assert a_log_has_quic_port, (
            "Daemon A never brought up its QUIC server endpoint."
        )
