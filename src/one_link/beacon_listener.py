"""Coherence Beacon UDP listener — actual multicast socket integration.

Bundle 50 shipped the beacon wire format. Bundle 54 wires it onto a
real asyncio DatagramProtocol so daemons can emit + receive across
LAN segments where mDNS is sandboxed.

Design:

  - **Emitter**: a periodic 1-Hz task that mints a fresh
    ``encode_beacon(...)`` and sends to (BEACON_GROUP, BEACON_PORT)
    via a UDP socket joined to the multicast group with TTL=1
    (link-local). Cancellable; stops when the daemon exits.

  - **Receiver**: a DatagramProtocol that listens on the same
    multicast group, parses + verifies incoming beacons, and
    feeds discovered peers into a callback (typically the
    daemon's discovery registry).

  - **Asymmetry**: emitter + receiver can run independently. A
    daemon that wants to BE discoverable but not actively scan
    runs emitter only; a daemon scanning for peers but not
    advertising runs receiver only. Both is the normal case.

Threat caveats inherited from Bundle 50: spoofing (anyone on L2
can mint a beacon — it's a hint, not auth), tracking (emitting
reveals presence), amplification (rate-limited by emit cadence).

Platform notes
--------------

  - On Windows, IPv6 multicast can be flaky on some adapter
    configurations; the listener catches OSError on socket setup
    and reports unavailability rather than crashing the daemon.
  - On Linux without IPv6, the listener falls back to IPv4 mDNS-
    style multicast at 224.0.0.123:5354 (a fallback group; the
    canonical path stays IPv6 link-local).
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import struct
import sys
from dataclasses import dataclass, field
from typing import Callable, Optional

from one_link import beacon


log = logging.getLogger(__name__)


# IPv4 fallback group + port. Mirror of the IPv6 path for systems
# that disable IPv6.
BEACON_V4_GROUP = "224.0.0.123"


@dataclass
class BeaconConfig:
    short_id: str
    endpoint: str
    priv_seed: Optional[bytes] = None
    tick_seconds: float = 1.0 / beacon.BEACON_TICK_HZ
    on_peer_discovered: Optional[Callable[[beacon.Beacon], None]] = None
    # If True, the listener verifies incoming beacons + drops any
    # that fail (signature, freshness). If False, all parsable
    # beacons are surfaced. Default True for the normal trust posture.
    verify_incoming: bool = True
    # When verify_incoming is True, only accept beacons younger than
    # this many ms. 30 seconds matches Bundle 50 default.
    max_age_ms: int = 30_000


class _BeaconProtocol(asyncio.DatagramProtocol):
    """Receiver-side: parse + (optionally) verify beacons; pass
    to the configured callback. Errors are caught + logged so a
    single malformed beacon doesn't kill the listener."""

    def __init__(self, config: BeaconConfig, *,
                 self_short_id: str | None = None):
        self.config = config
        self.self_short_id = self_short_id
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        if len(data) > beacon.MAX_BEACON_LEN:
            log.debug(
                "beacon: dropped oversize %d bytes from %s",
                len(data), addr,
            )
            return
        try:
            if self.config.verify_incoming:
                parsed = beacon.verify_beacon(
                    data, max_age_ms=self.config.max_age_ms,
                )
            else:
                parsed = beacon.parse_beacon(data)
        except ValueError as e:
            log.debug("beacon: rejected from %s: %s", addr, e)
            return
        # Ignore self-emissions (we'll receive our own multicast).
        if (
            self.self_short_id is not None
            and parsed.short_id == self.self_short_id
        ):
            return
        cb = self.config.on_peer_discovered
        if cb is not None:
            try:
                cb(parsed)
            except Exception as e:
                log.warning("beacon: peer-discovered callback error: %s", e)

    def error_received(self, exc):
        log.debug("beacon: transport error: %s", exc)


async def start_listener(
    config: BeaconConfig,
    *,
    use_ipv6: bool = True,
    iface_index: int = 0,
) -> tuple[asyncio.DatagramTransport, _BeaconProtocol]:
    """Open a multicast UDP socket bound to BEACON_PORT, join the
    group, and start receiving beacons. Returns (transport, protocol)
    so the caller can ``transport.close()`` to stop."""
    family = socket.AF_INET6 if use_ipv6 else socket.AF_INET
    group = beacon.BEACON_GROUP if use_ipv6 else BEACON_V4_GROUP

    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if sys.platform != "win32":
            # SO_REUSEPORT is POSIX-only. The sys.platform narrow
            # tells mypy to resolve socket.SO_REUSEPORT against the
            # POSIX stub set; runtime can still throw OSError on
            # kernels that don't support it (e.g. older Linux), so
            # we keep the suppress.
            with contextlib.suppress(AttributeError, OSError):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        if use_ipv6:
            sock.bind(("::", beacon.BEACON_PORT))
            # IPV6_JOIN_GROUP: pack 16-byte addr + u32 ifindex.
            mreq = (
                socket.inet_pton(socket.AF_INET6, group)
                + struct.pack("@I", iface_index)
            )
            sock.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq,
            )
            sock.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1,
            )
        else:
            sock.bind(("0.0.0.0", beacon.BEACON_PORT))  # nosec B104
            mreq = struct.pack(
                "4s4s",
                socket.inet_aton(group),
                socket.inet_aton("0.0.0.0"),  # nosec B104
            )
            sock.setsockopt(
                socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq,
            )
            sock.setsockopt(
                socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1,
            )
        sock.setblocking(False)
    except OSError:
        sock.close()
        raise

    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _BeaconProtocol(config, self_short_id=config.short_id),
        sock=sock,
    )
    return transport, protocol  # type: ignore[return-value]


async def emit_loop(
    config: BeaconConfig,
    *,
    use_ipv6: bool = True,
    stop_event: Optional[asyncio.Event] = None,
) -> None:
    """Run the periodic beacon emit loop. Cancel the task or set
    ``stop_event`` to stop. Each tick mints a fresh
    ``encode_beacon(...)`` with the current timestamp."""
    family = socket.AF_INET6 if use_ipv6 else socket.AF_INET
    group = beacon.BEACON_GROUP if use_ipv6 else BEACON_V4_GROUP
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        if use_ipv6:
            sock.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS,
                struct.pack("@i", 1),
            )
        else:
            sock.setsockopt(
                socket.IPPROTO_IP, socket.IP_MULTICAST_TTL,
                struct.pack("@b", 1),
            )
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        try:
            while True:
                if stop_event is not None and stop_event.is_set():
                    return
                try:
                    blob = beacon.encode_beacon(
                        short_id=config.short_id,
                        endpoint=config.endpoint,
                        priv_seed=config.priv_seed,
                    )
                    addr = (group, beacon.BEACON_PORT, 0, 0) if use_ipv6 \
                        else (group, beacon.BEACON_PORT)
                    await loop.sock_sendto(sock, blob, addr)
                except (OSError, ValueError) as e:
                    log.debug("beacon: emit error: %s", e)
                try:
                    await asyncio.wait_for(
                        stop_event.wait() if stop_event else asyncio.sleep(
                            config.tick_seconds,
                        ),
                        timeout=config.tick_seconds,
                    )
                except asyncio.TimeoutError:
                    pass
        except asyncio.CancelledError:
            return
    finally:
        sock.close()


@dataclass
class BeaconService:
    """High-level convenience: bundle the listener + emitter under
    one start/stop."""
    config: BeaconConfig
    use_ipv6: bool = True
    _transport: Optional[asyncio.DatagramTransport] = None
    _emit_task: Optional[asyncio.Task] = None
    _stop: asyncio.Event = field(default_factory=asyncio.Event)

    async def start(self) -> None:
        try:
            self._transport, _ = await start_listener(
                self.config, use_ipv6=self.use_ipv6,
            )
        except OSError as e:
            log.warning(
                "beacon: listener failed (%s); emitter will still run "
                "but discovery is one-way",
                e,
            )
        self._emit_task = asyncio.create_task(
            emit_loop(
                self.config, use_ipv6=self.use_ipv6,
                stop_event=self._stop,
            ),
            name="beacon-emit-loop",
        )

    async def stop(self) -> None:
        self._stop.set()
        if self._emit_task is not None:
            self._emit_task.cancel()
            try:
                await self._emit_task
            except (asyncio.CancelledError, Exception):
                pass
        if self._transport is not None:
            self._transport.close()
