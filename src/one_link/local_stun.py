"""Private, process-local STUN address discovery for browser WebRTC.

Firefox intentionally replaces host ICE addresses with random ``.local``
names.  On some valid host-only paths (including isolated Firefox profiles on
Windows) those names cannot be resolved by the remote ICE agent, so both peers
finish gathering candidates but never form a candidate pair.  Public STUN
works around that failure, but Quiet and Off-grid must not contact a third
party merely to connect two devices on the same LAN.

This module implements the small RFC 8489 subset needed for an unauthenticated
Binding transaction.  The responder:

* binds beside the local UI listener and is advertised only to a request from
  loopback or a directly connected/local address;
* returns only XOR-MAPPED-ADDRESS plus FINGERPRINT (no TURN allocation,
  credentials, relay, persistence, or discovery service);
* rejects malformed, oversized, non-Binding, and bad-fingerprint datagrams;
* rate-limits globally and per source, bounds source bookkeeping, and never
  emits a response larger than 52 bytes.

The browser can therefore obtain a standards-compliant numeric
server-reflexive candidate from the same machine it already reached over
HTTPS.  Firefox may deduplicate that no-NAT result; the request-scoped config
also supplies the accepted peer address (and, for loopback, a bounded set of
assigned interface addresses) for the signed numeric host-candidate fallback.
No outside network request is introduced, and signed One Link SDP/identity
verification remains the authority above ICE.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict, deque
from collections.abc import Callable
import ipaddress
import socket
import struct
import time
from typing import Any, cast
import zlib


STUN_MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS = 0x0101
STUN_XOR_MAPPED_ADDRESS = 0x0020
STUN_FINGERPRINT = 0x8028
STUN_FINGERPRINT_XOR = 0x5354554E
STUN_HEADER_BYTES = 20
STUN_MAX_REQUEST_BYTES = 1024
STUN_RESPONSE_IPV4_BYTES = 40
STUN_RESPONSE_IPV6_BYTES = 52

_GLOBAL_RATE_WINDOW_SECONDS = 1.0
_GLOBAL_RATE_LIMIT = 1024
_SOURCE_RATE_WINDOW_SECONDS = 60.0
_SOURCE_RATE_LIMIT = 120
_MAX_TRACKED_SOURCES = 2048


def _canonical_ip(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse a socket address without accepting hostnames or zone ambiguity."""

    if not isinstance(value, str) or not value:
        return None
    raw = value.split("%", 1)[0]
    try:
        parsed = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    return parsed


def _binding_transaction_id(data: bytes) -> bytes | None:
    """Return a validated Binding-request transaction id, else ``None``."""

    if not isinstance(data, bytes) or not (STUN_HEADER_BYTES <= len(data) <= STUN_MAX_REQUEST_BYTES):
        return None
    try:
        message_type, body_length, cookie = struct.unpack("!HHI", data[:8])
    except struct.error:
        return None
    # RFC 8489 section 5.1: the most significant two type bits are zero,
    # length is padded to 32 bits, and the declared body is the entire packet.
    if message_type & 0xC000:
        return None
    if message_type != STUN_BINDING_REQUEST or cookie != STUN_MAGIC_COOKIE:
        return None
    if body_length % 4 or body_length != len(data) - STUN_HEADER_BYTES:
        return None

    cursor = STUN_HEADER_BYTES
    fingerprint_seen = False
    while cursor < len(data):
        if cursor + 4 > len(data):
            return None
        attr_type, attr_length = struct.unpack("!HH", data[cursor : cursor + 4])
        value_start = cursor + 4
        value_end = value_start + attr_length
        padded_end = value_end + ((4 - (attr_length % 4)) % 4)
        if value_end > len(data) or padded_end > len(data):
            return None
        if fingerprint_seen:
            return None
        if attr_type == STUN_FINGERPRINT:
            if attr_length != 4 or padded_end != len(data):
                return None
            supplied = struct.unpack("!I", data[value_start:value_end])[0]
            expected = (zlib.crc32(data[:cursor]) & 0xFFFFFFFF) ^ STUN_FINGERPRINT_XOR
            if supplied != expected:
                return None
            fingerprint_seen = True
        cursor = padded_end
    if cursor != len(data):
        return None
    return data[8:20]


def build_binding_success(
    transaction_id: bytes,
    mapped_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    mapped_port: int,
) -> bytes:
    """Build one RFC 8489 Binding Success response.

    The function is intentionally pure so byte-level known-answer tests can
    prove header lengths, XOR mapping, transaction binding, and fingerprint.
    """

    if not isinstance(transaction_id, bytes) or len(transaction_id) != 12:
        raise ValueError("STUN transaction id must be exactly 12 bytes")
    if not isinstance(mapped_port, int) or not 1 <= mapped_port <= 65535:
        raise ValueError("mapped UDP port is outside 1..65535")

    xor_port = mapped_port ^ (STUN_MAGIC_COOKIE >> 16)
    if isinstance(mapped_ip, ipaddress.IPv4Address):
        family = 0x01
        mask = STUN_MAGIC_COOKIE.to_bytes(4, "big")
    elif isinstance(mapped_ip, ipaddress.IPv6Address):
        family = 0x02
        mask = STUN_MAGIC_COOKIE.to_bytes(4, "big") + transaction_id
    else:  # pragma: no cover - the public annotation constrains callers
        raise TypeError("mapped address must be IPv4 or IPv6")
    encoded_ip = bytes(left ^ right for left, right in zip(mapped_ip.packed, mask, strict=True))
    mapped_value = struct.pack("!BBH", 0, family, xor_port) + encoded_ip
    mapped_attr = struct.pack("!HH", STUN_XOR_MAPPED_ADDRESS, len(mapped_value)) + mapped_value

    # RFC 8489 section 14.5: the header length includes FINGERPRINT, while
    # the CRC input stops immediately before the FINGERPRINT attribute.
    body_length = len(mapped_attr) + 8
    header = struct.pack(
        "!HHI12s",
        STUN_BINDING_SUCCESS,
        body_length,
        STUN_MAGIC_COOKIE,
        transaction_id,
    )
    fingerprint = (zlib.crc32(header + mapped_attr) & 0xFFFFFFFF) ^ STUN_FINGERPRINT_XOR
    response = header + mapped_attr + struct.pack("!HHI", STUN_FINGERPRINT, 4, fingerprint)
    expected_size = (
        STUN_RESPONSE_IPV4_BYTES
        if isinstance(mapped_ip, ipaddress.IPv4Address)
        else STUN_RESPONSE_IPV6_BYTES
    )
    if len(response) != expected_size:  # invariant guard, not input handling
        raise AssertionError("unexpected STUN response size")
    return response


class _LocalStunProtocol(asyncio.DatagramProtocol):
    """Bounded UDP responder; all mutable state stays on one event loop."""

    def __init__(
        self,
        *,
        source_allowed: Callable[[ipaddress.IPv4Address | ipaddress.IPv6Address], bool],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._source_allowed = source_allowed
        self._clock = clock
        self._transport: asyncio.DatagramTransport | None = None
        self._global_hits: deque[float] = deque()
        self._source_hits: OrderedDict[str, deque[float]] = OrderedDict()
        self.accepted = 0
        self.dropped = 0

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(asyncio.DatagramTransport, transport)

    @staticmethod
    def _trim(hits: deque[float], *, now: float, window: float) -> None:
        cutoff = now - window
        while hits and hits[0] <= cutoff:
            hits.popleft()

    def _within_rate_limit(self, source_key: str) -> bool:
        now = self._clock()
        self._trim(self._global_hits, now=now, window=_GLOBAL_RATE_WINDOW_SECONDS)
        if len(self._global_hits) >= _GLOBAL_RATE_LIMIT:
            return False

        hits = self._source_hits.get(source_key)
        if hits is None:
            if len(self._source_hits) >= _MAX_TRACKED_SOURCES:
                self._source_hits.popitem(last=False)
            hits = deque()
            self._source_hits[source_key] = hits
        else:
            self._source_hits.move_to_end(source_key)
        self._trim(hits, now=now, window=_SOURCE_RATE_WINDOW_SECONDS)
        if len(hits) >= _SOURCE_RATE_LIMIT:
            return False
        self._global_hits.append(now)
        hits.append(now)
        return True

    def datagram_received(self, data: bytes, addr: Any) -> None:
        transport = self._transport
        if transport is None or not isinstance(addr, tuple) or len(addr) < 2:
            self.dropped += 1
            return
        source_ip = _canonical_ip(addr[0])
        source_port = addr[1]
        if (
            source_ip is None
            or not isinstance(source_port, int)
            or not 1 <= source_port <= 65535
            or not self._source_allowed(source_ip)
        ):
            self.dropped += 1
            return
        transaction_id = _binding_transaction_id(data)
        if transaction_id is None or not self._within_rate_limit(str(source_ip)):
            self.dropped += 1
            return
        response = build_binding_success(transaction_id, source_ip, source_port)
        # sendto is non-blocking. No user-controlled bytes are reflected and
        # the response has a fixed 40/52-byte ceiling.
        transport.sendto(response, addr)
        self.accepted += 1

    def error_received(self, exc: Exception) -> None:
        # UDP ICMP errors are expected when a browser closes an ICE socket.
        # Keeping only a counter avoids logging address-bearing diagnostics.
        del exc
        self.dropped += 1


def _local_interface_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Return directly connected interface networks without shelling out."""

    networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = {
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
    }
    try:
        import psutil  # type: ignore[import-untyped]

        for entries in psutil.net_if_addrs().values():
            for entry in entries:
                if entry.family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                address = str(entry.address or "").split("%", 1)[0]
                netmask = str(entry.netmask or "").split("%", 1)[0]
                if not address or not netmask:
                    continue
                try:
                    networks.add(ipaddress.ip_network(f"{address}/{netmask}", strict=False))
                except ValueError:
                    continue
    except (ImportError, OSError):
        # Packaged builds include psutil. The conservative private/link-local
        # fallback in _source_allowed keeps the service useful if an embedder
        # intentionally omits it.
        pass
    return tuple(sorted(networks, key=lambda network: (network.version, str(network))))


def _local_interface_addresses() -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    """Enumerate numeric interface addresses for same-process browser pairs."""

    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = {
        ipaddress.ip_address("127.0.0.1"),
        ipaddress.ip_address("::1"),
    }
    try:
        import psutil  # type: ignore[import-untyped]

        for entries in psutil.net_if_addrs().values():
            for entry in entries:
                if entry.family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                parsed = _canonical_ip(str(entry.address or ""))
                if (
                    parsed is not None
                    and not parsed.is_unspecified
                    and not parsed.is_multicast
                    and not parsed.is_reserved
                    and not parsed.is_link_local
                ):
                    addresses.add(parsed)
    except (ImportError, OSError):
        pass
    return tuple(sorted(addresses, key=lambda address: (address.version, int(address))))


class LocalStunService:
    """Lifecycle and request-scoped advertisement for the local responder."""

    def __init__(self) -> None:
        self._transports: dict[int, asyncio.DatagramTransport] = {}
        self._protocols: dict[int, _LocalStunProtocol] = {}
        self._ports: dict[int, int] = {}
        self._networks = _local_interface_networks()
        self._interface_addresses = _local_interface_addresses()
        self._bind_host: str | None = None

    @property
    def running(self) -> bool:
        return bool(self._transports)

    @property
    def ports(self) -> dict[int, int]:
        return dict(self._ports)

    def _source_allowed(
        self,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> bool:
        if address.is_unspecified or address.is_multicast or address.is_reserved:
            return False
        if address.is_loopback:
            return True
        # RFC1918 space may be routed across VPNs or enterprise networks, and
        # IPv6 LANs may use globally scoped on-link prefixes.  In both cases,
        # advertise/respond only when the source belongs to a prefix actually
        # assigned to this machine.  This keeps "LAN-scoped" literal instead
        # of treating every private address on the Internet as local.
        return any(address.version == network.version and address in network for network in self._networks)

    async def start(self, bind_host: str) -> None:
        if self.running:
            raise RuntimeError("local STUN service is already running")
        normalized = str(bind_host or "").strip().lower()
        if normalized == "localhost":
            normalized = "127.0.0.1"
        parsed = _canonical_ip(normalized)
        if parsed is None:
            raise ValueError("local STUN bind host must be a numeric IP address")
        family = socket.AF_INET if isinstance(parsed, ipaddress.IPv4Address) else socket.AF_INET6
        host = str(parsed)
        loop = asyncio.get_running_loop()
        protocol = _LocalStunProtocol(source_allowed=self._source_allowed)
        transport_raw, _created = await loop.create_datagram_endpoint(
            lambda: protocol,
            local_addr=(host, 0),
            family=family,
        )
        transport = cast(asyncio.DatagramTransport, transport_raw)
        sockname = transport.get_extra_info("sockname")
        if not isinstance(sockname, tuple) or len(sockname) < 2:
            transport.close()
            raise RuntimeError("local STUN socket has no bound address")
        port = sockname[1]
        if not isinstance(port, int) or not 1 <= port <= 65535:
            transport.close()
            raise RuntimeError("local STUN socket has no valid port")
        self._bind_host = host
        self._transports[parsed.version] = transport
        self._protocols[parsed.version] = protocol
        self._ports[parsed.version] = port

    def _request_addresses(
        self,
        request: Any,
    ) -> tuple[
        ipaddress.IPv4Address | ipaddress.IPv6Address,
        ipaddress.IPv4Address | ipaddress.IPv6Address,
    ] | None:
        transport = getattr(request, "transport", None)
        if transport is None:
            return None
        peername = transport.get_extra_info("peername")
        sockname = transport.get_extra_info("sockname")
        if (
            not isinstance(peername, tuple)
            or len(peername) < 1
            or not isinstance(sockname, tuple)
            or len(sockname) < 1
        ):
            return None
        peer_ip = _canonical_ip(peername[0])
        local_ip = _canonical_ip(sockname[0])
        if peer_ip is None or local_ip is None or not self._source_allowed(peer_ip):
            return None
        if local_ip.is_unspecified or local_ip.is_multicast or local_ip.is_link_local:
            return None
        if peer_ip.version != local_ip.version:
            return None
        return peer_ip, local_ip

    def candidate_address_for_request(self, request: Any) -> str | None:
        """Return the OS-observed client address for signed SDP augmentation.

        Firefox's mDNS candidate may remain unresolved even after a local STUN
        Binding transaction because a no-NAT mapped address is redundant with
        the hidden host candidate. The HTTPS socket already provides the exact
        interface the browser used to reach this daemon. Supplying that numeric
        address lets the browser retain its original mDNS candidates while
        signing an additional route to the same ICE socket ports.
        """

        addresses = self.candidate_addresses_for_request(request)
        return addresses[0] if addresses else None

    def candidate_addresses_for_request(self, request: Any) -> list[str]:
        """Return a bounded set of truthful numeric addresses for this client."""

        request_addresses = self._request_addresses(request)
        if request_addresses is None:
            return []
        peer_ip, _local_ip = request_addresses
        # Scoped IPv6 link-local addresses cannot be represented safely in an
        # SDP connection-address without its interface zone identifier.
        if isinstance(peer_ip, ipaddress.IPv6Address) and peer_ip.is_link_local:
            return []
        candidates = [peer_ip]
        # Two browser profiles on this same machine both reach the daemon over
        # loopback, but Firefox can decline loopback ICE checks. Add this
        # machine's real interface addresses as well; every candidate still
        # uses a browser-generated socket port and remains in the signed SDP.
        if peer_ip.is_loopback:
            candidates.extend(
                address
                for address in self._interface_addresses
                if address.version == peer_ip.version and not address.is_loopback
            )
        unique: list[str] = []
        for candidate in candidates:
            rendered = str(candidate)
            if rendered not in unique:
                unique.append(rendered)
            if len(unique) >= 8:
                break
        return unique

    def url_for_request(self, request: Any) -> str | None:
        """Return a local STUN URI only to a local/directly connected client."""

        addresses = self._request_addresses(request)
        if addresses is None:
            return None
        _peer_ip, local_ip = addresses
        port = self._ports.get(local_ip.version)
        if port is None:
            return None
        host = f"[{local_ip}]" if isinstance(local_ip, ipaddress.IPv6Address) else str(local_ip)
        return f"stun:{host}:{port}"

    async def stop(self) -> None:
        transports = tuple(self._transports.values())
        self._transports.clear()
        self._protocols.clear()
        self._ports.clear()
        self._bind_host = None
        for transport in transports:
            transport.close()
        if transports:
            # Let selector/proactor loops process connection_lost before the
            # owning aiohttp runner and event loop are torn down.
            await asyncio.sleep(0)


__all__ = [
    "LocalStunService",
    "STUN_BINDING_REQUEST",
    "STUN_BINDING_SUCCESS",
    "STUN_FINGERPRINT",
    "STUN_FINGERPRINT_XOR",
    "STUN_HEADER_BYTES",
    "STUN_MAGIC_COOKIE",
    "STUN_XOR_MAPPED_ADDRESS",
    "build_binding_success",
]
