"""Byte-level, abuse-boundary, lifecycle, and request-scope proofs for local STUN."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import struct
from types import SimpleNamespace
from typing import Any
import zlib

import pytest

from one_link.local_stun import (
    _LocalStunProtocol,
    _binding_transaction_id,
    LocalStunService,
    STUN_BINDING_REQUEST,
    STUN_BINDING_SUCCESS,
    STUN_FINGERPRINT,
    STUN_FINGERPRINT_XOR,
    STUN_MAGIC_COOKIE,
    STUN_XOR_MAPPED_ADDRESS,
    build_binding_success,
)


def _request(transaction_id: bytes, *, fingerprint: bool = False) -> bytes:
    assert len(transaction_id) == 12
    if not fingerprint:
        return struct.pack(
            "!HHI12s",
            STUN_BINDING_REQUEST,
            0,
            STUN_MAGIC_COOKIE,
            transaction_id,
        )
    header = struct.pack(
        "!HHI12s",
        STUN_BINDING_REQUEST,
        8,
        STUN_MAGIC_COOKIE,
        transaction_id,
    )
    checksum = (zlib.crc32(header) & 0xFFFFFFFF) ^ STUN_FINGERPRINT_XOR
    return header + struct.pack("!HHI", STUN_FINGERPRINT, 4, checksum)


def _decode_success(packet: bytes) -> tuple[bytes, str, int]:
    message_type, body_length, cookie, transaction_id = struct.unpack(
        "!HHI12s",
        packet[:20],
    )
    assert message_type == STUN_BINDING_SUCCESS
    assert cookie == STUN_MAGIC_COOKIE
    assert body_length == len(packet) - 20
    attr_type, attr_length = struct.unpack("!HH", packet[20:24])
    assert attr_type == STUN_XOR_MAPPED_ADDRESS
    zero, family, xor_port = struct.unpack("!BBH", packet[24:28])
    assert zero == 0
    xor_address = packet[28 : 24 + attr_length]
    mask = STUN_MAGIC_COOKIE.to_bytes(4, "big")
    if family == 0x02:
        mask += transaction_id
    address = bytes(
        left ^ right for left, right in zip(xor_address, mask, strict=True)
    )
    parsed = ipaddress.ip_address(address)
    fingerprint_type, fingerprint_len, supplied = struct.unpack("!HHI", packet[-8:])
    assert fingerprint_type == STUN_FINGERPRINT
    assert fingerprint_len == 4
    expected = (zlib.crc32(packet[:-8]) & 0xFFFFFFFF) ^ STUN_FINGERPRINT_XOR
    assert supplied == expected
    return transaction_id, str(parsed), xor_port ^ (STUN_MAGIC_COOKIE >> 16)


@pytest.mark.parametrize("fingerprint", [False, True])
def test_binding_request_parser_accepts_canonical_browser_shapes(fingerprint: bool) -> None:
    transaction_id = bytes.fromhex("b7e7a701bc34d686fa87dfae")
    assert _binding_transaction_id(
        _request(transaction_id, fingerprint=fingerprint)
    ) == transaction_id


@pytest.mark.parametrize(
    "mutate",
    [
        lambda packet: packet[:19],
        lambda packet: b"\x40" + packet[1:],
        lambda packet: packet[:4] + b"\x00\x00\x00\x00" + packet[8:],
        lambda packet: packet[:2] + b"\x00\x04" + packet[4:],
        lambda packet: packet + b"\x00\x00\x00\x00",
        lambda packet: packet[:-1] + bytes([packet[-1] ^ 1]),
    ],
)
def test_binding_request_parser_rejects_malformed_or_unbound_bytes(mutate: Any) -> None:
    packet = _request(bytes(range(12)), fingerprint=True)
    assert _binding_transaction_id(mutate(packet)) is None


@pytest.mark.parametrize(
    ("address", "port", "expected_size"),
    [
        ("192.168.50.7", 49152, 40),
        ("2001:db8:1234::7", 65535, 52),
    ],
)
def test_binding_success_round_trip_xor_mapping_and_fingerprint(
    address: str,
    port: int,
    expected_size: int,
) -> None:
    transaction_id = bytes(range(12))
    response = build_binding_success(
        transaction_id,
        ipaddress.ip_address(address),
        port,
    )
    assert len(response) == expected_size
    assert _decode_success(response) == (transaction_id, address, port)


@pytest.mark.parametrize(
    ("transaction_id", "address", "port"),
    [
        (b"short", "127.0.0.1", 3478),
        (bytes(12), "127.0.0.1", 0),
        (bytes(12), "127.0.0.1", 65536),
    ],
)
def test_binding_success_rejects_invalid_authority(
    transaction_id: bytes,
    address: str,
    port: int,
) -> None:
    with pytest.raises(ValueError):
        build_binding_success(transaction_id, ipaddress.ip_address(address), port)


class _CaptureTransport:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
        self.sent.append((data, addr))


def test_protocol_is_fixed_response_bounded_and_drops_nonlocal_sources() -> None:
    allowed = {ipaddress.ip_address("127.0.0.1")}
    protocol = _LocalStunProtocol(source_allowed=lambda address: address in allowed)
    transport = _CaptureTransport()
    protocol.connection_made(transport)  # type: ignore[arg-type]
    transaction_id = bytes(range(12))

    protocol.datagram_received(_request(transaction_id), ("127.0.0.1", 54321))
    assert len(transport.sent) == 1
    response, destination = transport.sent[0]
    assert destination == ("127.0.0.1", 54321)
    assert len(response) == 40
    assert _decode_success(response) == (transaction_id, "127.0.0.1", 54321)

    protocol.datagram_received(_request(transaction_id), ("203.0.113.7", 54321))
    protocol.datagram_received(b"not stun", ("127.0.0.1", 54321))
    assert len(transport.sent) == 1
    assert protocol.accepted == 1
    assert protocol.dropped == 2


def test_protocol_rate_limit_is_per_source_and_global_bookkeeping_is_bounded() -> None:
    now = [1_000.0]
    protocol = _LocalStunProtocol(
        source_allowed=lambda _address: True,
        clock=lambda: now[0],
    )
    transport = _CaptureTransport()
    protocol.connection_made(transport)  # type: ignore[arg-type]
    packet = _request(bytes(range(12)))
    for port in range(40_000, 40_121):
        protocol.datagram_received(packet, ("127.0.0.1", port))
    assert len(transport.sent) == 120
    assert protocol.dropped == 1

    now[0] += 61.0
    protocol.datagram_received(packet, ("127.0.0.1", 50_000))
    assert len(transport.sent) == 121


def test_service_scope_is_bound_to_real_interface_prefixes() -> None:
    service = LocalStunService()
    service._networks = (  # type: ignore[attr-defined]
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("192.168.50.0/24"),
        ipaddress.ip_network("2001:db8:50::/64"),
    )

    assert service._source_allowed(ipaddress.ip_address("127.0.0.1"))
    assert service._source_allowed(ipaddress.ip_address("192.168.50.77"))
    assert service._source_allowed(ipaddress.ip_address("2001:db8:50::77"))
    # Other RFC1918 and globally-scoped IPv6 networks may be routed, but they
    # are not local merely because the address class looks LAN-like.
    assert not service._source_allowed(ipaddress.ip_address("10.20.30.40"))
    assert not service._source_allowed(ipaddress.ip_address("192.168.51.77"))
    assert not service._source_allowed(ipaddress.ip_address("2001:db8:51::77"))


class _ReplyProtocol(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future[bytes]) -> None:
        self.future = future
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: Any) -> None:
        del addr
        if not self.future.done():
            self.future.set_result(bytes(data))


class _HttpTransport:
    def __init__(self, *, peer: str = "127.0.0.1", local: str = "127.0.0.1") -> None:
        self.peer = peer
        self.local = local

    def get_extra_info(self, key: str) -> Any:
        return {
            "peername": (self.peer, 50_001),
            "sockname": (self.local, 7_124),
        }.get(key)


@pytest.mark.asyncio
async def test_service_real_udp_loopback_and_request_scoped_uri() -> None:
    service = LocalStunService()
    await service.start("127.0.0.1")
    try:
        port = service.ports[4]
        loop = asyncio.get_running_loop()
        reply: asyncio.Future[bytes] = loop.create_future()
        client_transport_raw, _ = await loop.create_datagram_endpoint(
            lambda: _ReplyProtocol(reply),
            remote_addr=("127.0.0.1", port),
            family=socket.AF_INET,
        )
        client_transport = client_transport_raw  # type: ignore[assignment]
        transaction_id = bytes.fromhex("00112233445566778899aabb")
        client_transport.sendto(_request(transaction_id, fingerprint=True))
        response = await asyncio.wait_for(reply, timeout=2.0)
        client_sockname = client_transport.get_extra_info("sockname")
        assert _decode_success(response) == (
            transaction_id,
            "127.0.0.1",
            client_sockname[1],
        )
        client_transport.close()

        request = SimpleNamespace(transport=_HttpTransport())
        assert service.url_for_request(request) == f"stun:127.0.0.1:{port}"
        candidates = service.candidate_addresses_for_request(request)
        assert candidates[0] == "127.0.0.1"
        assert 1 <= len(candidates) <= 8
        assert len(candidates) == len(set(candidates))
        assert service.url_for_request(SimpleNamespace(transport=None)) is None
    finally:
        await service.stop()
    assert service.running is False
    assert service.ports == {}


@pytest.mark.asyncio
async def test_public_peer_ice_config_adds_only_local_nonrelaying_authority() -> None:
    from one_link.server import UIServer

    service = LocalStunService()
    await service.start("127.0.0.1")
    try:
        server = object.__new__(UIServer)
        server._local_stun = service
        server._resolved_stun_servers = lambda: []  # type: ignore[method-assign]

        local_response = await server.api_peer_rtc_ice_config_public(
            SimpleNamespace(transport=_HttpTransport())
        )
        import json

        local = json.loads(local_response.text)
        assert local["sovereignty_default"] is True
        assert local["iceServers"] == [{"urls": f"stun:127.0.0.1:{service.ports[4]}"}]
        assert local["local_address_discovery"]["enabled"] is True
        assert local["local_address_discovery"]["external"] is False
        assert local["local_address_discovery"]["candidate_addresses"][0] == (
            "127.0.0.1"
        )
        assert local_response.headers["Cache-Control"] == "no-store"

        outside_response = await server.api_peer_rtc_ice_config_public(
            SimpleNamespace(
                transport=_HttpTransport(peer="8.8.8.8", local="192.168.1.20")
            )
        )
        outside = json.loads(outside_response.text)
        assert outside["iceServers"] == []
        assert outside["local_address_discovery"]["enabled"] is False
        assert outside["local_address_discovery"]["candidate_addresses"] == []
    finally:
        await service.stop()
