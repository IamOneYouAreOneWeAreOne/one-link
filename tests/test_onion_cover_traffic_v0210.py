"""Tests for D05 cover-traffic generation in ``one_link_native.onion``.

Exercises:
  - build_cover_packet construction (default + custom body length)
  - is_cover_payload detection at the destination
  - Wire-indistinguishability: cover packet size == real packet size
    for the same circuit + body length
  - Round-trip: cover packet peels cleanly through every hop
  - Error paths (oversize body)
"""

from __future__ import annotations

import pytest

try:
    from one_link_native import onion as native_onion  # type: ignore[import-not-found]
    HAS_NATIVE = True
except ImportError:
    HAS_NATIVE = False
    native_onion = None  # type: ignore[assignment]


pytestmark = pytest.mark.skipif(
    not HAS_NATIVE,
    reason="one_link_native.onion not installed",
)


def _make_hops(n: int):
    """Build a list of (id, pubkey) hops + their secrets for testing."""
    hops = []
    secrets = []
    for i in range(n):
        sk_bytes = bytes([i + 1] * 32)
        # Derive pubkey via the native helper.
        pk = native_onion.derive_pubkey(sk_bytes)
        hop_id = bytes([i + 1] * 32)
        hops.append((hop_id, pk))
        secrets.append(sk_bytes)
    return hops, secrets


def test_cover_magic_constant_exposed() -> None:
    assert native_onion.COVER_MAGIC == b"\xC0\xCC\xE3\xAF"
    assert len(native_onion.COVER_MAGIC) == 4


def test_default_cover_body_len_exposed() -> None:
    assert native_onion.DEFAULT_COVER_BODY_LEN > 0
    assert native_onion.DEFAULT_COVER_BODY_LEN == 256


def test_is_cover_payload_recognizes_magic() -> None:
    payload = native_onion.COVER_MAGIC + b"random body"
    assert native_onion.is_cover_payload(payload) is True


def test_is_cover_payload_rejects_real_frame() -> None:
    # Real wire frames start with a 4-byte length prefix (high byte
    # < 0x10 for valid frames). Cover magic starts with 0xC0.
    real = b"\x00\x00\x00\x10{\"t\":\"TEXT\"}"
    assert native_onion.is_cover_payload(real) is False


def test_is_cover_payload_handles_short() -> None:
    assert native_onion.is_cover_payload(b"") is False
    assert native_onion.is_cover_payload(b"\xC0") is False
    assert native_onion.is_cover_payload(b"\xC0\xCC") is False


def test_build_cover_packet_returns_bytes() -> None:
    hops, _ = _make_hops(3)
    pkt = native_onion.build_cover_packet(hops)
    assert isinstance(pkt, bytes)
    assert len(pkt) > 0


def test_build_cover_packet_custom_body_len() -> None:
    hops, _ = _make_hops(3)
    pkt = native_onion.build_cover_packet(hops, body_len=100)
    assert isinstance(pkt, bytes)


def test_cover_packet_round_trip_through_hops() -> None:
    """Build + peel through every hop. Destination should see a
    payload that is_cover_payload identifies."""
    hops, secrets = _make_hops(3)
    pkt = native_onion.build_cover_packet(hops, body_len=64)
    current = pkt
    for i, sk in enumerate(secrets):
        # peel returns (kind, next_hop_or_empty, inner_or_payload).
        kind, _next_hop, body = native_onion.peel_one_layer(sk, current)
        if kind == "deliver":
            assert i == len(secrets) - 1
            assert native_onion.is_cover_payload(body)
            # body: 64 + 4 magic = 68
            assert len(body) == 64 + 4
            return
        assert kind == "forward"
        current = body
    pytest.fail("destination never reached")


def test_cover_packet_size_matches_real() -> None:
    """Wire-indistinguishability: a cover packet of body_len N is
    the same on-wire size as a real packet of body length N + 4
    (because cover adds the 4-byte magic)."""
    hops, _ = _make_hops(3)
    cover = native_onion.build_cover_packet(hops, body_len=100)
    real_payload = b"X" * (100 + 4)  # match the inner size
    real = native_onion.build_onion(hops, real_payload)
    assert len(cover) == len(real)


def test_cover_packet_oversize_body_rejected() -> None:
    hops, _ = _make_hops(2)
    # Anything that pushes body_len + 4 > MAX_USER_PAYLOAD must fail.
    with pytest.raises(ValueError):
        native_onion.build_cover_packet(hops, body_len=native_onion.MAX_USER_PAYLOAD + 100)


def test_cover_packet_with_default_body_len() -> None:
    hops, _ = _make_hops(2)
    pkt_default = native_onion.build_cover_packet(hops)  # body_len=0 → default
    pkt_explicit = native_onion.build_cover_packet(
        hops, body_len=native_onion.DEFAULT_COVER_BODY_LEN
    )
    # Same on-wire size (both use the default body length).
    assert len(pkt_default) == len(pkt_explicit)


def test_cover_packet_through_5_hop_paranoid_circuit() -> None:
    """Paranoid mode uses 5-hop circuits — verify cover traffic works
    at MAX_HOPS."""
    hops, secrets = _make_hops(5)
    pkt = native_onion.build_cover_packet(hops, body_len=128)
    current = pkt
    for i, sk in enumerate(secrets):
        kind, _next_hop, body = native_onion.peel_one_layer(sk, current)
        if kind == "deliver":
            assert i == 4
            assert native_onion.is_cover_payload(body)
            return
        assert kind == "forward"
        current = body
    pytest.fail("never reached destination in 5-hop circuit")
