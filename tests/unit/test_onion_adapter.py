"""Acceptance tests for onion_native (Phase F3 wiring)."""

from __future__ import annotations

import os

import pytest


def _native_available() -> bool:
    try:
        from one_link_native import onion  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.onion not installed",
)


def _make_hop(seed_byte: int):
    """Return (sk_bytes, hop_id, pubkey) for a relay seeded by `seed_byte`."""
    from one_link import onion_native as on

    sk = bytes([seed_byte] * 32)
    pubkey = on.derive_pubkey(sk)
    hop_id = bytes([seed_byte] * on.HOP_ID_LEN)
    return sk, hop_id, pubkey


# ── Module / constants ────────────────────────────────────────────


def test_module_imports():
    from one_link import onion_native as on

    assert on.HAS_NATIVE is True
    assert on.MAX_HOPS == 5
    assert on.HOP_ID_LEN == 32
    assert on.MAX_USER_PAYLOAD > 0


# ── Build / peel ──────────────────────────────────────────────────


def test_one_hop_circuit_round_trip():
    from one_link import onion_native as on

    dest_sk, dest_id, dest_pk = _make_hop(0x11)
    packet = on.build_onion([(dest_id, dest_pk)], b"hello")
    outcome, next_hop, payload = on.peel_one_layer(dest_sk, packet)
    assert outcome == "deliver"
    assert next_hop == b""
    assert payload == b"hello"


def test_three_hop_circuit_round_trip():
    from one_link import onion_native as on

    r1_sk, r1_id, r1_pk = _make_hop(0x21)
    r2_sk, r2_id, r2_pk = _make_hop(0x22)
    dest_sk, dest_id, dest_pk = _make_hop(0x23)

    packet = on.build_onion(
        [(r1_id, r1_pk), (r2_id, r2_pk), (dest_id, dest_pk)],
        b"three-hop payload",
    )

    # r1 → r2
    outcome, nh, inner = on.peel_one_layer(r1_sk, packet)
    assert outcome == "forward"
    assert nh == r2_id

    # r2 → dest
    outcome, nh, inner = on.peel_one_layer(r2_sk, inner)
    assert outcome == "forward"
    assert nh == dest_id

    # dest delivers
    outcome, nh, payload = on.peel_one_layer(dest_sk, inner)
    assert outcome == "deliver"
    assert nh == b""
    assert payload == b"three-hop payload"


def test_wrong_relay_key_fails_aead():
    from one_link import onion_native as on

    _, r1_id, r1_pk = _make_hop(0x31)
    _, dest_id, dest_pk = _make_hop(0x32)
    packet = on.build_onion([(r1_id, r1_pk), (dest_id, dest_pk)], b"x")
    wrong_sk = bytes([0x99] * 32)
    with pytest.raises(ValueError, match="AEAD"):
        on.peel_one_layer(wrong_sk, packet)


def test_tampered_ciphertext_rejected():
    from one_link import onion_native as on

    dest_sk, dest_id, dest_pk = _make_hop(0x41)
    packet = bytearray(on.build_onion([(dest_id, dest_pk)], b"x"))
    packet[-5] ^= 0x01  # flip a byte inside ciphertext
    with pytest.raises(ValueError, match="AEAD"):
        on.peel_one_layer(dest_sk, bytes(packet))


# ── Edge cases ────────────────────────────────────────────────────


def test_empty_payload_works():
    from one_link import onion_native as on

    dest_sk, dest_id, dest_pk = _make_hop(0x51)
    packet = on.build_onion([(dest_id, dest_pk)], b"")
    outcome, _, payload = on.peel_one_layer(dest_sk, packet)
    assert outcome == "deliver"
    assert payload == b""


def test_payload_oversize_rejected():
    from one_link import onion_native as on

    _, dest_id, dest_pk = _make_hop(0x61)
    huge = b"\x00" * (on.MAX_USER_PAYLOAD + 1)
    with pytest.raises(ValueError, match="max"):
        on.build_onion([(dest_id, dest_pk)], huge)


def test_empty_circuit_rejected():
    from one_link import onion_native as on

    with pytest.raises(ValueError, match="at least one hop"):
        on.build_onion([], b"payload")


def test_too_many_hops_rejected():
    from one_link import onion_native as on

    hops = [_make_hop(i)[1:] for i in range(on.MAX_HOPS + 1)]
    with pytest.raises(ValueError, match="max"):
        on.build_onion(hops, b"payload")


def test_bad_hop_id_length_rejected():
    from one_link import onion_native as on

    bogus_id = b"short"
    _, _, pk = _make_hop(0x71)
    with pytest.raises(ValueError, match="hop id"):
        on.build_onion([(bogus_id, pk)], b"x")


def test_bad_pubkey_length_rejected():
    from one_link import onion_native as on

    _, hop_id, _ = _make_hop(0x72)
    with pytest.raises(ValueError, match="hop pubkey"):
        on.build_onion([(hop_id, b"too short")], b"x")


# ── Cross-circuit isolation ───────────────────────────────────────


def test_two_circuits_with_same_relays_dont_cross_contaminate():
    from one_link import onion_native as on

    sk1, id1, pk1 = _make_hop(0x81)
    sk2, id2, pk2 = _make_hop(0x82)

    p_a = on.build_onion([(id1, pk1), (id2, pk2)], b"path-a")
    p_b = on.build_onion([(id2, pk2), (id1, pk1)], b"path-b")

    # Each peel uses the right key.
    o_a = on.peel_one_layer(sk1, p_a)
    o_b = on.peel_one_layer(sk2, p_b)
    assert o_a[0] == "forward"
    assert o_b[0] == "forward"

    # Cross-feeding fails.
    with pytest.raises(ValueError, match="AEAD"):
        on.peel_one_layer(sk2, p_a)
    with pytest.raises(ValueError, match="AEAD"):
        on.peel_one_layer(sk1, p_b)


def test_derive_pubkey_deterministic():
    from one_link import onion_native as on

    sk = bytes([7] * 32)
    pk1 = on.derive_pubkey(sk)
    pk2 = on.derive_pubkey(sk)
    assert pk1 == pk2
    assert len(pk1) == 32


def test_derive_pubkey_validates_length():
    from one_link import onion_native as on

    with pytest.raises(ValueError, match="32 bytes"):
        on.derive_pubkey(b"too short")
