"""Acceptance tests for the row 7 pluggable-transport obfuscation
primitive (one_link.obfs_native)."""

from __future__ import annotations

import os

import pytest


def _native_available() -> bool:
    try:
        from one_link_native import obfs  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.obfs not installed",
)


def test_module_imports():
    from one_link import obfs_native as obfs

    assert obfs.HAS_NATIVE is True
    assert obfs.OBFS_KEY_LEN == 32
    assert obfs.OBFS_NONCE_LEN == 12


def test_round_trip():
    from one_link import obfs_native as obfs

    key = os.urandom(32)
    nonce = obfs.derive_nonce(conn_id=0xCAFE, packet_counter=1)
    plain = b"hello obfuscated world"
    obf = obfs.obfuscate(key, nonce, plain)
    assert len(obf) == len(plain)
    assert obf != plain
    recovered = obfs.deobfuscate(key, nonce, obf)
    assert recovered == plain


def test_length_preservation():
    from one_link import obfs_native as obfs

    key = bytes(32)
    nonce = bytes(12)
    for size in [0, 1, 16, 64, 256, 1024, 1280, 2400]:
        plain = b"\xAA" * size
        obf = obfs.obfuscate(key, nonce, plain)
        assert len(obf) == size


def test_different_keys_differ():
    from one_link import obfs_native as obfs

    nonce = bytes(12)
    plain = b"input bytes"
    o1 = obfs.obfuscate(bytes([1] * 32), nonce, plain)
    o2 = obfs.obfuscate(bytes([2] * 32), nonce, plain)
    assert o1 != o2


def test_different_nonces_differ():
    from one_link import obfs_native as obfs

    key = bytes([7] * 32)
    plain = b"input bytes"
    o1 = obfs.obfuscate(key, obfs.derive_nonce(1, 1), plain)
    o2 = obfs.obfuscate(key, obfs.derive_nonce(1, 2), plain)
    assert o1 != o2
    o3 = obfs.obfuscate(key, obfs.derive_nonce(2, 1), plain)
    assert o1 != o3


def test_derive_nonce_length_and_determinism():
    from one_link import obfs_native as obfs

    n1 = obfs.derive_nonce(0xDEADBEEF, 0x123456789ABCDEF0)
    n2 = obfs.derive_nonce(0xDEADBEEF, 0x123456789ABCDEF0)
    assert len(n1) == 12
    assert n1 == n2


def test_wrong_key_length_rejected():
    from one_link import obfs_native as obfs

    nonce = bytes(12)
    with pytest.raises(ValueError, match="32 bytes"):
        obfs.obfuscate(b"short", nonce, b"x")
    with pytest.raises(ValueError, match="32 bytes"):
        obfs.deobfuscate(b"short", nonce, b"x")


def test_wrong_nonce_length_rejected():
    from one_link import obfs_native as obfs

    key = bytes(32)
    with pytest.raises(ValueError, match="12 bytes"):
        obfs.obfuscate(key, b"short", b"x")


def test_derive_nonce_validates_ranges():
    from one_link import obfs_native as obfs

    with pytest.raises(ValueError):
        obfs.derive_nonce(-1, 0)
    with pytest.raises(ValueError):
        obfs.derive_nonce(2**32, 0)
    with pytest.raises(ValueError):
        obfs.derive_nonce(0, -1)
    with pytest.raises(ValueError):
        obfs.derive_nonce(0, 2**64)


# ── Handshake + Session ───────────────────────────────────────


def test_generate_bridge_keypair_lengths():
    from one_link import obfs_native as obfs

    sk, pk, bid = obfs.generate_bridge_keypair()
    assert len(sk) == obfs.BRIDGE_SECRET_LEN == 32
    assert len(pk) == obfs.BRIDGE_PUBKEY_LEN == 32
    assert len(bid) == obfs.BRIDGE_ID_LEN == 32


def test_handshake_round_trip_seals_in_both_directions():
    from one_link import obfs_native as obfs

    sk, pk, bid = obfs.generate_bridge_keypair()
    now = 1_700_000_000

    client_hs = obfs.ClientHandshake(pk, bid, now)
    first = client_hs.first_message()
    assert len(first) == obfs.HANDSHAKE_LEN == 48

    reply, server_session = obfs.server_accept(sk, bid, first, now)
    assert len(reply) == obfs.HANDSHAKE_LEN

    client_session = client_hs.finish(reply)

    # Client → server.
    p = b"hello from client over the bridge"
    on_wire = client_session.seal_outbound(p, 1)
    recovered = server_session.open_inbound(on_wire, 1)
    assert recovered == p

    # Server → client.
    p2 = b"reply from the bridge"
    on_wire2 = server_session.seal_outbound(p2, 1)
    recovered2 = client_session.open_inbound(on_wire2, 1)
    assert recovered2 == p2


def test_handshake_with_wrong_bridge_id_rejected():
    from one_link import obfs_native as obfs

    sk, pk, _bid = obfs.generate_bridge_keypair()
    wrong_id = b"\x99" * obfs.BRIDGE_ID_LEN
    now = 1_700_000_000

    client_hs = obfs.ClientHandshake(pk, wrong_id, now)
    with pytest.raises(ValueError, match="MAC"):
        obfs.server_accept(sk, b"\x00" * obfs.BRIDGE_ID_LEN, client_hs.first_message(), now)


def test_handshake_tolerates_one_epoch_of_skew():
    """Server clock ~1 hour ahead of client still authenticates."""
    from one_link import obfs_native as obfs

    sk, pk, bid = obfs.generate_bridge_keypair()
    client_now = 1_700_000_000
    server_now = client_now + obfs.HANDSHAKE_EPOCH_SECS  # 1 hour ahead

    client_hs = obfs.ClientHandshake(pk, bid, client_now)
    reply, _server = obfs.server_accept(sk, bid, client_hs.first_message(), server_now)
    assert len(reply) == obfs.HANDSHAKE_LEN


def test_handshake_rejects_two_epoch_skew():
    """Client off by > 1 hour: server rejects."""
    from one_link import obfs_native as obfs

    sk, pk, bid = obfs.generate_bridge_keypair()
    client_now = 1_700_000_000
    server_now = client_now + 2 * obfs.HANDSHAKE_EPOCH_SECS  # 2 hours ahead

    client_hs = obfs.ClientHandshake(pk, bid, client_now)
    with pytest.raises(ValueError, match="MAC"):
        obfs.server_accept(sk, bid, client_hs.first_message(), server_now)


def test_client_handshake_rejects_tampered_reply():
    """Bridge reply tampering caught by the client's auth-tag check."""
    from one_link import obfs_native as obfs

    sk, pk, bid = obfs.generate_bridge_keypair()
    now = 1_700_000_000

    client_hs = obfs.ClientHandshake(pk, bid, now)
    reply, _ = obfs.server_accept(sk, bid, client_hs.first_message(), now)
    tampered = bytearray(reply)
    tampered[40] ^= 0x01
    with pytest.raises(ValueError, match="MAC"):
        client_hs.finish(bytes(tampered))


def test_client_handshake_finish_only_once():
    """Second finish() call raises (state was consumed)."""
    from one_link import obfs_native as obfs

    sk, pk, bid = obfs.generate_bridge_keypair()
    now = 1_700_000_000

    client_hs = obfs.ClientHandshake(pk, bid, now)
    reply, _ = obfs.server_accept(sk, bid, client_hs.first_message(), now)
    _session = client_hs.finish(reply)
    with pytest.raises(RuntimeError):
        client_hs.finish(reply)


def test_session_close_disables_further_use():
    from one_link import obfs_native as obfs

    sk, pk, bid = obfs.generate_bridge_keypair()
    now = 1_700_000_000

    client_hs = obfs.ClientHandshake(pk, bid, now)
    reply, _ = obfs.server_accept(sk, bid, client_hs.first_message(), now)
    session = client_hs.finish(reply)
    assert session.is_open()
    session.close()
    assert not session.is_open()
    with pytest.raises(RuntimeError):
        session.seal_outbound(b"x", 1)


def test_distinct_clients_get_distinct_session_keys():
    """Two clients handshaking with the same bridge produce different
    ciphertexts for the same plaintext."""
    from one_link import obfs_native as obfs

    sk, pk, bid = obfs.generate_bridge_keypair()
    now = 1_700_000_000

    hs_a = obfs.ClientHandshake(pk, bid, now)
    reply_a, _ = obfs.server_accept(sk, bid, hs_a.first_message(), now)
    session_a = hs_a.finish(reply_a)

    hs_b = obfs.ClientHandshake(pk, bid, now)
    reply_b, _ = obfs.server_accept(sk, bid, hs_b.first_message(), now)
    session_b = hs_b.finish(reply_b)

    assert reply_a != reply_b
    p = b"same plaintext"
    assert session_a.seal_outbound(p, 1) != session_b.seal_outbound(p, 1)


def test_handshake_with_wrong_bridge_secret_rejected():
    """Probe attacker without the bridge secret can't pretend to be the bridge."""
    from one_link import obfs_native as obfs

    _, pk, bid = obfs.generate_bridge_keypair()
    wrong_sk = b"\x99" * obfs.BRIDGE_SECRET_LEN
    now = 1_700_000_000

    client_hs = obfs.ClientHandshake(pk, bid, now)
    # The wrong-secret server WILL still produce a reply (it has the
    # bridge_id, so HMAC verifies). But its ECDH yields a different
    # shared secret → client's finish() also produces a session,
    # but the keys won't match. So the seal/open round-trip fails.
    reply, server_session = obfs.server_accept(
        wrong_sk, bid, client_hs.first_message(), now
    )
    client_session = client_hs.finish(reply)
    p = b"test"
    on_wire = client_session.seal_outbound(p, 1)
    recovered = server_session.open_inbound(on_wire, 1)
    # ECDH mismatch → recovered != p.
    assert recovered != p


def test_handshake_input_lengths_validated():
    from one_link import obfs_native as obfs

    now = 0
    with pytest.raises(ValueError):
        obfs.ClientHandshake(b"too short", b"\x00" * 32, now)
    with pytest.raises(ValueError):
        obfs.ClientHandshake(b"\x00" * 32, b"short", now)
    with pytest.raises(ValueError):
        obfs.server_accept(b"short", b"\x00" * 32, b"\x00" * 48, now)
    with pytest.raises(ValueError):
        obfs.server_accept(b"\x00" * 32, b"short", b"\x00" * 48, now)


def test_tamper_propagates_to_output():
    """No integrity at this layer — flipped bits propagate. The upper
    layer's MAC/AEAD/TLS catches them."""
    from one_link import obfs_native as obfs

    key = bytes([5] * 32)
    nonce = obfs.derive_nonce(0xABCD, 42)
    plain = b"original"
    obf = bytearray(obfs.obfuscate(key, nonce, plain))
    obf[2] ^= 0x01
    recovered = obfs.deobfuscate(key, nonce, bytes(obf))
    # Bit flip propagates one-to-one.
    expected = bytearray(plain)
    expected[2] ^= 0x01
    assert bytes(recovered) == bytes(expected)
