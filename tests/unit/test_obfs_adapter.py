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
