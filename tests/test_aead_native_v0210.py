"""File engine v2 — algebraic-correctness tests for ``one_link.aead_native``.

Per ADR-0002 verification gates: AES-256-GCM and ChaCha20-Poly1305 round
trip; tampering rejection (ciphertext / AAD / tag / nonce / chunk_id /
cipher kind); frame-index isolation; max-size and empty edge cases.

Tests skip when the native module isn't available (e.g. dev environments
without Rust). When green, these are the canonical correctness contract
that any future AEAD reimplementation has to honor.
"""

from __future__ import annotations

import secrets

import pytest

from one_link import aead_native


pytestmark = pytest.mark.skipif(
    not aead_native.HAS_NATIVE,
    reason="one_link_native not installed; run `cd native && maturin develop --release`",
)


# ─── basic loadability + diagnostics ──────────────────────────────────


def test_native_constants_present():
    assert aead_native.FRAME_KEY_LEN == 32
    assert aead_native.AEAD_TAG_LEN == 16
    assert aead_native.AEAD_FRAME_PLAINTEXT_LEN == 16 * 1024
    assert aead_native.MAX_CHUNK_PLAINTEXT_LEN == 256 * 1024


def test_diagnostics_schema():
    diag = aead_native.diagnostics()
    assert diag.native_available is True
    assert diag.preferred_kind in ("aes", "chacha")
    assert isinstance(diag.host_has_hardware_aes, bool)
    assert diag.frame_key_len == 32
    assert diag.aead_tag_len == 16
    assert diag.aead_frame_plaintext_len == 16 * 1024
    assert diag.max_chunk_plaintext_len == 256 * 1024


# ─── round trip on both ciphers ───────────────────────────────────────


@pytest.mark.parametrize("kind", ["aes", "chacha"])
@pytest.mark.parametrize("size", [0, 1, 100, 16 * 1024, 16 * 1024 + 1, 64 * 1024, 256 * 1024])
def test_chunk_round_trip(kind, size):
    key = secrets.token_bytes(32)
    chunk_id = secrets.token_bytes(32)
    cipher = aead_native.AeadCipher.with_kind(key, kind)
    plaintext = secrets.token_bytes(size)
    ct = cipher.encrypt_chunk(chunk_id, plaintext)
    if size == 0:
        assert len(ct) == 0
    else:
        frame_count = (size + 16383) // 16384
        assert len(ct) == size + frame_count * 16
    recovered = cipher.decrypt_chunk(chunk_id, size, ct)
    assert recovered == plaintext


def test_default_for_host_round_trip():
    key = secrets.token_bytes(32)
    chunk_id = secrets.token_bytes(32)
    cipher = aead_native.AeadCipher.default_for_host(key)
    assert cipher.kind in ("aes", "chacha")
    plaintext = b"hello, default cipher!"
    ct = cipher.encrypt_chunk(chunk_id, plaintext)
    assert cipher.decrypt_chunk(chunk_id, len(plaintext), ct) == plaintext


# ─── tampering and cross-binding rejection ────────────────────────────


def test_tampered_ciphertext_rejected():
    key = secrets.token_bytes(32)
    chunk_id = secrets.token_bytes(32)
    cipher = aead_native.AeadCipher.with_kind(key, "aes")
    pt = b"sensitive data" * 100
    ct = bytearray(cipher.encrypt_chunk(chunk_id, pt))
    ct[0] ^= 0x01
    with pytest.raises(Exception):
        cipher.decrypt_chunk(chunk_id, len(pt), bytes(ct))


def test_cross_chunk_id_rejected():
    key = secrets.token_bytes(32)
    chunk_id_a = secrets.token_bytes(32)
    chunk_id_b = secrets.token_bytes(32)
    while chunk_id_b == chunk_id_a:
        chunk_id_b = secrets.token_bytes(32)
    cipher = aead_native.AeadCipher.with_kind(key, "aes")
    pt = b"top secret"
    ct = cipher.encrypt_chunk(chunk_id_a, pt)
    with pytest.raises(Exception):
        cipher.decrypt_chunk(chunk_id_b, len(pt), ct)


def test_cross_cipher_kind_rejected():
    """Encrypt with AES, decrypt with ChaCha (or vice versa) — must fail."""
    key = secrets.token_bytes(32)
    chunk_id = secrets.token_bytes(32)
    aes = aead_native.AeadCipher.with_kind(key, "aes")
    chacha = aead_native.AeadCipher.with_kind(key, "chacha")
    pt = b"asymmetric ciphers"
    ct = aes.encrypt_chunk(chunk_id, pt)
    with pytest.raises(Exception):
        chacha.decrypt_chunk(chunk_id, len(pt), ct)


def test_cross_key_rejected():
    key_a = secrets.token_bytes(32)
    key_b = secrets.token_bytes(32)
    while key_b == key_a:
        key_b = secrets.token_bytes(32)
    chunk_id = secrets.token_bytes(32)
    cipher_a = aead_native.AeadCipher.with_kind(key_a, "aes")
    cipher_b = aead_native.AeadCipher.with_kind(key_b, "aes")
    pt = b"under different keys"
    ct = cipher_a.encrypt_chunk(chunk_id, pt)
    with pytest.raises(Exception):
        cipher_b.decrypt_chunk(chunk_id, len(pt), ct)


def test_wrong_plaintext_length_rejected():
    key = secrets.token_bytes(32)
    chunk_id = secrets.token_bytes(32)
    cipher = aead_native.AeadCipher.with_kind(key, "aes")
    pt = b"x" * 50_000
    ct = cipher.encrypt_chunk(chunk_id, pt)
    # Lie about the plaintext length.
    with pytest.raises(Exception):
        cipher.decrypt_chunk(chunk_id, len(pt) - 1, ct)


def test_oversized_plaintext_rejected():
    key = secrets.token_bytes(32)
    chunk_id = secrets.token_bytes(32)
    cipher = aead_native.AeadCipher.with_kind(key, "aes")
    pt = b"x" * (256 * 1024 + 1)
    with pytest.raises(Exception):
        cipher.encrypt_chunk(chunk_id, pt)


# ─── single-frame random access ───────────────────────────────────────


def test_frame_round_trip():
    key = secrets.token_bytes(32)
    chunk_id = secrets.token_bytes(32)
    cipher = aead_native.AeadCipher.with_kind(key, "aes")
    pt = b"frame-level data" * 500
    ct, tag = cipher.encrypt_frame(chunk_id, 7, pt)
    assert len(tag) == 16
    recovered = cipher.decrypt_frame(chunk_id, 7, ct, tag)
    assert recovered == pt


def test_frame_index_swap_rejected():
    key = secrets.token_bytes(32)
    chunk_id = secrets.token_bytes(32)
    cipher = aead_native.AeadCipher.with_kind(key, "aes")
    pt = b"y" * 100
    ct, tag = cipher.encrypt_frame(chunk_id, 0, pt)
    # Decrypt as if it were frame 1 — must fail.
    with pytest.raises(Exception):
        cipher.decrypt_frame(chunk_id, 1, ct, tag)


def test_frame_oversized_plaintext_rejected():
    key = secrets.token_bytes(32)
    chunk_id = secrets.token_bytes(32)
    cipher = aead_native.AeadCipher.with_kind(key, "aes")
    pt = b"z" * (16 * 1024 + 1)
    with pytest.raises(Exception):
        cipher.encrypt_frame(chunk_id, 0, pt)


# ─── argument validation ──────────────────────────────────────────────


def test_unknown_kind_rejected():
    key = secrets.token_bytes(32)
    with pytest.raises(Exception):
        aead_native.AeadCipher.with_kind(key, "blowfish")


def test_bad_key_length_rejected():
    with pytest.raises(Exception):
        aead_native.AeadCipher.with_kind(b"\x00" * 31, "aes")
    with pytest.raises(Exception):
        aead_native.AeadCipher.with_kind(b"\x00" * 33, "aes")


def test_bad_chunk_id_rejected():
    key = secrets.token_bytes(32)
    cipher = aead_native.AeadCipher.with_kind(key, "aes")
    with pytest.raises(Exception):
        cipher.encrypt_chunk(b"\x00" * 31, b"data")


def test_bad_tag_length_rejected():
    key = secrets.token_bytes(32)
    chunk_id = secrets.token_bytes(32)
    cipher = aead_native.AeadCipher.with_kind(key, "aes")
    ct, _tag = cipher.encrypt_frame(chunk_id, 0, b"data")
    with pytest.raises(Exception):
        cipher.decrypt_frame(chunk_id, 0, ct, b"\x00" * 15)


# ─── repr ─────────────────────────────────────────────────────────────


def test_cipher_repr_includes_kind():
    key = secrets.token_bytes(32)
    aes = aead_native.AeadCipher.with_kind(key, "aes")
    chacha = aead_native.AeadCipher.with_kind(key, "chacha")
    assert "aes" in repr(aes).lower()
    assert "chacha" in repr(chacha).lower()
