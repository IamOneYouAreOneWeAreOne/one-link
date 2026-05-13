"""Acceptance tests for pqsig_native (row 1)."""

from __future__ import annotations

import pytest


def _native_available() -> bool:
    try:
        from one_link_native import pqsig  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.pqsig not installed",
)


def test_module_imports():
    from one_link import pqsig_native as pq

    assert pq.HAS_NATIVE is True
    assert pq.HYBRID_SK_LEN == 64
    assert pq.HYBRID_VK_LEN == 1984
    assert pq.HYBRID_SIG_LEN == 3373


def test_generate_keypair_lengths():
    from one_link import pqsig_native as pq

    sk, vk = pq.generate_keypair()
    assert len(sk) == pq.HYBRID_SK_LEN
    assert len(vk) == pq.HYBRID_VK_LEN


def test_sign_verify_round_trip():
    from one_link import pqsig_native as pq

    sk, vk = pq.generate_keypair()
    msg = b"hello hybrid world"
    sig = pq.sign(sk, msg)
    assert len(sig) == pq.HYBRID_SIG_LEN
    pq.verify(vk, msg, sig)


def test_derive_vk_matches_keypair():
    from one_link import pqsig_native as pq

    sk, vk = pq.generate_keypair()
    vk2 = pq.derive_vk(sk)
    assert vk == vk2


def test_tampered_ed25519_half_rejected():
    from one_link import pqsig_native as pq

    sk, vk = pq.generate_keypair()
    sig = bytearray(pq.sign(sk, b"hello"))
    sig[0] ^= 0x01
    with pytest.raises(ValueError, match="Ed25519"):
        pq.verify(vk, b"hello", bytes(sig))


def test_tampered_ml_dsa_half_rejected():
    from one_link import pqsig_native as pq

    sk, vk = pq.generate_keypair()
    sig = bytearray(pq.sign(sk, b"hello"))
    # Flip a byte in the ML-DSA half (past Ed25519's 64).
    sig[100] ^= 0x01
    with pytest.raises(ValueError, match="ML-DSA"):
        pq.verify(vk, b"hello", bytes(sig))


def test_cross_message_replay_rejected():
    from one_link import pqsig_native as pq

    sk, vk = pq.generate_keypair()
    sig = pq.sign(sk, b"message-a")
    with pytest.raises(ValueError):
        pq.verify(vk, b"message-b", sig)


def test_cross_key_replay_rejected():
    from one_link import pqsig_native as pq

    sk_a, _ = pq.generate_keypair()
    _, vk_b = pq.generate_keypair()
    sig = pq.sign(sk_a, b"x")
    with pytest.raises(ValueError):
        pq.verify(vk_b, b"x", sig)


def test_wrong_sk_length_rejected():
    from one_link import pqsig_native as pq

    with pytest.raises(ValueError):
        pq.sign(b"too short", b"x")
    with pytest.raises(ValueError):
        pq.derive_vk(b"too short")


def test_wrong_vk_length_rejected():
    from one_link import pqsig_native as pq

    sk, _ = pq.generate_keypair()
    sig = pq.sign(sk, b"x")
    with pytest.raises(ValueError):
        pq.verify(b"too short", b"x", sig)


def test_wrong_sig_length_rejected():
    from one_link import pqsig_native as pq

    _, vk = pq.generate_keypair()
    with pytest.raises(ValueError):
        pq.verify(vk, b"x", b"too short")


def test_empty_message_signs_and_verifies():
    from one_link import pqsig_native as pq

    sk, vk = pq.generate_keypair()
    sig = pq.sign(sk, b"")
    pq.verify(vk, b"", sig)


def test_large_message_signs_and_verifies():
    from one_link import pqsig_native as pq

    sk, vk = pq.generate_keypair()
    msg = b"\xAA" * 100_000
    sig = pq.sign(sk, msg)
    pq.verify(vk, msg, sig)


def test_deterministic_sign_per_sk():
    """sign_deterministic produces the same sig for same (sk, msg)."""
    from one_link import pqsig_native as pq

    sk, _ = pq.generate_keypair()
    sig1 = pq.sign(sk, b"test")
    sig2 = pq.sign(sk, b"test")
    assert sig1 == sig2
