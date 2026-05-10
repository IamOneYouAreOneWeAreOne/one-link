"""v0.20.7 — Ring signatures (anonymous group credentials).

A ring signature lets a signer prove "I'm one of the N pubkeys in
this ring" without revealing which. AOS construction (Abe-Ohkubo-
Suzuki, 2002), pure Ed25519/Curve25519, no pairings.

These tests pin:
  - sign + verify round-trip with rings of various sizes
  - The signer's position is unrecoverable from the signature
  - Verify rejects: wrong ring, wrong message, tampered signature,
    signer not in ring (sign-side rejection)
  - Two different signers in the same ring produce different
    signatures (no determinism leak)
  - Two signatures from the SAME signer are not directly linkable
    (the AOS variant we ship is non-linkable; a future linkable
    variant adds a key image)
"""
from __future__ import annotations

import os

import pytest

from one_link import ring_sig as rs


def _gen_seed():
    return os.urandom(32)


def _make_ring(n: int):
    """Return list of (priv_seed, pubkey) pairs."""
    return [(s := _gen_seed(), rs.public_key_from_priv_seed(s)) for _ in range(n)]


# ── round-trip ───────────────────────────────────────────────────


def test_sign_verify_2_member_ring():
    pairs = _make_ring(2)
    ring = [pub for _, pub in pairs]
    msg = b"hello from someone in the ring"
    sig = rs.sign(priv_seed=pairs[0][0], ring=ring, message=msg)
    assert rs.verify(ring=ring, message=msg, signature=sig)


def test_sign_verify_5_member_ring():
    pairs = _make_ring(5)
    ring = [pub for _, pub in pairs]
    msg = b"x"
    # Try every position as the signer.
    for signer_idx in range(5):
        sig = rs.sign(
            priv_seed=pairs[signer_idx][0],
            ring=ring, message=msg,
        )
        assert rs.verify(ring=ring, message=msg, signature=sig)


def test_sign_verify_10_member_ring():
    pairs = _make_ring(10)
    ring = [pub for _, pub in pairs]
    msg = b"longer ring, more obscurity"
    sig = rs.sign(priv_seed=pairs[7][0], ring=ring, message=msg)
    assert rs.verify(ring=ring, message=msg, signature=sig)
    expected_len = 32 * (10 + 1)
    assert len(sig) == expected_len


# ── verify failure modes ──────────────────────────────────────────


def test_verify_rejects_wrong_message():
    pairs = _make_ring(3)
    ring = [pub for _, pub in pairs]
    sig = rs.sign(priv_seed=pairs[0][0], ring=ring, message=b"original")
    assert not rs.verify(ring=ring, message=b"different", signature=sig)


def test_verify_rejects_wrong_ring():
    pairs = _make_ring(3)
    ring = [pub for _, pub in pairs]
    sig = rs.sign(priv_seed=pairs[0][0], ring=ring, message=b"x")
    # Swap one ring member for a fresh pubkey.
    new_ring = [pub for _, pub in pairs]
    new_ring[1] = rs.public_key_from_priv_seed(_gen_seed())
    assert not rs.verify(ring=new_ring, message=b"x", signature=sig)


def test_verify_rejects_tampered_signature():
    pairs = _make_ring(3)
    ring = [pub for _, pub in pairs]
    sig = bytearray(rs.sign(
        priv_seed=pairs[0][0], ring=ring, message=b"x",
    ))
    sig[10] ^= 0xff
    assert not rs.verify(ring=ring, message=b"x", signature=bytes(sig))


def test_verify_rejects_truncated_signature():
    pairs = _make_ring(3)
    ring = [pub for _, pub in pairs]
    sig = rs.sign(priv_seed=pairs[0][0], ring=ring, message=b"x")
    assert not rs.verify(ring=ring, message=b"x", signature=sig[:-1])


def test_verify_rejects_zero_signature():
    """A zero signature must not pass — guards against parser bugs."""
    pairs = _make_ring(3)
    ring = [pub for _, pub in pairs]
    zero = b"\x00" * (32 * (len(ring) + 1))
    assert not rs.verify(ring=ring, message=b"x", signature=zero)


# ── sign-side errors ─────────────────────────────────────────────


def test_sign_rejects_signer_not_in_ring():
    pairs = _make_ring(3)
    ring = [pub for _, pub in pairs]
    outsider_seed = _gen_seed()
    with pytest.raises(ValueError, match="not in the ring"):
        rs.sign(
            priv_seed=outsider_seed, ring=ring, message=b"x",
        )


def test_sign_rejects_ring_too_small():
    """A 1-member ring is just a Schnorr signature with no anonymity
    set; refuse to sign."""
    seed = _gen_seed()
    pub = rs.public_key_from_priv_seed(seed)
    with pytest.raises(ValueError, match="at least 2"):
        rs.sign(priv_seed=seed, ring=[pub], message=b"x")


def test_sign_rejects_invalid_pubkey_in_ring():
    pairs = _make_ring(3)
    ring = [pub for _, pub in pairs]
    ring[1] = b"\x00" * 31  # wrong size
    with pytest.raises(ValueError, match="32 bytes"):
        rs.sign(priv_seed=pairs[0][0], ring=ring, message=b"x")


# ── anonymity properties ─────────────────────────────────────────


def test_two_signers_produce_different_signatures():
    """Different signers in the same ring → different signatures."""
    pairs = _make_ring(5)
    ring = [pub for _, pub in pairs]
    msg = b"x"
    sig_a = rs.sign(priv_seed=pairs[0][0], ring=ring, message=msg)
    sig_b = rs.sign(priv_seed=pairs[2][0], ring=ring, message=msg)
    assert sig_a != sig_b
    # Both verify.
    assert rs.verify(ring=ring, message=msg, signature=sig_a)
    assert rs.verify(ring=ring, message=msg, signature=sig_b)


def test_same_signer_two_signatures_differ():
    """Each sign() call uses fresh randomness for the s_i nonces; two
    signatures from the same signer are different and not directly
    linkable (we don't ship a key image — that'd be the linkable
    variant). Both verify."""
    pairs = _make_ring(3)
    ring = [pub for _, pub in pairs]
    msg = b"x"
    sig1 = rs.sign(priv_seed=pairs[0][0], ring=ring, message=msg)
    sig2 = rs.sign(priv_seed=pairs[0][0], ring=ring, message=msg)
    assert sig1 != sig2
    assert rs.verify(ring=ring, message=msg, signature=sig1)
    assert rs.verify(ring=ring, message=msg, signature=sig2)


def test_signature_length_predictable():
    """Length is 32 * (N+1). Verifiable by anyone scanning the wire."""
    for n in (2, 3, 5, 10):
        pairs = _make_ring(n)
        ring = [pub for _, pub in pairs]
        sig = rs.sign(priv_seed=pairs[0][0], ring=ring, message=b"x")
        assert len(sig) == 32 * (n + 1)


# ── realistic flows ───────────────────────────────────────────────


def test_anonymous_group_credential_flow():
    """A receiver wants verifiable provenance ("the message came
    from a member of group G") but not identification ("which
    member"). Group G has 5 members; any of them can sign."""
    members = _make_ring(5)
    ring = [pub for _, pub in members]
    # Member 3 wants to drop a leak to a journalist anonymously.
    leak = b"the dossier reveals that..."
    sig = rs.sign(priv_seed=members[3][0], ring=ring, message=leak)
    # Journalist verifies: someone in ring signed this.
    assert rs.verify(ring=ring, message=leak, signature=sig)
    # An attacker who tries the leak under a ring of NON-members
    # (replacing one pubkey with their own + 4 randoms) cannot
    # forge a valid signature for that ring.
    attacker_ring = [rs.public_key_from_priv_seed(_gen_seed()) for _ in range(5)]
    attacker_seed = _gen_seed()
    attacker_ring[0] = rs.public_key_from_priv_seed(attacker_seed)
    attacker_sig = rs.sign(
        priv_seed=attacker_seed, ring=attacker_ring, message=leak,
    )
    # Attacker's signature verifies under THEIR ring but NOT the
    # original group's ring — provenance is preserved.
    assert rs.verify(ring=attacker_ring, message=leak, signature=attacker_sig)
    assert not rs.verify(ring=ring, message=leak, signature=attacker_sig)


def test_public_key_deterministic():
    seed = _gen_seed()
    a = rs.public_key_from_priv_seed(seed)
    b = rs.public_key_from_priv_seed(seed)
    assert a == b
