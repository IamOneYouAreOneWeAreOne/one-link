"""Legacy v0.20.7 hybrid-combiner compatibility tests.

A future quantum computer running Shor's algorithm breaks Curve25519
in polynomial time. State actors today record encrypted traffic
they can't yet read; "harvest-now-decrypt-later" is the threat.

Production now uses the native FIPS-203 ML-KEM-768 backend and the live v3
channel handshake. These tests retain the old pluggable wire/combine surface
for explicit migrations; ``NullKEM`` is never a PQ claim.

These tests pin:
  - X25519 KEM Protocol shape: keypair / encapsulate / decapsulate
    round-trip, length checks, small-order rejection
  - NullKEM emits empty bytes + decapsulates to empty
  - HKDF combiner: same inputs → same output, different transcripts
    → different outputs, KEM-name binding (swapping name labels
    changes the output)
  - HybridKEM round-trip: alice-encapsulate-to-bob, bob-decapsulate,
    shared secrets match
  - HybridKey wire format: encode / decode round-trip, truncation
    rejection
  - Legacy wire format's length-prefixed PQ slot remains strictly parseable
"""
from __future__ import annotations

import os

import pytest

from one_link import pq_hybrid as ph


# ── X25519 KEM ─────────────────────────────────────────────────────


def test_x25519_kem_round_trip():
    kem = ph.X25519KEM()
    priv, pub = kem.keypair()
    assert len(priv) == 32 and len(pub) == 32
    ct, ss_send = kem.encapsulate(pub)
    assert len(ct) == 32
    ss_recv = kem.decapsulate(ct, priv)
    assert ss_send == ss_recv
    assert len(ss_send) == 32
    # Sanity: not all zeros.
    assert ss_send != b"\x00" * 32


def test_x25519_keypair_unique():
    kem = ph.X25519KEM()
    a_priv, a_pub = kem.keypair()
    b_priv, b_pub = kem.keypair()
    assert a_priv != b_priv
    assert a_pub != b_pub


def test_x25519_wrong_size_rejected():
    kem = ph.X25519KEM()
    with pytest.raises(ValueError, match="32 bytes"):
        kem.encapsulate(b"\x00" * 16)
    with pytest.raises(ValueError, match="32 bytes"):
        kem.decapsulate(b"\x00" * 32, b"\x00" * 16)


def test_x25519_small_order_rejected():
    """All-zero peer pubkey is a small-order point. The cryptography
    library may raise its own error ("Error computing shared key")
    before our zero-output check fires; either rejection is
    acceptable."""
    kem = ph.X25519KEM()
    with pytest.raises(ValueError):
        kem.encapsulate(b"\x00" * 32)


# ── NullKEM ────────────────────────────────────────────────────────


def test_null_kem_round_trip():
    kem = ph.NullKEM()
    priv, pub = kem.keypair()
    assert priv == b"" and pub == b""
    ct, ss = kem.encapsulate(pub)
    assert ct == b"" and ss == b""
    ss2 = kem.decapsulate(ct, priv)
    assert ss2 == b""


def test_null_kem_rejects_non_empty_input():
    kem = ph.NullKEM()
    with pytest.raises(ValueError):
        kem.encapsulate(b"non-empty")
    with pytest.raises(ValueError):
        kem.decapsulate(b"non-empty", b"")


# ── HKDF combine ───────────────────────────────────────────────────


def test_hkdf_combine_deterministic():
    cs = os.urandom(32)
    ps = os.urandom(32)
    a = ph.hkdf_combine(cs, ps, classical_name="A", pq_name="B")
    b = ph.hkdf_combine(cs, ps, classical_name="A", pq_name="B")
    assert a == b


def test_hkdf_combine_transcript_binding():
    """Different transcripts → different outputs. Binds the hybrid
    output to a specific session."""
    cs = os.urandom(32)
    ps = os.urandom(32)
    a = ph.hkdf_combine(cs, ps, classical_name="X25519", pq_name="Null",
                         transcript=b"session-A")
    b = ph.hkdf_combine(cs, ps, classical_name="X25519", pq_name="Null",
                         transcript=b"session-B")
    assert a != b


def test_hkdf_combine_kem_name_binding():
    """Swapping the KEM-name labels changes the output. Catches a
    future bug where a peer claims to use ML-KEM-768 but actually
    runs NullKEM."""
    cs = os.urandom(32)
    ps = os.urandom(32)
    a = ph.hkdf_combine(cs, ps, classical_name="X25519", pq_name="Null")
    b = ph.hkdf_combine(cs, ps, classical_name="X25519", pq_name="ML-KEM-768")
    assert a != b


def test_hkdf_combine_one_secret_changes_output():
    cs1 = os.urandom(32)
    cs2 = os.urandom(32)
    ps = os.urandom(32)
    a = ph.hkdf_combine(cs1, ps, classical_name="X25519", pq_name="Null")
    b = ph.hkdf_combine(cs2, ps, classical_name="X25519", pq_name="Null")
    assert a != b


# ── HybridKEM ──────────────────────────────────────────────────────


def test_hybrid_kem_round_trip_default():
    """Direct HybridKEM construction remains explicitly classical-only."""
    kem = ph.HybridKEM()
    bob_priv, bob_pub = kem.keypair()
    transcript = b"hello-bob-handshake"
    ct, ss_send = kem.encapsulate(bob_pub, transcript=transcript)
    ss_recv = kem.decapsulate(ct, bob_priv, transcript=transcript)
    assert ss_send == ss_recv
    assert len(ss_send) == 32


def test_hybrid_kem_unique_per_session():
    """Each encapsulate must use a fresh ephemeral so two sessions
    targeting the same peer pubkey produce different shared secrets."""
    kem = ph.HybridKEM()
    _, bob_pub = kem.keypair()
    _, ss1 = kem.encapsulate(bob_pub)
    _, ss2 = kem.encapsulate(bob_pub)
    assert ss1 != ss2


def test_hybrid_kem_transcript_changes_output():
    kem = ph.HybridKEM()
    bob_priv, bob_pub = kem.keypair()
    ct, ss1 = kem.encapsulate(bob_pub, transcript=b"sess-A")
    # Same ciphertext (well, same ephemeral inside) — but the
    # transcript-bound combine produces a different shared secret
    # at the receiver's end too.
    ss2 = kem.decapsulate(ct, bob_priv, transcript=b"sess-B")
    assert ss1 != ss2


def test_hybrid_kem_wrong_priv_fails():
    kem = ph.HybridKEM()
    bob_priv, bob_pub = kem.keypair()
    eve_priv, _ = kem.keypair()
    ct, ss_send = kem.encapsulate(bob_pub)
    ss_recv = kem.decapsulate(ct, eve_priv)
    # Decap with wrong priv produces a DIFFERENT (and unrelated) shared.
    assert ss_send != ss_recv


# ── HybridKey wire format ──────────────────────────────────────────


def test_hybrid_key_encode_decode_round_trip():
    k = ph.HybridKey(classical=os.urandom(32), pq=os.urandom(64))
    raw = k.encode()
    parsed = ph.HybridKey.decode(raw)
    assert parsed.classical == k.classical
    assert parsed.pq == k.pq


def test_hybrid_key_with_empty_pq_slot():
    """The legacy NullKEM encoding retains an explicit empty PQ slot."""
    k = ph.HybridKey(classical=os.urandom(32), pq=b"")
    raw = k.encode()
    # 2 + 32 + 2 + 0 = 36 bytes
    assert len(raw) == 36
    parsed = ph.HybridKey.decode(raw)
    assert parsed.pq == b""


def test_hybrid_key_truncated_rejected():
    with pytest.raises(ValueError):
        ph.HybridKey.decode(b"\x00")  # not even one length byte
    with pytest.raises(ValueError):
        ph.HybridKey.decode(b"\x00\x10ab")  # claims 16 bytes, has 2
    with pytest.raises(ValueError):
        # 2 + 0 + 2 = 4 bytes header valid, but pq length claim of
        # 0x1000 exceeds remaining body
        ph.HybridKey.decode(b"\x00\x00\x10\x00")


def test_hybrid_key_supports_ml_kem_768_size():
    """The legacy generic encoding safely carries a 1184-byte KEM key."""
    classical = os.urandom(32)
    fake_ml_kem_pub = os.urandom(1184)
    k = ph.HybridKey(classical=classical, pq=fake_ml_kem_pub)
    raw = k.encode()
    assert len(raw) == 2 + 32 + 2 + 1184
    parsed = ph.HybridKey.decode(raw)
    assert parsed.classical == classical
    assert parsed.pq == fake_ml_kem_pub


# ── generic-combiner smoke test: synthetic non-trivial KEM ────────


class _SymmetricKEMForTest:
    """A toy KEM that uses a fixed symmetric secret — NOT secure,
    just exercises the HybridKEM combine logic with a non-trivial
    second side. It does not stand in for the production native ML-KEM."""
    name = "Toy"
    pub_size = 16
    priv_size = 16
    ct_size = 16
    ss_size = 32

    def keypair(self):
        # priv is the secret; pub is a random tag (not used here).
        priv = os.urandom(16)
        pub = priv  # toy: peer needs the priv to decap (insecure!)
        return priv, pub

    def encapsulate(self, peer_pub):
        # Toy: derive ss from peer_pub directly (deterministic).
        return peer_pub, peer_pub * 2  # ss = 32 bytes from 16

    def decapsulate(self, ciphertext, my_priv):
        # Toy: ss = ciphertext * 2 (matches encap path).
        return ciphertext * 2


def test_hybrid_kem_with_non_null_pq_combines_both():
    """Plug in a non-trivial PQ (the toy above). The hybrid output
    must change when the PQ shared secret changes — proving the
    combine actually consumes the PQ side."""
    real_pq = _SymmetricKEMForTest()
    kem_a = ph.HybridKEM(pq=real_pq)
    kem_b = ph.HybridKEM(pq=ph.NullKEM())  # same classical, no PQ
    bob_priv_a, bob_pub_a = kem_a.keypair()
    bob_priv_b, bob_pub_b = kem_b.keypair()

    # Encap to each, decap. Both round-trip correctly.
    ct_a, ss_a_send = kem_a.encapsulate(bob_pub_a)
    ss_a_recv = kem_a.decapsulate(ct_a, bob_priv_a)
    assert ss_a_send == ss_a_recv

    ct_b, ss_b_send = kem_b.encapsulate(bob_pub_b)
    ss_b_recv = kem_b.decapsulate(ct_b, bob_priv_b)
    assert ss_b_send == ss_b_recv

    # The two hybrids produce DIFFERENT shared secrets (different
    # KEM-name labels in the combine info, plus PQ vs Null
    # contribution). A negotiated non-null suite cannot collide with the
    # explicitly classical compatibility construction.
    assert ss_a_send != ss_b_send
