"""Shamir Secret Sharing primitive — pin every cryptographic property
the threshold-of-N cluster relies on.
"""
from __future__ import annotations

import os
import secrets

import pytest

from one_link.threshold import (
    Share, combine, combine_master_key, split, split_master_key,
)


# ── basic round-trip ─────────────────────────────────────────────────


def test_round_trip_2_of_3():
    secret = b"hunter2's master key blob 32 byt"
    assert len(secret) == 32
    shares = split(secret, threshold=2, num_shares=3)
    assert len(shares) == 3
    assert all(s.x in (1, 2, 3) for s in shares)
    assert all(len(s.y) == 32 for s in shares)
    # Any 2 of 3 reconstruct.
    for indices in [(0, 1), (0, 2), (1, 2)]:
        subset = [shares[i] for i in indices]
        assert combine(subset) == secret


def test_round_trip_3_of_5():
    secret = os.urandom(32)
    shares = split(secret, threshold=3, num_shares=5)
    # Every 3-subset reconstructs.
    from itertools import combinations
    for indices in combinations(range(5), 3):
        subset = [shares[i] for i in indices]
        assert combine(subset) == secret


def test_round_trip_arbitrary_length():
    for length in (1, 7, 16, 32, 64, 128, 256):
        secret = os.urandom(length)
        shares = split(secret, threshold=2, num_shares=3)
        assert combine(shares[:2]) == secret


# ── information-theoretic threshold property ────────────────────────


def test_one_share_alone_is_zero_knowledge():
    """k-of-N with k>1: holding ONE share reveals NO information
    about the secret. Specifically: for any 1-share, every possible
    secret is equally consistent with that share (because we can
    pick coefficients to interpolate any secret through that share).
    Test: split TWO different secrets, get share #1 from each; the
    distributions over share #1 should be statistically
    indistinguishable (both uniform over GF(256) per byte)."""
    n = 1000
    secret_a = b"\x00" * 32
    secret_b = b"\xff" * 32
    a_share1_bytes = bytearray()
    b_share1_bytes = bytearray()
    for _ in range(n):
        sa = split(secret_a, threshold=2, num_shares=3)
        sb = split(secret_b, threshold=2, num_shares=3)
        a_share1_bytes += sa[0].y
        b_share1_bytes += sb[0].y
    # Both sample sets should have ~uniform byte distribution.
    # We don't do a full chi-square; just check the means are close
    # to the expected 127.5 within a generous tolerance.
    a_mean = sum(a_share1_bytes) / len(a_share1_bytes)
    b_mean = sum(b_share1_bytes) / len(b_share1_bytes)
    assert abs(a_mean - 127.5) < 5.0, a_mean
    assert abs(b_mean - 127.5) < 5.0, b_mean


def test_extra_shares_dont_break_reconstruction():
    """Caller may supply MORE than threshold shares; the math
    over-determines but converges to the same answer."""
    secret = os.urandom(32)
    shares = split(secret, threshold=2, num_shares=5)
    # All 5 → still reconstructs.
    assert combine(shares) == secret
    # 3 → reconstructs (over-determined for threshold=2).
    assert combine(shares[:3]) == secret


# ── error handling ───────────────────────────────────────────────────


def test_split_rejects_invalid_threshold():
    with pytest.raises(ValueError, match="threshold must satisfy"):
        split(b"x", threshold=1, num_shares=3)
    with pytest.raises(ValueError, match="threshold must satisfy"):
        split(b"x", threshold=4, num_shares=3)
    with pytest.raises(ValueError, match="threshold must satisfy"):
        split(b"x", threshold=2, num_shares=256)


def test_split_rejects_empty_secret():
    with pytest.raises(ValueError, match="at least 1 byte"):
        split(b"", threshold=2, num_shares=3)


def test_combine_rejects_duplicate_indices():
    s = Share(x=5, y=b"abc")
    with pytest.raises(ValueError, match="duplicate share index"):
        combine([s, s])


def test_combine_rejects_inconsistent_lengths():
    a = Share(x=1, y=b"ab")
    b = Share(x=2, y=b"abc")
    with pytest.raises(ValueError, match="inconsistent lengths"):
        combine([a, b])


def test_combine_rejects_too_few_shares():
    with pytest.raises(ValueError, match="at least 2 shares"):
        combine([Share(x=1, y=b"ab")])


# ── deterministic mode (testing only) ───────────────────────────────


def test_deterministic_split_via_caller_randomness():
    """When the caller supplies randomness explicitly, the split
    is deterministic. Used by unit tests to pin exact wire bytes;
    NEVER used in production."""
    secret = b"\x00\x01\x02\x03"
    randomness = b"\xaa\xbb\xcc\xdd"  # 4 bytes for threshold=2,
    # which needs (threshold-1)*len(secret) = 1*4 = 4 bytes
    shares_a = split(
        secret, threshold=2, num_shares=3, randomness=randomness,
    )
    shares_b = split(
        secret, threshold=2, num_shares=3, randomness=randomness,
    )
    assert shares_a == shares_b


def test_deterministic_split_wrong_randomness_length_rejects():
    with pytest.raises(ValueError, match="randomness must be"):
        split(b"abc", threshold=3, num_shares=4, randomness=b"x")


# ── high-level master-key helpers ────────────────────────────────────


def test_master_key_round_trip_2_of_3():
    """Mirrors the canonical "3 devices, threshold 2" cluster bootstrap.
    Each share blob is 33 bytes (1 index byte + 32 share bytes)."""
    master = secrets.token_bytes(32)
    blobs = split_master_key(master, n_devices=3, threshold=2)
    assert len(blobs) == 3
    assert all(len(b) == 33 for b in blobs)
    # Any 2 reconstruct.
    assert combine_master_key(blobs[:2]) == master
    assert combine_master_key(blobs[1:]) == master
    assert combine_master_key([blobs[0], blobs[2]]) == master


def test_master_key_helper_rejects_wrong_length():
    with pytest.raises(ValueError, match="32 bytes"):
        split_master_key(b"too short", n_devices=3, threshold=2)


# ── share encoding round-trip ────────────────────────────────────────


def test_share_to_bytes_round_trip():
    s = Share(x=42, y=b"\x01\x02\x03\x04")
    blob = s.to_bytes()
    assert blob[0] == 42
    assert blob[1:] == s.y
    parsed = Share.from_bytes(blob)
    assert parsed == s


def test_share_to_bytes_rejects_invalid_index():
    with pytest.raises(ValueError):
        Share(x=0, y=b"x").to_bytes()
    with pytest.raises(ValueError):
        Share(x=256, y=b"x").to_bytes()


# ── adversarial — wrong shares produce wrong (not arbitrary) output ─


def test_wrong_share_combo_yields_wrong_secret_not_crash():
    """If an attacker provides a forged share alongside legitimate
    ones, reconstruction produces a wrong secret rather than
    crashing or revealing the real one. The cluster protocol
    layered on top of this primitive is responsible for binding
    share-transmissions to authenticated channels (Ed25519 sig
    over each share's wire envelope) so this scenario doesn't
    arise; we test it here to document that the primitive
    silently fails-closed-with-garbage rather than fails-open."""
    real_secret = b"the real master key bytes 32 byt"
    real_shares = split(real_secret, threshold=2, num_shares=3)
    forged = Share(x=2, y=os.urandom(32))
    # Combine real share #1 + forged "share #2" → some random
    # 32 bytes that are NOT the real secret.
    result = combine([real_shares[0], forged])
    assert result != real_secret
    assert len(result) == 32  # right shape, wrong content


# ── stress: large secret + max participants ─────────────────────────


def test_max_participants_with_large_secret():
    secret = os.urandom(256)
    shares = split(secret, threshold=128, num_shares=255)
    assert combine(shares) == secret
    # Any 128-subset:
    import random
    random.seed(42)
    indices = random.sample(range(255), 128)
    subset = [shares[i] for i in indices]
    assert combine(subset) == secret
