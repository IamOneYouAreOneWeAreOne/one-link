"""Acceptance test for the row 9 wiring of native threshold recovery
into social_recovery.py (the wrap-shares / combine-shares end-to-end
flow).

These tests only run when one_link_native.threshold_recovery is
available — they prove the native path is actually exercised by the
daemon's social recovery flow."""

from __future__ import annotations

import os

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _native_available() -> bool:
    try:
        from one_link_native import threshold_recovery  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.threshold_recovery not installed",
)


def _ed25519_keypairs(n: int):
    """Return list of (seed_bytes_32, pubkey_bytes_32) tuples."""
    keys = []
    for _ in range(n):
        sk = Ed25519PrivateKey.generate()
        seed = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pk = sk.public_key().public_bytes_raw()
        keys.append((seed, pk))
    return keys


def test_social_recovery_uses_native_when_available():
    """The module-level _NATIVE_AVAILABLE flag should be True."""
    from one_link import social_recovery as sr

    assert sr._NATIVE_AVAILABLE is True


def test_social_recovery_round_trip_via_native():
    """Wrap + unwrap + combine round-trips correctly with native
    Shamir on the inside."""
    from one_link import social_recovery as sr

    seed = os.urandom(32)
    guardians = _ed25519_keypairs(5)
    guardian_pubkeys = [pk for _seed, pk in guardians]

    # Wrap.
    wrapped = sr.split_and_wrap(
        seed=seed,
        contact_ed_pubs=guardian_pubkeys,
        threshold_k=3,
        total_n=5,
    )
    assert len(wrapped) == 5
    assert len(wrapped) == 5

    # Each guardian unwraps their own share.
    unwrapped_pairs = []
    for guardian_seed, _guardian_pk in guardians:
        for w in wrapped:
            try:
                share_idx, share_bytes = sr.unwrap_share(
                    wrapped=w.encoded, my_ed_priv_seed=guardian_seed
                )
                unwrapped_pairs.append((share_idx, share_bytes))
                break
            except Exception:
                continue

    # Should have 5 successful unwraps (one per guardian).
    assert len(unwrapped_pairs) == 5

    # Combine any 3.
    seed_recovered = sr.combine_shares(unwrapped_pairs[:3])
    assert seed_recovered == seed

    # Different subset of 3 also works.
    seed_recovered_2 = sr.combine_shares(unwrapped_pairs[2:])
    assert seed_recovered_2 == seed


def test_social_recovery_below_threshold_fails():
    """Combining < threshold shares should NOT reconstruct the seed."""
    from one_link import social_recovery as sr

    seed = os.urandom(32)
    guardians = _ed25519_keypairs(5)
    guardian_pubkeys = [pk for _seed, pk in guardians]

    wrapped = sr.split_and_wrap(
        seed=seed,
        contact_ed_pubs=guardian_pubkeys,
        threshold_k=3,
        total_n=5,
    )
    assert len(wrapped) == 5
    unwrapped_pairs = []
    for guardian_seed, _ in guardians:
        for w in wrapped:
            try:
                share_idx, share_bytes = sr.unwrap_share(
                    wrapped=w.encoded, my_ed_priv_seed=guardian_seed
                )
                unwrapped_pairs.append((share_idx, share_bytes))
                break
            except Exception:
                continue

    # With only 2 shares, combine produces SOMETHING (the wrong seed)
    # — Shamir is information-theoretic so 2 < threshold reveals
    # nothing about the secret. Reconstructed value != real seed.
    try:
        wrong_seed = sr.combine_shares(unwrapped_pairs[:2])
        assert wrong_seed != seed
    except ValueError:
        # Some impls raise instead of returning garbage; that's also OK.
        pass


def test_split_compat_and_combine_compat_round_trip():
    """The native split_compat / combine_compat pair round-trips
    independently of social_recovery."""
    from one_link import threshold_recovery_native as tr

    secret = os.urandom(32)
    shares = tr.split_compat(secret, threshold=3, num_shares=5)
    assert len(shares) == 5
    for i, (x, y) in enumerate(shares):
        assert x == i + 1
        assert len(y) == 32

    # Combine any 3 shares.
    recovered = tr.combine_compat(shares[:3], threshold=3)
    assert recovered == secret

    recovered_2 = tr.combine_compat(shares[2:], threshold=3)
    assert recovered_2 == secret


def test_split_compat_rejects_bad_params():
    from one_link import threshold_recovery_native as tr

    with pytest.raises((ValueError, TypeError)):
        tr.split_compat(b"x", threshold=3, num_shares=2)  # k > n
    with pytest.raises((ValueError, TypeError)):
        tr.split_compat(b"", threshold=3, num_shares=5)  # empty secret
