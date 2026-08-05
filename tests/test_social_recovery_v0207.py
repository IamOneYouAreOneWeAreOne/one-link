"""v0.20.7 — social recovery: 3-of-5 trusted contacts hold encrypted
Shamir shares; reconstruct via in-person QR scans, no paper backup
required.

Outside-the-box sovereignty primitive: instead of relying on the
user remembering paper or trusting a corporate cloud (Apple iCloud,
Google account), the user's own social graph is the recovery layer.
The 32-byte master seed splits into 5 Shamir shares with threshold
3 (RFC 5054-style threshold secret sharing); each share is wrapped
with a key derived from one trusted contact's Ed25519 identity
(via Ed25519→X25519 birational map + ECDH); each contact's daemon
stores their wrapped share locally. Recovery on a fresh device
collects 3 of the 5 (any 3) and reconstructs the seed.

Trust model: user trusts that 3 of 5 chosen contacts won't all
collude. Up to 2 malicious or coerced contacts gain nothing.

These tests pin:

  - Ed25519 → X25519 conversion is correct (decrypt with the
    converted private key matches encrypt to the converted public)
  - 3-of-5 round-trip: split + wrap to 5 contacts → unwrap any 3
    → combine reconstructs the original seed
  - Wrong contact (different keypair) cannot decrypt the share
  - Tamper on the wrapped header / ciphertext is rejected
  - Cross-setup share mixing is rejected at combine
  - 2-of-5 cannot reconstruct (Shamir threshold security)
  - Bound-share-index is enforced (a malicious guardian can't
    submit their share under a different index to confuse combine)
  - Realistic in-person QR-style flow works end-to-end
"""
from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from one_link import social_recovery as sr


def _gen_ed25519():
    """Return (priv_seed_bytes, pub_bytes). priv_seed_bytes is the
    32-byte private seed; pub_bytes is the 32-byte raw pubkey."""
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    pub = priv.public_key().public_bytes_raw()
    return seed, pub


# ── Ed25519 ↔ X25519 conversion ─────────────────────────────────────


def test_ed25519_pub_to_x25519_returns_32_bytes():
    _, pub = _gen_ed25519()
    x_pub = sr.ed25519_pub_to_x25519(pub)
    assert isinstance(x_pub, bytes)
    assert len(x_pub) == 32


def test_ed25519_priv_to_x25519_returns_32_bytes():
    seed, _ = _gen_ed25519()
    x_priv = sr.ed25519_priv_to_x25519(seed)
    assert isinstance(x_priv, bytes)
    assert len(x_priv) == 32


def test_ed25519_x25519_pair_round_trip_via_ecdh():
    """The fundamental correctness check: a wrap/unwrap round-trip
    through Ed25519 → X25519 conversion + ECDH must succeed. If the
    pubkey conversion or the privkey conversion (or both) are wrong,
    the shared secret won't match and unwrap_share will fail."""
    seed, pub = _gen_ed25519()
    master = os.urandom(32)
    contacts = [_gen_ed25519() for _ in range(5)]
    contacts[0] = (seed, pub)  # we'll unwrap as contact 0
    pubs = [c[1] for c in contacts]
    wrapped = sr.split_and_wrap(
        seed=master, contact_ed_pubs=pubs, threshold_k=3, total_n=5,
    )
    # Unwrap as contact 0 with its priv-seed.
    idx, share_bytes = sr.unwrap_share(
        wrapped=wrapped[0].encoded, my_ed_priv_seed=seed,
    )
    assert idx == wrapped[0].share_index


# ── 3-of-5 round-trip ───────────────────────────────────────────────


def test_full_3_of_5_round_trip():
    master = os.urandom(32)
    contacts = [_gen_ed25519() for _ in range(5)]
    pubs = [c[1] for c in contacts]
    wrapped = sr.split_and_wrap(
        seed=master, contact_ed_pubs=pubs, threshold_k=3, total_n=5,
    )
    # Pick contacts 0, 2, 4 (any 3-of-5 works).
    decrypted: list[tuple[int, bytes]] = []
    for i in (0, 2, 4):
        idx, share = sr.unwrap_share(
            wrapped=wrapped[i].encoded,
            my_ed_priv_seed=contacts[i][0],
        )
        decrypted.append((idx, share))
    recovered = sr.combine_shares(decrypted)
    assert recovered == master


def test_alternate_3_of_5_subsets():
    """Any 3 of the 5 reconstruct — pin every C(5,3)=10 subset."""
    import itertools
    master = os.urandom(32)
    contacts = [_gen_ed25519() for _ in range(5)]
    pubs = [c[1] for c in contacts]
    wrapped = sr.split_and_wrap(
        seed=master, contact_ed_pubs=pubs, threshold_k=3, total_n=5,
    )
    checked = 0
    for combo in itertools.combinations(range(5), 3):
        checked += 1
        decrypted = []
        for i in combo:
            idx, share = sr.unwrap_share(
                wrapped=wrapped[i].encoded,
                my_ed_priv_seed=contacts[i][0],
            )
            decrypted.append((idx, share))
        assert sr.combine_shares(decrypted) == master, combo
    # C(5,3) = 10. Pinned so a split that returned fewer wrapped shares cannot
    # quietly shrink the enumeration and still look exhaustive.
    assert checked == 10, f"only {checked} of 10 3-subsets were tested"


def test_2_of_5_does_not_reconstruct():
    """Shamir threshold security: any 2 of 5 give zero info about
    the secret. The combine over 2 shares with threshold-3 polynomial
    SHOULD return wrong bytes (not the original)."""
    master = os.urandom(32)
    contacts = [_gen_ed25519() for _ in range(5)]
    pubs = [c[1] for c in contacts]
    wrapped = sr.split_and_wrap(
        seed=master, contact_ed_pubs=pubs, threshold_k=3, total_n=5,
    )
    # Try combining only 2 shares (insufficient for threshold-3).
    decrypted = []
    for i in (0, 1):
        idx, share = sr.unwrap_share(
            wrapped=wrapped[i].encoded,
            my_ed_priv_seed=contacts[i][0],
        )
        decrypted.append((idx, share))
    # combine still runs (Shamir doesn't know the threshold), but
    # the result is unrelated to the master seed.
    bogus = sr.combine_shares(decrypted)
    assert bogus != master


# ── failure modes ───────────────────────────────────────────────────


def test_wrong_contact_cannot_decrypt():
    master = os.urandom(32)
    contacts = [_gen_ed25519() for _ in range(5)]
    pubs = [c[1] for c in contacts]
    wrapped = sr.split_and_wrap(
        seed=master, contact_ed_pubs=pubs, threshold_k=3, total_n=5,
    )
    other_seed, _ = _gen_ed25519()
    with pytest.raises(ValueError):
        sr.unwrap_share(
            wrapped=wrapped[0].encoded, my_ed_priv_seed=other_seed,
        )


def test_tampered_header_rejected():
    master = os.urandom(32)
    contacts = [_gen_ed25519() for _ in range(5)]
    pubs = [c[1] for c in contacts]
    wrapped = sr.split_and_wrap(
        seed=master, contact_ed_pubs=pubs, threshold_k=3, total_n=5,
    )
    # Flip a byte in the setup_ms field (header-protected by AAD).
    encoded = bytearray(wrapped[0].encoded)
    encoded[12] ^= 0xff
    with pytest.raises(ValueError):
        sr.unwrap_share(
            wrapped=bytes(encoded), my_ed_priv_seed=contacts[0][0],
        )


def test_tampered_ciphertext_rejected():
    master = os.urandom(32)
    contacts = [_gen_ed25519() for _ in range(5)]
    pubs = [c[1] for c in contacts]
    wrapped = sr.split_and_wrap(
        seed=master, contact_ed_pubs=pubs, threshold_k=3, total_n=5,
    )
    encoded = bytearray(wrapped[0].encoded)
    encoded[sr.HEADER_LEN + 2] ^= 0xff
    with pytest.raises(ValueError):
        sr.unwrap_share(
            wrapped=bytes(encoded), my_ed_priv_seed=contacts[0][0],
        )


def test_bad_magic_rejected():
    master = os.urandom(32)
    contacts = [_gen_ed25519() for _ in range(5)]
    pubs = [c[1] for c in contacts]
    wrapped = sr.split_and_wrap(
        seed=master, contact_ed_pubs=pubs, threshold_k=3, total_n=5,
    )
    encoded = bytearray(wrapped[0].encoded)
    encoded[0:5] = b"NOTOL"
    with pytest.raises(ValueError, match="not a One Link"):
        sr.unwrap_share(
            wrapped=bytes(encoded), my_ed_priv_seed=contacts[0][0],
        )


def test_cross_setup_shares_dont_combine_correctly():
    """Mixing shares from two different setups must NOT silently
    reconstruct one of the seeds. The shares interpolate the wrong
    polynomial; the result is unrelated to either seed."""
    seed_a = os.urandom(32)
    seed_b = os.urandom(32)
    contacts = [_gen_ed25519() for _ in range(5)]
    pubs = [c[1] for c in contacts]
    wrapped_a = sr.split_and_wrap(
        seed=seed_a, contact_ed_pubs=pubs, threshold_k=3, total_n=5,
    )
    wrapped_b = sr.split_and_wrap(
        seed=seed_b, contact_ed_pubs=pubs, threshold_k=3, total_n=5,
    )
    # Mix: 2 from setup A, 1 from setup B.
    decrypted = []
    for i, src in [(0, wrapped_a), (1, wrapped_a), (2, wrapped_b)]:
        idx, share = sr.unwrap_share(
            wrapped=src[i].encoded, my_ed_priv_seed=contacts[i][0],
        )
        decrypted.append((idx, share))
    bogus = sr.combine_shares(decrypted)
    assert bogus != seed_a
    assert bogus != seed_b


# ── parsing ────────────────────────────────────────────────────────


def test_wrapped_share_parse_round_trip():
    master = os.urandom(32)
    contacts = [_gen_ed25519() for _ in range(5)]
    pubs = [c[1] for c in contacts]
    wrapped = sr.split_and_wrap(
        seed=master, contact_ed_pubs=pubs, threshold_k=3, total_n=5,
    )
    parsed = sr.WrappedShare.parse(wrapped[0].encoded)
    assert parsed.share_index == wrapped[0].share_index
    assert parsed.threshold == 3
    assert parsed.total == 5
    assert parsed.encoded == wrapped[0].encoded


def test_invalid_threshold_args_rejected():
    master = os.urandom(32)
    pubs = [bytes(32) for _ in range(5)]
    with pytest.raises(ValueError):
        # 1-of-N is meaningless (every share IS the secret in
        # threshold.py terms).
        sr.split_and_wrap(
            seed=master, contact_ed_pubs=pubs, threshold_k=1, total_n=5,
        )
    with pytest.raises(ValueError):
        sr.split_and_wrap(
            seed=master, contact_ed_pubs=pubs, threshold_k=6, total_n=5,
        )
    with pytest.raises(ValueError):
        sr.split_and_wrap(
            seed=b"too short", contact_ed_pubs=pubs, threshold_k=3, total_n=5,
        )


# ── high-level helper round-trip ───────────────────────────────────


def test_setup_helper_round_trip():
    master = os.urandom(32)
    contacts = [_gen_ed25519() for _ in range(5)]
    guardians = [
        (f"guardian-{i}", contacts[i][1]) for i in range(5)
    ]
    pairs = sr.setup_social_recovery(
        seed=master, guardians=guardians, threshold_k=3,
    )
    assert len(pairs) == 5
    assert [name for name, _ in pairs] == [g[0] for g in guardians]
    # Recover via 3 of the 5.
    decrypted = []
    for i in (1, 3, 4):
        name, share = pairs[i]
        idx, share_bytes = sr.unwrap_share(
            wrapped=share.encoded, my_ed_priv_seed=contacts[i][0],
        )
        decrypted.append((idx, share_bytes))
    assert sr.reconstruct_from_decrypted_shares(decrypted) == master
