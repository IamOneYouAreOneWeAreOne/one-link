"""v0.20.7 master-seed + BIP-39 backup phrase recovery.

Pins:
  - mnemonic encode/decode round-trip on random seeds.
  - Checksum catches any single-word typo.
  - master_seed persistence across calls (DPAPI on Windows, raw
    bytes-with-0o600 elsewhere).
  - Distinct domain-separated subkey derivations (DRK ≠ identity ≠
    cluster-seed even from the same master seed).
  - Identity derivation produces a usable Ed25519 keypair.
  - Two daemons starting from the SAME master seed derive
    byte-identical identities — the recovery property the
    user-visible 24-word backup phrase relies on.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from one_link import master_seed, mnemonic


# ── mnemonic encode/decode ──────────────────────────────────────────


def test_mnemonic_round_trip_random():
    for _ in range(50):
        seed = os.urandom(32)
        phrase = mnemonic.encode(seed)
        assert len(phrase.split()) == 24
        assert mnemonic.decode(phrase) == seed


def test_mnemonic_typo_caught_by_checksum():
    seed = os.urandom(32)
    phrase = mnemonic.encode(seed)
    words = phrase.split()
    # Swap one word for another from the wordlist.
    swapped = words[:]
    # Pick a different valid word at position 5.
    for w in ("zebra", "yellow", "voyage", "able"):
        if w != swapped[5]:
            swapped[5] = w
            break
    typo_phrase = " ".join(swapped)
    with pytest.raises(ValueError, match="checksum"):
        mnemonic.decode(typo_phrase)


def test_mnemonic_unknown_word_rejected():
    with pytest.raises(ValueError, match="unknown BIP-39 word"):
        mnemonic.decode("not " * 23 + "real")


def test_mnemonic_wrong_count_rejected():
    with pytest.raises(ValueError, match="must be 24 words"):
        mnemonic.decode("abandon " * 12)
    with pytest.raises(ValueError, match="must be 24 words"):
        mnemonic.decode("")


def test_mnemonic_normalizes_case_and_whitespace():
    seed = os.urandom(32)
    phrase = mnemonic.encode(seed)
    # Add extra whitespace + uppercase. decode should still work.
    messy = "   " + phrase.upper().replace(" ", "  \t  ") + "   "
    assert mnemonic.decode(messy) == seed


def test_mnemonic_is_valid_helper():
    seed = os.urandom(32)
    phrase = mnemonic.encode(seed)
    assert mnemonic.is_valid(phrase) is True
    assert mnemonic.is_valid("garbage word " * 8) is False


def test_mnemonic_completion_helper():
    matches = list(mnemonic.words_for_completion("abou"))
    # The BIP-39 wordlist has exactly one word starting with "abou".
    assert matches == ["about"]


# ── master seed persistence ─────────────────────────────────────────


def test_master_seed_load_or_create_round_trip(tmp_path: Path):
    seed1, created1 = master_seed.load_or_create_seed(tmp_path)
    assert created1 is True
    assert len(seed1) == 32
    seed2, created2 = master_seed.load_or_create_seed(tmp_path)
    assert created2 is False
    assert seed1 == seed2


def test_master_seed_has_seed_helper(tmp_path: Path):
    assert master_seed.has_seed(tmp_path) is False
    master_seed.load_or_create_seed(tmp_path)
    assert master_seed.has_seed(tmp_path) is True


def test_master_seed_store_explicit(tmp_path: Path):
    canned = bytes(range(32))
    master_seed.store_seed(tmp_path, canned)
    assert master_seed.load_seed(tmp_path) == canned


def test_master_seed_load_returns_none_when_absent(tmp_path: Path):
    assert master_seed.load_seed(tmp_path) is None


def test_master_seed_store_rejects_wrong_length(tmp_path: Path):
    with pytest.raises(ValueError, match="32 bytes"):
        master_seed.store_seed(tmp_path, b"too short")


# ── derived keys are domain-separated ────────────────────────────────


def test_derived_keys_are_distinct(tmp_path: Path):
    """The DRK, identity-priv, and cluster-seed all derive from the
    same master seed but via distinct HKDF info strings — so a leak
    of one doesn't compromise the others. Test: byte-equality fails
    for every pair."""
    seed = bytes(range(32))
    drk = master_seed.derive_drk(seed)
    ident_priv = master_seed.derive_identity_priv(seed)
    cluster = master_seed.derive_cluster_seed(seed)
    ident_raw = ident_priv.private_bytes_raw()
    assert drk != ident_raw
    assert drk != cluster
    assert ident_raw != cluster
    assert len(drk) == 32 and len(cluster) == 32 and len(ident_raw) == 32


def test_derived_keys_are_deterministic(tmp_path: Path):
    """Same seed → same derived keys, byte-equal across calls.
    This is the property recovery relies on."""
    seed = bytes(range(32))
    drk_a = master_seed.derive_drk(seed)
    drk_b = master_seed.derive_drk(seed)
    assert drk_a == drk_b
    ident_a = master_seed.derive_identity_priv(seed).private_bytes_raw()
    ident_b = master_seed.derive_identity_priv(seed).private_bytes_raw()
    assert ident_a == ident_b


# ── full recovery scenario ──────────────────────────────────────────


def test_full_recovery_phrase_round_trip(tmp_path: Path):
    """The user-facing scenario:
      1. Fresh install → daemon mints master seed, encodes BIP-39 phrase.
      2. User writes down phrase.
      3. Laptop is destroyed.
      4. New laptop install → user types phrase → daemon stores
         the decoded seed.
      5. Identity + DRK derived from the restored seed are
         byte-identical to the original.
    Pins the recovery promise: same phrase → same identity →
    peers continue to recognize.
    """
    # Step 1: original install.
    original_dir = tmp_path / "original"
    original_dir.mkdir()
    seed_orig, created = master_seed.load_or_create_seed(original_dir)
    assert created
    drk_orig = master_seed.derive_drk(seed_orig)
    ident_orig = master_seed.derive_identity_priv(seed_orig)
    fp_orig = ident_orig.public_key().public_bytes_raw()

    # Step 2: user-visible 24-word phrase.
    phrase = mnemonic.encode(seed_orig)
    assert len(phrase.split()) == 24

    # Step 4-5: new install. Different config dir, no existing seed.
    new_dir = tmp_path / "new"
    new_dir.mkdir()
    assert master_seed.load_seed(new_dir) is None

    # User types phrase → decode → store.
    seed_recovered = mnemonic.decode(phrase)
    master_seed.store_seed(new_dir, seed_recovered)

    seed_loaded = master_seed.load_seed(new_dir)
    assert seed_loaded == seed_orig
    drk_recovered = master_seed.derive_drk(seed_loaded)
    ident_recovered = master_seed.derive_identity_priv(seed_loaded)
    fp_recovered = ident_recovered.public_key().public_bytes_raw()

    # The whole point: byte-identical keys after recovery.
    assert drk_recovered == drk_orig
    assert fp_recovered == fp_orig


def test_two_independent_seeds_diverge(tmp_path: Path):
    """Sanity check: the recovery property doesn't accidentally
    mean "any user with any phrase becomes any user." Distinct seeds
    must yield distinct identities."""
    a = bytes([0x11] * 32)
    b = bytes([0x22] * 32)
    fp_a = master_seed.derive_identity_priv(a).public_key().public_bytes_raw()
    fp_b = master_seed.derive_identity_priv(b).public_key().public_bytes_raw()
    assert fp_a != fp_b
    drk_a = master_seed.derive_drk(a)
    drk_b = master_seed.derive_drk(b)
    assert drk_a != drk_b
