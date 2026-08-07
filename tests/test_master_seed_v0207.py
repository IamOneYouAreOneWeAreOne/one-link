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
import random
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


def _swap_one_word(seed: bytes, position: int = 5) -> str:
    """A phrase with exactly one word replaced by a different valid word."""
    words = mnemonic.encode(seed).split()
    for w in ("zebra", "yellow", "voyage", "able"):
        if w != words[position]:
            words[position] = w
            break
    return " ".join(words)


def test_mnemonic_typo_caught_by_checksum():
    """A one-word typo is rejected -- DETERMINISTICALLY.

    This used to draw `os.urandom(32)` every run. BIP-39 at 256 bits carries an EIGHT-BIT
    checksum, so a single-word substitution passes by chance about 1 time in 256: the test
    failed roughly 0.4% of runs, and every one of those failures would be read as flakiness
    and re-run away. Measured on this machine: 19 misses in 4000 trials, 1 in 211.

    A security test whose verdict is a coin flip is worse than no test -- it trains everyone
    to ignore it. Fixed seed, so this either always passes or always fails.
    """
    seed = bytes.fromhex(
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
    with pytest.raises(ValueError, match="checksum"):
        mnemonic.decode(_swap_one_word(seed))


def test_a_one_word_typo_is_caught_only_255_TIMES_IN_256():
    """The property the deterministic test above deliberately hides, stated out loud.

    An 8-bit checksum cannot catch every single-word typo, and a user restoring a wallet
    deserves to know that recovery can succeed onto the WRONG seed. This measures the real
    rate rather than implying the check is total.

    Seeded RNG so the measurement is reproducible -- a flaky test about flakiness would be
    an unusually poor joke.
    """
    rng = random.Random(0xC0FFEE)
    trials, missed = 2000, 0
    for _ in range(trials):
        seed = bytes(rng.getrandbits(8) for _ in range(32))
        try:
            mnemonic.decode(_swap_one_word(seed))
            missed += 1
        except ValueError:
            pass

    rate = missed / trials
    # An 8-bit checksum gives 1/256 = 0.39%. Bounds are wide enough that ordinary sampling
    # noise cannot fail this, and tight enough that a checksum silently shrinking to 4 bits
    # (1/16) or vanishing entirely would.
    assert 0.0005 < rate < 0.02, (
        f"single-word typos slip through {missed}/{trials} = {rate:.4%}. Expected ~0.39% for "
        "an 8-bit checksum; far above means the checksum weakened, far below means this "
        "measurement stopped measuring anything")


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
