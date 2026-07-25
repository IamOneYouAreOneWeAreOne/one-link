"""Acceptance tests for proximity_pair_native (Phase F1.4 wiring)."""

from __future__ import annotations

import pytest


def _native_available() -> bool:
    try:
        from one_link_native import proximity_pair  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.proximity_pair not installed",
)


def test_module_imports():
    from one_link import proximity_pair_native as pp

    assert pp.HAS_NATIVE is True
    assert pp.AMPLIFIED_KEY_BYTES == 32
    assert pp.OBSERVATION_BYTES_DEFAULT == 128
    assert pp.SYNDROME_BLOCK_BITS_DEFAULT == 8
    assert pp.CASCADE_PASSES_DEFAULT == 4
    assert pp.PRODUCTION_FACTOR2_AVAILABLE is False


def test_quantize_observations_basic():
    from one_link import proximity_pair_native as pp

    obs = bytes((i * 17) % 256 for i in range(256))
    bits = pp.quantize_observations(obs, min_bytes=128, guard_band=0.1)
    # All bits must be 0 or 1.
    assert all(b in (0, 1) for b in bits)
    # Both classes present (non-trivial input distribution).
    assert 0 in bits
    assert 1 in bits


def test_quantize_observation_too_short_raises():
    from one_link import proximity_pair_native as pp

    with pytest.raises(ValueError):
        pp.quantize_observations(b"too short", min_bytes=128)


def test_block_syndrome_deterministic():
    from one_link import proximity_pair_native as pp

    bits = bytes([1, 0, 1, 1, 0, 0, 1, 0] * 8)
    s1 = pp.block_syndrome(bits, block_bits=8)
    s2 = pp.block_syndrome(bits, block_bits=8)
    assert s1 == s2
    assert len(s1) == 8  # 64 bits / 8 = 8 blocks


def test_reconcile_aligns_block_parities():
    from one_link import proximity_pair_native as pp

    # Peer + me, with one bit flipped in my version.
    peer = bytes([1, 0, 1, 1, 0, 0, 1, 0] * 8)  # 64 bits
    my = bytearray(peer)
    my[5] ^= 1
    peer_syn = pp.block_syndrome(peer)
    reconciled = pp.reconcile_with_syndrome(bytes(my), peer_syn)
    # After reconciliation, block syndromes match.
    rec_syn = pp.block_syndrome(reconciled)
    assert rec_syn == peer_syn


def test_multi_pass_syndromes_length():
    from one_link import proximity_pair_native as pp

    bits = bytes([1, 0] * 64)
    syndromes = pp.multi_pass_syndromes(bits, block_bits=8, passes=4)
    assert len(syndromes) == 4
    # Each syndrome is one byte per block.
    for s in syndromes:
        assert len(s) == 128 // 8  # 16 blocks


def test_multi_pass_roundtrip_aligns_block_parities():
    from one_link import proximity_pair_native as pp

    peer = bytes([(i * 7) & 1 for i in range(512)])
    my = bytearray(peer)
    for pos in (10, 50, 100):
        my[pos] ^= 1
    seed = 0xCAFE_BABE
    syndromes = pp.multi_pass_syndromes(
        peer, block_bits=8, passes=4, permutation_seed=seed
    )
    reconciled = pp.multi_pass_reconcile(
        bytes(my),
        syndromes,
        block_bits=8,
        passes=4,
        permutation_seed=seed,
    )
    # Post-CASCADE: last-pass syndrome of reconciled matches.
    from one_link_native import proximity_pair as _np
    last_perm = _np.permutation_for_pass(seed, 3, len(reconciled))
    permuted = bytes(reconciled[p] for p in last_perm)
    final_syn = pp.block_syndrome(permuted, block_bits=8)
    assert final_syn == syndromes[3]


def test_privacy_amplify_deterministic():
    from one_link import proximity_pair_native as pp

    bits = bytes([1, 0, 1, 1, 0, 0, 1, 0])
    salt = b"x" * 32
    k1 = pp.privacy_amplify(bits, salt=salt)
    k2 = pp.privacy_amplify(bits, salt=salt)
    assert k1 == k2
    assert len(k1) == 32


def test_privacy_amplify_salt_size_validated():
    from one_link import proximity_pair_native as pp

    with pytest.raises(ValueError):
        pp.privacy_amplify(b"\x01\x00", salt=b"too short")


def test_privacy_amplify_different_salt_yields_different_key():
    from one_link import proximity_pair_native as pp

    bits = bytes([1, 0] * 8)
    k1 = pp.privacy_amplify(bits, salt=b"\x01" * 32)
    k2 = pp.privacy_amplify(bits, salt=b"\x02" * 32)
    assert k1 != k2


def test_research_pipeline_returns_explicitly_unconfirmed_candidate():
    from one_link import proximity_pair_native as pp

    # Alice + Bob co-located (tiny perturbation).
    base = bytes((i * 7 + 13) % 256 for i in range(512))
    alice_obs = base
    bob_obs = bytearray(base)
    bob_obs[5] = (bob_obs[5] + 1) % 256
    bob_obs[100] = (bob_obs[100] - 1) % 256

    bob_bits = pp.quantize_observations(bytes(bob_obs))
    bob_syndrome = pp.block_syndrome(bob_bits)

    salt = b"OL-proximity-pair-v1-default-sal"
    alice_key = pp.derive_unconfirmed_candidate(
        my_observations=alice_obs,
        peer_syndrome=bob_syndrome,
        salt=salt,
    )
    assert len(alice_key) == 32
    # Fixed-size research output only; this is not an agreement assertion.


def test_legacy_factor2_secret_api_fails_closed_even_with_valid_inputs():
    from one_link import proximity_pair_native as pp

    with pytest.raises(pp.Factor2UnavailableError, match="not available"):
        pp.derive_factor2_secret(
            my_observations=bytes(range(256)) * 2,
            peer_syndrome=b"\x00" * 64,
            salt=b"x" * 32,
        )


def test_hamming_reconcile_byte_identical_at_low_error_rate():
    """Restricted SEC fixture: <=1 error per 120-bit block converges.

    This does not establish real observation alignment, entropy, proximity,
    or a production Factor-2 key.
    """
    from one_link import proximity_pair_native as pp

    # Alice's bits = Bob's bits with 3 errors spread across 3 blocks.
    bob_bits = bytes(((i * 13 + 7) & 1) for i in range(360))  # 3 blocks
    alice_bits = bytearray(bob_bits)
    alice_bits[10] ^= 1   # block 0
    alice_bits[150] ^= 1  # block 1
    alice_bits[330] ^= 1  # block 2

    bob_parity = pp.hamming_parity(bob_bits)
    alice_reconciled = pp.hamming_reconcile(bytes(alice_bits), bob_parity)

    # BIT-IDENTICAL output.
    assert alice_reconciled == bob_bits

    # Privacy amplify both sides with same salt → same key.
    salt = b"OL-proximity-pair-v1-default-sal"
    alice_key = pp.privacy_amplify(alice_reconciled, salt=salt)
    bob_key = pp.privacy_amplify(bob_bits, salt=salt)
    assert alice_key == bob_key, "byte-identical keys after Hamming reconciliation"


def test_hamming_parity_length():
    """Parity output length matches the Hamming(127,120) block structure."""
    from one_link import proximity_pair_native as pp

    # 240 bits = 2 full blocks → 14 parity bytes
    bits = bytes(((i * 7) & 1) for i in range(240))
    p = pp.hamming_parity(bits)
    assert len(p) == 14

    # 130 bits = 1 full + 1 partial → 14 parity bytes (partial padded)
    bits = bytes(((i * 7) & 1) for i in range(130))
    p = pp.hamming_parity(bits)
    assert len(p) == 14


def test_unrelated_fixture_derives_different_unconfirmed_candidate():
    from one_link import proximity_pair_native as pp

    alice_obs = bytes((i * 7) % 256 for i in range(512))
    attacker_obs = bytes((i * 19 + 50) % 256 for i in range(512))
    salt = b"x" * 32

    alice_bits = pp.quantize_observations(alice_obs)
    alice_syn = pp.block_syndrome(alice_bits)
    alice_key = pp.derive_unconfirmed_candidate(
        my_observations=alice_obs,
        peer_syndrome=alice_syn,
        salt=salt,
    )
    attacker_key = pp.derive_unconfirmed_candidate(
        my_observations=attacker_obs,
        peer_syndrome=alice_syn,  # attacker has alice's syndrome but wrong obs
        salt=salt,
    )
    # This deterministic fixture differs; it is not a security or proximity
    # proof and the candidates are never accepted as keys here.
    assert alice_key != attacker_key
