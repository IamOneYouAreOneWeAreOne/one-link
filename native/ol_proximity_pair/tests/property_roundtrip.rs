//! Property tests for ol_proximity_pair primitives.
//! Matches the F1.1 bar: 1M iterations on the most-leveraged
//! properties.

use proptest::prelude::*;

use ol_proximity_pair::{
    block_syndrome, hamming_reconcile, parity_bits_for_block,
    parity_bits_for_string, permutation_for_pass, privacy_amplify,
    HAMMING_DATA_BITS,
};

fn cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        5_000_000
    } else {
        1_000_000
    }
}

fn light_cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        500_000
    } else {
        100_000
    }
}

// ── Properties: GF arithmetic ↔ quantize ↔ block_syndrome ────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(),
        max_global_rejects: cases() * 4,
        .. ProptestConfig::default()
    })]

    /// block_syndrome with block_size=8 on N bits produces ceil(N/8) bytes.
    #[test]
    fn block_syndrome_size_invariant(
        bits_count in 0usize..=512,
        seed in any::<u64>(),
    ) {
        let mut bits = vec![0u8; bits_count];
        let mut s = seed;
        for b in &mut bits {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = ((s >> 33) & 1) as u8;
        }
        let s8 = block_syndrome(&bits, 8);
        let expected = bits_count.div_ceil(8);
        prop_assert_eq!(s8.len(), expected);
    }

    /// XOR of all bits in a block matches that block's parity bit.
    #[test]
    fn block_syndrome_is_block_xor(
        bits in prop::collection::vec(any::<u8>(), 0..=256),
    ) {
        let bits01: Vec<u8> = bits.iter().map(|b| b & 1).collect();
        let s = block_syndrome(&bits01, 8);
        for (i, parity) in s.iter().enumerate() {
            let start = i * 8;
            let end = (start + 8).min(bits01.len());
            let expected: u8 = bits01[start..end].iter().fold(0, |a, b| a ^ b);
            prop_assert_eq!(*parity, expected);
        }
    }
}

// ── Properties: Hamming SEC ──────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: light_cases(),
        max_global_rejects: light_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Hamming roundtrip with NO error: parity matches, reconcile = input.
    #[test]
    fn hamming_no_error_is_identity(
        bits in prop::collection::vec(0u8..=1u8, 0..=480),
    ) {
        let parity = parity_bits_for_string(&bits);
        let r = hamming_reconcile(&bits, &parity);
        prop_assert_eq!(r, bits);
    }

    /// Hamming single-error correction is EXACT: flipping ONE data
    /// bit, then reconciling against peer-parity (= correct parity)
    /// produces the peer's bits byte-identical.
    #[test]
    fn hamming_single_error_correctly_decoded(
        peer_bits_seed in any::<u64>(),
        block_index in 0usize..3,
        error_position_in_block in 0usize..HAMMING_DATA_BITS,
    ) {
        // Build a 3-block-padded bit string.
        let total = 3 * HAMMING_DATA_BITS;
        let mut peer_bits = vec![0u8; total];
        let mut s = peer_bits_seed;
        for b in &mut peer_bits {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = ((s >> 33) & 1) as u8;
        }
        let peer_parity = parity_bits_for_string(&peer_bits);
        // Inject ONE error.
        let abs_pos = block_index * HAMMING_DATA_BITS + error_position_in_block;
        let mut my_bits = peer_bits.clone();
        my_bits[abs_pos] ^= 1;
        let reconciled = hamming_reconcile(&my_bits, &peer_parity);
        prop_assert_eq!(reconciled, peer_bits);
    }

    /// parity_bits_for_block roundtrips into its block's parity.
    #[test]
    fn hamming_parity_block_invariant(seed in any::<u64>()) {
        let mut bits = vec![0u8; HAMMING_DATA_BITS];
        let mut s = seed;
        for b in &mut bits {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = ((s >> 33) & 1) as u8;
        }
        let p1 = parity_bits_for_block(&bits);
        let p2 = parity_bits_for_block(&bits);
        prop_assert_eq!(p1, p2); // deterministic
    }
}

// ── Properties: Privacy amplification ────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases() / 5,
        .. ProptestConfig::default()
    })]

    /// Same (bits, salt) → same key.
    #[test]
    fn privacy_amplify_deterministic(
        bits in prop::collection::vec(0u8..=1u8, 1..=512),
        salt in any::<[u8; 32]>(),
    ) {
        let k1 = privacy_amplify(&bits, &salt);
        let k2 = privacy_amplify(&bits, &salt);
        prop_assert_eq!(k1, k2);
        prop_assert_eq!(k1.len(), 32);
    }

    /// Single-bit change in input → different key (avalanche).
    #[test]
    fn privacy_amplify_avalanche(
        bits in prop::collection::vec(0u8..=1u8, 8..=512),
        flip_pos_rand in any::<u32>(),
        salt in any::<[u8; 32]>(),
    ) {
        let flip_pos = (flip_pos_rand as usize) % bits.len();
        let k1 = privacy_amplify(&bits, &salt);
        let mut bits2 = bits.clone();
        bits2[flip_pos] ^= 1;
        let k2 = privacy_amplify(&bits2, &salt);
        prop_assert_ne!(k1, k2);
    }
}

// ── Properties: Permutation determinism ──────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases() / 10,
        .. ProptestConfig::default()
    })]

    /// permutation_for_pass(seed, pass, n) is a bijection on [0, n).
    #[test]
    fn permutation_is_bijection(
        seed in any::<u64>(),
        pass_idx in 0usize..32,
        n in 1usize..=256,
    ) {
        let perm = permutation_for_pass(seed, pass_idx, n);
        prop_assert_eq!(perm.len(), n);
        let mut seen = vec![false; n];
        for &p in &perm {
            prop_assert!(p < n);
            prop_assert!(!seen[p], "duplicate index {} in permutation", p);
            seen[p] = true;
        }
        prop_assert!(seen.iter().all(|&s| s));
    }

    /// Same seed + pass + n → same permutation.
    #[test]
    fn permutation_deterministic(
        seed in any::<u64>(),
        pass_idx in 0usize..32,
        n in 1usize..=128,
    ) {
        let p1 = permutation_for_pass(seed, pass_idx, n);
        let p2 = permutation_for_pass(seed, pass_idx, n);
        prop_assert_eq!(p1, p2);
    }
}
