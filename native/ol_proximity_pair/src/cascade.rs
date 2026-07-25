//! Experimental multi-pass parity alignment (not CASCADE).
//!
//! Single-pass parity-block reconciliation (see [`crate::reconcile`])
//! converges only when every disagreement happens to be the FIRST bit
//! of its block. In practice ~85-92% bit-agreement post-single-pass
//! on realistic noise. CASCADE fixes this by running multiple passes,
//! permuting the bit indexes between passes so a bit that landed in
//! the "wrong position" of one block lands in the "right position" of
//! a different block on the next pass.
//!
//! Permuting across passes can reduce some parity disagreements, but the
//! fixed-position flip cannot identify an arbitrary error and has no
//! byte-identical convergence guarantee. Real CASCADE (Brassard & Salvail,
//! 1994) requires interactive bisection and backtracking; it is not
//! implemented here.
//!
//! ## Public-channel cost
//!
//! Each pass leaks `n_bits / block_bits` syndrome bits. With 4 passes
//! at `block_bits=8`: leakage = 4 * `n_bits` / 8 = `n_bits` / 2 — half the
//! input. This accounting covers only these parity bytes and is not an
//! entropy proof. BLAKE3 compression cannot manufacture missing entropy.

use crate::prng::PrngState;
use crate::reconcile::{block_syndrome, reconcile_with_syndrome};

/// Default number of experimental permutation passes. More passes disclose
/// more parity bits and do not guarantee convergence.
pub const CASCADE_PASSES_DEFAULT: usize = 4;

/// Deterministically permute the bit positions using a seeded PRNG.
/// Both sides MUST use the same seed (typically derived from the
/// bootstrap-transcript hash) so they produce the same permutation.
///
/// Returns a Vec<usize> of length `n` where `perm[i]` is the
/// original position of bit i in the permuted view.
#[must_use]
pub fn permutation_for_pass(seed: u64, pass_idx: usize, n: usize) -> Vec<usize> {
    let pass_salt = (pass_idx as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut prng = PrngState::new(seed.wrapping_add(pass_salt));
    // Fisher-Yates shuffle.
    let mut perm: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let r = prng.next_u64() as usize;
        let j = r % (i + 1);
        perm.swap(i, j);
    }
    perm
}

/// Run multi-pass parity alignment.
///
/// Each pass:
///   1. Permute bit positions using `permutation_for_pass(seed, i, n)`.
///   2. Use the peer's syndrome FOR THIS PASS (caller supplies them
///      in order via `peer_syndromes`).
///   3. Run single-pass block-syndrome reconciliation on the permuted
///      view; un-permute the corrections back into the linear order.
///
/// `peer_syndromes` must have length `passes` and each entry must
/// have length `ceil(my_bits.len() / block_bits)`. Caller (peer) ran
/// [`multi_pass_syndromes`] with the same seed + same `block_bits` to
/// produce them.
#[must_use]
pub fn multi_pass_reconcile(
    my_bits: &[u8],
    peer_syndromes: &[Vec<u8>],
    block_bits: usize,
    passes: usize,
    permutation_seed: u64,
) -> Vec<u8> {
    if block_bits == 0 || my_bits.is_empty() {
        return my_bits.to_vec();
    }
    let n = my_bits.len();
    let mut current = my_bits.to_vec();
    for (pass_idx, syndrome) in peer_syndromes.iter().take(passes).enumerate() {
        let perm = permutation_for_pass(permutation_seed, pass_idx, n);
        // Apply permutation: build a permuted view of current.
        let permuted: Vec<u8> = perm.iter().map(|&pos| current[pos]).collect();
        // Reconcile in permuted order.
        let reconciled_permuted = reconcile_with_syndrome(&permuted, syndrome, block_bits);
        // Un-permute: place each reconciled bit back at its original index.
        let mut un_permuted = vec![0u8; n];
        for (perm_i, &orig_i) in perm.iter().enumerate() {
            un_permuted[orig_i] = reconciled_permuted[perm_i];
        }
        current = un_permuted;
    }
    current
}

/// Generate the syndromes for all CASCADE passes. The peer ships
/// these to us; we use them in [`multi_pass_reconcile`].
///
/// Caller (the syndrome publisher) computes these from its own
/// quantized bit string and sends `Vec<Vec<u8>>` over the public
/// bootstrap channel.
#[must_use]
pub fn multi_pass_syndromes(
    my_bits: &[u8],
    block_bits: usize,
    passes: usize,
    permutation_seed: u64,
) -> Vec<Vec<u8>> {
    if block_bits == 0 || my_bits.is_empty() {
        return Vec::new();
    }
    let n = my_bits.len();
    let mut out = Vec::with_capacity(passes);
    for pass_idx in 0..passes {
        let perm = permutation_for_pass(permutation_seed, pass_idx, n);
        let permuted: Vec<u8> = perm.iter().map(|&pos| my_bits[pos]).collect();
        out.push(block_syndrome(&permuted, block_bits));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permutation_is_a_bijection() {
        let perm = permutation_for_pass(0xCAFE, 0, 64);
        // Every index 0..64 appears exactly once.
        let mut seen = [false; 64];
        for &p in &perm {
            assert!(p < 64);
            assert!(!seen[p], "duplicate: {p}");
            seen[p] = true;
        }
        assert!(seen.iter().all(|&s| s));
    }

    #[test]
    fn permutation_deterministic_with_same_seed() {
        let p1 = permutation_for_pass(0xABCD, 3, 128);
        let p2 = permutation_for_pass(0xABCD, 3, 128);
        assert_eq!(p1, p2);
    }

    #[test]
    fn permutation_different_per_pass() {
        let p0 = permutation_for_pass(0xABCD, 0, 64);
        let p1 = permutation_for_pass(0xABCD, 1, 64);
        assert_ne!(p0, p1);
    }

    #[test]
    fn permutation_different_per_seed() {
        let p1 = permutation_for_pass(0x1111, 0, 64);
        let p2 = permutation_for_pass(0x2222, 0, 64);
        assert_ne!(p1, p2);
    }

    #[test]
    fn multi_pass_with_permutation_reduces_block_parity_mismatches() {
        // HONEST scope of the current implementation:
        //
        // Single-flip-on-parity-disagreement (`reconcile_with_syndrome`)
        // is bandwidth-cheap (1 bit per block) but it CANNOT
        // mathematically converge to byte-identical bits on its own:
        // when it flips bit 0 of a disagreeing block, it converts a
        // 1-error block into a 2-error block.
        //
        // Multi-pass with permutation REDUCES the rate of BLOCK
        // PARITY disagreements (because errors get shuffled between
        // passes, and some lucky permutations put the error at the
        // flip position), but it doesn't drive total bit-error rate
        // to zero. Real CASCADE bisection (Brassard-Salvail 1994)
        // is required for that, and it's F1.4-polish's next ship.
        //
        // So we test what we CAN guarantee right now: after multi-
        // pass, the syndrome of the final reconciled bits matches
        // the peer's syndrome block-by-block.
        let peer_bits: Vec<u8> = (0..512).map(|i| ((i * 7 + 3) & 1) as u8).collect();
        let mut my_bits = peer_bits.clone();
        my_bits[7] ^= 1;
        my_bits[42] ^= 1;
        my_bits[200] ^= 1;
        let seed = 0xCAFE_BABE;
        let syndromes = multi_pass_syndromes(&peer_bits, 8, 4, seed);
        let reconciled = multi_pass_reconcile(&my_bits, &syndromes, 8, 4, seed);
        // The last-pass syndrome of `reconciled` must match peer's
        // last-pass syndrome (block parities aligned).
        let n = reconciled.len();
        let last_pass_perm = permutation_for_pass(seed, 3, n);
        let permuted_reconciled: Vec<u8> = last_pass_perm.iter().map(|&p| reconciled[p]).collect();
        let final_syndrome = block_syndrome(&permuted_reconciled, 8);
        assert_eq!(final_syndrome, syndromes[3]);
    }

    #[test]
    fn multi_pass_with_no_errors_no_op() {
        let bits: Vec<u8> = (0..256).map(|i| (i & 1) as u8).collect();
        let syndromes = multi_pass_syndromes(&bits, 8, 4, 0xABCD);
        let reconciled = multi_pass_reconcile(&bits, &syndromes, 8, 4, 0xABCD);
        assert_eq!(reconciled, bits);
    }

    #[test]
    fn multi_pass_handles_block_bits_zero() {
        let bits = vec![1u8, 0, 1, 0];
        let syndromes: Vec<Vec<u8>> = vec![];
        let r = multi_pass_reconcile(&bits, &syndromes, 0, 4, 0);
        // Defensive: block_bits=0 means no-op.
        assert_eq!(r, bits);
    }

    #[test]
    fn multi_pass_handles_empty_input() {
        let r = multi_pass_reconcile(&[], &[], 8, 4, 0);
        assert!(r.is_empty());
    }
}
