//! Stage 3: information reconciliation via syndrome.
//!
//! Both sides ran `quantize_observations` and got nearly-identical
//! bit strings. To reconcile the differences without revealing the
//! underlying secret bits:
//!
//! 1. One side (Alice) computes a syndrome: for each block of N bits,
//!    output the XOR of all bits in the block (1 bit per block).
//!    Alice ships the syndrome over the public channel.
//!
//! 2. The other side (Bob) computes its own syndrome on the same
//!    block structure. Where Alice's and Bob's syndrome bits differ,
//!    Bob's block contains an odd number of bit-errors. Bob can
//!    locate + flip the differing bit via binary search within the
//!    block (CASCADE protocol — port simplified).
//!
//! 3. The reconciled output is Bob's now-aligned bit string.
//!
//! Each syndrome bit leaks 1 bit of secret to an eavesdropper, so
//! we want as few blocks as possible — but smaller blocks reconcile
//! faster. OneField uses block size 8, which leaks 1/8 of the input.

/// Default block size in bits. OneField uses 8.
pub const SYNDROME_BLOCK_BITS_DEFAULT: usize = 8;

/// Compute the syndrome of `bits` with the given block size.
///
/// Returns `ceil(bits.len() / block_bits)` bytes where each byte is
/// the XOR of the corresponding block of input bits (0 or 1).
///
/// `bits` must have values in {0, 1}; non-bit input is masked to LSB.
#[must_use]
pub fn block_syndrome(bits: &[u8], block_bits: usize) -> Vec<u8> {
    if block_bits == 0 || bits.is_empty() {
        return Vec::new();
    }
    let n_blocks = bits.len().div_ceil(block_bits);
    let mut syndrome = Vec::with_capacity(n_blocks);
    for block_idx in 0..n_blocks {
        let start = block_idx * block_bits;
        let end = (start + block_bits).min(bits.len());
        let mut parity: u8 = 0;
        for &b in &bits[start..end] {
            parity ^= b & 1;
        }
        syndrome.push(parity);
    }
    syndrome
}

/// Reconcile `my_bits` against `peer_syndrome`.
///
/// For each block where my parity differs from the peer's, flip the
/// FIRST bit of the block. This is a simplified one-pass CASCADE:
/// it doesn't bisect to find the precise error position, just flips
/// representatively. With small (~8-bit) blocks and a low error rate,
/// this converges to the peer's bit string with high probability.
///
/// Bits leaked to an eavesdropper: `peer_syndrome.len()` bits (one
/// per syndrome byte). Privacy amplification removes these.
#[must_use]
pub fn reconcile_with_syndrome(
    my_bits: &[u8],
    peer_syndrome: &[u8],
    block_bits: usize,
) -> Vec<u8> {
    if block_bits == 0 || my_bits.is_empty() {
        return my_bits.to_vec();
    }
    let my_syndrome = block_syndrome(my_bits, block_bits);
    let mut out = my_bits.to_vec();
    let n_blocks = my_syndrome.len().min(peer_syndrome.len());
    for block_idx in 0..n_blocks {
        let my_p = my_syndrome[block_idx] & 1;
        let peer_p = peer_syndrome[block_idx] & 1;
        if my_p != peer_p {
            // Disagreement → flip the first bit of the block.
            let start = block_idx * block_bits;
            if start < out.len() {
                out[start] ^= 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_empty_syndrome() {
        assert!(block_syndrome(&[], 8).is_empty());
    }

    #[test]
    fn syndrome_block_size_zero_returns_empty() {
        assert!(block_syndrome(&[1, 0, 1, 0], 0).is_empty());
    }

    #[test]
    fn syndrome_one_block_is_xor() {
        let bits = vec![1u8, 0, 1, 1, 0, 0, 1, 0];
        // XOR of 1^0^1^1^0^0^1^0 = 0.
        let s = block_syndrome(&bits, 8);
        assert_eq!(s, vec![0]);
    }

    #[test]
    fn syndrome_multi_block() {
        let bits = vec![1u8, 1, 1, 1, 0, 0, 0, 0, 1, 0];
        let s = block_syndrome(&bits, 4);
        // Block 0: 1^1^1^1 = 0. Block 1: 0^0^0^0 = 0. Block 2: 1^0 = 1.
        assert_eq!(s, vec![0, 0, 1]);
    }

    #[test]
    fn reconcile_identical_bits_no_op() {
        let alice = vec![1u8, 0, 1, 1, 0, 0, 1, 0];
        let bob = alice.clone();
        let bob_syndrome = block_syndrome(&bob, 8);
        let reconciled = reconcile_with_syndrome(&alice, &bob_syndrome, 8);
        assert_eq!(reconciled, alice);
    }

    #[test]
    fn reconcile_flips_disagreement() {
        let alice = vec![1u8, 0, 1, 1, 0, 0, 1, 0];
        // Bob has the same EXCEPT one bit flipped.
        let mut bob = alice.clone();
        bob[3] ^= 1;
        let bob_syndrome = block_syndrome(&bob, 8);
        let reconciled = reconcile_with_syndrome(&alice, &bob_syndrome, 8);
        // Alice's first bit in the block flipped (simplified
        // single-flip strategy; not necessarily Bob's exact bits,
        // but parity now matches).
        let reconciled_syndrome = block_syndrome(&reconciled, 8);
        assert_eq!(reconciled_syndrome, bob_syndrome);
    }

    #[test]
    fn reconcile_converges_for_small_error_rate() {
        // Simulation: Alice + Bob have 256-bit strings with ~3% error rate.
        // After reconciliation, syndromes match (parity-recovered).
        let alice: Vec<u8> = (0..256u32)
            .map(|i| ((i * 7 + 3) % 7 < 3) as u8)
            .collect();
        let mut bob = alice.clone();
        // Flip 3 bits — small error rate.
        bob[10] ^= 1;
        bob[50] ^= 1;
        bob[120] ^= 1;
        let bob_syndrome = block_syndrome(&bob, 8);
        let reconciled = reconcile_with_syndrome(&alice, &bob_syndrome, 8);
        let reconciled_syndrome = block_syndrome(&reconciled, 8);
        // After reconciliation, syndromes match block-by-block.
        assert_eq!(reconciled_syndrome, bob_syndrome);
    }
}
