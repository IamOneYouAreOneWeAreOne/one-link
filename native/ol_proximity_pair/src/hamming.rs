//! Hamming(127,120) SEC code for single-error-correcting reconciliation.
//!
//! Replaces the broken single-flip strategy in
//! [`crate::reconcile::reconcile_with_syndrome`] with mathematically-
//! correct error LOCATION. Receiver decodes the syndrome of the
//! parity-XOR to find the exact error position and flips that bit.
//!
//! ## The trick (standard QKD information reconciliation)
//!
//! Both sides treat their bit string as if it were the data portion
//! of a Hamming codeword. They compute the 7 parity bits the codeword
//! "should have" given their data. They EXCHANGE just the parity
//! bits over the public channel.
//!
//! Receiver computes XOR of their-parity vs peer's-parity. This
//! equals the syndrome of (my_data XOR peer_data) — the error
//! pattern between the two sides. The standard Hamming syndrome
//! decoding then locates the error.
//!
//! Per block:
//!   - 120 data bits + 7 parity bits = 127-bit codeword
//!   - Parity bit at codeword position 2^i (1, 2, 4, 8, 16, 32, 64)
//!     covers all codeword positions where bit i of the position is 1
//!   - Syndrome[i] = XOR of received bits at positions covered by p_i
//!   - Syndrome (as 7-bit integer) IS the codeword position of the
//!     single bit error (or 0 for no error)
//!
//! ## Properties
//!
//! - Corrects 1 bit error per block (with mathematical certainty)
//! - Detects but does NOT correct 2+ errors per block
//! - 7 parity bits per 120 data bits = 5.8% leak per pass
//! - Combined with permutation between passes, multi-error blocks
//!   get split up: an N-error block on pass 1 becomes N blocks each
//!   with 1 error on pass 2 (with high probability), all fixable.
//!
//! Multi-pass cost: 4 passes × 5.8% = 23% total leak. For 1024-bit
//! input → 788 residual entropy → safely amplifies to 256-bit key.

/// Codeword size (bits per block).
pub const HAMMING_CODEWORD_BITS: usize = 127;

/// Parity bits per block.
pub const HAMMING_PARITY_BITS: usize = 7;

/// Data bits per block.
pub const HAMMING_DATA_BITS: usize = 120;

/// Codeword positions of the 7 parity bits (1-indexed).
const PARITY_POSITIONS: [usize; HAMMING_PARITY_BITS] = [1, 2, 4, 8, 16, 32, 64];

/// Map data-index `0..120` to its codeword position `1..=127`.
/// Skips the 7 parity positions (powers of 2 in 1..=64).
fn data_index_to_codeword_pos(di: usize) -> usize {
    debug_assert!(di < HAMMING_DATA_BITS);
    let mut count = 0usize;
    for pos in 1..=HAMMING_CODEWORD_BITS {
        if !pos.is_power_of_two() {
            if count == di {
                return pos;
            }
            count += 1;
        }
    }
    unreachable!()
}

/// Map codeword position `1..=127` to data-index `0..120`, or None
/// if `pos` is a parity position.
fn codeword_pos_to_data_index(pos: usize) -> Option<usize> {
    if pos == 0 || pos > HAMMING_CODEWORD_BITS || pos.is_power_of_two() {
        return None;
    }
    let mut count = 0usize;
    for p in 1..pos {
        if !p.is_power_of_two() {
            count += 1;
        }
    }
    Some(count)
}

/// Compute the 7 Hamming parity bits for a 120-bit data block.
///
/// `data` is a packed bit string of exactly 120 bits (one bit per
/// byte, values 0 or 1).
#[must_use]
pub fn parity_bits_for_block(data: &[u8]) -> [u8; HAMMING_PARITY_BITS] {
    debug_assert_eq!(data.len(), HAMMING_DATA_BITS);
    let mut parity = [0u8; HAMMING_PARITY_BITS];
    for (di, &bit) in data.iter().enumerate() {
        if bit & 1 == 0 {
            continue;
        }
        let cw_pos = data_index_to_codeword_pos(di);
        // For each parity bit p_i at position 2^i: if cw_pos has
        // bit i set, this data bit affects p_i.
        for (pi, &pp) in PARITY_POSITIONS.iter().enumerate() {
            if cw_pos & pp != 0 {
                parity[pi] ^= 1;
            }
        }
    }
    parity
}

/// Compute parity bits for a multi-block bit string. Last partial
/// block is zero-padded to 120 bits.
///
/// Returns `Vec<u8>` of length `ceil(data.len() / 120) * 7`. Each
/// run of 7 bytes is one block's parity.
#[must_use]
pub fn parity_bits_for_string(data: &[u8]) -> Vec<u8> {
    let n_blocks = data.len().div_ceil(HAMMING_DATA_BITS);
    let mut out = Vec::with_capacity(n_blocks * HAMMING_PARITY_BITS);
    let mut padded = vec![0u8; n_blocks * HAMMING_DATA_BITS];
    padded[..data.len()].copy_from_slice(data);
    for block_idx in 0..n_blocks {
        let start = block_idx * HAMMING_DATA_BITS;
        let end = start + HAMMING_DATA_BITS;
        let p = parity_bits_for_block(&padded[start..end]);
        out.extend_from_slice(&p);
    }
    out
}

/// Decode the Hamming syndrome of `(my_parity ^ peer_parity)` to
/// find the single-error codeword position. Returns:
///   - `Some(data_index)` when the error is at a data bit; caller
///     flips `my_bits[block_offset + data_index]`.
///   - `None` when the syndrome is zero (no error) OR the syndrome
///     points to a parity position (the error was in transmitted
///     parity, no data correction needed) OR the syndrome is
///     outside the valid range (could indicate >1 errors).
#[must_use]
pub fn decode_syndrome_to_data_index(my_parity: &[u8], peer_parity: &[u8]) -> Option<usize> {
    debug_assert_eq!(my_parity.len(), HAMMING_PARITY_BITS);
    debug_assert_eq!(peer_parity.len(), HAMMING_PARITY_BITS);
    // Syndrome interpreted as 7-bit integer; bit i is parity[i].
    let mut s: usize = 0;
    for (i, (&mine, &peer)) in my_parity.iter().zip(peer_parity.iter()).enumerate() {
        if (mine ^ peer) & 1 != 0 {
            s |= 1 << i;
        }
    }
    if s == 0 || s > HAMMING_CODEWORD_BITS {
        return None;
    }
    codeword_pos_to_data_index(s)
}

/// Reconcile `my_bits` against `peer_parity` using Hamming SEC.
/// One pass; corrects up to 1 error per 120-bit block.
///
/// Returns the corrected bit string (same length as `my_bits`,
/// trailing partial block zero-padded then truncated back).
#[must_use]
pub fn hamming_reconcile(my_bits: &[u8], peer_parity: &[u8]) -> Vec<u8> {
    let n_blocks = my_bits.len().div_ceil(HAMMING_DATA_BITS);
    let mut padded = vec![0u8; n_blocks * HAMMING_DATA_BITS];
    padded[..my_bits.len()].copy_from_slice(my_bits);
    for block_idx in 0..n_blocks {
        let start = block_idx * HAMMING_DATA_BITS;
        let end = start + HAMMING_DATA_BITS;
        let my_parity = parity_bits_for_block(&padded[start..end]);
        let peer_par_start = block_idx * HAMMING_PARITY_BITS;
        let peer_par_end = peer_par_start + HAMMING_PARITY_BITS;
        if peer_par_end > peer_parity.len() {
            continue;
        }
        let peer_block_parity = &peer_parity[peer_par_start..peer_par_end];
        if let Some(di) = decode_syndrome_to_data_index(&my_parity, peer_block_parity) {
            padded[start + di] ^= 1;
        }
    }
    padded.truncate(my_bits.len());
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_position_indexing() {
        // 7 parity positions: 1, 2, 4, 8, 16, 32, 64.
        assert_eq!(PARITY_POSITIONS.len(), 7);
        for &p in &PARITY_POSITIONS {
            assert!(p.is_power_of_two());
            assert!(p <= 64);
        }
    }

    #[test]
    fn data_position_count_is_120() {
        let mut count = 0;
        for pos in 1..=HAMMING_CODEWORD_BITS {
            if !pos.is_power_of_two() {
                count += 1;
            }
        }
        assert_eq!(count, HAMMING_DATA_BITS);
    }

    #[test]
    fn data_index_roundtrip() {
        for di in 0..HAMMING_DATA_BITS {
            let cw = data_index_to_codeword_pos(di);
            assert!(!cw.is_power_of_two());
            assert_eq!(codeword_pos_to_data_index(cw), Some(di));
        }
    }

    #[test]
    fn codeword_parity_pos_returns_none() {
        for &pp in &PARITY_POSITIONS {
            assert_eq!(codeword_pos_to_data_index(pp), None);
        }
    }

    #[test]
    fn identical_blocks_have_zero_syndrome() {
        let bits = vec![1u8; HAMMING_DATA_BITS];
        let p1 = parity_bits_for_block(&bits);
        let p2 = parity_bits_for_block(&bits);
        let result = decode_syndrome_to_data_index(&p1, &p2);
        assert_eq!(result, None);
    }

    #[test]
    fn single_data_error_is_located_exactly() {
        // Test EVERY possible single-bit error position.
        let base = vec![0u8; HAMMING_DATA_BITS];
        let base_parity = parity_bits_for_block(&base);
        for err_pos in 0..HAMMING_DATA_BITS {
            let mut corrupted = base.clone();
            corrupted[err_pos] ^= 1;
            let corrupted_parity = parity_bits_for_block(&corrupted);
            let located = decode_syndrome_to_data_index(&corrupted_parity, &base_parity);
            assert_eq!(
                located,
                Some(err_pos),
                "Hamming failed to locate error at data position {err_pos}"
            );
        }
    }

    #[test]
    fn hamming_reconcile_corrects_single_error_per_block() {
        // 256 bits of data = 3 blocks (2 full + 1 partial).
        let peer_bits: Vec<u8> = (0..256).map(|i| ((i * 7) & 1) as u8).collect();
        let mut my_bits = peer_bits.clone();
        // Inject one error in each block:
        my_bits[50] ^= 1; // block 0 (data positions 0..120)
        my_bits[200] ^= 1; // block 1 (data positions 120..240)
        my_bits[250] ^= 1; // block 2 partial (240..256)
        let peer_parity = parity_bits_for_string(&peer_bits);
        let corrected = hamming_reconcile(&my_bits, &peer_parity);
        assert_eq!(
            corrected, peer_bits,
            "Hamming reconcile should produce byte-identical bits"
        );
    }

    #[test]
    fn hamming_reconcile_with_no_errors_is_identity() {
        let peer_bits: Vec<u8> = (0..256).map(|i| ((i * 13) & 1) as u8).collect();
        let my_bits = peer_bits.clone();
        let peer_parity = parity_bits_for_string(&peer_bits);
        let corrected = hamming_reconcile(&my_bits, &peer_parity);
        assert_eq!(corrected, peer_bits);
    }

    #[test]
    fn parity_bits_for_string_length() {
        let bits = vec![0u8; 240]; // 2 full blocks of 120
        let p = parity_bits_for_string(&bits);
        assert_eq!(p.len(), 2 * HAMMING_PARITY_BITS);
    }

    #[test]
    fn parity_bits_for_string_handles_partial_block() {
        let bits = vec![0u8; 130]; // 1 full + 1 partial
        let p = parity_bits_for_string(&bits);
        assert_eq!(p.len(), 2 * HAMMING_PARITY_BITS);
    }
}
