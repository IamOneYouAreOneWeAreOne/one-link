//! Adversarial test vectors for ol_proximity_pair.
//!
//! Catches known-attack patterns + edge cases that random property
//! tests might miss. Matches F1.1 (ol_threshold_recovery)
//! adversarial-vector pattern.

use ol_proximity_pair::{
    block_syndrome, hamming_reconcile, parity_bits_for_block,
    parity_bits_for_string, permutation_for_pass, privacy_amplify,
    quantize_observations, QuantizeConfig, HAMMING_DATA_BITS,
};

// ── Quantization: pathological observation inputs ─────────────────

#[test]
fn adversarial_observation_too_short_is_typed_error() {
    use ol_proximity_pair::PairError;
    let cfg = QuantizeConfig {
        min_bytes: 256,
        guard_band: 0.1,
    };
    let err = quantize_observations(&[0u8; 32], &cfg).unwrap_err();
    assert!(matches!(err, PairError::ObservationTooShort { .. }));
}

#[test]
fn adversarial_all_identical_observations_full_guard_drop() {
    // If every byte is the same, the guard band drops everything.
    // Output is an empty bit string — caller should detect and
    // re-probe with more dispersion.
    let cfg = QuantizeConfig {
        min_bytes: 32,
        guard_band: 0.5,
    };
    let obs = vec![0x42u8; 128];
    let bits = quantize_observations(&obs, &cfg).unwrap();
    // All identical → median=value → every observation inside guard.
    assert!(bits.is_empty());
}

#[test]
fn adversarial_extreme_bimodal_observations_dont_panic() {
    // Half zeros, half 0xFF — pathological bimodal.
    // Median lands on one mode (sorted[N/2] is integer-indexed),
    // so guard-band dynamics produce a degenerate split. The
    // EXACT split isn't the property we test; the property is
    // that the pipeline doesn't panic + produces SOMETHING usable
    // (callers re-probe on degenerate output).
    let mut obs = vec![0u8; 64];
    obs.extend(std::iter::repeat(0xFFu8).take(64));
    let cfg = QuantizeConfig {
        min_bytes: 32,
        guard_band: 0.05,
    };
    let bits = quantize_observations(&obs, &cfg).unwrap();
    // No panic; output is well-defined bits.
    assert!(bits.iter().all(|&b| b == 0 || b == 1));
}

#[test]
fn adversarial_quantize_zero_guard_still_has_floor_guard() {
    // guard_band=0.0 input → impl applies a 1-byte floor guard
    // (max(range*0, 1.0) == 1.0), so a few observations near the
    // median are still dropped. The exact count depends on the
    // distribution; the property is that classification is
    // non-empty and well-formed.
    let cfg = QuantizeConfig {
        min_bytes: 8,
        guard_band: 0.0,
    };
    let obs: Vec<u8> = (0..32u8).collect();
    let bits = quantize_observations(&obs, &cfg).unwrap();
    // Floor guard drops ~3 observations near the median.
    assert!(!bits.is_empty());
    assert!(bits.len() <= obs.len());
    assert!(bits.iter().all(|&b| b == 0 || b == 1));
}

// ── Block syndrome: adversarial bit inputs ───────────────────────

#[test]
fn adversarial_syndrome_block_size_0_returns_empty() {
    let s = block_syndrome(&[1, 0, 1, 0], 0);
    assert!(s.is_empty());
}

#[test]
fn adversarial_syndrome_block_size_larger_than_input() {
    // block_size=64 but only 8 bits of input → 1 syndrome bit
    let s = block_syndrome(&[1, 1, 1, 1, 0, 0, 0, 0], 64);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0], 0); // 4 ones XORed = 0
}

#[test]
fn adversarial_syndrome_empty_input_empty_output() {
    let s = block_syndrome(&[], 8);
    assert!(s.is_empty());
}

#[test]
fn adversarial_syndrome_handles_non_01_bytes_via_lsb_mask() {
    // Implementation uses `b & 1`; high bits don't affect parity.
    let s1 = block_syndrome(&[0xFFu8; 8], 8);
    let s2 = block_syndrome(&[0x01u8; 8], 8);
    assert_eq!(s1, s2);
}

// ── Hamming SEC: adversarial patterns ────────────────────────────

#[test]
fn adversarial_hamming_no_data_returns_empty() {
    let r = hamming_reconcile(&[], &[]);
    assert!(r.is_empty());
}

#[test]
fn adversarial_hamming_truncated_parity_bytes_no_panic() {
    // Parity input shorter than expected (peer was buggy or
    // truncated). hamming_reconcile must not panic; it just leaves
    // the unhandled blocks unchanged.
    let bits = vec![1u8; 240]; // 2 blocks
    let r = hamming_reconcile(&bits, &[]); // empty parity
    assert_eq!(r.len(), bits.len());
}

#[test]
fn adversarial_hamming_extra_parity_bytes_no_panic() {
    let bits = vec![1u8; 120]; // 1 block
    let too_much_parity = vec![0u8; 70]; // 10 blocks worth
    let r = hamming_reconcile(&bits, &too_much_parity);
    assert_eq!(r.len(), bits.len()); // output length preserved
}

#[test]
fn adversarial_hamming_partial_last_block_handled() {
    // 130 bits = 1 full + 1 partial (10 bits). parity_bits_for_string
    // pads to 240 internally → 2 parity blocks. Reconcile must
    // produce 130-byte output.
    let bits: Vec<u8> = (0..130).map(|i| (i & 1) as u8).collect();
    let parity = parity_bits_for_string(&bits);
    let r = hamming_reconcile(&bits, &parity);
    assert_eq!(r, bits);
}

#[test]
fn adversarial_hamming_two_errors_one_block_miscorrect_but_no_panic() {
    // Hamming SEC can only correct 1 error per block. With 2 errors
    // in the same block, it'll miscorrect (decode to a third
    // position). The function must NOT panic; the wrong output is
    // documented and addressed via multi-pass permutation.
    let mut bits = vec![0u8; HAMMING_DATA_BITS];
    bits[5] = 1; // make it non-trivial
    bits[100] = 1;
    let parity = parity_bits_for_block(&bits);
    let mut my_bits = bits.clone();
    my_bits[10] ^= 1;
    my_bits[20] ^= 1; // 2 errors
    // Build a buffer that hamming_reconcile can use.
    let mut my_padded = vec![0u8; HAMMING_DATA_BITS];
    my_padded.copy_from_slice(&my_bits);
    let _r = hamming_reconcile(&my_padded, &parity);
    // No panic. The miscorrection is documented behavior.
}

// ── Privacy amplification: adversarial input ─────────────────────

#[test]
fn adversarial_privacy_amplify_empty_input() {
    let salt = [0x42u8; 32];
    let k = privacy_amplify(&[], &salt);
    assert_eq!(k.len(), 32);
}

#[test]
fn adversarial_privacy_amplify_giant_input_no_overflow() {
    // 10k bits — proves no allocation/length-overflow bugs.
    let bits = vec![1u8; 10_000];
    let salt = [0u8; 32];
    let k = privacy_amplify(&bits, &salt);
    assert_eq!(k.len(), 32);
}

#[test]
fn adversarial_privacy_amplify_non_bit_input_masked_lsb() {
    // privacy_amplify packs `b & 1`; high bits don't change output.
    let salt = [0u8; 32];
    let bits_clean = [0u8, 1, 0, 1, 0, 1, 0, 1];
    let bits_dirty = [0xFEu8, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF, 0xFE, 0xFF];
    let k1 = privacy_amplify(&bits_clean, &salt);
    let k2 = privacy_amplify(&bits_dirty, &salt);
    assert_eq!(k1, k2);
}

// ── Permutation: adversarial cases ───────────────────────────────

#[test]
fn adversarial_permutation_n_zero() {
    let perm = permutation_for_pass(0xCAFE, 0, 0);
    assert!(perm.is_empty());
}

#[test]
fn adversarial_permutation_n_one() {
    let perm = permutation_for_pass(0xCAFE, 0, 1);
    assert_eq!(perm, vec![0]);
}

#[test]
fn adversarial_permutation_high_pass_idx() {
    // Pass indices up to u32::MAX must be handled.
    let perm = permutation_for_pass(0xCAFE, 1_000_000, 64);
    assert_eq!(perm.len(), 64);
    let mut seen = vec![false; 64];
    for p in perm {
        assert!(!seen[p]);
        seen[p] = true;
    }
}

#[test]
fn adversarial_permutation_seed_zero_well_defined() {
    let perm = permutation_for_pass(0, 0, 16);
    assert_eq!(perm.len(), 16);
}

// ── End-to-end: hostile bit patterns through full pipeline ───────

#[test]
fn adversarial_pipeline_all_ones_observations() {
    let cfg = QuantizeConfig {
        min_bytes: 128,
        guard_band: 0.1,
    };
    let obs = vec![0xFFu8; 256];
    // All-identical → guard drops everything → empty bits.
    let bits = quantize_observations(&obs, &cfg).unwrap();
    let parity = parity_bits_for_string(&bits);
    let r = hamming_reconcile(&bits, &parity);
    let salt = [0u8; 32];
    let _ = privacy_amplify(&r, &salt);
    // No panic across the full pipeline on degenerate input.
}

#[test]
fn adversarial_pipeline_random_high_entropy() {
    let cfg = QuantizeConfig {
        min_bytes: 256,
        guard_band: 0.1,
    };
    let obs: Vec<u8> =
        (0..512u32).map(|i| ((i.wrapping_mul(0x9E3779B9)) & 0xFF) as u8).collect();
    let bits = quantize_observations(&obs, &cfg).unwrap();
    let parity = parity_bits_for_string(&bits);
    let r = hamming_reconcile(&bits, &parity);
    let salt = [0u8; 32];
    let key = privacy_amplify(&r, &salt);
    assert_eq!(key.len(), 32);
}
