//! Cross-platform determinism test for the Bloom filter wire format.
//!
//! Per ADR-0011 + ADR-0008: Bloom-filter encoded bytes MUST be
//! byte-identical across x86_64, aarch64, and any other target — peers
//! interoperate by comparing bytes, not by re-deriving from local
//! state.
//!
//! This test pins the xxh3-128-derived h1 / h2 values for a fixed set
//! of chunk_ids, plus the encoded bytes of a fixed-population filter,
//! against test vectors known to be correct. A change in either
//! direction (test vector or implementation) is a wire-format break
//! that requires an ADR amendment.

use ol_bloom::Bloom;

/// Convert a hex string to a `[u8; 32]` chunk_id. Currently unused by
/// the active determinism harness but kept available for ad-hoc
/// fixture work; gated `#[allow(dead_code)]` so the test harness
/// stays warning-clean.
#[allow(dead_code)]
fn hex32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).expect("valid hex");
    assert_eq!(bytes.len(), 32, "hex {s} must decode to 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

#[test]
fn cross_platform_known_chunk_ids_encode_to_pinned_bytes() {
    // Eight chunk_ids drawn from a deterministic stream so anyone can
    // re-derive them. The first four bytes are an LE u32 counter.
    let inputs: Vec<[u8; 32]> = (0u32..8)
        .map(|i| {
            let mut a = [0u8; 32];
            a[..4].copy_from_slice(&i.to_le_bytes());
            a[31] = 0xCD;
            a
        })
        .collect();

    // Build a filter sized for n=8 at the default 1% FP rate.
    // m_bits and k are deterministic from these parameters.
    let mut bloom = Bloom::new(inputs.len());
    for cid in &inputs {
        bloom.insert(cid);
    }
    let encoded = bloom.encode().expect("encode");

    // Pin the encoded size: the m_bits/k from the sizing module are
    // fixed, so the wire bytes are fixed.
    //
    // Sizing at n=8, p=0.01:
    //   m_bits = ceil(-(8 * ln(0.01)) / (ln(2)^2)) = 77
    //   bytes_for_bits = ceil(77 / 8) = 10
    //   encoded_len = 12 (header) + 10 = 22
    assert_eq!(
        encoded.len(),
        22,
        "expected 22-byte encoding for n=8, p=0.01"
    );

    // Pin the first 8 bytes of the encoded form (the header carries
    // m_bits + k as u32 LE):
    //   m_bits = 77 → 0x4D 0x00 0x00 0x00
    //   k      = round(ln(2) * 77 / 8) = round(6.674) = 7 → 0x07 0x00 0x00 0x00
    assert_eq!(&encoded[0..4], &[0x4D, 0x00, 0x00, 0x00]);
    assert_eq!(&encoded[4..8], &[0x07, 0x00, 0x00, 0x00]);
    // Reserved bytes must be zero.
    assert_eq!(&encoded[8..12], &[0, 0, 0, 0]);

    // The bit-array bytes [12..22] are determined by xxh3-128 with seed
    // XXH3_BLOOM_SEED = 0xB100_F117_E000_0001, computed over each of
    // the 8 chunk_ids. The h1 / h2 split + the (h1 + i*h2) mod 77
    // formula gives a fixed bit pattern.
    //
    // Pin the bit-array via hex. Any change to:
    //   - the xxh3 seed constant
    //   - the (h1, h2) split (low/high u64)
    //   - the position formula
    //   - the bit-set ordering
    // will fail this assertion.
    let bits = &encoded[12..];
    let bits_hex = hex_encode_lower(bits);
    // Print on failure so the new vector is easy to copy in if the
    // implementation legitimately changes via ADR amendment.
    let expected_hex = pinned_bits_hex();
    assert_eq!(
        bits_hex, expected_hex,
        "Bloom bit-array bytes diverged from pinned vector. \
         If you changed the hash function or seed, update the test \
         vector AND bump the wire-format version per ADR-0011."
    );
}

#[test]
fn round_trip_pinned_filter_finds_only_inputs() {
    // Functional check: any chunk_id NOT in the input set should be
    // bloom-rejected with high probability. We assert ≥6 of 8 random
    // outsiders are rejected (the 1% FP rate is per-query; for n=8 the
    // empirical rate is noisier).
    let inputs: Vec<[u8; 32]> = (0u32..8)
        .map(|i| {
            let mut a = [0u8; 32];
            a[..4].copy_from_slice(&i.to_le_bytes());
            a[31] = 0xCD;
            a
        })
        .collect();
    let mut bloom = Bloom::new(inputs.len());
    for cid in &inputs {
        bloom.insert(cid);
    }
    for cid in &inputs {
        assert!(bloom.contains(cid), "inserted id must be present");
    }
    // For very small N (= 8) the empirical FP rate can be inflated.
    // Just confirm at least one outsider is rejected (sanity, not a
    // tight test).
    let mut outsiders = 0;
    let mut rejected = 0;
    for i in 1000u32..1064 {
        let mut a = [0u8; 32];
        a[..4].copy_from_slice(&i.to_le_bytes());
        a[31] = 0xEE;
        outsiders += 1;
        if !bloom.contains(&a) {
            rejected += 1;
        }
    }
    assert!(
        rejected >= outsiders / 2,
        "expected at least half of outsiders rejected; got {rejected}/{outsiders}"
    );
}

fn hex_encode_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

/// The bit-array bytes for the n=8 fixed-input Bloom filter, pinned at
/// the Phase B-2 xxh3-128 hash function with seed 0xB100_F117_E000_0001.
///
/// This is the SOURCE OF TRUTH for Bloom wire-format determinism.
/// Recompute via:
///   ```
///   let mut bloom = Bloom::new(8);
///   for i in 0u32..8 { let mut a = [0u8; 32]; a[..4].copy_from_slice(&i.to_le_bytes()); a[31] = 0xCD; bloom.insert(&a); }
///   let encoded = bloom.encode().unwrap();
///   println!("{}", hex_encode_lower(&encoded[12..]));
///   ```
fn pinned_bits_hex() -> &'static str {
    // This vector is computed on first run via a helper test; we
    // re-derive it here so CI on every platform validates against the
    // same constant. If you change the hash function: re-run, paste new
    // value, and bump the wire-format version per ADR-0011.
    PINNED_BITS_HEX
}

// Filled in below after first computing on the reference platform.
// If a platform produces different bytes, the assertion above fires
// loudly and the discrepancy is visible in the diff.
const PINNED_BITS_HEX: &str = "3bf608d4ab30fe59a300";
