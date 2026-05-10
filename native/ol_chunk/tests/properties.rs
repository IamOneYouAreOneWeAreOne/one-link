//! Property tests for `ol_chunk` covering the algebraic laws of chunking
//! and BLAKE3 derivation that downstream crates depend on.

use ol_chunk::{blake3_wrap, scan_to_vec};
use proptest::prelude::*;

proptest! {
    /// Property: scans are deterministic across runs over the same input.
    #[test]
    fn cdc_scan_is_deterministic(buf in prop::collection::vec(any::<u8>(), 0..200_000)) {
        let a = scan_to_vec(&buf);
        let b = scan_to_vec(&buf);
        prop_assert_eq!(a, b);
    }

    /// Property: chunk boundaries tile the input exactly.
    #[test]
    fn cdc_boundaries_tile_exactly(buf in prop::collection::vec(any::<u8>(), 1..200_000)) {
        let boundaries = scan_to_vec(&buf);
        if !boundaries.is_empty() {
            prop_assert_eq!(boundaries[0].start, 0);
            prop_assert_eq!(boundaries.last().unwrap().end, buf.len());
            for w in boundaries.windows(2) {
                prop_assert_eq!(w[0].end, w[1].start);
            }
        }
    }

    /// Property: every chunk's raw_address equals BLAKE3 of its content.
    #[test]
    fn raw_address_matches_blake3(buf in prop::collection::vec(any::<u8>(), 0..100_000)) {
        for boundary in scan_to_vec(&buf) {
            let expected = blake3::hash(&buf[boundary.start..boundary.end]);
            prop_assert_eq!(boundary.raw_address, *expected.as_bytes());
        }
    }

    /// Property: raw and convergent addresses are domain-separated.
    /// For any non-empty plaintext, `chunk_address_raw(p) != chunk_address_convergent(p)`.
    #[test]
    fn raw_vs_convergent_addresses_differ(plain in prop::collection::vec(any::<u8>(), 1..10_000)) {
        let raw = blake3_wrap::chunk_address_raw(&plain);
        let conv = blake3_wrap::chunk_address_convergent(&plain);
        prop_assert_ne!(raw, conv);
    }

    /// Property: convergent address is deterministic across callers.
    #[test]
    fn convergent_address_is_deterministic(plain in prop::collection::vec(any::<u8>(), 0..10_000)) {
        let a = blake3_wrap::chunk_address_convergent(&plain);
        let b = blake3_wrap::chunk_address_convergent(&plain);
        prop_assert_eq!(a, b);
    }

    /// Property: AEAD key changes when chunk_id changes.
    #[test]
    fn aead_key_distinct_for_distinct_chunk_ids(
        chain in prop::array::uniform32(any::<u8>()),
        chunk_a in prop::array::uniform32(any::<u8>()),
        chunk_b in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(chunk_a != chunk_b);
        let key_a = blake3_wrap::derive_aead_key(&chain, &chunk_a);
        let key_b = blake3_wrap::derive_aead_key(&chain, &chunk_b);
        prop_assert_ne!(key_a, key_b);
    }

    /// Property: AEAD key changes when ratchet chain key changes.
    #[test]
    fn aead_key_distinct_for_distinct_chain_keys(
        chunk in prop::array::uniform32(any::<u8>()),
        chain_a in prop::array::uniform32(any::<u8>()),
        chain_b in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(chain_a != chain_b);
        let key_a = blake3_wrap::derive_aead_key(&chain_a, &chunk);
        let key_b = blake3_wrap::derive_aead_key(&chain_b, &chunk);
        prop_assert_ne!(key_a, key_b);
    }

    /// Property: stripe seed has the low 6 bits cleared.
    #[test]
    fn stripe_seed_clears_low_6_bits(chunk in prop::array::uniform32(any::<u8>())) {
        let (seed, _pos) = blake3_wrap::derive_stripe_seed(&chunk, 10);
        prop_assert_eq!(seed & 0x3F, 0);
    }

    /// Property: stripe position is in [0, k).
    #[test]
    fn stripe_position_in_range(
        chunk in prop::array::uniform32(any::<u8>()),
        k in 1u8..=64,
    ) {
        let (_seed, pos) = blake3_wrap::derive_stripe_seed(&chunk, k);
        prop_assert!(pos < k);
    }

    /// Property: ratchet_key_id is distinct from the AEAD key prefix
    /// (domain separation between contexts).
    #[test]
    fn ratchet_id_distinct_from_aead_key_prefix(
        chain in prop::array::uniform32(any::<u8>()),
        chunk in prop::array::uniform32(any::<u8>()),
    ) {
        let aead = blake3_wrap::derive_aead_key(&chain, &chunk);
        let ratchet = blake3_wrap::derive_ratchet_key_id(&chain, &chunk);
        prop_assert_ne!(&aead[..16], &ratchet[..]);
    }
}
