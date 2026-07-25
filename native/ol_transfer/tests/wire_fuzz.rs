//! Proptest-based fuzz coverage for the Phase B-2 wire-format decoders.
//!
//! These tests feed random byte streams into the `decode_*` functions
//! and assert they never panic and never produce out-of-bounds data.
//! Either the decode succeeds with sane output, or it returns a
//! `MalformedPayload` error.

use ol_transfer::wire::{
    decode_chunk_not_found, decode_chunk_request, decode_chunk_response, decode_missing_chunks,
    decode_scoped_bloom,
};
use proptest::prelude::*;

proptest! {
    /// `decode_chunk_request` accepts only 32-byte inputs and never panics.
    #[test]
    fn chunk_request_decode_total(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let r = decode_chunk_request(&bytes);
        if bytes.len() == 32 {
            prop_assert!(r.is_ok());
            let id = r.unwrap();
            prop_assert_eq!(&id[..], &bytes[..]);
        } else {
            prop_assert!(r.is_err());
        }
    }

    #[test]
    fn chunk_not_found_decode_total(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let r = decode_chunk_not_found(&bytes);
        if bytes.len() == 32 {
            prop_assert!(r.is_ok());
        } else {
            prop_assert!(r.is_err());
        }
    }

    #[test]
    fn chunk_response_decode_total(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let r = decode_chunk_response(&bytes);
        if bytes.len() >= 2 {
            prop_assert!(r.is_ok());
            let (k, f, p) = r.unwrap();
            prop_assert_eq!(k, bytes[0]);
            prop_assert_eq!(f, bytes[1]);
            prop_assert_eq!(p, &bytes[2..]);
        } else {
            prop_assert!(r.is_err());
        }
    }

    #[test]
    fn missing_chunks_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
        // Any byte stream MUST either decode to a valid Vec or return
        // Err — never panic.
        let _ = decode_missing_chunks(&bytes);
    }

    #[test]
    fn scoped_bloom_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = decode_scoped_bloom(&bytes);
    }

    /// Round-trip property: encode then decode preserves the want_list
    /// and bloom bytes.
    #[test]
    fn scoped_bloom_round_trip(
        ids in prop::collection::vec(prop::array::uniform32(any::<u8>()), 0..50),
        bloom_bytes in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let payload = ol_transfer::wire::encode_scoped_bloom(&ids, &bloom_bytes)
            .expect("bounded generated form encodes");
        let (decoded_ids, decoded_bloom) = decode_scoped_bloom(&payload).expect("encoded form decodes");
        prop_assert_eq!(decoded_ids, ids);
        prop_assert_eq!(decoded_bloom, &bloom_bytes[..]);
    }
}
