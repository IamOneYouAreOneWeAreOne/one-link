//! Proptest fuzz coverage for `ol_fountain` wire-format decoders.
//!
//! Every byte stream fed to `FountainPacket::decode` and to
//! `LtDecoder::ingest` MUST either succeed or return Err — never panic.

use ol_fountain::{FountainPacket, LtDecoder};
use proptest::prelude::*;

proptest! {
    #[test]
    fn fountain_packet_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = FountainPacket::decode(&bytes);
    }

    /// Round trip: encode a packet, decode it back, assert fields match.
    #[test]
    fn fountain_packet_round_trip(
        chunk_id in prop::array::uniform32(any::<u8>()),
        k in 1u32..512,
        symbol_id in 0u32..2048,
        source_seed in any::<u32>(),
        payload in prop::collection::vec(any::<u8>(), 1..2048),
    ) {
        let padded_len = (k as usize) * payload.len();
        let source_length = 1 + source_seed % u32::try_from(padded_len).unwrap();
        let p = FountainPacket::new(chunk_id, k, symbol_id, source_length, payload.clone());
        let encoded = p.encode().expect("bounded packet encodes");
        let decoded = FountainPacket::decode(&encoded).expect("encoded form decodes");
        prop_assert_eq!(decoded.chunk_id, chunk_id);
        prop_assert_eq!(decoded.k, k);
        prop_assert_eq!(decoded.symbol_id, symbol_id);
        prop_assert_eq!(decoded.source_length, source_length);
        prop_assert_eq!(decoded.payload, payload);
    }

    /// `LtDecoder::ingest` is total over random payloads: success or
    /// Err, never panic.
    #[test]
    fn decoder_ingest_never_panics(
        k in 1u32..32,
        symbol_id in 0u32..1023,
        payload in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let mut dec = LtDecoder::new(k, 1024, (k as usize) * 1024).unwrap();
        let _ = dec.ingest(symbol_id, &payload);
    }
}
