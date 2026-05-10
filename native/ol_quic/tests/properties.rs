//! Property tests for `ol_quic`.
//!
//! Covers the algebraic laws of:
//!
//! - Frame encode → decode → header-byte round-trip across every kind
//!   and randomized payloads.
//! - Varint encode → decode → equality for the full u64 range.
//! - Identity public key bytes ↔ fingerprint relationship.
//! - Cert subject pubkey extracted via x509 parser equals the
//!   identity's public key bytes.

use ol_quic::{
    proto::{decode_varint, encode_varint, varint_len, Frame, FrameKind},
    Identity, MAX_BULK_FRAME_BYTES, MAX_CONTROL_FRAME_BYTES,
};
use proptest::prelude::*;

fn arb_frame_kind() -> impl Strategy<Value = FrameKind> {
    prop_oneof![
        Just(FrameKind::ChunkRequest),
        Just(FrameKind::ChunkResponse),
        Just(FrameKind::ChunkNotFound),
        Just(FrameKind::ManifestSync),
        Just(FrameKind::ManifestRecord),
        Just(FrameKind::ManifestSyncEnd),
        Just(FrameKind::BloomFilter),
        Just(FrameKind::MissingChunks),
        Just(FrameKind::CapabilityCheck),
        Just(FrameKind::CapabilityAck),
        Just(FrameKind::Ping),
        Just(FrameKind::Pong),
        Just(FrameKind::ProtoError),
        Just(FrameKind::Close),
    ]
}

proptest! {
    /// Property: every FrameKind round-trips through its byte form.
    #[test]
    fn frame_kind_byte_round_trip(kind in arb_frame_kind()) {
        prop_assert_eq!(FrameKind::from_u8(kind.as_u8()), Some(kind));
    }

    /// Property: random byte values that are NOT registered kinds yield None.
    #[test]
    fn unregistered_kind_byte_yields_none(b in 0u8..=u8::MAX) {
        let registered: &[u8] = &[
            0x01, 0x02, 0x03,  // chunk
            0x10, 0x11, 0x12,  // manifest
            0x20, 0x21,         // bloom / missing
            0x30, 0x31,         // capability
            0xF0, 0xF1,         // ping / pong
            0xFE, 0xFF,         // proto error / close
        ];
        if registered.contains(&b) {
            prop_assert!(FrameKind::from_u8(b).is_some());
        } else {
            prop_assert!(FrameKind::from_u8(b).is_none());
        }
    }

    /// Property: varint encode/decode round-trip across the full u64 range.
    #[test]
    fn varint_round_trip(n in any::<u64>()) {
        let mut buf = Vec::new();
        encode_varint(&mut buf, n);
        let (decoded, consumed) = decode_varint(&buf, 0).unwrap();
        prop_assert_eq!(decoded, n);
        prop_assert_eq!(consumed, varint_len(n));
        prop_assert_eq!(consumed, buf.len());
    }

    /// Property: a varint with the high bit set on its last byte but no
    /// continuation is rejected (truncation detection).
    #[test]
    fn varint_truncated_rejected(prefix_bytes in prop::collection::vec(0x80u8..=0xFFu8, 1..=8)) {
        // All bytes have high bit set ⇒ varint never terminates ⇒ should
        // error rather than wrap or overflow.
        let result = decode_varint(&prefix_bytes, 0);
        prop_assert!(result.is_err());
    }

    /// Property: encoding then decoding a frame yields the same kind +
    /// payload.
    #[test]
    fn frame_encode_decode_round_trip(
        kind in arb_frame_kind(),
        // Payload size capped by per-kind max; we draw small enough to
        // be fast but large enough to exercise multi-byte varints.
        payload in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let frame = match Frame::new(kind, payload.clone()) {
            Ok(f) => f,
            Err(_) => return Ok(()),  // payload too large for the kind; skip
        };
        let encoded = frame.encode();
        prop_assert_eq!(encoded[0], kind.as_u8());
        let (length, consumed) = decode_varint(&encoded, 1).unwrap();
        prop_assert_eq!(length as usize, payload.len());
        prop_assert_eq!(&encoded[1 + consumed..], &payload[..]);
        prop_assert_eq!(encoded.len(), frame.on_wire_len());
    }

    /// Property: frame max-payload caps reject oversized inputs.
    #[test]
    fn frame_max_payload_caps(kind in arb_frame_kind()) {
        let max = kind.max_payload_bytes();
        // Just-fit payload always succeeds.
        let fit = vec![0u8; max as usize];
        prop_assert!(Frame::new(kind, fit).is_ok());
        // Strictly-larger payload always fails.
        let over = vec![0u8; (max + 1) as usize];
        prop_assert!(Frame::new(kind, over).is_err());
    }

    /// Property: bulk vs control caps match the registered values.
    #[test]
    fn bulk_kind_implies_one_mib_cap(kind in arb_frame_kind()) {
        let max = kind.max_payload_bytes();
        let is_bulk = matches!(kind, FrameKind::ChunkResponse | FrameKind::ManifestRecord);
        if is_bulk {
            prop_assert_eq!(max, MAX_BULK_FRAME_BYTES);
        } else {
            prop_assert_eq!(max, MAX_CONTROL_FRAME_BYTES);
        }
    }
}

// Identity properties — done with a smaller iteration count because each
// test case generates a fresh Ed25519 keypair (slow).

#[test]
fn identity_fingerprint_is_blake3_of_pubkey() {
    for _ in 0..16 {
        let id = Identity::generate().unwrap();
        let computed = *blake3::hash(&id.public_key_bytes()).as_bytes();
        assert_eq!(id.fingerprint(), computed);
    }
}

#[test]
fn identity_pkcs8_pem_round_trip_preserves_fingerprint() {
    for _ in 0..16 {
        let original = Identity::generate().unwrap();
        let pem = original.to_pkcs8_pem();
        let restored = Identity::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(original.fingerprint(), restored.fingerprint());
        assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
    }
}

#[test]
fn cert_pubkey_matches_identity_pubkey() {
    for _ in 0..16 {
        let id = Identity::generate().unwrap();
        let cert = id.cert_der();
        let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();
        let cert_pubkey = parsed.public_key().subject_public_key.data.as_ref();
        assert_eq!(cert_pubkey, &id.public_key_bytes());
    }
}
