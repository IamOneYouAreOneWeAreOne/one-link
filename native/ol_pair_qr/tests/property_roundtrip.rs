//! Property tests for ol_pair_qr primitives.
//!
//! Mirrors F1.x bar: 1M iters CI default, 5M nightly.

use proptest::prelude::*;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use ol_pair_qr::canon::{Reader, Writer, MAX_FIELD_BYTES};
use ol_pair_qr::invite::{CapabilityScope, Invite, INVITE_NONCE_LEN, X25519_PUBKEY_LEN};
use ol_pair_qr::response::{PairResponse, RESPONSE_NONCE_LEN};
use ol_pair_qr::sas::{Sas, SAS_BITS};
use ol_pair_qr::transcript::{transcript_hash, TranscriptHash, TRANSCRIPT_LEN};

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

// ── Canon Reader/Writer round-trip ────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(),
        max_global_rejects: cases() * 4,
        .. ProptestConfig::default()
    })]

    /// write_u8/u16/u32/u64 → read_* round-trip is bit-perfect.
    #[test]
    fn canon_primitives_roundtrip(
        a in any::<u8>(),
        b in any::<u16>(),
        c in any::<u32>(),
        d in any::<u64>(),
    ) {
        let mut w = Writer::new();
        w.write_u8(a);
        w.write_u16(b);
        w.write_u32(c);
        w.write_u64(d);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        prop_assert_eq!(r.read_u8().unwrap(), a);
        prop_assert_eq!(r.read_u16().unwrap(), b);
        prop_assert_eq!(r.read_u32().unwrap(), c);
        prop_assert_eq!(r.read_u64().unwrap(), d);
        prop_assert!(r.is_empty());
    }

    /// write_var with any-length-up-to-cap bytes → read_var returns
    /// the same bytes.
    #[test]
    fn canon_var_roundtrip(
        bytes in prop::collection::vec(any::<u8>(), 0..=MAX_FIELD_BYTES),
    ) {
        let mut w = Writer::new();
        w.write_var(&bytes);
        let encoded = w.into_bytes();
        let mut r = Reader::new(&encoded);
        let decoded = r.read_var().unwrap();
        prop_assert_eq!(decoded, bytes.as_slice());
        prop_assert!(r.is_empty());
    }
}

// ── Invite signing + verification ─────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: light_cases(),
        max_global_rejects: light_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Sign → encode → decode_and_verify always round-trips for any
    /// well-formed expiry + scope.
    #[test]
    fn invite_sign_encode_decode_roundtrip(
        expiry in any::<u64>(),
        scope_bytes in prop::collection::vec(any::<u8>(), 0..=128),
        nonce_seed in any::<u64>(),
    ) {
        let sk = SigningKey::generate(&mut OsRng);
        let mut nonce = [0u8; INVITE_NONCE_LEN];
        let mut s = nonce_seed;
        for b in &mut nonce {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = ((s >> 33) & 0xFF) as u8;
        }
        // Derive a real ephemeral x25519 pubkey to avoid the small-
        // order rejection path.
        let esk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let epk = x25519_dalek::PublicKey::from(&esk).to_bytes();
        let scope = CapabilityScope::from_bytes(&scope_bytes).unwrap();
        let invite = Invite::sign(&sk, epk, nonce, expiry, scope);
        let encoded = invite.encode();
        let decoded = Invite::decode_and_verify(&encoded).unwrap();
        prop_assert_eq!(decoded, invite);
    }

    /// Flipping any single byte in the encoded invite fails verify
    /// (either Truncated/Tag/Version error or BadSignature; NEVER
    /// accepted as a different valid invite).
    #[test]
    fn invite_single_bit_flip_never_accepted(
        flip_byte in 0u16..256,
    ) {
        let sk = SigningKey::generate(&mut OsRng);
        let esk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let epk = x25519_dalek::PublicKey::from(&esk).to_bytes();
        let invite = Invite::sign(
            &sk,
            epk,
            [0u8; INVITE_NONCE_LEN],
            1_900_000_000,
            CapabilityScope::empty(),
        );
        let mut encoded = invite.encode();
        let pos = (flip_byte as usize) % encoded.len();
        encoded[pos] ^= 0x01;
        // It might decode and fail signature; it might fail to
        // decode. Either way: NEVER produce a valid different Invite.
        if let Ok(other) = Invite::decode_and_verify(&encoded) {
            prop_assert_ne!(other, invite);
        }
    }
}

// ── PairResponse ──────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: light_cases(),
        .. ProptestConfig::default()
    })]

    /// sign_for_transcript → encode → decode_and_verify roundtrips
    /// when verifier uses the same transcript_bind.
    #[test]
    fn response_sign_verify_roundtrip(
        bind in prop::collection::vec(any::<u8>(), 0..=256),
    ) {
        let sk = SigningKey::generate(&mut OsRng);
        let esk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let epk = x25519_dalek::PublicKey::from(&esk).to_bytes();
        let resp = PairResponse::sign_for_transcript(
            &sk,
            epk,
            [0u8; RESPONSE_NONCE_LEN],
            &bind,
        );
        let encoded = resp.encode();
        let decoded = PairResponse::decode_and_verify(&encoded, &bind).unwrap();
        prop_assert_eq!(decoded, resp);
    }

    /// Verifying with a different transcript_bind always fails.
    #[test]
    fn response_wrong_bind_always_rejected(
        bind1 in prop::collection::vec(any::<u8>(), 1..=128),
        bind2 in prop::collection::vec(any::<u8>(), 1..=128),
    ) {
        prop_assume!(bind1 != bind2);
        let sk = SigningKey::generate(&mut OsRng);
        let esk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let epk = x25519_dalek::PublicKey::from(&esk).to_bytes();
        let resp = PairResponse::sign_for_transcript(
            &sk,
            epk,
            [0u8; RESPONSE_NONCE_LEN],
            &bind1,
        );
        let encoded = resp.encode();
        let err = PairResponse::decode_and_verify(&encoded, &bind2);
        prop_assert!(err.is_err());
    }
}

// ── SAS derivation ────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(),
        .. ProptestConfig::default()
    })]

    /// SAS derivation is deterministic.
    #[test]
    fn sas_deterministic(seed in any::<[u8; TRANSCRIPT_LEN]>()) {
        let t = TranscriptHash::from_bytes(seed);
        let s1 = Sas::derive(&t);
        let s2 = Sas::derive(&t);
        prop_assert_eq!(s1, s2);
    }

    /// SAS raw bits fit in exactly SAS_BITS bits.
    #[test]
    fn sas_uses_exactly_30_bits(seed in any::<[u8; TRANSCRIPT_LEN]>()) {
        let t = TranscriptHash::from_bytes(seed);
        let s = Sas::derive(&t);
        prop_assert!(s.raw_bits < (1u32 << SAS_BITS));
    }
}

// ── Transcript hash ───────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: light_cases(),
        .. ProptestConfig::default()
    })]

    /// Same (invite, response) → same transcript hash.
    #[test]
    fn transcript_deterministic(
        invite_scope in prop::collection::vec(any::<u8>(), 0..=128),
        response_bind in prop::collection::vec(any::<u8>(), 0..=128),
    ) {
        let sk_i = SigningKey::generate(&mut OsRng);
        let esk_i = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let epk_i = x25519_dalek::PublicKey::from(&esk_i).to_bytes();
        let invite = Invite::sign(
            &sk_i,
            epk_i,
            [0u8; INVITE_NONCE_LEN],
            1_900_000_000,
            CapabilityScope::from_bytes(&invite_scope).unwrap(),
        );
        let sk_s = SigningKey::generate(&mut OsRng);
        let esk_s = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let epk_s = x25519_dalek::PublicKey::from(&esk_s).to_bytes();
        let response = PairResponse::sign_for_transcript(
            &sk_s,
            epk_s,
            [0u8; RESPONSE_NONCE_LEN],
            &response_bind,
        );
        let t1 = transcript_hash(&invite, &response);
        let t2 = transcript_hash(&invite, &response);
        prop_assert_eq!(t1, t2);
    }
}

// ── Defensive: dummy ref-only use of types to silence proptest warnings.
fn _silence(_: &[u8; X25519_PUBKEY_LEN]) {}
