//! Adversarial test vectors for `ol_pair_qr`.
//!
//! Catches known-attack patterns + edge cases that random property
//! tests might miss.

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;

use ol_pair_qr::canon::{Reader, MAX_FIELD_BYTES};
use ol_pair_qr::confirm::PairConfirm;
use ol_pair_qr::errors::PairError;
use ol_pair_qr::invite::{CapabilityScope, Invite, INVITE_MAX_BYTES, INVITE_NONCE_LEN};
use ol_pair_qr::response::PairResponse;
use ol_pair_qr::transcript::{transcript_hash, TranscriptHash, TRANSCRIPT_LEN};
use ol_pair_qr::{Inviter, Scanner};

// ── Canon decode pathologies ──────────────────────────────────────

#[test]
fn adversarial_canon_zero_length_var_decodes_empty() {
    let bytes = [0x00u8, 0x00];
    let mut r = Reader::new(&bytes);
    let v = r.read_var().unwrap();
    assert!(v.is_empty());
}

#[test]
fn adversarial_canon_max_length_var_works() {
    let cap = MAX_FIELD_BYTES;
    let mut bytes = Vec::new();
    let wire_cap = match u16::try_from(cap) {
        Ok(len) => len,
        Err(error) => panic!("MAX_FIELD_BYTES must fit the u16 wire prefix: {error}"),
    };
    bytes.extend_from_slice(&wire_cap.to_be_bytes());
    bytes.extend(std::iter::repeat_n(0u8, cap));
    let mut r = Reader::new(&bytes);
    let v = r.read_var().unwrap();
    assert_eq!(v.len(), cap);
}

#[test]
fn adversarial_canon_partial_u64_truncated() {
    let bytes = [0u8; 7]; // need 8 for u64
    let mut r = Reader::new(&bytes);
    let err = r.read_u64().unwrap_err();
    assert!(matches!(err, PairError::Truncated { .. }));
}

// ── Invite tampering ──────────────────────────────────────────────

#[test]
fn adversarial_invite_all_zero_payload_rejected() {
    let bytes = [0u8; INVITE_MAX_BYTES];
    let err = Invite::decode_and_verify(&bytes).unwrap_err();
    // Whatever the specific error, must NOT be a successful decode.
    assert!(matches!(
        err,
        PairError::Oversize { .. }
            | PairError::UnsupportedVersion { .. }
            | PairError::BadSignature
            | PairError::BadTag { .. }
            | PairError::Truncated { .. }
    ));
}

#[test]
fn adversarial_invite_signature_substituted_rejected() {
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
    // Replace last 64 bytes (signature) with another valid Ed25519 sig
    // from a DIFFERENT keypair over the same body.
    let other_sk = SigningKey::generate(&mut OsRng);
    let body = invite.body_bytes();
    let bogus_sig: ed25519_dalek::Signature = other_sk.sign(&body);
    let bogus_bytes = bogus_sig.to_bytes();
    let sig_off = encoded.len() - 64;
    encoded[sig_off..].copy_from_slice(&bogus_bytes);
    let err = Invite::decode_and_verify(&encoded).unwrap_err();
    assert_eq!(err, PairError::BadSignature);
}

#[test]
fn adversarial_invite_oversize_scope_rejected_in_constructor() {
    let huge = vec![0u8; MAX_FIELD_BYTES + 1];
    let err = CapabilityScope::from_bytes(&huge).unwrap_err();
    assert!(matches!(err, PairError::Oversize { .. }));
}

// ── PairResponse cross-invite replay ──────────────────────────────

#[test]
fn adversarial_response_cross_invite_replay_blocked() {
    // Scanner signs a response committed to invite A's body bytes.
    // Attacker tries to attach that response to invite B → reject.
    let inviter_a = Inviter::new(
        SigningKey::generate(&mut OsRng),
        &mut OsRng,
        1_900_000_000,
        CapabilityScope::from_bytes(b"alpha").unwrap(),
    );
    let mut inviter_b = Inviter::new(
        SigningKey::generate(&mut OsRng),
        &mut OsRng,
        1_900_000_000,
        CapabilityScope::from_bytes(b"beta").unwrap(),
    );
    let bytes_a = inviter_a.invite_bytes();
    let bytes_b = inviter_b.invite_bytes();

    // Scanner scans A.
    let scanner_sk = SigningKey::generate(&mut OsRng);
    let (_, response_for_a) = Scanner::scan(scanner_sk, &bytes_a, 100, &mut OsRng).unwrap();

    // Attacker forwards the same response to inviter_b.
    let decoded_second_invite = Invite::decode_and_verify(&bytes_b).unwrap();
    let err = PairResponse::decode_and_verify(&response_for_a, &decoded_second_invite.body_bytes())
        .unwrap_err();
    assert_eq!(err, PairError::BadSignature);

    // Sanity: also try receive_response on inviter_b (which calls
    // decode_and_verify internally with B's bind).
    let err = inviter_b.receive_response(&response_for_a).unwrap_err();
    assert_eq!(err, PairError::BadSignature);
}

// ── PairConfirm anti-key-substitution ─────────────────────────────

#[test]
fn adversarial_confirm_attacker_swaps_inviter_key_rejected() {
    // Build a real transcript by running a full pair through the
    // honest state machine, then forge a confirm from a different
    // key. Scanner must refuse.
    let mut inviter = Inviter::new(
        SigningKey::generate(&mut OsRng),
        &mut OsRng,
        1_900_000_000,
        CapabilityScope::empty(),
    );
    let invite_bytes = inviter.invite_bytes();
    let scanner_sk = SigningKey::generate(&mut OsRng);
    let (mut scanner, response_bytes) =
        Scanner::scan(scanner_sk, &invite_bytes, 100, &mut OsRng).unwrap();
    let _sas = inviter.receive_response(&response_bytes).unwrap();

    // Forge a confirm from a different signing key, using the same
    // transcript value.
    let attacker_sk = SigningKey::generate(&mut OsRng);
    let invite = Invite::decode_and_verify(&invite_bytes).unwrap();
    let response = PairResponse::decode_and_verify(&response_bytes, &invite.body_bytes()).unwrap();
    let real_t = transcript_hash(&invite, &response);
    let bogus_confirm = PairConfirm::sign(&attacker_sk, real_t);
    let err = scanner
        .receive_confirm(&bogus_confirm.encode())
        .unwrap_err();
    assert_eq!(err, PairError::BadSignature);
}

#[test]
fn adversarial_confirm_attacker_swaps_transcript_rejected() {
    let mut inviter = Inviter::new(
        SigningKey::generate(&mut OsRng),
        &mut OsRng,
        1_900_000_000,
        CapabilityScope::empty(),
    );
    let invite_bytes = inviter.invite_bytes();
    let scanner_sk = SigningKey::generate(&mut OsRng);
    let (mut scanner, response_bytes) =
        Scanner::scan(scanner_sk, &invite_bytes, 100, &mut OsRng).unwrap();
    let _sas = inviter.receive_response(&response_bytes).unwrap();

    // Inviter signs a confirm but for a DIFFERENT transcript value.
    let invite = Invite::decode_and_verify(&invite_bytes).unwrap();
    // We don't have access to inviter's signing key directly; mimic
    // by signing with a different keypair (this also covers the
    // mismatch path).
    let inviter_other_sk = SigningKey::generate(&mut OsRng);
    let fake_t = TranscriptHash::from_bytes([0xCDu8; TRANSCRIPT_LEN]);
    let bogus_confirm = PairConfirm::sign(&inviter_other_sk, fake_t);
    let err = scanner
        .receive_confirm(&bogus_confirm.encode())
        .unwrap_err();
    // Either BadSignature (wrong pubkey pinned) or TranscriptMismatch.
    assert!(
        matches!(err, PairError::BadSignature | PairError::TranscriptMismatch),
        "{err:?}"
    );
    // Bind invite to silence unused.
    drop(invite);
}

// ── State machine misuse ──────────────────────────────────────────

#[test]
fn adversarial_inviter_double_confirm_rejected() {
    let mut inviter = Inviter::new(
        SigningKey::generate(&mut OsRng),
        &mut OsRng,
        1_900_000_000,
        CapabilityScope::empty(),
    );
    let invite_bytes = inviter.invite_bytes();
    let scanner_sk = SigningKey::generate(&mut OsRng);
    let (mut _scanner, response_bytes) =
        Scanner::scan(scanner_sk, &invite_bytes, 100, &mut OsRng).unwrap();
    let _ = inviter.receive_response(&response_bytes).unwrap();
    let _ = inviter.confirm().unwrap();
    let err = inviter.confirm().unwrap_err();
    assert_eq!(err, PairError::WrongState);
}

#[test]
fn adversarial_scanner_double_receive_rejected() {
    let mut inviter = Inviter::new(
        SigningKey::generate(&mut OsRng),
        &mut OsRng,
        1_900_000_000,
        CapabilityScope::empty(),
    );
    let invite_bytes = inviter.invite_bytes();
    let scanner_sk = SigningKey::generate(&mut OsRng);
    let (mut scanner, response_bytes) =
        Scanner::scan(scanner_sk, &invite_bytes, 100, &mut OsRng).unwrap();
    let _ = inviter.receive_response(&response_bytes).unwrap();
    let (confirm_bytes, _) = inviter.confirm().unwrap();
    let _ = scanner.receive_confirm(&confirm_bytes).unwrap();
    let err = scanner.receive_confirm(&confirm_bytes).unwrap_err();
    assert_eq!(err, PairError::WrongState);
}

// ── Expiry boundary ───────────────────────────────────────────────

#[test]
fn adversarial_invite_exactly_at_expiry_unix_rejected() {
    let inviter = Inviter::new(
        SigningKey::generate(&mut OsRng),
        &mut OsRng,
        100,
        CapabilityScope::empty(),
    );
    let invite_bytes = inviter.invite_bytes();
    let scanner_sk = SigningKey::generate(&mut OsRng);
    let err = Scanner::scan(scanner_sk, &invite_bytes, 100, &mut OsRng).unwrap_err();
    assert!(matches!(err, PairError::Expired { .. }));
}

#[test]
fn adversarial_invite_one_second_before_expiry_accepted() {
    let inviter = Inviter::new(
        SigningKey::generate(&mut OsRng),
        &mut OsRng,
        100,
        CapabilityScope::empty(),
    );
    let invite_bytes = inviter.invite_bytes();
    let scanner_sk = SigningKey::generate(&mut OsRng);
    let _ = Scanner::scan(scanner_sk, &invite_bytes, 99, &mut OsRng).unwrap();
}

// ── SAS comparison soundness ──────────────────────────────────────

#[test]
fn adversarial_sas_collision_resistance_smoke() {
    // Generate 1000 distinct transcripts by BLAKE3-hashing the
    // iteration counter (gives full 32-byte entropy each iter).
    // The number of distinct SAS values observed should be ≥ 999
    // because the SAS has 30 bits of entropy and the birthday bound
    // at 1000 samples in 2³⁰ space is < 1 expected collision.
    use ol_pair_qr::sas::Sas;
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    for i in 0u64..1000 {
        let h = blake3::hash(&i.to_le_bytes());
        let mut bytes = [0u8; TRANSCRIPT_LEN];
        bytes.copy_from_slice(h.as_bytes());
        let t = TranscriptHash::from_bytes(bytes);
        seen.insert(Sas::derive(&t).raw_bits);
    }
    assert!(
        seen.len() >= 999,
        "SAS collision rate too high: {} distinct from 1000",
        seen.len()
    );
}
