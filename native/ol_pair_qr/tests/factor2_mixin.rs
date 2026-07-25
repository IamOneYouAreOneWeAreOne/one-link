//! Factor-2 channel-reciprocity mix-in integration tests.
//!
//! Confirms:
//! - Both peers using the same factor-2 candidate complete explicit
//!   bidirectional key confirmation before either high-level inviter API
//!   releases its chain key.
//! - Different factor-2 candidates fail closed instead of silently
//!   producing divergent ratchet state.
//! - The plain non-F2 path still works (additive opt-in).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use ol_pair_qr::invite::CapabilityScope;
use ol_pair_qr::{Inviter, InviterState, PairError, Scanner, ScannerState};

fn make_pair() -> (Inviter, Scanner, Vec<u8>) {
    let mut inviter = Inviter::new(
        SigningKey::generate(&mut OsRng),
        &mut OsRng,
        1_900_000_000,
        CapabilityScope::from_bytes(b"contact").unwrap(),
    );
    let invite_bytes = inviter.invite_bytes();
    let (scanner, response_bytes) = Scanner::scan(
        SigningKey::generate(&mut OsRng),
        &invite_bytes,
        100,
        &mut OsRng,
    )
    .unwrap();
    let _ = inviter.receive_response(&response_bytes).unwrap();
    (inviter, scanner, invite_bytes)
}

#[test]
fn factor2_same_key_produces_matching_chain_keys() {
    let (mut inviter, mut scanner, _) = make_pair();
    let f2 = [0xA5u8; 32];
    let confirm_bytes = inviter.confirm_with_factor2(&f2).unwrap();
    assert_eq!(inviter.state(), InviterState::AwaitingFactor2Ack);
    let (ack, k_scanner) = scanner
        .receive_confirm_with_factor2(&confirm_bytes, &f2)
        .unwrap();
    assert_eq!(scanner.state(), ScannerState::Done);
    let k_inviter = inviter.receive_factor2_ack(&ack).unwrap();
    assert_eq!(inviter.state(), InviterState::Done);
    assert_eq!(k_inviter, k_scanner);
}

#[test]
fn factor2_different_keys_fail_closed_without_releasing_scanner_key() {
    let (mut inviter, mut scanner, _) = make_pair();
    let f2a = [0xA5u8; 32];
    let mut f2b = [0xA5u8; 32];
    f2b[0] ^= 0x01;
    let confirm_bytes = inviter.confirm_with_factor2(&f2a).unwrap();
    let err = scanner
        .receive_confirm_with_factor2(&confirm_bytes, &f2b)
        .unwrap_err();
    assert_eq!(err, PairError::Factor2KeyConfirmationFailed);
    assert_eq!(scanner.state(), ScannerState::AwaitingConfirm);
    assert_eq!(inviter.state(), InviterState::AwaitingFactor2Ack);
}

#[test]
fn factor2_mix_differs_from_plain_path() {
    // Plain path
    let (mut inviter_plain, mut scanner_plain, _) = make_pair();
    let (cb_plain, k_plain_inviter) = inviter_plain.confirm().unwrap();
    let k_plain_scanner = scanner_plain.receive_confirm(&cb_plain).unwrap();
    assert_eq!(k_plain_inviter, k_plain_scanner);

    // Factor-2 path with arbitrary key — independent pairing run.
    let (mut inviter_f2, mut scanner_f2, _) = make_pair();
    let f2 = [0xA5u8; 32];
    let cb_f2 = inviter_f2.confirm_with_factor2(&f2).unwrap();
    let (ack_f2, k_f2_scanner) = scanner_f2
        .receive_confirm_with_factor2(&cb_f2, &f2)
        .unwrap();
    let k_f2_inviter = inviter_f2.receive_factor2_ack(&ack_f2).unwrap();
    assert_eq!(k_f2_inviter, k_f2_scanner);

    // The two chain keys differ (different transcripts AND F2 mix-in).
    assert_ne!(k_plain_inviter, k_f2_inviter);
}

#[test]
fn factor2_only_one_side_supplies_is_rejected() {
    let (mut inviter, mut scanner, _) = make_pair();
    let f2 = [0xA5u8; 32];
    let confirm_bytes = inviter.confirm_with_factor2(&f2).unwrap();
    let err = scanner.receive_confirm(&confirm_bytes).unwrap_err();
    assert!(matches!(err, PairError::Oversize { .. }));
    assert_eq!(scanner.state(), ScannerState::AwaitingConfirm);
}

#[test]
fn factor2_tampered_inviter_proof_is_rejected() {
    let (mut inviter, mut scanner, _) = make_pair();
    let f2 = [0xA5u8; 32];
    let mut confirm_bytes = inviter.confirm_with_factor2(&f2).unwrap();
    let last = confirm_bytes.len() - 1;
    confirm_bytes[last] ^= 1;
    let err = scanner
        .receive_confirm_with_factor2(&confirm_bytes, &f2)
        .unwrap_err();
    assert_eq!(err, PairError::Factor2KeyConfirmationFailed);
    assert_eq!(scanner.state(), ScannerState::AwaitingConfirm);
}

#[test]
fn factor2_tampered_ack_is_rejected_without_releasing_inviter_key() {
    let (mut inviter, mut scanner, _) = make_pair();
    let f2 = [0xA5u8; 32];
    let confirm_bytes = inviter.confirm_with_factor2(&f2).unwrap();
    let (mut ack, _scanner_key) = scanner
        .receive_confirm_with_factor2(&confirm_bytes, &f2)
        .unwrap();
    ack[0] ^= 1;
    let err = inviter.receive_factor2_ack(&ack).unwrap_err();
    assert_eq!(err, PairError::Factor2KeyConfirmationFailed);
    assert_eq!(inviter.state(), InviterState::AwaitingFactor2Ack);
}

#[test]
fn factor2_truncated_frames_are_rejected_before_parsing() {
    let (mut inviter, mut scanner, _) = make_pair();
    let f2 = [0xA5u8; 32];
    let mut confirm_bytes = inviter.confirm_with_factor2(&f2).unwrap();
    confirm_bytes.pop();
    let err = scanner
        .receive_confirm_with_factor2(&confirm_bytes, &f2)
        .unwrap_err();
    assert!(matches!(err, PairError::BadFactor2ConfirmationLen { .. }));

    let err = inviter.receive_factor2_ack(&[0u8; 31]).unwrap_err();
    assert!(matches!(err, PairError::BadFactor2ConfirmationLen { .. }));
}

#[test]
fn factor2_endpoint_smoke_using_proximity_pair_output() {
    // Run a TINY ol_proximity_pair pipeline end-to-end on contrived
    // observations and feed its 32-byte privacy-amplified key into
    // the Factor-2 mix-in. This proves the API surface lines up.
    use ol_proximity_pair::{privacy_amplify, quantize_observations, QuantizeConfig};

    // Two peers with identical observations → identical bits.
    let obs: Vec<u8> = (0..128u32).map(|i| (i & 0xFF) as u8).collect();
    let cfg = QuantizeConfig {
        min_bytes: 32,
        guard_band: 0.1,
    };
    let bits_a = quantize_observations(&obs, &cfg).unwrap();
    let bits_b = quantize_observations(&obs, &cfg).unwrap();
    assert_eq!(bits_a, bits_b);
    let salt = [0u8; 32];
    let f2_a = privacy_amplify(&bits_a, &salt);
    let f2_b = privacy_amplify(&bits_b, &salt);
    assert_eq!(f2_a, f2_b);

    let (mut inviter, mut scanner, _) = make_pair();
    let cb = inviter.confirm_with_factor2(&f2_a).unwrap();
    let (ack, k_s) = scanner.receive_confirm_with_factor2(&cb, &f2_b).unwrap();
    let k_i = inviter.receive_factor2_ack(&ack).unwrap();
    assert_eq!(k_i, k_s);
}
