//! Adversarial test vectors — known-attack inputs that any correct
//! threshold-recovery implementation must handle gracefully.
//!
//! Catches regressions that random property-based testing might miss:
//! degenerate parameter combinations, structurally-crafted shares,
//! boundary-condition secret content.

use ol_threshold_recovery::field_bound::{
    field_bound_reconstruct, field_bound_split, FieldBindingError, FieldWitness,
};
use ol_threshold_recovery::prng::PrngState;
use ol_threshold_recovery::shamir::{
    max_participants, params_valid, reconstruct_byte, reconstruct_bytes, share_byte, share_bytes,
    Share, ShareError,
};

// ── Adversarial: malformed share inputs ───────────────────────────

#[test]
fn adversarial_share_x_zero_rejected() {
    // x = 0 is reserved for the secret; sharing at x = 0 would
    // reveal the secret directly.
    let s = vec![Share::new(0, 0xAA), Share::new(1, 0xBB)];
    assert_eq!(
        reconstruct_byte(&s, 2).unwrap_err(),
        ShareError::InvalidShareX
    );
}

#[test]
fn adversarial_all_zero_shares() {
    // If an attacker supplies all-zero shares, reconstruct should
    // not crash. Returns whatever Lagrange gives at x = 0 over a
    // constant-0 polynomial (which is 0). Either way: no panic.
    let s = vec![Share::new(1, 0), Share::new(2, 0), Share::new(3, 0)];
    let r = reconstruct_byte(&s, 3);
    assert!(r.is_ok());
    // Polynomial through (1,0), (2,0), (3,0) is identically 0.
    // So p(0) = 0.
    assert_eq!(r.unwrap(), 0);
}

#[test]
fn adversarial_far_too_few_shares_errs() {
    // Requesting reconstruction with K = 5 but supplying only 1 share.
    let s = vec![Share::new(1, 0x42)];
    assert!(matches!(
        reconstruct_byte(&s, 5).unwrap_err(),
        ShareError::NotEnoughShares { .. }
    ));
}

#[test]
fn adversarial_k_zero_rejected_at_share_time() {
    let mut st = PrngState::new(0);
    assert_eq!(
        share_byte(0, 0, 5, &mut st).unwrap_err(),
        ShareError::InvalidParams { k: 0, n: 5 }
    );
}

#[test]
fn adversarial_k_gt_n_rejected_at_share_time() {
    let mut st = PrngState::new(0);
    assert_eq!(
        share_byte(0, 6, 5, &mut st).unwrap_err(),
        ShareError::InvalidParams { k: 6, n: 5 }
    );
}

#[test]
fn adversarial_n_over_255_rejected_at_share_time() {
    let mut st = PrngState::new(0);
    assert_eq!(
        share_byte(0, 1, 256, &mut st).unwrap_err(),
        ShareError::InvalidParams { k: 1, n: 256 }
    );
}

#[test]
fn adversarial_max_n_255_succeeds() {
    let mut st = PrngState::new(0xABCD);
    let s = share_byte(0x42, 100, max_participants(), &mut st).unwrap();
    assert_eq!(s.len(), 255);
    // Any 100 of 255 must reconstruct.
    let sub = &s[..100];
    assert_eq!(reconstruct_byte(sub, 100).unwrap(), 0x42);
}

// ── Adversarial: secret content patterns that might trip naive impls ──

#[test]
fn adversarial_all_zero_secret_64b() {
    let secret = vec![0u8; 64];
    let mut st = PrngState::new(0);
    let streams = share_bytes(&secret, 3, 5, &mut st).unwrap();
    let xs = vec![1u8, 2, 3];
    let refs: Vec<&[u8]> = streams[..3].iter().map(Vec::as_slice).collect();
    assert_eq!(reconstruct_bytes(&xs, &refs, 3).unwrap(), secret);
}

#[test]
fn adversarial_all_ff_secret_64b() {
    let secret = vec![0xFFu8; 64];
    let mut st = PrngState::new(0);
    let streams = share_bytes(&secret, 3, 5, &mut st).unwrap();
    let xs = vec![1u8, 2, 3];
    let refs: Vec<&[u8]> = streams[..3].iter().map(Vec::as_slice).collect();
    assert_eq!(reconstruct_bytes(&xs, &refs, 3).unwrap(), secret);
}

#[test]
fn adversarial_high_entropy_secret_typical_master_key() {
    // 32 bytes of high-entropy "master Ed25519 seed" shape input.
    let secret: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(13).wrapping_add(7))
        .collect();
    let mut st = PrngState::new(0xDEAD_BEEF_CAFE_F00D);
    let streams = share_bytes(&secret, 3, 5, &mut st).unwrap();
    let xs = vec![1u8, 3, 5];
    let refs: Vec<&[u8]> = [&streams[0], &streams[2], &streams[4]]
        .iter()
        .map(|v| v.as_slice())
        .collect();
    assert_eq!(reconstruct_bytes(&xs, &refs, 3).unwrap(), secret);
}

#[test]
fn adversarial_long_secret_4kb() {
    // Stress: 4096-byte secret (multiple cache lines, typical "key
    // bundle" size). Each byte should reconstruct independently.
    let secret: Vec<u8> = (0..4096u32)
        .map(|i| i.to_le_bytes()[0].wrapping_mul(31))
        .collect();
    let mut st = PrngState::new(0x1111_2222);
    let streams = share_bytes(&secret, 3, 5, &mut st).unwrap();
    let xs = vec![1u8, 2, 3];
    let refs: Vec<&[u8]> = streams[..3].iter().map(Vec::as_slice).collect();
    let recovered = reconstruct_bytes(&xs, &refs, 3).unwrap();
    assert_eq!(recovered, secret);
}

// ── Adversarial: field-bound layer attack patterns ────────────────

#[test]
fn adversarial_field_bound_attacker_swaps_witness_components() {
    // Real witness, attacker supplies wrong (a) epoch (b) holder score
    // (c) field seed. Each MUST fail recovery.
    let secret = b"32-byte master Ed25519 seed!!!!\x00";
    let real_seed = [0x42u8; 32];
    let real_scores = vec![0.10, 0.20, 0.30, 0.40, 0.50];
    let real_epoch = 1_700_000_000u64;
    let real = FieldWitness {
        field_seed: real_seed,
        holder_scores: real_scores.clone(),
        epoch_ns: real_epoch,
    };
    let mut st = PrngState::new(0xCAFE);
    let masked = field_bound_split(secret, 3, 5, &mut st, &real).unwrap();
    let xs = vec![1u8, 2, 3];
    let supplied: Vec<&[u8]> = masked[..3].iter().map(Vec::as_slice).collect();
    let indices = vec![0usize, 1, 2];

    // (a) Wrong epoch.
    let mut wrong_epoch = real.clone();
    wrong_epoch.epoch_ns = real_epoch.wrapping_add(1);
    let r = field_bound_reconstruct(&xs, &supplied, &indices, 3, &wrong_epoch).unwrap();
    assert_ne!(r, secret);

    // (b) Wrong score (one byte changed in one float).
    let mut wrong_scores = real.clone();
    wrong_scores.holder_scores[0] += f64::EPSILON; // smallest perturbation
    let r = field_bound_reconstruct(&xs, &supplied, &indices, 3, &wrong_scores).unwrap();
    assert_ne!(r, secret);

    // (c) Wrong seed (single byte flip).
    let mut wrong_seed = real.clone();
    wrong_seed.field_seed[0] ^= 1;
    let r = field_bound_reconstruct(&xs, &supplied, &indices, 3, &wrong_seed).unwrap();
    assert_ne!(r, secret);
}

#[test]
fn adversarial_field_bound_score_out_of_range_caught() {
    let mut witness = FieldWitness {
        field_seed: [0u8; 32],
        holder_scores: vec![0.5; 5],
        epoch_ns: 0,
    };
    // Negative score.
    witness.holder_scores[2] = -0.01;
    let mut st = PrngState::new(0);
    let err = field_bound_split(b"x", 3, 5, &mut st, &witness).unwrap_err();
    assert!(matches!(
        err,
        FieldBindingError::FieldScoreOutOfRange { .. }
    ));

    // Above 1.
    witness.holder_scores[2] = 1.01;
    let err = field_bound_split(b"x", 3, 5, &mut st, &witness).unwrap_err();
    assert!(matches!(
        err,
        FieldBindingError::FieldScoreOutOfRange { .. }
    ));
}

#[test]
fn adversarial_field_bound_score_count_mismatch() {
    let witness = FieldWitness {
        field_seed: [0u8; 32],
        holder_scores: vec![0.5; 3], // 3 scores
        epoch_ns: 0,
    };
    let mut st = PrngState::new(0);
    let err = field_bound_split(b"x", 2, 5, &mut st, &witness).unwrap_err();
    assert!(matches!(
        err,
        FieldBindingError::ScoreCountMismatch {
            expected: 5,
            got: 3
        }
    ));
}

#[test]
fn adversarial_field_bound_replay_with_different_epoch_fails() {
    // Defense-in-depth scenario: an attacker captures old masked
    // shares from a previous epoch, then re-uses them with the
    // current witness. Wrong epoch -> wrong OTPs -> no recovery.
    let secret = b"32-byte master seed for recovery";
    let w_old = FieldWitness {
        field_seed: [0x42u8; 32],
        holder_scores: vec![0.1, 0.3, 0.5, 0.7, 0.9],
        epoch_ns: 100,
    };
    let w_new = FieldWitness {
        field_seed: [0x42u8; 32],
        holder_scores: vec![0.1, 0.3, 0.5, 0.7, 0.9],
        epoch_ns: 200,
    };
    let mut st = PrngState::new(0);
    let masked_old = field_bound_split(secret, 3, 5, &mut st, &w_old).unwrap();
    let xs = vec![1u8, 2, 3];
    let supplied: Vec<&[u8]> = masked_old[..3].iter().map(Vec::as_slice).collect();
    let indices = vec![0usize, 1, 2];
    let r = field_bound_reconstruct(&xs, &supplied, &indices, 3, &w_new).unwrap();
    assert_ne!(r, secret);
}

// ── Adversarial: structural / API misuse ─────────────────────────

#[test]
fn adversarial_share_with_collision_in_x() {
    // Two shares with x = 1 — degenerate; recovery should error.
    let s = vec![Share::new(1, 0xAA), Share::new(1, 0xBB)];
    assert!(matches!(
        reconstruct_byte(&s, 2).unwrap_err(),
        ShareError::DuplicateShareX
    ));
}

#[test]
fn adversarial_max_k_at_max_n() {
    // Edge: K = N = 255. Hardest case in GF(2^8).
    let mut st = PrngState::new(0xFFFF);
    let s = share_byte(0xAB, 255, 255, &mut st).unwrap();
    assert_eq!(s.len(), 255);
    // Every share is required.
    assert_eq!(reconstruct_byte(&s, 255).unwrap(), 0xAB);
}

#[test]
fn adversarial_params_valid_boundary_conditions() {
    assert!(params_valid(1, 1));
    assert!(params_valid(255, 255));
    assert!(params_valid(1, 255));
    assert!(!params_valid(0, 1));
    assert!(!params_valid(1, 0));
    assert!(!params_valid(2, 1));
    assert!(!params_valid(0, 0));
    assert!(!params_valid(1, 256));
}
