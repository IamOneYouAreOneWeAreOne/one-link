//! Adversarial vectors for Row 8 Layer 9 active routing.

use ol_device_mesh::active_routing::{
    pick_device_for_context, CohortPrior, DeviceActionRecord, RoutingContext,
    RoutingHistory, MAX_POSTERIOR_COUNT,
};
use ol_device_mesh::{DeviceClass, DEVICE_ID_LEN};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn ctx() -> RoutingContext {
    RoutingContext {
        contact_pin: [1; 32],
        hour_bucket: 9,
        day_of_week: 1,
        message_class: *b"DM  ",
        urgency: 1,
    }
}

// ── Context-hash adversarial ──────────────────────────────────────

#[test]
fn adversarial_context_tampered_yields_different_bucket() {
    // Any field change must move the record to a different bucket
    // (so an attacker can't drift the posterior by tweaking, say,
    // urgency).
    let base = ctx();
    let mut perturbed = base;
    perturbed.urgency = 2;
    assert_ne!(base.canonical_hash(), perturbed.canonical_hash());
    perturbed = base;
    perturbed.message_class = *b"FILE";
    assert_ne!(base.canonical_hash(), perturbed.canonical_hash());
}

// ── Record-saturation adversarial ─────────────────────────────────

#[test]
fn adversarial_saturation_halves_then_continues() {
    // Pour observations until the counter saturates; verify the
    // posterior stays usable after the half-decay kicks in.
    let mut r = DeviceActionRecord::empty([0; 32], [0; 16]);
    for _ in 0..(MAX_POSTERIOR_COUNT * 3) {
        r.observe(true, 1);
    }
    // Should not have grown unboundedly.
    assert!(r.alpha + r.beta <= MAX_POSTERIOR_COUNT + 2);
    // Posterior mean should still favour the majority signal.
    assert!(r.posterior_mean() > 0.5);
}

// ── History adversarial ───────────────────────────────────────────

#[test]
fn adversarial_history_lookup_missing_pair_returns_none() {
    let h = RoutingHistory::empty();
    let rec = h.record(&[0; 32], &[0; DEVICE_ID_LEN]);
    assert!(rec.is_none());
}

#[test]
fn adversarial_history_decay_floor_at_one() {
    // Even with extreme decay, alpha + beta floor at (1, 1) — the
    // picker never divides by zero on empty Beta.
    let mut h = RoutingHistory::empty();
    h.observe([1; 32], [1; DEVICE_ID_LEN], true, 100, 1, 1);
    h.decay_all(1_000_000_000, 60);
    let rec = h.record(&[1; 32], &[1; DEVICE_ID_LEN]).unwrap();
    assert!(rec.alpha >= 1);
    assert!(rec.beta >= 1);
}

// ── Picker adversarial ────────────────────────────────────────────

#[test]
fn adversarial_picker_empty_candidates_none() {
    let mut rng = ChaCha20Rng::from_seed([0; 32]);
    let pick = pick_device_for_context(
        &ctx(),
        &[],
        &RoutingHistory::empty(),
        &CohortPrior::uniform(),
        &mut rng,
    );
    assert!(pick.is_none());
}

#[test]
fn adversarial_picker_extreme_skew_doesnt_panic() {
    // History with maxed-out alpha + beta; ensure the gamma
    // sampler doesn't underflow / panic.
    let mut h = RoutingHistory::empty();
    let ctx_hash = ctx().canonical_hash();
    for _ in 0..(MAX_POSTERIOR_COUNT + 10) {
        h.observe(ctx_hash, [0x01; DEVICE_ID_LEN], true, 1, 1, 1);
    }
    let mut rng = ChaCha20Rng::from_seed([1; 32]);
    let pick = pick_device_for_context(
        &ctx(),
        &[([0x01; DEVICE_ID_LEN], DeviceClass::Phone)],
        &h,
        &CohortPrior::uniform(),
        &mut rng,
    );
    assert_eq!(pick, Some([0x01; DEVICE_ID_LEN]));
}

#[test]
fn adversarial_picker_attacker_can_only_bias_via_observations() {
    // An attacker who doesn't have observe access can't bias the
    // picker. Construct two identical pickers and ensure outputs
    // match for the same RNG seed.
    let h = RoutingHistory::empty();
    let candidates = vec![
        ([0x01u8; DEVICE_ID_LEN], DeviceClass::Phone),
        ([0x02u8; DEVICE_ID_LEN], DeviceClass::Laptop),
    ];
    let mut rng1 = ChaCha20Rng::from_seed([0xAA; 32]);
    let mut rng2 = ChaCha20Rng::from_seed([0xAA; 32]);
    let p1 = pick_device_for_context(
        &ctx(),
        &candidates,
        &h,
        &CohortPrior::uniform(),
        &mut rng1,
    );
    let p2 = pick_device_for_context(
        &ctx(),
        &candidates,
        &h,
        &CohortPrior::uniform(),
        &mut rng2,
    );
    assert_eq!(p1, p2);
}

#[test]
fn adversarial_record_history_drift_under_intermittent_decay() {
    // Bias toward laptop, then sweep decay, then bias toward phone.
    // The picker should track the most recent signal.
    let mut h = RoutingHistory::empty();
    let ctx_hash = ctx().canonical_hash();
    // Phase 1: laptop wins.
    for _ in 0..200 {
        h.observe(ctx_hash, [0x02; DEVICE_ID_LEN], true, 100, 1, 1);
        h.observe(ctx_hash, [0x01; DEVICE_ID_LEN], false, 100, 1, 1);
    }
    // Aggressive decay (one half-life).
    h.decay_all(160, 60);
    // Phase 2: phone wins.
    for _ in 0..200 {
        h.observe(ctx_hash, [0x01; DEVICE_ID_LEN], true, 200, 1, 1);
        h.observe(ctx_hash, [0x02; DEVICE_ID_LEN], false, 200, 1, 1);
    }
    let mut rng = ChaCha20Rng::from_seed([0x77; 32]);
    let candidates = vec![
        ([0x01u8; DEVICE_ID_LEN], DeviceClass::Phone),
        ([0x02u8; DEVICE_ID_LEN], DeviceClass::Laptop),
    ];
    let mut phone_picks = 0;
    let trials = 200;
    for _ in 0..trials {
        if let Some(p) = pick_device_for_context(
            &ctx(),
            &candidates,
            &h,
            &CohortPrior::uniform(),
            &mut rng,
        ) {
            if p == [0x01; DEVICE_ID_LEN] {
                phone_picks += 1;
            }
        }
    }
    // After decay + phase 2, phone should dominate.
    assert!(
        phone_picks > trials * 6 / 10,
        "phone {phone_picks}/{trials} — decay didn't track drift"
    );
}
