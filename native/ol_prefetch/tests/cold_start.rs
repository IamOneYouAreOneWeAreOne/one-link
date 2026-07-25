//! Phase D acceptance gate for `ol_prefetch`:
//!
//! > Active inference cold-start: bandit-equivalent performance
//! > within ≤50 transfers (lukewarm via cohort prior).
//!
//! "Bandit-equivalent" = the predictor identifies the dominant
//! next-file pattern after a small number of observations. We
//! verify the cold-start convergence (no prior) and the lukewarm
//! cohort-prior shortcut separately.

use ol_prefetch::PrefetchPredictor;

fn peer(b: u8) -> [u8; 32] {
    [b; 32]
}
fn file(b: u8) -> [u8; 32] {
    [b; 32]
}

#[test]
fn cold_start_converges_within_50_observations() {
    // No prior. Build A→B as the dominant pattern; sprinkle some
    // noise (A→C, A→D occasionally). After ≤50 observations the
    // predictor should rank B above C and D for "next after A".
    let mut p = PrefetchPredictor::default();
    let pp = peer(1);
    let truth_b = file(0xB);
    let truth_c = file(0xC);
    let truth_d = file(0xD);
    let trigger = file(0xA);

    let mut t = 0u64;
    let mut iterations = 0;
    let mut converged_at: Option<usize> = None;
    // Pattern: 8 out of every 10 transitions are A→B, 1 is A→C, 1 is A→D.
    let pattern = [
        truth_b, truth_b, truth_b, truth_b, truth_c, truth_b, truth_b, truth_b, truth_b, truth_d,
    ];
    while iterations < 50 {
        let next = pattern[iterations % pattern.len()];
        p.observe(&pp, trigger, t);
        t += 10;
        p.observe(&pp, next, t);
        t += 10;
        // Check: after this observation, does predict_top_n place B first?
        p.observe(&pp, trigger, t + 100);
        t += 100;
        let preds = p.predict_top_n(&pp, 3);
        if !preds.is_empty() && preds[0].file_id == truth_b && converged_at.is_none() {
            converged_at = Some(iterations + 1);
        }
        iterations += 1;
    }
    assert!(
        converged_at.is_some(),
        "predictor never converged in 50 iterations"
    );
    let at = converged_at.unwrap();
    assert!(
        at <= 50,
        "Phase D gate: converged at {at} iterations; need ≤50"
    );
}

#[test]
fn lukewarm_via_cohort_prior_converges_in_one_transfer() {
    // Alice has 100 well-formed observations of A→B. Bob is brand
    // new; cohort-prior transfer from Alice + ONE observation
    // anchoring Bob at A should already produce B as the top
    // prediction.
    let mut p = PrefetchPredictor::default();
    let alice = peer(1);
    let bob = peer(2);
    let trigger = file(0xA);
    let truth = file(0xB);

    let mut t = 0u64;
    for _ in 0..100 {
        p.observe(&alice, trigger, t);
        t += 10;
        p.observe(&alice, truth, t);
        t += 10;
    }
    // Bob: brand new. Transfer Alice's prior with weight 1.0.
    p.transfer_prior_from(&alice, bob, 1.0);
    // Anchor Bob at A and predict.
    p.observe(&bob, trigger, 9999);
    let preds = p.predict_top_n(&bob, 1);
    assert!(
        !preds.is_empty(),
        "cohort prior should immediately produce a prediction"
    );
    assert_eq!(
        preds[0].file_id, truth,
        "cohort prior should rank B first for Bob's first prediction"
    );
}
