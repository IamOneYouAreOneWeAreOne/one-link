//! Property tests for Row 8 Layer 9 active-inference routing.

use proptest::prelude::*;
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use ol_device_mesh::active_routing::{
    pick_device_for_context, CohortPrior, DeviceActionRecord, RoutingContext, RoutingHistory,
};
use ol_device_mesh::{DeviceClass, DEVICE_ID_LEN};

fn cheap_cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        5_000_000
    } else {
        1_000_000
    }
}

fn ctx_strategy() -> impl Strategy<Value = RoutingContext> {
    (
        any::<[u8; 32]>(),
        any::<u8>(),
        any::<u8>(),
        any::<[u8; 4]>(),
        any::<u8>(),
    )
        .prop_map(|(c, h, d, cl, u)| RoutingContext {
            contact_pin: c,
            hour_bucket: h,
            day_of_week: d,
            message_class: cl,
            urgency: u,
        })
}

// ── 1M-iter properties on hashes + posterior math ────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cheap_cases(),
        max_global_rejects: cheap_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Context hash is a pure function of context fields.
    #[test]
    fn context_hash_deterministic(ctx in ctx_strategy()) {
        prop_assert_eq!(ctx.canonical_hash(), ctx.canonical_hash());
    }

    /// Posterior mean is in [0, 1] for any (alpha, beta) >= (1, 1).
    #[test]
    fn posterior_mean_in_range(
        alpha in 1u32..1_000_000,
        beta in 1u32..1_000_000,
    ) {
        let r = DeviceActionRecord {
            context_hash: [0; 32],
            device_id: [0; DEVICE_ID_LEN],
            alpha,
            beta,
            last_updated_unix: 0,
        };
        let m = r.posterior_mean();
        prop_assert!(m >= 0.0);
        prop_assert!(m <= 1.0);
    }

    /// Observing `acted = true` weakly INCREASES the posterior mean;
    /// observing `acted = false` weakly DECREASES it.
    #[test]
    fn observe_moves_posterior_in_expected_direction(
        alpha in 1u32..500u32,
        beta in 1u32..500u32,
    ) {
        let base = DeviceActionRecord {
            context_hash: [0; 32],
            device_id: [0; DEVICE_ID_LEN],
            alpha,
            beta,
            last_updated_unix: 0,
        };
        let mean_before = base.posterior_mean();
        let mut after_act = base;
        after_act.observe(true, 1);
        let mut after_dis = base;
        after_dis.observe(false, 1);
        prop_assert!(after_act.posterior_mean() >= mean_before - 1e-12);
        prop_assert!(after_dis.posterior_mean() <= mean_before + 1e-12);
    }
}

// ── Thompson-sampling convergence (deterministic seed) ────────────

#[test]
fn picker_convergence_to_majority_winner() {
    // Seeded RNG so the test is deterministic.
    let mut rng = ChaCha20Rng::from_seed([0xAA; 32]);
    let ctx = RoutingContext {
        contact_pin: [1; 32],
        hour_bucket: 9,
        day_of_week: 1,
        message_class: *b"DM  ",
        urgency: 1,
    };
    let candidates = vec![
        ([0x01u8; DEVICE_ID_LEN], DeviceClass::Phone),
        ([0x02u8; DEVICE_ID_LEN], DeviceClass::Laptop),
    ];
    let mut history = RoutingHistory::empty();
    let ctx_hash = ctx.canonical_hash();
    // Strong evidence: phone gets 50 acts; laptop gets 50 dismisses.
    for _ in 0..50 {
        history.observe(ctx_hash, [0x01; DEVICE_ID_LEN], true, 1, 1, 1);
        history.observe(ctx_hash, [0x02; DEVICE_ID_LEN], false, 1, 1, 1);
    }
    let cohort = CohortPrior::uniform();
    let mut phone_picks = 0;
    let trials = 500;
    for _ in 0..trials {
        if let Some(p) = pick_device_for_context(&ctx, &candidates, &history, &cohort, &mut rng) {
            if p == [0x01; DEVICE_ID_LEN] {
                phone_picks += 1;
            }
        }
    }
    // Posterior on phone is ~51/52 ≈ 0.98; on laptop ~1/52 ≈ 0.019.
    // Phone should sweep the vast majority.
    assert!(
        phone_picks >= 450,
        "phone won only {phone_picks}/{trials}; expected >=450"
    );
}

#[test]
fn picker_explores_when_uninformed() {
    // No history → Thompson sampling on Beta(1,1) gives uniform-ish
    // picks. Empirically, each of 3 candidates should win ~1/3.
    let mut rng = ChaCha20Rng::from_seed([0xBB; 32]);
    let ctx = RoutingContext {
        contact_pin: [1; 32],
        hour_bucket: 9,
        day_of_week: 1,
        message_class: *b"DM  ",
        urgency: 1,
    };
    let candidates = vec![
        ([0x01u8; DEVICE_ID_LEN], DeviceClass::Phone),
        ([0x02u8; DEVICE_ID_LEN], DeviceClass::Laptop),
        ([0x03u8; DEVICE_ID_LEN], DeviceClass::Desktop),
    ];
    let history = RoutingHistory::empty();
    let cohort = CohortPrior::uniform();
    let mut counts = std::collections::HashMap::<[u8; DEVICE_ID_LEN], u32>::new();
    let trials = 600;
    for _ in 0..trials {
        if let Some(p) = pick_device_for_context(&ctx, &candidates, &history, &cohort, &mut rng) {
            *counts.entry(p).or_default() += 1;
        }
    }
    // No candidate should sweep > 60% in the uninformed regime.
    for c in counts.values() {
        assert!(*c < (trials * 6 / 10));
    }
}

// ── OsRng-backed sanity ─────────────────────────────────────────

#[test]
fn picker_never_panics_with_os_rng() {
    let ctx = RoutingContext {
        contact_pin: [0; 32],
        hour_bucket: 0,
        day_of_week: 0,
        message_class: [0; 4],
        urgency: 0,
    };
    let candidates = vec![([0; DEVICE_ID_LEN], DeviceClass::Generic)];
    let _ = pick_device_for_context(
        &ctx,
        &candidates,
        &RoutingHistory::empty(),
        &CohortPrior::uniform(),
        &mut OsRng,
    );
}
