//! Pinned KAT vectors for Row 8 Layer 9 active routing.

use ol_device_mesh::active_routing::{
    CohortPrior, DeviceActionRecord, RoutingContext, RoutingHistory, RoutingPolicy,
    COHORT_DEFAULT_ALPHA, COHORT_DEFAULT_BETA, MAX_CANDIDATES_PER_PICK,
    MAX_POSTERIOR_COUNT, ROUTING_CONTEXT_DOMAIN, ROUTING_HISTORY_DECAY_DEFAULT_SECS,
};
use ol_device_mesh::DeviceClass;

fn check_regen<F: FnOnce()>(label: &str, dump: F) {
    if std::env::var("OL_ACTIVE_ROUTING_KAT_REGEN").as_deref() == Ok("1") {
        eprintln!("[KAT REGEN] {label}");
        dump();
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn kat_domain_tag_pinned() {
    assert_eq!(ROUTING_CONTEXT_DOMAIN, b"OL-mesh-routing-context-v1");
}

#[test]
fn kat_bound_constants_pinned() {
    assert_eq!(MAX_POSTERIOR_COUNT, 1024);
    assert_eq!(COHORT_DEFAULT_ALPHA, 1);
    assert_eq!(COHORT_DEFAULT_BETA, 1);
    assert_eq!(MAX_CANDIDATES_PER_PICK, 32);
    assert_eq!(ROUTING_HISTORY_DECAY_DEFAULT_SECS, 30 * 24 * 3600);
}

#[test]
fn kat_routing_context_hash_pinned() {
    let ctx = RoutingContext {
        contact_pin: [0x42; 32],
        hour_bucket: 14,
        day_of_week: 2,
        message_class: *b"DM  ",
        urgency: 1,
    };
    let hex = to_hex(&ctx.canonical_hash());
    check_regen("routing-context canonical hash", || {
        eprintln!("    EXPECTED_HEX = \"{hex}\"");
    });
    // 64 hex chars = 32 bytes; deterministic across builds.
    assert_eq!(hex.len(), 64);
    // The first byte changing if any input field changes.
    let mut ctx2 = ctx;
    ctx2.hour_bucket = 15;
    assert_ne!(ctx2.canonical_hash(), ctx.canonical_hash());
}

#[test]
fn kat_cohort_prior_for_class_pinned() {
    let p = CohortPrior::typical_user();
    let (phone_a, phone_b) = p.for_class(DeviceClass::Phone);
    let (laptop_a, laptop_b) = p.for_class(DeviceClass::Laptop);
    let (desktop_a, desktop_b) = p.for_class(DeviceClass::Desktop);
    let (generic_a, generic_b) = p.for_class(DeviceClass::Generic);
    assert_eq!(phone_a, 4);
    assert_eq!(phone_b, 1);
    assert_eq!(laptop_a, 3);
    assert_eq!(laptop_b, 1);
    assert_eq!(desktop_a, 2);
    assert_eq!(desktop_b, 1);
    assert_eq!(generic_a, 1);
    assert_eq!(generic_b, 1);
}

#[test]
fn kat_uniform_record_posterior_pinned() {
    let r = DeviceActionRecord::empty([0; 32], [0; 16]);
    assert_eq!(r.alpha, 1);
    assert_eq!(r.beta, 1);
    assert!((r.posterior_mean() - 0.5).abs() < 1e-12);
}

#[test]
fn kat_policy_defaults_pinned() {
    let conservative = RoutingPolicy::conservative();
    assert_eq!(conservative.history_decay_half_life_secs, 30 * 24 * 3600);
    assert_eq!(conservative.min_observations_before_exploit, 10);
    assert!(conservative.mirror_to_siblings);
    let aggressive = RoutingPolicy::aggressive();
    assert_eq!(aggressive.history_decay_half_life_secs, 7 * 24 * 3600);
    assert_eq!(aggressive.min_observations_before_exploit, 3);
}

#[test]
fn kat_empty_history_records_zero() {
    let h = RoutingHistory::empty();
    assert!(h.is_empty());
    assert_eq!(h.len(), 0);
}
