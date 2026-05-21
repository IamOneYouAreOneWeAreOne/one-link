//! Proptest properties for `ol_align`.
//!
//! These complement the unit tests in `align.rs` by exploring the input
//! space rather than fixed examples.

use ol_align::{trust_score, AlignError, Relationship, DEFAULT_L_PAIRED};
use proptest::prelude::*;

proptest! {
    /// Total: `trust_score` never panics for any input.
    /// Either returns Ok(x) with x in [0, 1], or returns a structured error.
    /// At extreme decay f32 exp underflows to exactly 0.0, which is the
    /// semantically correct "trust fully exhausted" value.
    #[test]
    fn trust_score_total(
        hop in -10.0f32..100.0,
        staleness in -86400.0f32..(365.0 * 86400.0),
        l in -10.0f32..1000.0,
    ) {
        match trust_score(hop, staleness, l) {
            Ok(t) => {
                prop_assert!(t.is_finite());
                prop_assert!((0.0..=1.0).contains(&t));
            }
            Err(_) => {
                // Errors are fine; just verify they correspond to expected
                // invalidity classes.
                prop_assert!(
                    hop < 0.0 || staleness < 0.0 || l <= 0.0
                        || !hop.is_finite() || !staleness.is_finite() || !l.is_finite()
                );
            }
        }
    }

    /// Monotone in hop_distance: at fixed (staleness, L), more hops ->
    /// strictly less trust (modulo floating-point precision).
    #[test]
    fn monotone_in_hops(
        hop1 in 0.0f32..10.0,
        delta in 0.1f32..10.0,
        staleness in 0.0f32..(86400.0 * 30.0),
    ) {
        let hop2 = hop1 + delta;
        let t1 = trust_score(hop1, staleness, DEFAULT_L_PAIRED).unwrap();
        let t2 = trust_score(hop2, staleness, DEFAULT_L_PAIRED).unwrap();
        prop_assert!(t1 >= t2);
    }

    /// Monotone in staleness: at fixed (hop, L), staler -> less trust.
    #[test]
    fn monotone_in_staleness(
        s1 in 0.0f32..(86400.0 * 10.0),
        delta in 1.0f32..(86400.0 * 30.0),
        hop in 0.0f32..5.0,
    ) {
        let s2 = s1 + delta;
        let t1 = trust_score(hop, s1, DEFAULT_L_PAIRED).unwrap();
        let t2 = trust_score(hop, s2, DEFAULT_L_PAIRED).unwrap();
        prop_assert!(t1 >= t2);
    }

    /// Larger L_session => slower decay => more trust at fixed (hop, staleness).
    /// (Paired session length >= Known session length => paired trust >= known trust.)
    #[test]
    fn paired_dominates_known(
        hop in 0.0f32..3.0,
        staleness in 0.0f32..(86400.0 * 60.0),
    ) {
        let paired = trust_score(hop, staleness, Relationship::Paired.default_l_session()).unwrap();
        let known = trust_score(hop, staleness, Relationship::Known.default_l_session()).unwrap();
        prop_assert!(paired >= known);
    }

    /// Negative hop_distance always rejected.
    #[test]
    fn rejects_negative_hop_always(
        hop in -100.0f32..-0.01,
        staleness in 0.0f32..86400.0,
    ) {
        let r = trust_score(hop, staleness, DEFAULT_L_PAIRED);
        // proptest's prop_assert! macro can't parse `{ .. }` inside matches!,
        // so we destructure manually instead.
        let is_neg_hop = matches!(&r, Err(AlignError::NegativeHopDistance { .. }));
        prop_assert!(is_neg_hop);
    }
}
