//! Proptest properties for `ol_selector`.
//!
//! Verifies invariants that must hold across the entire input space.

use ol_decide::{
    Context, Decide, EventKind, NetworkType, PeerRelationship, RadioState, Urgency, UserMode,
};
use ol_selector::{BatchDecision, Decision, OnionHops, Path, SmartRules, Transport};
use proptest::prelude::*;

fn arb_event_kind() -> impl Strategy<Value = EventKind> {
    prop_oneof![
        Just(EventKind::Msg),
        Just(EventKind::File),
        Just(EventKind::Sync),
        Just(EventKind::Heartbeat),
        Just(EventKind::Pair),
    ]
}

fn arb_peer() -> impl Strategy<Value = PeerRelationship> {
    prop_oneof![
        Just(PeerRelationship::Paired),
        Just(PeerRelationship::Known),
        Just(PeerRelationship::Stranger),
    ]
}

fn arb_urgency() -> impl Strategy<Value = Urgency> {
    prop_oneof![Just(Urgency::Foreground), Just(Urgency::Background)]
}

fn arb_radio() -> impl Strategy<Value = RadioState> {
    prop_oneof![
        Just(RadioState::Active),
        Just(RadioState::ShortDrx),
        Just(RadioState::LongDrx),
    ]
}

fn arb_network() -> impl Strategy<Value = NetworkType> {
    prop_oneof![
        Just(NetworkType::Wifi),
        Just(NetworkType::Cellular),
        Just(NetworkType::Metered),
    ]
}

fn arb_user_mode() -> impl Strategy<Value = UserMode> {
    prop_oneof![
        Just(UserMode::Normal),
        Just(UserMode::Paranoid),
        Just(UserMode::BatterySave),
        Just(UserMode::LatencyStrict),
    ]
}

fn arb_context() -> impl Strategy<Value = Context> {
    (
        arb_event_kind(),
        0usize..16_000_000,
        arb_peer(),
        arb_urgency(),
        arb_radio(),
        arb_network(),
        arb_user_mode(),
        0.0f32..1.0,
        0.0f32..1.0,
    )
        .prop_map(
            |(kind, size, peer, urgency, radio_state, network, user_mode, observed_loss, pattern_strength)| {
                Context {
                    kind,
                    size,
                    peer,
                    urgency,
                    radio_state,
                    network,
                    user_mode,
                    observed_loss,
                    pattern_strength,
                }
            },
        )
}

proptest! {
    /// `decide` is total: never panics, always returns a Decision.
    /// All sub-fields are valid enum variants by construction.
    #[test]
    fn decide_is_total(ctx in arb_context()) {
        let d = SmartRules.decide(&ctx);
        let _ = d; // construction proves validity
    }

    /// Paranoid mode ALWAYS gets 5-hop onion + cover traffic.
    /// This is the mode contract from the integration map.
    #[test]
    fn paranoid_always_max_privacy(ctx in arb_context().prop_map(|c| Context {
        user_mode: UserMode::Paranoid,
        ..c
    })) {
        let d = SmartRules.decide(&ctx);
        prop_assert_eq!(d.onion_hops, OnionHops::Five);
        prop_assert!(d.cover_traffic);
    }

    /// Battery save mode NEVER turns cover traffic on. Privacy cost
    /// per integration map mode contract.
    #[test]
    fn battery_save_never_cover(ctx in arb_context().prop_map(|c| Context {
        user_mode: UserMode::BatterySave,
        ..c
    })) {
        let d = SmartRules.decide(&ctx);
        prop_assert!(!d.cover_traffic);
    }

    /// Foreground chat messages NEVER batch (Gap 14 tail-fix invariant).
    /// urgent_bypass instead.
    #[test]
    fn foreground_chat_never_batched(ctx in arb_context().prop_map(|c| Context {
        kind: EventKind::Msg,
        urgency: Urgency::Foreground,
        ..c
    })) {
        let d = SmartRules.decide(&ctx);
        prop_assert!(d.batch_decision != BatchDecision::Batch,
                     "foreground msg was batched: got {:?}", d.batch_decision);
    }

    /// Latency-strict mode NEVER batches (mode contract from Gap 20).
    #[test]
    fn latency_strict_never_batches(ctx in arb_context().prop_map(|c| Context {
        user_mode: UserMode::LatencyStrict,
        ..c
    })) {
        let d = SmartRules.decide(&ctx);
        prop_assert_ne!(d.batch_decision, BatchDecision::Batch);
    }

    /// Onion hops floor: non-paired peers ALWAYS get >= 3 hops.
    /// (1-hop is only available to paired + battery_save).
    #[test]
    fn non_paired_at_least_3_hops(ctx in arb_context().prop_filter(
        "non-paired peer",
        |c| c.peer != PeerRelationship::Paired,
    )) {
        let d = SmartRules.decide(&ctx);
        let n = d.onion_hops.as_u8();
        prop_assert!(n >= 3, "non-paired got {n}-hop onion");
    }

    /// Small messages (< 1280 bytes) ALWAYS use classical path.
    /// (Anchor floor wastes bytes on tiny payloads — Gap 9.)
    /// We construct contexts directly with a small-size strategy instead
    /// of filtering, so proptest doesn't reject 99.99% of `arb_context`'s
    /// 0..16M size range.
    #[test]
    fn small_msgs_use_classical(
        kind in arb_event_kind(),
        size in 0usize..1280,
        peer in arb_peer(),
        urgency in arb_urgency(),
        radio_state in arb_radio(),
        network in arb_network(),
        user_mode in arb_user_mode(),
        observed_loss in 0.0f32..1.0,
        pattern_strength in 0.0f32..1.0,
    ) {
        let ctx = Context {
            kind, size, peer, urgency, radio_state, network, user_mode,
            observed_loss, pattern_strength,
        };
        let d = SmartRules.decide(&ctx);
        prop_assert_eq!(d.path, Path::Classical);
    }

    /// Decision encoded fields are valid enums.
    #[test]
    fn decision_fields_valid(ctx in arb_context()) {
        let d = SmartRules.decide(&ctx);
        let n = d.onion_hops.as_u8();
        prop_assert!(matches!(n, 1 | 3 | 5));
        let _: Transport = d.transport; // exists in enum
        let _: Path = d.path;
        let _: BatchDecision = d.batch_decision;
    }

    /// `safe_default` is independent of context.
    #[test]
    fn safe_default_is_constant(ctx in arb_context()) {
        let d = SmartRules.safe_default(&ctx);
        prop_assert_eq!(d, Decision::safe_default());
    }
}
