//! The 14-rule Smart-Rules tree (Gap 17).
//!
//! Each sub-decision is its own function so they remain readable +
//! testable in isolation. Each function is pure — no state, no I/O.

use crate::decision::{BatchDecision, Decision, OnionHops, Path, Transport};
use ol_decide::{
    Context, Decide, EventKind, NetworkType, PeerRelationship, RadioState, Urgency, UserMode,
};

/// The Smart-Rules selector. Stateless; one instance is fine for the
/// whole daemon.
#[derive(Debug, Default, Clone, Copy)]
pub struct SmartRules;

impl SmartRules {
    /// Construct. Same as `Default::default`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Decide<Decision> for SmartRules {
    fn decide(&self, ctx: &Context) -> Decision {
        Decision {
            transport: pick_transport(ctx),
            path: pick_path(ctx),
            onion_hops: pick_onion_hops(ctx),
            cover_traffic: pick_cover_traffic(ctx),
            batch_decision: pick_batch(ctx),
            anchor_lay: pick_anchor(ctx),
            predictor_warm: pick_predictor_warm(ctx),
        }
    }

    fn safe_default(&self, _ctx: &Context) -> Decision {
        Decision::safe_default()
    }

    fn name(&self) -> &'static str {
        "SmartRules"
    }
}

// ───────────────────────────────────────────────────────────────────
// Sub-decisions — each is one rule from the Gap 17 14-rule tree
// ───────────────────────────────────────────────────────────────────

/// Rule: transport choice.
///
/// ```text
/// paranoid                    → Relay (hide path always)
/// latency_strict              → QuicDatagram (size<8K) or QuicStream
///                                (NEVER relay — relay doubles RTT,
///                                 which violates the LatencyStrict
///                                 contract from Gap 20)
/// file & size > 500KB         → QuicStream (bulk)
/// stranger | cellular         → Relay (hide path on metered/untrusted)
/// foreground & size < 8KB     → QuicDatagram (no head-of-line block)
/// else                        → QuicStream
/// ```
fn pick_transport(ctx: &Context) -> Transport {
    if ctx.user_mode == UserMode::Paranoid {
        return Transport::Relay;
    }
    // LatencyStrict must short-circuit BEFORE the stranger/cellular →
    // Relay branch. Per the F4 contract from Gap 20, LatencyStrict's
    // p99 ≤ 80ms target excludes any relay path (doubles RTT). The
    // selector accepts the privacy cost of going direct in exchange
    // for the latency the user asked for.
    if ctx.user_mode == UserMode::LatencyStrict {
        return if ctx.size < 8_000 {
            Transport::QuicDatagram
        } else {
            Transport::QuicStream
        };
    }
    if ctx.kind == EventKind::File && ctx.size > 500_000 {
        return Transport::QuicStream;
    }
    if ctx.peer == PeerRelationship::Stranger || ctx.network == NetworkType::Cellular {
        return Transport::Relay;
    }
    if ctx.urgency == Urgency::Foreground && ctx.size < 8_000 {
        return Transport::QuicDatagram;
    }
    Transport::QuicStream
}

/// Rule: classical vs coherence path.
///
/// ```text
/// size < 1280                → Classical (anchor floor wastes bytes)
/// file & size > 100KB        → Coherence (CDC dedup wins on large files)
/// user_mode = LatencyStrict  → Classical (predictability for latency)
/// else                       → Coherence (warmup-friendly default)
/// ```
fn pick_path(ctx: &Context) -> Path {
    if ctx.size < 1280 {
        return Path::Classical;
    }
    if ctx.kind == EventKind::File && ctx.size > 100_000 {
        return Path::Coherence;
    }
    if ctx.user_mode == UserMode::LatencyStrict {
        return Path::Classical;
    }
    Path::Coherence
}

/// Rule: onion-circuit hop count.
///
/// ```text
/// paranoid                       → Five
/// stranger | cellular | metered  → Three
/// paired & battery_save          → One
/// else                           → Three (floor for non-paired)
/// ```
fn pick_onion_hops(ctx: &Context) -> OnionHops {
    if ctx.user_mode == UserMode::Paranoid {
        return OnionHops::Five;
    }
    if ctx.peer == PeerRelationship::Stranger
        || ctx.network == NetworkType::Cellular
        || ctx.network == NetworkType::Metered
    {
        return OnionHops::Three;
    }
    if ctx.peer == PeerRelationship::Paired && ctx.user_mode == UserMode::BatterySave {
        return OnionHops::One;
    }
    OnionHops::Three
}

/// Rule: cover traffic on/off.
///
/// ```text
/// battery_save    → off (cover is bandwidth + energy expensive)
/// onion ≥ 3 hops  → on (cover only meaningful with full onion)
/// paranoid        → on
/// else            → off
/// ```
fn pick_cover_traffic(ctx: &Context) -> bool {
    if ctx.user_mode == UserMode::BatterySave {
        return false;
    }
    if ctx.user_mode == UserMode::Paranoid {
        return true;
    }
    // hops ≥ 3 implies the onion is the privacy front; cover augments.
    matches!(pick_onion_hops(ctx), OnionHops::Three | OnionHops::Five)
}

/// Rule: batch / emit-now / urgent-bypass.
///
/// This rule is the Gap 14 latency-tail fix in action.
///
/// ```text
/// foreground & (msg or size<2KB)  → UrgentBypass (NEVER delay urgent chat)
/// latency_strict                  → EmitNow
/// background & LongDrx            → Batch (amortize radio wake)
/// else                            → EmitNow
/// ```
fn pick_batch(ctx: &Context) -> BatchDecision {
    if ctx.urgency == Urgency::Foreground && (ctx.kind == EventKind::Msg || ctx.size < 2048) {
        return BatchDecision::UrgentBypass;
    }
    if ctx.user_mode == UserMode::LatencyStrict {
        return BatchDecision::EmitNow;
    }
    if ctx.urgency == Urgency::Background && ctx.radio_state == RadioState::LongDrx {
        return BatchDecision::Batch;
    }
    BatchDecision::EmitNow
}

/// Rule: anchor-lay for sub-RTT loss recovery.
///
/// ```text
/// battery_save           → only on observed loss > 10% (save bytes)
/// paranoid               → always lay (resilience > bandwidth)
/// observed_loss > 5%     → yes
/// cellular & file        → yes (cellular often re-transmits at chunk granularity)
/// latency_strict & file  → yes (re-transmit on loss adds latency)
/// else                   → no (anchor laying costs bandwidth)
/// ```
fn pick_anchor(ctx: &Context) -> bool {
    if ctx.user_mode == UserMode::BatterySave {
        return ctx.observed_loss > 0.10;
    }
    if ctx.user_mode == UserMode::Paranoid {
        return true;
    }
    if ctx.observed_loss > 0.05 {
        return true;
    }
    if ctx.network == NetworkType::Cellular && ctx.kind == EventKind::File {
        return true;
    }
    if ctx.user_mode == UserMode::LatencyStrict && ctx.kind == EventKind::File {
        return true;
    }
    false
}

/// Rule: pre-warm the predictor for this event.
///
/// ```text
/// battery_save                     → never (no speculative work)
/// latency_strict & strong pattern  → yes (favor speed over caution)
/// pattern_strength > 0.5           → yes (predictor has signal)
/// else                             → no (cold predictor pollutes pattern store)
/// ```
fn pick_predictor_warm(ctx: &Context) -> bool {
    if ctx.user_mode == UserMode::BatterySave {
        return false;
    }
    if ctx.user_mode == UserMode::LatencyStrict && ctx.pattern_strength > 0.3 {
        return true;
    }
    ctx.pattern_strength > 0.5
}

#[cfg(test)]
mod tests {
    use super::*;
    use ol_decide::Context;

    // ───── Helpers ─────────────────────────────────────────────────

    fn paired_msg(size: usize) -> Context {
        Context {
            kind: EventKind::Msg,
            size,
            peer: PeerRelationship::Paired,
            urgency: Urgency::Foreground,
            radio_state: RadioState::Active,
            network: NetworkType::Wifi,
            user_mode: UserMode::Normal,
            observed_loss: 0.0,
            pattern_strength: 0.5,
        }
    }

    fn stranger_file(size: usize) -> Context {
        Context {
            kind: EventKind::File,
            size,
            peer: PeerRelationship::Stranger,
            urgency: Urgency::Foreground,
            radio_state: RadioState::Active,
            network: NetworkType::Wifi,
            user_mode: UserMode::Normal,
            observed_loss: 0.0,
            pattern_strength: 0.5,
        }
    }

    fn paranoid_heartbeat() -> Context {
        Context {
            kind: EventKind::Heartbeat,
            size: 64,
            peer: PeerRelationship::Paired,
            urgency: Urgency::Background,
            radio_state: RadioState::LongDrx,
            network: NetworkType::Cellular,
            user_mode: UserMode::Paranoid,
            observed_loss: 0.0,
            pattern_strength: 0.0,
        }
    }

    // ───── Transport ───────────────────────────────────────────────

    #[test]
    fn transport_big_file_paired_uses_quic_stream() {
        let c = Context {
            kind: EventKind::File,
            size: 5_000_000,
            ..paired_msg(0)
        };
        assert_eq!(pick_transport(&c), Transport::QuicStream);
    }

    #[test]
    fn transport_stranger_uses_relay() {
        assert_eq!(pick_transport(&stranger_file(100)), Transport::Relay);
    }

    #[test]
    fn transport_cellular_uses_relay() {
        let c = Context {
            network: NetworkType::Cellular,
            ..paired_msg(100)
        };
        assert_eq!(pick_transport(&c), Transport::Relay);
    }

    #[test]
    fn transport_small_foreground_msg_uses_datagram() {
        assert_eq!(pick_transport(&paired_msg(500)), Transport::QuicDatagram);
    }

    // ───── Path ────────────────────────────────────────────────────

    #[test]
    fn path_small_msg_uses_classical() {
        assert_eq!(pick_path(&paired_msg(100)), Path::Classical);
    }

    #[test]
    fn path_big_file_uses_coherence() {
        let c = Context {
            kind: EventKind::File,
            size: 200_000,
            ..paired_msg(0)
        };
        assert_eq!(pick_path(&c), Path::Coherence);
    }

    #[test]
    fn path_latency_strict_uses_classical() {
        let c = Context {
            size: 10_000,
            user_mode: UserMode::LatencyStrict,
            ..paired_msg(0)
        };
        assert_eq!(pick_path(&c), Path::Classical);
    }

    // ───── Onion hops ──────────────────────────────────────────────

    #[test]
    fn onion_paranoid_uses_five_hops() {
        let c = Context {
            user_mode: UserMode::Paranoid,
            ..paired_msg(100)
        };
        assert_eq!(pick_onion_hops(&c), OnionHops::Five);
    }

    #[test]
    fn onion_stranger_uses_three_hops() {
        assert_eq!(pick_onion_hops(&stranger_file(100)), OnionHops::Three);
    }

    #[test]
    fn onion_paired_battery_save_uses_one_hop() {
        let c = Context {
            user_mode: UserMode::BatterySave,
            ..paired_msg(100)
        };
        assert_eq!(pick_onion_hops(&c), OnionHops::One);
    }

    #[test]
    fn onion_default_floor_is_three_for_non_paired() {
        // Even with no other indicator, non-paired peers get 3-hop floor.
        let c = Context {
            peer: PeerRelationship::Known,
            ..paired_msg(100)
        };
        assert_eq!(pick_onion_hops(&c), OnionHops::Three);
    }

    // ───── Cover traffic ───────────────────────────────────────────

    #[test]
    fn cover_battery_save_off() {
        let c = Context {
            user_mode: UserMode::BatterySave,
            ..paired_msg(100)
        };
        assert!(!pick_cover_traffic(&c));
    }

    #[test]
    fn cover_paranoid_on() {
        let c = Context {
            user_mode: UserMode::Paranoid,
            ..paired_msg(100)
        };
        assert!(pick_cover_traffic(&c));
    }

    #[test]
    fn cover_3hop_default_on() {
        // Normal mode, stranger -> 3-hop -> cover on.
        assert!(pick_cover_traffic(&stranger_file(100)));
    }

    // ───── Batch ───────────────────────────────────────────────────

    #[test]
    fn batch_foreground_chat_bypasses() {
        // Foreground chat msg of any size -> urgent_bypass (Gap 14 fix).
        assert_eq!(pick_batch(&paired_msg(500)), BatchDecision::UrgentBypass);
    }

    #[test]
    fn batch_foreground_small_anything_bypasses() {
        // Even a small file qualifies if < 2KB and foreground.
        let c = Context {
            kind: EventKind::Sync,
            size: 1_000,
            urgency: Urgency::Foreground,
            ..paired_msg(0)
        };
        assert_eq!(pick_batch(&c), BatchDecision::UrgentBypass);
    }

    #[test]
    fn batch_background_long_drx_batches() {
        let c = Context {
            kind: EventKind::Heartbeat,
            urgency: Urgency::Background,
            radio_state: RadioState::LongDrx,
            ..paired_msg(0)
        };
        assert_eq!(pick_batch(&c), BatchDecision::Batch);
    }

    #[test]
    fn batch_latency_strict_emits_now() {
        let c = Context {
            kind: EventKind::Sync,
            urgency: Urgency::Background,
            user_mode: UserMode::LatencyStrict,
            ..paired_msg(0)
        };
        assert_eq!(pick_batch(&c), BatchDecision::EmitNow);
    }

    // ───── Anchor lay ──────────────────────────────────────────────

    #[test]
    fn anchor_high_loss_yes() {
        let c = Context {
            observed_loss: 0.10,
            ..paired_msg(100)
        };
        assert!(pick_anchor(&c));
    }

    #[test]
    fn anchor_low_loss_no() {
        let c = Context {
            observed_loss: 0.01,
            ..paired_msg(100)
        };
        assert!(!pick_anchor(&c));
    }

    #[test]
    fn anchor_cellular_file_yes() {
        let c = Context {
            kind: EventKind::File,
            network: NetworkType::Cellular,
            ..paired_msg(100)
        };
        assert!(pick_anchor(&c));
    }

    // ───── Predictor warm ──────────────────────────────────────────

    #[test]
    fn predictor_warm_at_high_pattern() {
        let c = Context {
            pattern_strength: 0.8,
            ..paired_msg(100)
        };
        assert!(pick_predictor_warm(&c));
    }

    #[test]
    fn predictor_cold_at_low_pattern() {
        let c = Context {
            pattern_strength: 0.2,
            ..paired_msg(100)
        };
        assert!(!pick_predictor_warm(&c));
    }

    // ───── Mode-aware refinement (F3) ──────────────────────────────

    #[test]
    fn paranoid_always_relay_transport() {
        // Even big files via paranoid → relay path.
        let c = Context {
            kind: EventKind::File,
            size: 10_000_000,
            user_mode: UserMode::Paranoid,
            ..paired_msg(0)
        };
        assert_eq!(pick_transport(&c), Transport::Relay);
    }

    #[test]
    fn battery_save_anchor_only_on_high_loss() {
        // Default loss 0.07: normal would anchor, battery_save would not.
        let c = Context {
            observed_loss: 0.07,
            user_mode: UserMode::BatterySave,
            ..paired_msg(100)
        };
        assert!(!pick_anchor(&c));
        // But at 0.12 (above battery threshold) it does.
        let c = Context {
            observed_loss: 0.12,
            user_mode: UserMode::BatterySave,
            ..paired_msg(100)
        };
        assert!(pick_anchor(&c));
    }

    #[test]
    fn paranoid_always_anchor() {
        let c = Context {
            observed_loss: 0.0,
            user_mode: UserMode::Paranoid,
            ..paired_msg(100)
        };
        assert!(pick_anchor(&c));
    }

    #[test]
    fn latency_strict_anchor_file_always() {
        let c = Context {
            kind: EventKind::File,
            size: 500_000,
            observed_loss: 0.0,
            user_mode: UserMode::LatencyStrict,
            ..paired_msg(0)
        };
        assert!(pick_anchor(&c));
    }

    #[test]
    fn battery_save_never_predictor_warm() {
        let c = Context {
            pattern_strength: 0.9,
            user_mode: UserMode::BatterySave,
            ..paired_msg(100)
        };
        assert!(!pick_predictor_warm(&c));
    }

    #[test]
    fn latency_strict_warms_at_lower_threshold() {
        // 0.35 wouldn't warm under normal (needs > 0.5)
        // but does under latency_strict (needs > 0.3).
        let c = Context {
            pattern_strength: 0.35,
            user_mode: UserMode::LatencyStrict,
            ..paired_msg(100)
        };
        assert!(pick_predictor_warm(&c));
    }

    #[test]
    fn latency_strict_small_uses_datagram() {
        let c = Context {
            size: 500,
            urgency: Urgency::Background, // even background
            user_mode: UserMode::LatencyStrict,
            ..paired_msg(0)
        };
        assert_eq!(pick_transport(&c), Transport::QuicDatagram);
    }

    // ───── Full Decide impl ────────────────────────────────────────

    #[test]
    fn paranoid_heartbeat_is_full_privacy() {
        let d = SmartRules.decide(&paranoid_heartbeat());
        // Paranoid mode -> 5 hops + cover on regardless.
        assert_eq!(d.onion_hops, OnionHops::Five);
        assert!(d.cover_traffic);
    }

    #[test]
    fn safe_default_returned_unmodified() {
        let ctx = Context::safe_default(EventKind::Msg, 100);
        let d = SmartRules.safe_default(&ctx);
        assert_eq!(d, Decision::safe_default());
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(SmartRules.name(), "SmartRules");
    }
}
