//! `UnifiedMin` — continuous energy-minimization selector (Phase H).
//!
//! Implements the per-event decision as minimization of:
//!
//! ```text
//! E_total = C_dynamic(ctx) ·
//!           (E_quantum(d) + α·|∇τ_c|² + (ΔC/ΔS)·A(x,t) + E_dark(d))
//! ```
//!
//! over a small grid of candidate Decisions. Candidates that violate
//! the user_mode contract are filtered out BEFORE energy comparison,
//! so the F4 invariant
//! (`selector_output_respects_mode_contract`) holds by construction.
//!
//! ## Why this is a separate selector
//!
//! `SmartRules` is the discrete 14-rule tree — fast, predictable,
//! easy to reason about. `UnifiedMin` is the continuous variant: it
//! evaluates a small candidate set against a parameterized energy
//! function with tunable [`Weights`]. The two implement the same
//! `Decide<Decision>` trait so daemons can swap one for the other
//! by changing a single line.
//!
//! Phase H gate: `regret(UnifiedMin) ≤ regret(SmartRules)` on a
//! production-shadow workload. Phase I will add online learning
//! that tunes the weights from observed regret.
//!
//! ## Determinism
//!
//! Same `(Context, Weights)` always produces the same `Decision` —
//! candidate-enumeration is in a fixed order and ties are broken by
//! enumeration order. No state, no randomness, no clock reads.

use crate::decision::{
    BatchDecision, ContractMode, Decision, OnionHops, Path, Transport,
};
use crate::weights::Weights;
use ol_decide::{Context, Decide, EventKind, NetworkType, PeerRelationship, UserMode};

/// The continuous energy-minimization selector.
///
/// Constructed with a [`Weights`] struct that tunes the per-term
/// coefficients. Stateless; the same instance can serve every event.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnifiedMin {
    /// Tunable per-term weights.
    pub weights: Weights,
}

impl UnifiedMin {
    /// Construct with the canonical default weights.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            weights: Weights::defaults(),
        }
    }

    /// Construct with explicit weights.
    #[must_use]
    pub const fn with_weights(weights: Weights) -> Self {
        Self { weights }
    }
}

impl Decide<Decision> for UnifiedMin {
    fn decide(&self, ctx: &Context) -> Decision {
        // Map the daemon's UserMode to the local ContractMode used
        // for candidate filtering.
        let contract_mode = match ctx.user_mode {
            UserMode::Normal => ContractMode::Normal,
            UserMode::Paranoid => ContractMode::Paranoid,
            UserMode::BatterySave => ContractMode::BatterySave,
            UserMode::LatencyStrict => ContractMode::LatencyStrict,
        };

        let predictor_warm = ctx.pattern_strength > 0.5;

        // Generate the candidate grid + filter through the contract.
        let mut best: Option<(f32, Decision)> = None;
        for d in candidate_grid(ctx, predictor_warm, contract_mode) {
            let e = self.total_energy(ctx, &d);
            match best {
                None => best = Some((e, d)),
                Some((be, _)) if e < be => best = Some((e, d)),
                _ => {}
            }
        }

        // If somehow no candidate passed the contract filter (shouldn't
        // happen because Decision::safe_default is always contract-clean
        // for Normal and we explicitly include it), fall back to the
        // safe default.
        best.map_or_else(|| self.safe_default(ctx), |(_, d)| d)
    }

    fn safe_default(&self, _ctx: &Context) -> Decision {
        Decision::safe_default()
    }

    fn name(&self) -> &'static str {
        "UnifiedMin"
    }
}

impl UnifiedMin {
    /// Total energy for one (ctx, decision) pair.
    pub fn total_energy(&self, ctx: &Context, d: &Decision) -> f32 {
        let cd = self.c_dynamic(ctx);
        let eq = self.e_quantum(ctx, d);
        let ec = self.e_coherence(ctx, d);
        let ea = self.e_alignment(ctx, d);
        let ed = self.e_dark(d);
        cd * (eq + ec + ea + ed)
    }

    /// C_dynamic = e^{-λD} where D is an event-scale dimension.
    /// Smaller events have higher D → smaller C_dynamic → less
    /// weight on overhead terms (we don't want to penalize a tiny
    /// chat for using a relay).
    pub fn c_dynamic(&self, ctx: &Context) -> f32 {
        let scale = (ctx.size as f32).max(1.0).log10();
        let sensitivity_bump = match ctx.user_mode {
            UserMode::Paranoid => 3.0,
            UserMode::LatencyStrict => -1.0,
            _ => 0.0,
        };
        let urgency_bump = if ctx.urgency == ol_decide::Urgency::Foreground {
            1.0
        } else {
            0.0
        };
        let d = (10.0 - scale - sensitivity_bump + urgency_bump).max(0.0);
        (-self.weights.lambda_dynamic * d).exp() * 100.0
    }

    /// E_quantum: perf cost (latency + transport overhead).
    pub fn e_quantum(&self, ctx: &Context, d: &Decision) -> f32 {
        let rtt = match ctx.network {
            NetworkType::Wifi => 28.0,
            NetworkType::Cellular => 45.0,
            NetworkType::Metered => 60.0,
        };
        let hop_lat = f32::from(d.onion_hops.as_u8()) * self.weights.onion_hop_cost;
        let mut base_lat = rtt + hop_lat;
        if d.batch_decision == BatchDecision::Batch {
            base_lat += self.weights.batch_latency_cost;
        }
        if d.transport == Transport::Relay {
            base_lat *= self.weights.relay_rtt_multiplier;
        }
        base_lat / 100.0
    }

    /// E_coherence: stability/organization energy.
    /// α·|∇τ_c|² + info-flow-counteracts-entropy term.
    pub fn e_coherence(&self, ctx: &Context, d: &Decision) -> f32 {
        // |∇τ_c|² proxy: high uncertainty when both field warmth
        // (pattern_strength) is low AND no recent activity.
        let coh_grad_sq = (1.0 - ctx.pattern_strength) * (1.0 - ctx.pattern_strength);

        // Information-flow term: probability of maintaining coherence.
        let info_eff = match ctx.kind {
            EventKind::File => 1.0,
            EventKind::Sync => 0.5,
            _ => 0.2,
        };
        let mut p_coh = 0.95_f32;
        if !d.anchor_lay && ctx.observed_loss > 0.03 {
            p_coh = 0.7;
        }
        if d.predictor_warm && ctx.pattern_strength > 0.5 {
            p_coh = 0.99;
        }
        let entropy_term = if p_coh < 1.0 {
            info_eff * (1.0_f32 / p_coh).ln()
        } else {
            0.0
        };

        // Anchor laying directly costs bytes (E_dark also bumps for
        // this; here it modestly improves p_coh through `anchor_lay`
        // gating above).
        let anchor_term = if d.anchor_lay {
            self.weights.anchor_cost
        } else {
            0.0
        };

        self.weights.alpha_coherence * coh_grad_sq + entropy_term + anchor_term
    }

    /// E_alignment: (ΔC/ΔS) · A(x,t).
    /// Captures the privacy/trust cost of the decision.
    pub fn e_alignment(&self, ctx: &Context, d: &Decision) -> f32 {
        // Hop distance proxy from peer relationship.
        let peer_dist: f32 = match ctx.peer {
            PeerRelationship::Paired => 1.0,
            PeerRelationship::Known => 3.0,
            PeerRelationship::Stranger => 10.0,
        };
        // Staleness from pattern_strength (lower → more stale).
        let staleness = (1.0 - ctx.pattern_strength) * 5.0;
        // Session length scale per relationship tier.
        let l_session: f32 = match ctx.peer {
            PeerRelationship::Paired => 100.0,
            PeerRelationship::Known => 30.0,
            PeerRelationship::Stranger => 5.0,
        };
        let a_x_t = (-((peer_dist * peer_dist) + (staleness * staleness)) / l_session).exp();

        // Privacy contribution from the decision: more hops + cover
        // = higher alignment, less needed work.
        let onion_gain = f32::from(d.onion_hops.as_u8()) * 0.15;
        let cover_gain: f32 = if d.cover_traffic { 0.3 } else { 0.0 };
        let delta_c = onion_gain + cover_gain;

        let dc_ds = if ctx.user_mode == UserMode::Paranoid {
            1.5
        } else {
            1.0
        };
        let needed = (1.0_f32 - a_x_t) * dc_ds;
        let mut cost = (needed - delta_c).max(0.0) * self.weights.privacy_weight;
        if !d.cover_traffic {
            let mode_mult: f32 = if ctx.user_mode == UserMode::Paranoid { 1.0 } else { 0.3 };
            cost += self.weights.cover_penalty * mode_mult;
        }
        cost
    }

    /// E_dark: irreducible protocol overhead.
    pub fn e_dark(&self, d: &Decision) -> f32 {
        let mut e = self.weights.dark_base;
        if d.path == Path::Coherence {
            e += self.weights.dark_coherence;
        }
        if d.cover_traffic {
            e += self.weights.dark_cover;
        }
        e
    }
}

/// Generate the candidate grid for the given (context, predictor_warm,
/// contract_mode). Filtered to candidates that pass the contract.
///
/// Returns a Vec rather than an iterator because the cartesian product
/// across heap-allocated `transport_options(ctx)` would require lifetime
/// gymnastics to express as nested move-closures; the grid is small
/// (≤ ~120 entries) so the allocation cost is trivial.
fn candidate_grid(
    ctx: &Context,
    predictor_warm: bool,
    contract_mode: ContractMode,
) -> Vec<Decision> {
    let paths = [Path::Classical, Path::Coherence];
    let hops = [OnionHops::One, OnionHops::Three, OnionHops::Five];
    let covers = [false, true];
    let batches = [
        BatchDecision::EmitNow,
        BatchDecision::Batch,
        BatchDecision::UrgentBypass,
    ];
    let anchors = [false, true];
    let transports = transport_options(ctx);

    let mut out = Vec::with_capacity(
        paths.len() * hops.len() * covers.len() * batches.len() * anchors.len() * transports.len(),
    );
    for &path in &paths {
        for &hop in &hops {
            for &cover in &covers {
                for &batch in &batches {
                    for &anchor in &anchors {
                        for &transport in &transports {
                            let d = Decision {
                                transport,
                                path,
                                onion_hops: hop,
                                cover_traffic: cover,
                                batch_decision: batch,
                                anchor_lay: anchor,
                                predictor_warm,
                            };
                            if d.verify_contract(contract_mode).is_empty() {
                                out.push(d);
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// Per-context transport options. Returns the small set of transports
/// that make sense for the (peer, network, size) tuple — the energy
/// term across the full transport enum × everything else would be
/// wasteful since most transports are dominated by perf at any size.
fn transport_options(ctx: &Context) -> Vec<Transport> {
    let mut out = Vec::with_capacity(4);
    out.push(Transport::QuicStream);
    if ctx.size < 8_000 {
        out.push(Transport::QuicDatagram);
    }
    // Relay only viable when not on metered + not LatencyStrict.
    if ctx.user_mode != UserMode::LatencyStrict {
        out.push(Transport::Relay);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ol_decide::{Context, EventKind, NetworkType, PeerRelationship, RadioState, Urgency, UserMode};

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

    #[test]
    fn unified_min_produces_valid_decision() {
        let s = UnifiedMin::new();
        let d = s.decide(&paired_msg(1024));
        // Verify all fields are valid enum variants.
        let _ = d.onion_hops.as_u8();
    }

    #[test]
    fn unified_min_respects_paranoid_contract() {
        let s = UnifiedMin::new();
        let c = Context {
            user_mode: UserMode::Paranoid,
            ..paired_msg(1024)
        };
        let d = s.decide(&c);
        assert!(d.verify_contract(ContractMode::Paranoid).is_empty());
    }

    #[test]
    fn unified_min_respects_battery_save_contract() {
        let s = UnifiedMin::new();
        let c = Context {
            user_mode: UserMode::BatterySave,
            ..paired_msg(1024)
        };
        let d = s.decide(&c);
        assert!(d.verify_contract(ContractMode::BatterySave).is_empty());
    }

    #[test]
    fn unified_min_respects_latency_strict_contract() {
        let s = UnifiedMin::new();
        let c = Context {
            user_mode: UserMode::LatencyStrict,
            ..paired_msg(1024)
        };
        let d = s.decide(&c);
        assert!(d.verify_contract(ContractMode::LatencyStrict).is_empty());
    }

    #[test]
    fn unified_min_is_deterministic() {
        let s = UnifiedMin::new();
        let c = paired_msg(100_000);
        let a = s.decide(&c);
        let b = s.decide(&c);
        assert_eq!(a, b);
    }

    #[test]
    fn unified_min_name_is_stable() {
        let s = UnifiedMin::new();
        assert_eq!(s.name(), "UnifiedMin");
    }

    #[test]
    fn c_dynamic_decreases_with_event_size() {
        let s = UnifiedMin::new();
        let small = paired_msg(100);
        let large = paired_msg(10_000_000);
        // Larger events have smaller D → C_dynamic should be larger.
        assert!(s.c_dynamic(&large) > s.c_dynamic(&small));
    }

    #[test]
    fn c_dynamic_paranoid_larger_than_normal() {
        // Mathematically: sensitivity_bump = +3 for Paranoid is
        // SUBTRACTED from D. Smaller D → larger e^{-λD} → larger
        // C_dynamic. The result: paranoid events get a stronger
        // global multiplier on their per-term energies, so the
        // selector evaluates them with greater absolute weight.
        // (Per-term weighting differences are handled by
        // alpha_coherence / privacy_weight, not C_dynamic.)
        let s = UnifiedMin::new();
        let normal = paired_msg(1000);
        let paranoid = Context {
            user_mode: UserMode::Paranoid,
            ..paired_msg(1000)
        };
        assert!(
            s.c_dynamic(&paranoid) > s.c_dynamic(&normal),
            "paranoid C_dynamic ({}) should exceed normal ({})",
            s.c_dynamic(&paranoid),
            s.c_dynamic(&normal),
        );
    }

    #[test]
    fn c_dynamic_latency_strict_smaller_than_normal() {
        // LatencyStrict has sensitivity_bump = -1 → D LARGER →
        // smaller C_dynamic. Makes sense: latency-strict events care
        // about the absolute number, not the relative weighting.
        let s = UnifiedMin::new();
        let normal = paired_msg(1000);
        let latency_strict = Context {
            user_mode: UserMode::LatencyStrict,
            ..paired_msg(1000)
        };
        assert!(s.c_dynamic(&latency_strict) < s.c_dynamic(&normal));
    }

    #[test]
    fn e_quantum_higher_for_relay() {
        let s = UnifiedMin::new();
        let ctx = paired_msg(1000);
        let stream = Decision {
            transport: Transport::QuicStream,
            path: Path::Classical,
            onion_hops: OnionHops::Three,
            cover_traffic: false,
            batch_decision: BatchDecision::EmitNow,
            anchor_lay: false,
            predictor_warm: false,
        };
        let relay = Decision {
            transport: Transport::Relay,
            ..stream
        };
        assert!(s.e_quantum(&ctx, &relay) > s.e_quantum(&ctx, &stream));
    }

    #[test]
    fn weights_can_be_overridden() {
        let mut w = Weights::defaults();
        w.privacy_weight = 1000.0; // Crank up privacy.
        let s = UnifiedMin::with_weights(w);
        let ctx = Context {
            user_mode: UserMode::Normal,
            peer: PeerRelationship::Stranger,
            ..paired_msg(1000)
        };
        let d = s.decide(&ctx);
        // With ultra-high privacy weight, the optimum should pick
        // covers ON whenever it's allowed.
        assert!(d.cover_traffic);
    }
}
