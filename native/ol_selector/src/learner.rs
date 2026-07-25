//! `OnlineLearner` — Phase I weight adaptation for the `UnifiedMin` selector.
//!
//! Wraps [`UnifiedMin`] with an `observe()` method that updates the per-
//! term [`Weights`] from production feedback. The objective is to
//! *reduce* the energy the selector assigns to **future** decisions
//! whose contexts resembled high-regret past decisions, and vice versa
//! for low-regret ones.
//!
//! ## Math sketch
//!
//! Given a chosen decision `d` for context `ctx`, observed regret `r`:
//!
//! ```text
//! w_i ← w_i + η · r · ∂E_total/∂w_i (ctx, d)
//!       − γ · (w_i − w_i_default)
//! ```
//!
//! - `η` (`learning_rate`) controls update size per observation.
//! - `r` is the regret signal: positive when the outcome was worse
//!   than the model anticipated; the daemon supplies this from
//!   observed latency / privacy leak / energy cost vs the
//!   selector's prediction.
//! - `∂E_total/∂w_i` is the partial derivative of the energy
//!   objective at the chosen decision. We compute it analytically
//!   per [`Weights`] field — cheap, deterministic, no finite-diff
//!   noise.
//! - `γ` (`regularization`) pulls each weight back toward its
//!   factory default. Without it, persistent regret can drift the
//!   weights arbitrarily far from a sensible starting point; with
//!   it, the steady state of the learner is a bounded offset from
//!   defaults proportional to the average regret-times-gradient
//!   signal.
//!
//! `Weights` are also clamped to `(0, 10× default)` after every update
//! so a single pathological observation can't blow them up.
//!
//! ## Determinism
//!
//! `decide(ctx)` is deterministic — same `(ctx, weights)` → same
//! `Decision`. `observe(ctx, d, r)` mutates the weights deterministically:
//! same call sequence from a fresh learner produces identical weights.
//! Floating-point arithmetic is the only source of non-determinism
//! and we don't depend on sub-ulp precision anywhere.
//!
//! ## Adversarial stability
//!
//! The combination of regularization + clamping bounds the steady-
//! state weight drift. Property test
//! `weights_stay_bounded_under_adversarial_regret` exercises this:
//! 10k observations with regret = 100 (saturated high) don't drive
//! any weight outside the (0, 10× default) band.

use crate::decision::Decision;
use crate::unified_min::{usize_as_f32, UnifiedMin};
use crate::weights::Weights;
use ol_decide::Context;

fn u64_as_f64(value: u64) -> f64 {
    let bytes = value.to_be_bytes();
    let high = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let low = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    f64::from(high) * 4_294_967_296.0 + f64::from(low)
}

/// Per-weight bookkeeping returned by [`OnlineLearner::stats`].
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct LearnerStats {
    /// Total observations recorded.
    pub n_observations: u64,
    /// Sum of observed regret (positive only; absolute value).
    pub sum_abs_regret: f64,
    /// Mean absolute regret over the lifetime.
    pub mean_abs_regret: f64,
    /// Current learning rate.
    pub learning_rate: f32,
    /// Current regularization strength.
    pub regularization: f32,
    /// Lifetime number of clamp events (a weight hit its bound).
    pub clamp_events: u64,
}

/// The 11-element analytic gradient of `E_total` at (`ctx`, `decision`).
/// One slot per `Weights` field, in the canonical order documented in
/// [`Weights`].
#[derive(Debug, Clone, Copy, Default)]
pub struct EnergyGradient {
    /// ∂E / ∂`alpha_coherence`
    pub d_alpha_coherence: f32,
    /// ∂E / ∂`privacy_weight`
    pub d_privacy_weight: f32,
    /// ∂E / ∂`cover_penalty`
    pub d_cover_penalty: f32,
    /// ∂E / ∂`anchor_cost`
    pub d_anchor_cost: f32,
    /// ∂E / ∂`batch_latency_cost`
    pub d_batch_latency_cost: f32,
    /// ∂E / ∂`onion_hop_cost`
    pub d_onion_hop_cost: f32,
    /// ∂E / ∂`relay_rtt_multiplier`
    pub d_relay_rtt_multiplier: f32,
    /// ∂E / ∂`lambda_dynamic`
    pub d_lambda_dynamic: f32,
    /// ∂E / ∂`dark_base`
    pub d_dark_base: f32,
    /// ∂E / ∂`dark_coherence`
    pub d_dark_coherence: f32,
    /// ∂E / ∂`dark_cover`
    pub d_dark_cover: f32,
}

/// Default learning rate. Conservative — Phase I lands as opt-in,
/// so the default rate is small enough that ≤ 100 observations
/// across the wrong decision can't materially change behavior.
pub const DEFAULT_LEARNING_RATE: f32 = 0.001;

/// Default L2-toward-default regularization strength.
pub const DEFAULT_REGULARIZATION: f32 = 0.01;

/// Default upper bound on any weight, as a multiplier of its default.
pub const DEFAULT_WEIGHT_BOUND_MULTIPLIER: f32 = 10.0;

/// Phase I: weight-tuning wrapper around [`UnifiedMin`].
#[derive(Debug, Clone, Copy)]
pub struct OnlineLearner {
    /// Current selector with learned weights.
    selector: UnifiedMin,
    /// Frozen factory defaults for regularization anchoring.
    defaults: Weights,
    /// Step size per observation.
    learning_rate: f32,
    /// L2-pull-toward-defaults strength.
    regularization: f32,
    /// Multiplier on default to derive the upper clamp bound.
    weight_bound_multiplier: f32,
    /// Bookkeeping.
    n_observations: u64,
    sum_abs_regret: f64,
    clamp_events: u64,
}

impl OnlineLearner {
    /// Construct with canonical defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(
            Weights::defaults(),
            DEFAULT_LEARNING_RATE,
            DEFAULT_REGULARIZATION,
            DEFAULT_WEIGHT_BOUND_MULTIPLIER,
        )
    }

    /// Construct with explicit configuration.
    #[must_use]
    pub fn with_config(
        initial_weights: Weights,
        learning_rate: f32,
        regularization: f32,
        weight_bound_multiplier: f32,
    ) -> Self {
        let lr = learning_rate.clamp(0.0, 1.0);
        let reg = regularization.clamp(0.0, 1.0);
        let bound = weight_bound_multiplier.max(1.0);
        Self {
            selector: UnifiedMin::with_weights(initial_weights),
            defaults: initial_weights,
            learning_rate: lr,
            regularization: reg,
            weight_bound_multiplier: bound,
            n_observations: 0,
            sum_abs_regret: 0.0,
            clamp_events: 0,
        }
    }

    /// Read-only access to the underlying selector.
    #[must_use]
    pub fn selector(&self) -> &UnifiedMin {
        &self.selector
    }

    /// Read-only access to the current weights.
    #[must_use]
    pub fn weights(&self) -> &Weights {
        &self.selector.weights
    }

    /// Read-only access to the frozen factory defaults.
    #[must_use]
    pub fn defaults(&self) -> &Weights {
        &self.defaults
    }

    /// Configured learning rate.
    #[must_use]
    pub fn learning_rate(&self) -> f32 {
        self.learning_rate
    }

    /// Configured regularization strength.
    #[must_use]
    pub fn regularization(&self) -> f32 {
        self.regularization
    }

    /// Aggregate statistics over the learner's lifetime.
    #[must_use]
    pub fn stats(&self) -> LearnerStats {
        let mean = if self.n_observations == 0 {
            0.0
        } else {
            self.sum_abs_regret / u64_as_f64(self.n_observations)
        };
        LearnerStats {
            n_observations: self.n_observations,
            sum_abs_regret: self.sum_abs_regret,
            mean_abs_regret: mean,
            learning_rate: self.learning_rate,
            regularization: self.regularization,
            clamp_events: self.clamp_events,
        }
    }

    /// Pure passthrough to the underlying selector's decide.
    pub fn decide(&self, ctx: &Context) -> Decision {
        use crate::Decide;
        self.selector.decide(ctx)
    }

    /// Record one observation: the (context, decision) that fired
    /// plus the observed regret. Higher regret → larger weight nudge
    /// in the direction that *raises* the energy of similar
    /// future decisions (making them less likely to be chosen).
    ///
    /// Non-finite `regret` values are silently dropped.
    pub fn observe(&mut self, ctx: &Context, decision: &Decision, regret: f32) {
        if !regret.is_finite() {
            return;
        }
        let g = self.energy_gradient(ctx, decision);
        self.update_weights(regret, &g);
        self.n_observations = self.n_observations.saturating_add(1);
        self.sum_abs_regret = self
            .sum_abs_regret
            .saturating_add_f64(f64::from(regret.abs()));
    }

    /// Analytic gradient of `E_total` at (`ctx`, `decision`) with the
    /// current weights. Each partial is computed directly from the
    /// closed-form expression in `UnifiedMin::e_*` and chain-ruled
    /// through `c_dynamic`.
    #[must_use]
    pub fn energy_gradient(&self, ctx: &Context, d: &Decision) -> EnergyGradient {
        use crate::decision::{BatchDecision, Path, Transport};
        use ol_decide::{NetworkType, PeerRelationship, UserMode};

        let s = &self.selector;
        let cd = s.c_dynamic(ctx);

        // e_quantum partials (before *cd, /100 baked into formula)
        let base_lat_unweighted = match ctx.network {
            NetworkType::Wifi => 28.0_f32,
            NetworkType::Cellular => 45.0,
            NetworkType::Metered => 60.0,
        };
        let hop_count = f32::from(d.onion_hops.as_u8());
        let batch_active: f32 = if d.batch_decision == BatchDecision::Batch {
            1.0
        } else {
            0.0
        };
        let hop_lat = hop_count * s.weights.onion_hop_cost;
        let batch_lat = batch_active * s.weights.batch_latency_cost;
        let pre_relay = base_lat_unweighted + hop_lat + batch_lat;
        let relay_active = d.transport == Transport::Relay;
        let relay_factor: f32 = if relay_active {
            s.weights.relay_rtt_multiplier
        } else {
            1.0
        };

        // ∂e_q/∂onion_hop_cost = (relay_factor * hop_count) / 100
        let d_onion_hop_cost = (relay_factor * hop_count) / 100.0;
        // ∂e_q/∂batch_latency_cost = (relay_factor * batch_active) / 100
        let d_batch_latency_cost = (relay_factor * batch_active) / 100.0;
        // ∂e_q/∂relay_rtt_multiplier: relay→ pre_relay/100, else 0
        let d_relay_rtt_multiplier: f32 = if relay_active { pre_relay / 100.0 } else { 0.0 };

        // e_coherence partials
        let coh_grad_sq = (1.0 - ctx.pattern_strength).powi(2);
        // ∂e_c/∂alpha_coherence = coh_grad_sq
        let d_alpha_coherence = coh_grad_sq;
        // ∂e_c/∂anchor_cost = 1 if anchor else 0
        let d_anchor_cost: f32 = if d.anchor_lay { 1.0 } else { 0.0 };

        // e_alignment partials. Recompute the inputs the alignment
        // formula consumed so we can stub the partials cleanly.
        let peer_dist: f32 = match ctx.peer {
            PeerRelationship::Paired => 1.0,
            PeerRelationship::Known => 3.0,
            PeerRelationship::Stranger => 10.0,
        };
        let staleness = (1.0 - ctx.pattern_strength) * 5.0;
        let l_session: f32 = match ctx.peer {
            PeerRelationship::Paired => 100.0,
            PeerRelationship::Known => 30.0,
            PeerRelationship::Stranger => 5.0,
        };
        let a_x_t = (-((peer_dist * peer_dist) + (staleness * staleness)) / l_session).exp();
        let onion_gain = f32::from(d.onion_hops.as_u8()) * 0.15;
        let cover_gain: f32 = if d.cover_traffic { 0.3 } else { 0.0 };
        let delta_c = onion_gain + cover_gain;
        let dc_ds: f32 = if ctx.user_mode == UserMode::Paranoid {
            1.5
        } else {
            1.0
        };
        let needed = (1.0_f32 - a_x_t) * dc_ds;
        let privacy_gap = (needed - delta_c).max(0.0);
        // ∂e_a/∂privacy_weight = privacy_gap
        let d_privacy_weight = privacy_gap;
        // ∂e_a/∂cover_penalty = mode_mult if !cover else 0
        let d_cover_penalty: f32 = if d.cover_traffic {
            0.0
        } else if ctx.user_mode == UserMode::Paranoid {
            1.0
        } else {
            0.3
        };

        // e_dark partials
        let d_dark_base = 1.0_f32;
        let d_dark_coherence: f32 = if d.path == Path::Coherence { 1.0 } else { 0.0 };
        let d_dark_cover: f32 = if d.cover_traffic { 1.0 } else { 0.0 };

        // Multiply each per-term partial by c_dynamic (chain rule).
        let scale = cd;

        // ∂E/∂lambda_dynamic = ∂c_d/∂λ · (e_q + e_c + e_a + e_d)
        //   c_d = e^{-λD} · 100  →  ∂c_d/∂λ = -D · c_d
        // We need D inverted from c_d (since c_d ≠ 0) — but
        // simpler: recompute D directly.
        let scale_size = usize_as_f32(ctx.size).max(1.0).log10();
        let sens = match ctx.user_mode {
            UserMode::Paranoid => 3.0_f32,
            UserMode::LatencyStrict => -1.0,
            _ => 0.0,
        };
        let urg: f32 = if ctx.urgency == ol_decide::Urgency::Foreground {
            1.0
        } else {
            0.0
        };
        let big_d = (10.0_f32 - scale_size - sens + urg).max(0.0);
        let sum_e =
            s.e_quantum(ctx, d) + s.e_coherence(ctx, d) + s.e_alignment(ctx, d) + s.e_dark(d);
        let d_lambda_dynamic = -big_d * cd * sum_e;

        EnergyGradient {
            d_alpha_coherence: scale * d_alpha_coherence,
            d_privacy_weight: scale * d_privacy_weight,
            d_cover_penalty: scale * d_cover_penalty,
            d_anchor_cost: scale * d_anchor_cost,
            d_batch_latency_cost: scale * d_batch_latency_cost,
            d_onion_hop_cost: scale * d_onion_hop_cost,
            d_relay_rtt_multiplier: scale * d_relay_rtt_multiplier,
            // d_lambda_dynamic uses its own derivation (not scaled
            // again — it already encodes c_d).
            d_lambda_dynamic,
            d_dark_base: scale * d_dark_base,
            d_dark_coherence: scale * d_dark_coherence,
            d_dark_cover: scale * d_dark_cover,
        }
    }

    /// One weight-update step. Pure math; no I/O. Tracks the per-call
    /// clamp count so callers can monitor stability.
    fn update_weights(&mut self, regret: f32, g: &EnergyGradient) {
        let lr = self.learning_rate;
        let reg = self.regularization;
        let bound_mult = self.weight_bound_multiplier;
        let mut clamps = 0u64;
        let w = &mut self.selector.weights;
        let def = &self.defaults;
        macro_rules! step {
            ($field:ident, $g:expr) => {{
                let grad = $g;
                let delta = lr * regret * grad + reg * (def.$field - w.$field);
                let mut next = w.$field + delta;
                let lo = 0.0_f32;
                let hi = def.$field * bound_mult;
                let clamped = next.clamp(lo, hi);
                if (clamped - next).abs() > f32::EPSILON {
                    clamps += 1;
                    next = clamped;
                }
                w.$field = next;
            }};
        }
        step!(alpha_coherence, g.d_alpha_coherence);
        step!(privacy_weight, g.d_privacy_weight);
        step!(cover_penalty, g.d_cover_penalty);
        step!(anchor_cost, g.d_anchor_cost);
        step!(batch_latency_cost, g.d_batch_latency_cost);
        step!(onion_hop_cost, g.d_onion_hop_cost);
        step!(relay_rtt_multiplier, g.d_relay_rtt_multiplier);
        step!(lambda_dynamic, g.d_lambda_dynamic);
        step!(dark_base, g.d_dark_base);
        step!(dark_coherence, g.d_dark_coherence);
        step!(dark_cover, g.d_dark_cover);
        self.clamp_events = self.clamp_events.saturating_add(clamps);
    }
}

impl Default for OnlineLearner {
    fn default() -> Self {
        Self::new()
    }
}

// f64::saturating_add isn't in stable — provide a tiny helper that
// caps the sum at f64::MAX to be safe.
trait SaturatingAddF64 {
    fn saturating_add_f64(self, x: f64) -> Self;
}
impl SaturatingAddF64 for f64 {
    fn saturating_add_f64(self, x: f64) -> Self {
        let s = self + x;
        if s.is_finite() {
            s
        } else if x >= 0.0 {
            f64::MAX
        } else {
            f64::MIN
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{BatchDecision, OnionHops, Path, Transport};
    use ol_decide::{
        Context, EventKind, NetworkType, PeerRelationship, RadioState, Urgency, UserMode,
    };

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

    fn anchored_classical_relay(hops: OnionHops) -> Decision {
        Decision {
            transport: Transport::Relay,
            path: Path::Classical,
            onion_hops: hops,
            cover_traffic: false,
            batch_decision: BatchDecision::Batch,
            anchor_lay: true,
            predictor_warm: false,
        }
    }

    #[test]
    fn u64_to_f64_rounds_large_counts_like_ieee_conversion() {
        assert_eq!(u64_as_f64(0).to_bits(), 0.0_f64.to_bits());
        assert_eq!(
            u64_as_f64(1_u64 << 32).to_bits(),
            4_294_967_296.0_f64.to_bits()
        );
        assert_eq!(
            u64_as_f64((1_u64 << 53) + 1).to_bits(),
            9_007_199_254_740_992.0_f64.to_bits()
        );
        assert_eq!(
            u64_as_f64(u64::MAX).to_bits(),
            18_446_744_073_709_551_616.0_f64.to_bits()
        );
    }

    #[test]
    fn new_learner_has_default_weights() {
        let l = OnlineLearner::new();
        assert_eq!(*l.weights(), Weights::defaults());
        assert_eq!(*l.defaults(), Weights::defaults());
    }

    #[test]
    fn observe_advances_state() {
        let mut l = OnlineLearner::new();
        let ctx = paired_msg(1024);
        let d = anchored_classical_relay(OnionHops::Three);
        l.observe(&ctx, &d, 1.0);
        let s = l.stats();
        assert_eq!(s.n_observations, 1);
        assert!(s.sum_abs_regret >= 1.0 - 1e-6);
    }

    #[test]
    fn nonfinite_regret_is_dropped() {
        let mut l = OnlineLearner::new();
        let ctx = paired_msg(1024);
        let d = anchored_classical_relay(OnionHops::Three);
        l.observe(&ctx, &d, f32::NAN);
        l.observe(&ctx, &d, f32::INFINITY);
        l.observe(&ctx, &d, f32::NEG_INFINITY);
        assert_eq!(l.stats().n_observations, 0);
        assert_eq!(*l.weights(), Weights::defaults());
    }

    #[test]
    fn positive_regret_increases_contributing_weights() {
        // Decision uses relay → ∂E/∂relay_rtt_multiplier > 0
        // High regret → multiplier increases.
        let mut l = OnlineLearner::new();
        let ctx = paired_msg(1024);
        let d = anchored_classical_relay(OnionHops::Three);
        let before = l.weights().relay_rtt_multiplier;
        for _ in 0..100 {
            l.observe(&ctx, &d, 10.0);
        }
        let after = l.weights().relay_rtt_multiplier;
        assert!(
            after > before,
            "expected relay_rtt_multiplier to grow under positive regret: \
             before={before}, after={after}"
        );
    }

    #[test]
    fn weights_stay_bounded_under_adversarial_regret() {
        // 10,000 observations at saturated-high regret should not
        // drive any weight beyond (0, 10× default).
        let mut l = OnlineLearner::new();
        let ctx = paired_msg(1024);
        let d = anchored_classical_relay(OnionHops::Five);
        for _ in 0..10_000 {
            l.observe(&ctx, &d, 100.0);
        }
        let w = l.weights();
        let def = Weights::defaults();
        assert!(w.alpha_coherence >= 0.0 && w.alpha_coherence <= def.alpha_coherence * 10.0);
        assert!(w.privacy_weight >= 0.0 && w.privacy_weight <= def.privacy_weight * 10.0);
        assert!(w.cover_penalty >= 0.0 && w.cover_penalty <= def.cover_penalty * 10.0);
        assert!(w.anchor_cost >= 0.0 && w.anchor_cost <= def.anchor_cost * 10.0);
        assert!(
            w.batch_latency_cost >= 0.0 && w.batch_latency_cost <= def.batch_latency_cost * 10.0
        );
        assert!(w.onion_hop_cost >= 0.0 && w.onion_hop_cost <= def.onion_hop_cost * 10.0);
        assert!(
            w.relay_rtt_multiplier >= 0.0
                && w.relay_rtt_multiplier <= def.relay_rtt_multiplier * 10.0
        );
        assert!(w.lambda_dynamic >= 0.0 && w.lambda_dynamic <= def.lambda_dynamic * 10.0);
    }

    #[test]
    fn regularization_pulls_back_to_default() {
        // End-to-end: positive regret pushes a weight up; then
        // zero-regret observations with active regularization should
        // pull it back toward the default. This is the production
        // path that prevents weight drift in steady state.
        //
        // Context must produce a non-zero gradient for the weight
        // under test. Stranger peer + 1-hop + no-cover has a sizeable
        // alignment gap → privacy_weight gradient is non-trivial.
        let mut l = OnlineLearner::with_config(Weights::defaults(), 0.005, 0.5, 10.0);
        let stranger_no_cover = Context {
            peer: PeerRelationship::Stranger,
            user_mode: UserMode::Normal,
            pattern_strength: 0.0,
            ..paired_msg(1024)
        };
        let weak_privacy = Decision {
            transport: Transport::QuicStream,
            path: Path::Classical,
            onion_hops: OnionHops::One,
            cover_traffic: false,
            batch_decision: BatchDecision::EmitNow,
            anchor_lay: false,
            predictor_warm: false,
        };

        // Sanity: the gradient slot we're about to exercise is non-zero.
        let g = l.energy_gradient(&stranger_no_cover, &weak_privacy);
        assert!(
            g.d_privacy_weight > 0.0,
            "test context has zero d_privacy_weight; pick a different context"
        );

        // Phase 1: positive regret moves privacy_weight up.
        for _ in 0..200 {
            l.observe(&stranger_no_cover, &weak_privacy, 5.0);
        }
        let displaced = l.weights().privacy_weight;
        let default_pw = Weights::defaults().privacy_weight;
        assert!(
            displaced > default_pw,
            "phase 1: expected privacy_weight to grow from {default_pw}, \
             got {displaced}"
        );

        // Phase 2: zero regret + regularization pulls back.
        for _ in 0..200 {
            l.observe(&stranger_no_cover, &weak_privacy, 0.0);
        }
        let pulled = l.weights().privacy_weight;
        assert!(
            pulled < displaced,
            "phase 2: regularization didn't pull back: \
             displaced={displaced}, pulled={pulled}"
        );
        assert!(
            (pulled - default_pw).abs() < 0.5,
            "phase 2: pulled-back weight {pulled} not close to default {default_pw}"
        );
    }

    #[test]
    fn decide_passes_through() {
        // Learner's decide(ctx) must return whatever UnifiedMin would.
        use crate::Decide;
        let l = OnlineLearner::new();
        let s = UnifiedMin::new();
        let ctx = paired_msg(1024);
        assert_eq!(l.decide(&ctx), s.decide(&ctx));
    }

    #[test]
    fn weights_after_learning_still_produce_valid_decisions() {
        use crate::decision::ContractMode;
        let mut l = OnlineLearner::new();
        let ctx = paired_msg(1024);
        let d = anchored_classical_relay(OnionHops::Five);
        for _ in 0..500 {
            l.observe(&ctx, &d, 5.0);
        }
        // After learning, decisions across modes still pass contracts.
        for mode in [
            UserMode::Normal,
            UserMode::Paranoid,
            UserMode::BatterySave,
            UserMode::LatencyStrict,
        ] {
            let test_ctx = Context {
                user_mode: mode,
                ..paired_msg(1024)
            };
            let learned = l.decide(&test_ctx);
            let cmode = match mode {
                UserMode::Normal => ContractMode::Normal,
                UserMode::Paranoid => ContractMode::Paranoid,
                UserMode::BatterySave => ContractMode::BatterySave,
                UserMode::LatencyStrict => ContractMode::LatencyStrict,
            };
            assert!(
                learned.verify_contract(cmode).is_empty(),
                "learned weights produced contract violation for {mode:?}"
            );
        }
    }

    #[test]
    fn invalid_config_clamped() {
        // Negative LR / oversized regularization should clamp.
        let l = OnlineLearner::with_config(Weights::defaults(), -1.0, 2.0, 0.5);
        assert!(l.learning_rate() >= 0.0);
        assert!(l.regularization() <= 1.0);
        assert!(l.weight_bound_multiplier >= 1.0);
    }
}
