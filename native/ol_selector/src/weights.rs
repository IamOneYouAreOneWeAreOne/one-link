//! Tunable weights for the UnifiedMin selector.
//!
//! These are the constants the continuous energy-minimization
//! objective uses to weigh per-event trade-offs. They start at
//! hand-tuned defaults derived from Gap 22 and can be refined
//! online via gradient descent on observed regret (Phase I).

/// Tunable weights for [`UnifiedMin`](crate::UnifiedMin).
///
/// Each field corresponds to one term in the Equation-of-ONE
/// objective:
///
///   E_total = C_dynamic · (E_quantum + α·|∇τ_c|² + (ΔC/ΔS)·A(x,t) + E_dark)
///
/// where the per-term coefficients (`alpha_coherence`, `privacy_weight`,
/// etc.) live here. The defaults are the values that performed best
/// in the forge_shootouts Gap 22 simulations after a single tuning
/// pass.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Weights {
    /// `α` coefficient on coherence gradient |∇τ_c|². Higher → more
    /// stabilization preference (anchors get cheaper, coherence path
    /// preferred even for small payloads).
    pub alpha_coherence: f32,
    /// Multiplier on the alignment-energy "privacy must" term.
    /// Higher → stronger preference for onion + cover even at cost.
    pub privacy_weight: f32,
    /// Fixed penalty when cover_traffic is OFF and the user mode
    /// expects it (paranoid). Triggered when alignment can't reach
    /// the target without cover.
    pub cover_penalty: f32,
    /// Energy cost of laying an anchor (bytes spent).
    pub anchor_cost: f32,
    /// Latency cost (ms) added by batching (mean of DRX window).
    pub batch_latency_cost: f32,
    /// Per-hop latency overhead (ms) inside the onion.
    pub onion_hop_cost: f32,
    /// Multiplier applied to base RTT when the decision picks Relay
    /// (relay path adds ~1 extra RTT vs direct).
    pub relay_rtt_multiplier: f32,
    /// λ — exponent in C_dynamic = e^{-λD}. Higher → smaller events
    /// dominate the objective (perf-focused); lower → larger events
    /// dominate (coherence-focused).
    pub lambda_dynamic: f32,
    /// Dark-energy baseline (irreducible protocol overhead).
    pub dark_base: f32,
    /// Dark-energy bump when the coherence path is chosen.
    pub dark_coherence: f32,
    /// Dark-energy bump when cover traffic is on.
    pub dark_cover: f32,
}

impl Weights {
    /// Construct with the canonical defaults from Gap 22.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            alpha_coherence: 0.5,
            privacy_weight: 50.0,
            cover_penalty: 20.0,
            anchor_cost: 0.05,
            batch_latency_cost: 25.0,
            onion_hop_cost: 4.0,
            relay_rtt_multiplier: 2.0,
            lambda_dynamic: 0.3,
            dark_base: 0.1,
            dark_coherence: 0.05,
            dark_cover: 0.2,
        }
    }
}

impl Default for Weights {
    fn default() -> Self {
        Self::defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_design() {
        let w = Weights::defaults();
        // Sanity: all weights are finite + non-negative.
        assert!(w.alpha_coherence >= 0.0 && w.alpha_coherence.is_finite());
        assert!(w.privacy_weight >= 0.0 && w.privacy_weight.is_finite());
        assert!(w.cover_penalty >= 0.0 && w.cover_penalty.is_finite());
        assert!(w.anchor_cost >= 0.0 && w.anchor_cost.is_finite());
        assert!(w.batch_latency_cost >= 0.0 && w.batch_latency_cost.is_finite());
        assert!(w.onion_hop_cost >= 0.0 && w.onion_hop_cost.is_finite());
        assert!(w.relay_rtt_multiplier >= 1.0 && w.relay_rtt_multiplier.is_finite());
        assert!(w.lambda_dynamic >= 0.0 && w.lambda_dynamic.is_finite());
        assert!(w.dark_base >= 0.0 && w.dark_base.is_finite());
        assert!(w.dark_coherence >= 0.0 && w.dark_coherence.is_finite());
        assert!(w.dark_cover >= 0.0 && w.dark_cover.is_finite());
    }

    #[test]
    fn default_impl_matches_defaults() {
        let a = Weights::default();
        let b = Weights::defaults();
        assert_eq!(a, b);
    }
}
