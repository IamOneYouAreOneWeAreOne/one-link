//! Support-phase boundary kernel `k_phase(C_support)`.
//!
//! ## Theory
//!
//! The galaxy-side support-phase tightening (2026-03-29 audit) found
//! that the projected support channel stays **core-like** until
//! roughly 80% of cumulative source support is enclosed. The kernel
//! that reproduces this transition is
//!
//! ```text
//! k_phase = tanh((c0 − C_support) / w_phase)
//! ```
//!
//! with best-fit `c0 = 0.80` (transition midpoint at 80% support) and
//! `w_phase = 0.12` (transition width). Inside the support core,
//! `k_phase` is positive (boost); outside, it's negative (attenuate).
//!
//! ## Network mapping
//!
//! - `C_support[i]` = cumulative fraction of swarm-wide chunk supply
//!   enclosed within the topological neighborhood of peer `i`. Peers
//!   at the "center" of the swarm have low C_support (just their own
//!   neighborhood); peers near the edge have high C_support (most of
//!   the swarm is "behind" them).
//! - `k_phase` then gives a per-peer boost / penalty that modulates
//!   the source term: core peers are weighted up, edge peers are
//!   weighted down.

/// Configuration for the support-phase kernel.
#[derive(Debug, Clone, Copy)]
pub struct SupportPhaseConfig {
    /// Transition midpoint (cumulative-support fraction). Galaxy-side
    /// best fit is `0.80`.
    pub c0: f64,
    /// Transition width. Galaxy-side best fit is `0.12`.
    pub w_phase: f64,
}

impl Default for SupportPhaseConfig {
    fn default() -> Self {
        Self {
            c0: 0.80,
            w_phase: 0.12,
        }
    }
}

/// Apply `k_phase = tanh((c0 − C_support) / w_phase)` per peer.
///
/// `c_support[i] ∈ [0, 1]` is the cumulative-support fraction at peer
/// `i`. Returns the per-peer kernel value ∈ (−1, 1).
#[must_use]
pub fn support_phase_kernel(c_support: &[f64], config: SupportPhaseConfig) -> Vec<f64> {
    let w = config.w_phase.max(1e-12);
    c_support
        .iter()
        .map(|&cs| ((config.c0 - cs) / w).tanh())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_positive_below_c0_negative_above() {
        let cs = vec![0.0, 0.5, 0.80, 0.90, 1.0];
        let cfg = SupportPhaseConfig::default();
        let k = support_phase_kernel(&cs, cfg);
        assert!(k[0] > 0.0); // C_support = 0: deep core, positive
        assert!(k[1] > 0.0); // C_support = 0.5: still core
        assert!(k[2].abs() < 1e-12); // at c0 exactly: zero
        assert!(k[3] < 0.0); // past c0: edge regime
        assert!(k[4] < 0.0); // far past: deep edge
    }

    #[test]
    fn kernel_monotonic_decreasing() {
        // As C_support increases, k_phase decreases (boost → attenuate).
        let cs: Vec<f64> = (0..=10).map(|i| i as f64 / 10.0).collect();
        let k = support_phase_kernel(&cs, SupportPhaseConfig::default());
        for w in k.windows(2) {
            assert!(w[1] <= w[0], "kernel must be monotonic decreasing");
        }
    }

    #[test]
    fn kernel_saturates() {
        // Far from c0 in either direction the kernel saturates at ±1.
        let cs = vec![-2.0, 5.0]; // way below c0 / way above
        let k = support_phase_kernel(&cs, SupportPhaseConfig::default());
        assert!((k[0] - 1.0).abs() < 1e-9);
        assert!((k[1] + 1.0).abs() < 1e-9);
    }
}
