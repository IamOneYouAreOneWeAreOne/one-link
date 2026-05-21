//! `FieldObservations` — per-peer τ_c observation buffer with
//! trust-weighted EWMA updates + coherence-gradient computation.
//!
//! This module is the OBSERVATION SUBSTRATE that feeds the PDE solver:
//! the daemon writes per-peer τ_c samples here (D23 in the integration
//! map, line 3367 / 9268 / 10307 write sites), and the selector +
//! relay-picker read scalar field values + the gradient signal here
//! (D21 + D07 + D24).
//!
//! ## Why trust-weighted (Gap 4 — field poisoning defense)
//!
//! A naive EWMA absorbs every observation equally. A compromised peer
//! feeding bad τ_c values can drag the field into a sinkhole (Gap 4:
//! 15% attacker fraction drove the naive field ~12% off truth). The
//! trust weight scales the update:
//!
//! ```text
//! new_τ = (1 − α·trust) · old_τ + α·trust · observed
//! ```
//!
//! At trust = 1.0 this is the standard EWMA. At trust < 1.0 the update
//! is dampened proportionally. At trust = 0 the field is read-only
//! for that peer.
//!
//! Gap 4 evidence: trust-weighted EWMA cuts poisoning impact by 92%
//! at the same attacker fraction.
//!
//! ## The gradient signal (D24, RESEARCH-GRADE)
//!
//! `gradient_at(peer)` returns |∇τ_c|² approximated on the local graph
//! neighborhood (variance of neighbor τ + self-deviation from the
//! neighborhood mean). High values mark "coherence boundaries" where
//! the field is changing rapidly — useful as an anticipatory signal
//! for selector decisions like `anchor_lay`.
//!
//! Gap 25 noted precision was only 21% at the tuned threshold —
//! good recall but many false positives. The selector should NOT
//! treat the gradient as a binary trigger in production until the
//! threshold is calibrated. We surface it as a soft signal here.

use std::collections::HashMap;

use thiserror::Error;

/// Errors that may arise from FieldObservations operations.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum ObservationError {
    /// Learning rate α must be in (0, 1].
    #[error("alpha must be in (0, 1] (got {got})")]
    InvalidAlpha {
        /// The offending value.
        got: f32,
    },

    /// Observed τ must be in [0, 1] and finite.
    #[error("observed_tau must be in [0, 1] (got {got})")]
    InvalidObservation {
        /// The offending value.
        got: f32,
    },

    /// Trust weight must be in [0, 1] and finite.
    #[error("trust_weight must be in [0, 1] (got {got})")]
    InvalidTrust {
        /// The offending value.
        got: f32,
    },
}

/// Per-peer τ_c observation buffer with trust-weighted EWMA + gradient.
///
/// Stateful (holds per-peer values and adjacency); construct once and
/// share across the daemon.
///
/// Invariants:
///   - `alpha ∈ (0, 1]`
///   - All stored τ values in [0, 1]
///   - `len() == values.len()`
#[derive(Debug, Clone)]
pub struct FieldObservations {
    /// EWMA per-peer τ_c values.
    values: HashMap<String, f32>,
    /// Per-peer neighbor lists used by gradient computation.
    /// Daemon populates this from its mesh topology.
    neighbors: HashMap<String, Vec<String>>,
    /// EWMA learning rate at trust = 1.0.
    alpha: f32,
    /// Default initial value for newly-observed peers (avoids cold-
    /// start anchoring at 0).
    initial_value: f32,
}

impl FieldObservations {
    /// Construct with a given EWMA learning rate.
    ///
    /// Typical α: 0.05 — moderate responsiveness, ~20-sample window.
    ///
    /// # Errors
    /// Returns [`ObservationError::InvalidAlpha`] if α is not in (0, 1]
    /// or non-finite.
    pub fn new(alpha: f32) -> Result<Self, ObservationError> {
        if !alpha.is_finite() || !(0.0..=1.0).contains(&alpha) || alpha == 0.0 {
            return Err(ObservationError::InvalidAlpha { got: alpha });
        }
        Ok(Self {
            values: HashMap::new(),
            neighbors: HashMap::new(),
            alpha,
            initial_value: 0.5,
        })
    }

    /// Construct with explicit α + initial-value seeding.
    ///
    /// `initial_value` is used when the first observation lands for a
    /// previously-unknown peer. Default is 0.5 — neutral starting point.
    ///
    /// # Errors
    /// Same as [`new`](Self::new), plus rejects non-finite or out-of-range
    /// initial values.
    pub fn with_initial(alpha: f32, initial_value: f32) -> Result<Self, ObservationError> {
        let mut s = Self::new(alpha)?;
        if !initial_value.is_finite() || !(0.0..=1.0).contains(&initial_value) {
            return Err(ObservationError::InvalidObservation {
                got: initial_value,
            });
        }
        s.initial_value = initial_value;
        Ok(s)
    }

    /// Trust-weighted EWMA update for a peer.
    ///
    /// `trust_weight = 1.0` is the standard EWMA; `< 1.0` dampens the
    /// update proportionally; `0.0` makes this a no-op (the field is
    /// effectively read-only for that peer). Per Gap 4 (field
    /// poisoning defense).
    ///
    /// # Errors
    /// Returns [`ObservationError`] for invalid observation or trust
    /// (not in [0, 1] or non-finite).
    pub fn update(
        &mut self,
        peer_id: &str,
        observed_tau: f32,
        trust_weight: f32,
    ) -> Result<(), ObservationError> {
        if !observed_tau.is_finite() || !(0.0..=1.0).contains(&observed_tau) {
            return Err(ObservationError::InvalidObservation { got: observed_tau });
        }
        if !trust_weight.is_finite() || !(0.0..=1.0).contains(&trust_weight) {
            return Err(ObservationError::InvalidTrust { got: trust_weight });
        }

        let current = self.values.get(peer_id).copied().unwrap_or(self.initial_value);
        let effective_alpha = self.alpha * trust_weight;
        // Standard EWMA with damped α:
        //   new = (1 − α') · old + α' · obs
        let new_value = (1.0 - effective_alpha) * current + effective_alpha * observed_tau;
        // Clamp defensively in case of floating-point drift around the
        // unit interval.
        let clamped = new_value.clamp(0.0, 1.0);
        self.values.insert(peer_id.to_owned(), clamped);
        Ok(())
    }

    /// Current EWMA τ_c value for a peer, or None if never observed.
    #[must_use]
    pub fn tau_at(&self, peer_id: &str) -> Option<f32> {
        self.values.get(peer_id).copied()
    }

    /// Replace the neighbor list for a peer (used by gradient_at).
    ///
    /// Empty list disables gradient computation for that peer.
    pub fn set_neighbors(&mut self, peer_id: &str, neighbors: Vec<String>) {
        if neighbors.is_empty() {
            self.neighbors.remove(peer_id);
        } else {
            self.neighbors.insert(peer_id.to_owned(), neighbors);
        }
    }

    /// Coherence-gradient magnitude squared at this peer, approximated
    /// on the local graph neighborhood (D24).
    ///
    /// Returns:
    ///   `Some(|∇τ_c|²)` if neighbors are configured and at least one
    ///   neighbor has been observed.
    ///   `None` if no neighbors are configured or none have been seen.
    ///
    /// The formula is the discrete graph-Laplacian variance:
    ///   ∇²τ ≈ var(τ_neighbors) + (self_τ − mean(τ_neighbors))²
    ///
    /// Per Gap 25: this is RESEARCH-GRADE. Selector should not gate
    /// decisions on it as a binary signal until calibrated.
    #[must_use]
    pub fn gradient_at(&self, peer_id: &str) -> Option<f32> {
        let neighbors = self.neighbors.get(peer_id)?;
        let observed: Vec<f32> = neighbors
            .iter()
            .filter_map(|n| self.values.get(n).copied())
            .collect();
        if observed.is_empty() {
            return None;
        }
        let mean = observed.iter().sum::<f32>() / observed.len() as f32;
        let variance = observed
            .iter()
            .map(|t| (t - mean) * (t - mean))
            .sum::<f32>()
            / observed.len() as f32;
        let self_dev = self
            .values
            .get(peer_id)
            .map_or(0.0, |s| (s - mean) * (s - mean));
        Some(variance + self_dev)
    }

    /// Number of peers with at least one observation.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// True iff no peers have been observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Configured EWMA learning rate.
    #[must_use]
    pub fn alpha(&self) -> f32 {
        self.alpha
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fo() -> FieldObservations {
        FieldObservations::new(0.1).unwrap()
    }

    // ───── Construction ──────────────────────────────────────────────

    #[test]
    fn rejects_zero_alpha() {
        assert!(matches!(
            FieldObservations::new(0.0),
            Err(ObservationError::InvalidAlpha { .. })
        ));
    }

    #[test]
    fn rejects_negative_alpha() {
        assert!(matches!(
            FieldObservations::new(-0.1),
            Err(ObservationError::InvalidAlpha { .. })
        ));
    }

    #[test]
    fn rejects_oversize_alpha() {
        assert!(matches!(
            FieldObservations::new(1.5),
            Err(ObservationError::InvalidAlpha { .. })
        ));
    }

    #[test]
    fn rejects_nonfinite_alpha() {
        assert!(matches!(
            FieldObservations::new(f32::NAN),
            Err(ObservationError::InvalidAlpha { .. })
        ));
    }

    // ───── Update + read ────────────────────────────────────────────

    #[test]
    fn fresh_peer_seeded_at_initial_value() {
        let mut o = fo();
        // Update at trust=0.5, tau=0.9 over default initial 0.5.
        o.update("p1", 0.9, 1.0).unwrap();
        let v = o.tau_at("p1").unwrap();
        // new = 0.9 · 0.5 + 0.1 · 0.9 = 0.45 + 0.09 = 0.54
        assert!((v - 0.54).abs() < 1e-5);
    }

    #[test]
    fn ewma_converges_to_observed() {
        let mut o = fo();
        for _ in 0..200 {
            o.update("p1", 0.9, 1.0).unwrap();
        }
        let v = o.tau_at("p1").unwrap();
        assert!((v - 0.9).abs() < 0.01);
    }

    #[test]
    fn trust_zero_no_op() {
        let mut o = fo();
        o.update("p1", 0.99, 1.0).unwrap(); // anchor at non-default
        let before = o.tau_at("p1").unwrap();
        o.update("p1", 0.0, 0.0).unwrap(); // try to drag to 0
        let after = o.tau_at("p1").unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn low_trust_dampens_update() {
        let mut o1 = fo();
        let mut o2 = fo();
        // Same observation, different trust.
        for _ in 0..50 {
            o1.update("p", 0.0, 1.0).unwrap();
            o2.update("p", 0.0, 0.1).unwrap();
        }
        // o1 should be much closer to 0 than o2.
        assert!(o1.tau_at("p").unwrap() < o2.tau_at("p").unwrap());
    }

    #[test]
    fn rejects_oob_observation() {
        let mut o = fo();
        assert!(matches!(
            o.update("p", 1.5, 1.0),
            Err(ObservationError::InvalidObservation { .. })
        ));
        assert!(matches!(
            o.update("p", -0.1, 1.0),
            Err(ObservationError::InvalidObservation { .. })
        ));
        assert!(matches!(
            o.update("p", f32::NAN, 1.0),
            Err(ObservationError::InvalidObservation { .. })
        ));
    }

    #[test]
    fn rejects_oob_trust() {
        let mut o = fo();
        assert!(matches!(
            o.update("p", 0.5, 1.5),
            Err(ObservationError::InvalidTrust { .. })
        ));
        assert!(matches!(
            o.update("p", 0.5, -0.1),
            Err(ObservationError::InvalidTrust { .. })
        ));
    }

    #[test]
    fn tau_at_returns_none_for_unknown() {
        let o = fo();
        assert!(o.tau_at("never_seen").is_none());
    }

    // ───── Gradient ─────────────────────────────────────────────────

    #[test]
    fn gradient_none_without_neighbors() {
        let mut o = fo();
        o.update("p", 0.5, 1.0).unwrap();
        assert!(o.gradient_at("p").is_none());
    }

    #[test]
    fn gradient_zero_when_neighbors_match_self() {
        let mut o = fo();
        // Anchor everyone at the same value.
        for _ in 0..100 {
            for p in ["self", "a", "b", "c"] {
                o.update(p, 0.8, 1.0).unwrap();
            }
        }
        o.set_neighbors("self", vec!["a".into(), "b".into(), "c".into()]);
        let g = o.gradient_at("self").unwrap();
        assert!(g < 0.001, "expected ~0, got {g}");
    }

    #[test]
    fn gradient_positive_when_neighbors_diverge() {
        let mut o = fo();
        for _ in 0..200 {
            o.update("self", 0.5, 1.0).unwrap();
            o.update("a", 0.9, 1.0).unwrap();
            o.update("b", 0.1, 1.0).unwrap();
        }
        o.set_neighbors("self", vec!["a".into(), "b".into()]);
        let g = o.gradient_at("self").unwrap();
        // var = ((0.9 − 0.5)² + (0.1 − 0.5)²)/2 = 0.16
        // self_dev = (0.5 − 0.5)² = 0  → g ≈ 0.16
        assert!(g > 0.1, "expected > 0.1, got {g}");
    }

    #[test]
    fn gradient_self_deviation_contributes() {
        let mut o = fo();
        for _ in 0..200 {
            o.update("self", 0.1, 1.0).unwrap();
            o.update("a", 0.9, 1.0).unwrap();
            o.update("b", 0.9, 1.0).unwrap();
        }
        o.set_neighbors("self", vec!["a".into(), "b".into()]);
        let g = o.gradient_at("self").unwrap();
        // var = 0 (a=b), self_dev = (0.1 − 0.9)² = 0.64
        // → g ≈ 0.64 — large gradient at coherence boundary.
        assert!(g > 0.5, "expected > 0.5, got {g}");
    }

    #[test]
    fn empty_neighbors_clears_gradient_path() {
        let mut o = fo();
        o.update("p", 0.5, 1.0).unwrap();
        o.set_neighbors("p", vec!["a".into()]);
        o.set_neighbors("p", vec![]); // clear
        assert!(o.gradient_at("p").is_none());
    }

    // ───── Lifecycle ────────────────────────────────────────────────

    #[test]
    fn len_tracks_unique_peers() {
        let mut o = fo();
        assert!(o.is_empty());
        o.update("p1", 0.5, 1.0).unwrap();
        o.update("p2", 0.5, 1.0).unwrap();
        o.update("p1", 0.6, 1.0).unwrap(); // duplicate doesn't add
        assert_eq!(o.len(), 2);
    }

    // ───── Poisoning defense (Gap 4 invariant) ───────────────────────

    #[test]
    fn trust_weighted_resists_field_poisoning() {
        let mut o = FieldObservations::new(0.05).unwrap();
        // 85 honest observations from trusted peers, anchoring around 0.8.
        for _ in 0..85 {
            o.update("p", 0.8, 1.0).unwrap();
        }
        let honest_value = o.tau_at("p").unwrap();
        // 15 adversarial pull-to-zero observations from low-trust peers.
        for _ in 0..15 {
            o.update("p", 0.0, 0.1).unwrap(); // trust 0.1
        }
        let after_attack = o.tau_at("p").unwrap();
        // With trust-weighting, the attack should move the value by
        // less than 0.1. (Gap 4: trust-weighted cuts impact 92% vs naive.)
        assert!(
            (honest_value - after_attack).abs() < 0.1,
            "trust-weighted EWMA absorbed too much from low-trust attacker: \
             before={honest_value}, after={after_attack}"
        );
    }
}
