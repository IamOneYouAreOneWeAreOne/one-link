//! D25 — Wave-equation cascade predictor (RESEARCH-GRADE).
//!
//! Implements the second-order leapfrog scheme on the coherence field:
//!
//! ```text
//! ψ(t+dt) = 2·ψ(t) − ψ(t−dt) + c²·dt²·Laplacian(ψ) − γ·dt·(ψ(t)−ψ(t−dt))
//! ```
//!
//! Source of truth: `Coherence_Energy_Labs_Website/data/evidence/
//! Dark_Matter_Cosmology/S_ONE_DERIVATION_STORY.md` § wave-equation
//! limit; cross-referenced with `forge_shootouts/gap*_wave_eq.py` for
//! the production-tuned constants.
//!
//! ## Scope of this module
//!
//! The wave-step is the FORECAST half of the τ_c substrate: given the
//! current scalar field per node + the previous step, project one
//! `dt` forward + flag disturbances likely to cascade across the
//! mesh. The reaction-diffusion solver in [`crate::pde`] handles the
//! STEADY-STATE half; this module handles transient propagation.
//!
//! Per Gap 28 simulation results: wave-equation forecasting reduces
//! lost-message rate by ~20-25% on cascade-class outage events
//! (single uplink fails, mesh partition propagates outward). The
//! map's acceptance gate is >= 20% reduction (Phase J GATE).
//!
//! ## RESEARCH-GRADE
//!
//! The map flags D25 as research-grade. The selector should consume
//! the output as a soft signal (e.g. to bump anchor_lay probability)
//! NOT as a binary trigger, until the false-positive rate is
//! calibrated against the production workload.

use std::collections::HashMap;

use thiserror::Error;

/// Errors that may arise from wave-equation operations.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum WaveError {
    /// Time step `dt` must be positive.
    #[error("dt must be > 0 (got {got})")]
    InvalidDt {
        /// The offending value.
        got: f32,
    },
    /// Wave speed `c` must be non-negative.
    #[error("wave speed c must be >= 0 (got {got})")]
    InvalidWaveSpeed {
        /// The offending value.
        got: f32,
    },
    /// Damping coefficient `gamma` must be in [0, 1].
    #[error("gamma must be in [0, 1] (got {got})")]
    InvalidDamping {
        /// The offending value.
        got: f32,
    },
}

/// Default wave speed (units: τ_c-units per second). Calibrated from
/// the S_One screening-length derivation: c_eff = c / √3 · H_0 ≈ 1.0
/// in normalised τ_c units. The selector treats this as a constant;
/// per-domain calibrations (OneField, BioMesh) override.
pub const DEFAULT_WAVE_SPEED: f32 = 1.0;

/// Default damping. Without damping, the wave equation oscillates
/// indefinitely after a disturbance; γ ≈ 0.05 gives ~20 dt steps of
/// useful forecast before signal decays into the floor.
pub const DEFAULT_DAMPING: f32 = 0.05;

/// Default disturbance threshold for cascade warnings. Per Gap 28
/// calibration: |Δψ| > 0.15 flags a likely cascade. Tunable per
/// deploy via [`WaveStepper::with_threshold`].
pub const DEFAULT_CASCADE_THRESHOLD: f32 = 0.15;

/// Wave-equation forecaster.
///
/// Maintains two snapshots of the field — current (`psi_t`) and
/// previous (`psi_t_minus_dt`) — so the second-order leapfrog can
/// project forward without re-discretising. Neighbor topology
/// supplied externally; the same graph the FieldObservations uses
/// for gradient_at is the right input.
///
/// Thread-safety: not thread-safe by itself. Wrap in a Mutex if
/// stepped from multiple threads.
#[derive(Debug)]
pub struct WaveStepper {
    psi_t: HashMap<String, f32>,
    psi_t_minus_dt: HashMap<String, f32>,
    wave_speed: f32,
    damping: f32,
    cascade_threshold: f32,
    cascade_warnings: u64,
}

impl WaveStepper {
    /// Construct a wave-stepper with default parameters.
    #[must_use]
    pub fn new() -> Self {
        Self {
            psi_t: HashMap::new(),
            psi_t_minus_dt: HashMap::new(),
            wave_speed: DEFAULT_WAVE_SPEED,
            damping: DEFAULT_DAMPING,
            cascade_threshold: DEFAULT_CASCADE_THRESHOLD,
            cascade_warnings: 0,
        }
    }

    /// Override the wave speed `c`. Must be >= 0.
    pub fn with_wave_speed(mut self, c: f32) -> Result<Self, WaveError> {
        if c < 0.0 || !c.is_finite() {
            return Err(WaveError::InvalidWaveSpeed { got: c });
        }
        self.wave_speed = c;
        Ok(self)
    }

    /// Override the damping coefficient. Must be in [0, 1].
    pub fn with_damping(mut self, gamma: f32) -> Result<Self, WaveError> {
        if !(0.0..=1.0).contains(&gamma) || !gamma.is_finite() {
            return Err(WaveError::InvalidDamping { got: gamma });
        }
        self.damping = gamma;
        Ok(self)
    }

    /// Override the cascade-warning threshold.
    pub fn with_threshold(mut self, threshold: f32) -> Self {
        self.cascade_threshold = threshold.max(0.0);
        self
    }

    /// Seed the current snapshot from an external τ_c map.
    /// Use this on startup or after a field-state reset.
    pub fn seed(&mut self, values: &HashMap<String, f32>) {
        self.psi_t_minus_dt = values.clone();
        self.psi_t = values.clone();
    }

    /// Advance one time step `dt` using the leapfrog scheme.
    ///
    /// `neighbors`: per-node neighborhood (Laplacian support).
    /// Nodes missing from `neighbors` are treated as isolated and
    /// just damped; nodes missing from `psi_t` are seeded with 0.
    ///
    /// Returns the number of nodes whose disturbance |Δψ| crossed
    /// the cascade threshold during this step. Each crossing also
    /// increments the running [`cascade_warnings`] counter.
    pub fn step(
        &mut self,
        dt: f32,
        neighbors: &HashMap<String, Vec<String>>,
    ) -> Result<u32, WaveError> {
        if dt <= 0.0 || !dt.is_finite() {
            return Err(WaveError::InvalidDt { got: dt });
        }
        let c2_dt2 = self.wave_speed * self.wave_speed * dt * dt;
        let gamma_dt = self.damping * dt;
        let mut next: HashMap<String, f32> = HashMap::with_capacity(self.psi_t.len());
        let mut warnings: u32 = 0;
        // Collect nodes from both psi_t and neighbors so a newly-
        // discovered peer with no current value still gets stepped.
        let mut all_nodes: std::collections::BTreeSet<&String> = self.psi_t.keys().collect();
        for k in neighbors.keys() {
            all_nodes.insert(k);
        }
        for node in all_nodes {
            let current = *self.psi_t.get(node).unwrap_or(&0.0);
            let prev = *self.psi_t_minus_dt.get(node).unwrap_or(&current);
            // Graph Laplacian: mean(neighbors) − self.
            let lap = match neighbors.get(node) {
                Some(ns) if !ns.is_empty() => {
                    let sum: f32 = ns
                        .iter()
                        .map(|n| *self.psi_t.get(n).unwrap_or(&0.0))
                        .sum();
                    let mean = sum / ns.len() as f32;
                    mean - current
                }
                _ => 0.0,
            };
            // Leapfrog with damping:
            //   ψ(t+dt) = 2·ψ(t) − ψ(t−dt) + c²·dt²·Δψ − γ·dt·(ψ(t)−ψ(t−dt))
            let next_value = 2.0 * current
                - prev
                + c2_dt2 * lap
                - gamma_dt * (current - prev);
            // Cascade warning if disturbance |Δψ| > threshold.
            if (next_value - current).abs() > self.cascade_threshold {
                warnings += 1;
            }
            next.insert(node.clone(), next_value);
        }
        // Shift snapshots forward.
        self.psi_t_minus_dt = std::mem::replace(&mut self.psi_t, next);
        self.cascade_warnings += u64::from(warnings);
        Ok(warnings)
    }

    /// Current field value at `node` after the latest step.
    /// None if the node has never been observed.
    #[must_use]
    pub fn psi_at(&self, node: &str) -> Option<f32> {
        self.psi_t.get(node).copied()
    }

    /// Number of nodes currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.psi_t.len()
    }

    /// True iff no nodes are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.psi_t.is_empty()
    }

    /// Configured wave speed.
    #[must_use]
    pub fn wave_speed(&self) -> f32 {
        self.wave_speed
    }

    /// Configured damping.
    #[must_use]
    pub fn damping(&self) -> f32 {
        self.damping
    }

    /// Configured cascade threshold.
    #[must_use]
    pub fn cascade_threshold(&self) -> f32 {
        self.cascade_threshold
    }

    /// Cumulative cascade-warning count. Useful for the operator
    /// dashboard's `cascade_warnings` counter (integration map §11).
    #[must_use]
    pub fn cascade_warnings(&self) -> u64 {
        self.cascade_warnings
    }

    /// Reset the cascade-warning counter without dropping field state.
    pub fn reset_warnings(&mut self) {
        self.cascade_warnings = 0;
    }
}

impl Default for WaveStepper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _neighbors_chain(n: usize) -> HashMap<String, Vec<String>> {
        let mut out = HashMap::new();
        for i in 0..n {
            let mut ns = Vec::new();
            if i > 0 {
                ns.push(format!("n{}", i - 1));
            }
            if i < n - 1 {
                ns.push(format!("n{}", i + 1));
            }
            out.insert(format!("n{}", i), ns);
        }
        out
    }

    #[test]
    fn new_defaults() {
        let w = WaveStepper::new();
        assert_eq!(w.wave_speed(), DEFAULT_WAVE_SPEED);
        assert_eq!(w.damping(), DEFAULT_DAMPING);
        assert_eq!(w.cascade_threshold(), DEFAULT_CASCADE_THRESHOLD);
        assert_eq!(w.cascade_warnings(), 0);
        assert!(w.is_empty());
    }

    #[test]
    fn with_wave_speed_rejects_negative() {
        let r = WaveStepper::new().with_wave_speed(-1.0);
        assert!(matches!(r, Err(WaveError::InvalidWaveSpeed { .. })));
    }

    #[test]
    fn with_damping_rejects_out_of_range() {
        assert!(WaveStepper::new().with_damping(-0.1).is_err());
        assert!(WaveStepper::new().with_damping(1.5).is_err());
    }

    #[test]
    fn step_rejects_zero_dt() {
        let mut w = WaveStepper::new();
        let r = w.step(0.0, &HashMap::new());
        assert!(matches!(r, Err(WaveError::InvalidDt { .. })));
    }

    #[test]
    fn seed_then_step_constant_field_stays_constant() {
        let mut w = WaveStepper::new();
        let mut initial = HashMap::new();
        for i in 0..3 {
            initial.insert(format!("n{}", i), 0.5);
        }
        w.seed(&initial);
        let neighbors = _neighbors_chain(3);
        // A constant field has zero Laplacian and zero (ψ−prev), so
        // it should not change under the leapfrog update.
        w.step(0.1, &neighbors).unwrap();
        for i in 0..3 {
            let v = w.psi_at(&format!("n{}", i)).unwrap();
            assert!((v - 0.5).abs() < 1e-5);
        }
        // No cascade warnings on a constant field.
        assert_eq!(w.cascade_warnings(), 0);
    }

    #[test]
    fn step_propagates_disturbance() {
        let mut w = WaveStepper::new();
        let mut initial = HashMap::new();
        for i in 0..5 {
            initial.insert(format!("n{}", i), 0.5);
        }
        // Disturb node n2.
        initial.insert("n2".to_string(), 1.0);
        w.seed(&initial);
        let neighbors = _neighbors_chain(5);
        w.step(0.1, &neighbors).unwrap();
        // The neighbors of n2 should have moved away from 0.5 a bit.
        let n1 = w.psi_at("n1").unwrap();
        let n3 = w.psi_at("n3").unwrap();
        assert!(n1 > 0.5);
        assert!(n3 > 0.5);
    }

    #[test]
    fn step_returns_cascade_warning_count() {
        let mut w = WaveStepper::new().with_threshold(0.01); // very sensitive
        let mut initial = HashMap::new();
        for i in 0..3 {
            initial.insert(format!("n{}", i), 0.0);
        }
        initial.insert("n0".to_string(), 1.0);
        w.seed(&initial);
        let neighbors = _neighbors_chain(3);
        // High disturbance + low threshold -> warnings.
        let warns = w.step(0.5, &neighbors).unwrap();
        assert!(warns >= 1);
        assert!(w.cascade_warnings() >= 1);
    }

    #[test]
    fn isolated_node_just_damps() {
        let mut w = WaveStepper::new();
        let mut initial = HashMap::new();
        initial.insert("orphan".to_string(), 1.0);
        w.seed(&initial);
        // No neighbors mapping -> Laplacian is zero.
        w.step(0.1, &HashMap::new()).unwrap();
        let v = w.psi_at("orphan").unwrap();
        // Damping subtracts γ·dt·(current − prev). prev = current
        // (just seeded), so v should still be 1.0.
        assert!((v - 1.0).abs() < 1e-5);
    }

    #[test]
    fn reset_warnings_clears_counter() {
        let mut w = WaveStepper::new().with_threshold(0.01);
        let mut initial = HashMap::new();
        initial.insert("n0".to_string(), 1.0);
        initial.insert("n1".to_string(), 0.0);
        w.seed(&initial);
        let mut neighbors = HashMap::new();
        neighbors.insert("n0".to_string(), vec!["n1".to_string()]);
        neighbors.insert("n1".to_string(), vec!["n0".to_string()]);
        w.step(0.5, &neighbors).unwrap();
        assert!(w.cascade_warnings() > 0);
        w.reset_warnings();
        assert_eq!(w.cascade_warnings(), 0);
    }
}
