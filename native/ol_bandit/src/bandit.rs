//! Thompson-sampling Beta-Bernoulli bandit.
//!
//! Algorithm:
//!
//! 1. Maintain `(α, β)` per arm. Initialize to `(1, 1)` (uniform prior).
//! 2. `select`: for each arm, sample `θ_i ~ Beta(α_i, β_i)`. Return
//!    `argmax θ_i`.
//! 3. `update(arm_idx, reward)`: `α_{idx} += reward`,
//!    `β_{idx} += (1 - reward)`.
//!
//! Convergence: under a stationary reward distribution, the bandit
//! concentrates on the best arm within `O(K log T)` rounds where K is
//! the number of arms and T is the horizon.
//!
//! Phase C primitive acceptance gate (per `FILE_ENGINE_V2_PLAN.md`):
//!
//!   > Bandit converges on a known-optimum synthetic arm within ≤200
//!   > interactions in simulation.
//!
//! Verified in `tests/acceptance.rs`. This establishes convergence of
//! the generic sampler; it does not imply that every proposed transfer
//! knob has a production control loop.

use crate::error::BanditError;

/// Upper bound for a single adaptive decision model. Production route
/// selectors use fewer than 16 arms; 1024 preserves generous research
/// headroom while preventing an FFI integer from causing an unbounded
/// allocation and O(K) selection loop.
pub const MAX_ARMS: usize = 1024;

/// One arm of the bandit: a Beta(α, β) posterior over its expected
/// reward in `[0, 1]`.
#[derive(Debug, Clone, Copy)]
pub struct Arm {
    /// Beta parameter α (successes + 1 prior).
    pub alpha: f64,
    /// Beta parameter β (failures + 1 prior).
    pub beta: f64,
}

impl Default for Arm {
    fn default() -> Self {
        Self {
            alpha: 1.0,
            beta: 1.0,
        }
    }
}

impl Arm {
    /// Posterior mean: `α / (α + β)`. Used for tie-breaking and
    /// diagnostics; the bandit itself samples, not averages.
    #[inline]
    #[must_use]
    pub fn mean(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    /// Total observations (successes + failures + 2 for the uniform prior).
    #[inline]
    #[must_use]
    pub fn observations(&self) -> f64 {
        self.alpha + self.beta
    }
}

/// Tiny deterministic PRNG seed. The bandit accepts an `&mut dyn
/// BanditRng` rather than a fixed type so tests can use a seeded
/// RNG while production uses `rand::thread_rng`.
pub trait BanditRng {
    /// Draw a uniform sample in `[0, 1)`.
    fn next_f64(&mut self) -> f64;
}

/// SplitMix64-based PRNG keyed by a 64-bit seed. Cheap, deterministic,
/// statistically adequate for bandit sampling (we don't need cryptographic
/// quality here — the reward signal dominates noise).
#[derive(Debug, Clone, Copy)]
pub struct BanditSeed {
    state: u64,
}

impl BanditSeed {
    /// Seed the PRNG with a 64-bit value.
    #[inline]
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }
}

impl BanditRng for BanditSeed {
    #[inline]
    fn next_f64(&mut self) -> f64 {
        const TWO_POW_32: f64 = 4_294_967_296.0;
        const TWO_POW_53: f64 = 9_007_199_254_740_992.0;

        // SplitMix64 — produces a fresh u64 each call.
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        let bits = (z ^ (z >> 31)) >> 11; // 53-bit mantissa
        let high = u32::try_from(bits >> 32).expect("53-bit value has a 21-bit high word");
        let low = u32::try_from(bits & u64::from(u32::MAX)).expect("masked low word fits in u32");
        (f64::from(high) * TWO_POW_32 + f64::from(low)) / TWO_POW_53
    }
}

/// A multi-armed bandit over `K` arms.
#[derive(Debug, Clone)]
pub struct Bandit {
    arms: Vec<Arm>,
}

impl Bandit {
    /// Build a fresh bandit over `n_arms` with default uniform priors.
    ///
    /// # Errors
    ///
    /// [`BanditError::NoArms`] if `n_arms == 0`.
    pub fn new(n_arms: usize) -> Result<Self, BanditError> {
        if n_arms == 0 {
            return Err(BanditError::NoArms);
        }
        if n_arms > MAX_ARMS {
            return Err(BanditError::TooManyArms {
                got: n_arms,
                max: MAX_ARMS,
            });
        }
        Ok(Self {
            arms: vec![Arm::default(); n_arms],
        })
    }

    /// Number of arms.
    #[inline]
    #[must_use]
    pub fn n_arms(&self) -> usize {
        self.arms.len()
    }

    /// Borrow the arms for diagnostics.
    #[inline]
    #[must_use]
    pub fn arms(&self) -> &[Arm] {
        &self.arms
    }

    /// Select the next arm to play via Thompson sampling.
    ///
    /// Draws `θ_i` ~ `Beta(α_i`, `β_i`) for each arm; returns the index of
    /// the maximum.
    pub fn select<R: BanditRng>(&self, rng: &mut R) -> usize {
        let mut best_idx = 0usize;
        let mut best_sample = f64::NEG_INFINITY;
        for (i, arm) in self.arms.iter().enumerate() {
            let sample = sample_beta(arm.alpha, arm.beta, rng);
            if sample > best_sample {
                best_sample = sample;
                best_idx = i;
            }
        }
        best_idx
    }

    /// Update the bandit with the observed `reward` ∈ `[0, 1]` for
    /// `arm_idx`. Treats the reward as a Bernoulli-thinned success
    /// fraction: `α += r`, `β += (1 - r)`.
    ///
    /// # Errors
    ///
    /// - [`BanditError::ArmIndexOutOfRange`].
    /// - [`BanditError::InvalidReward`] for `r ∉ [0, 1]` or `NaN`.
    pub fn update(&mut self, arm_idx: usize, reward: f64) -> Result<(), BanditError> {
        if arm_idx >= self.arms.len() {
            return Err(BanditError::ArmIndexOutOfRange {
                got: arm_idx,
                n_arms: self.arms.len(),
            });
        }
        if !reward.is_finite() || !(0.0..=1.0).contains(&reward) {
            return Err(BanditError::InvalidReward { got: reward });
        }
        self.arms[arm_idx].alpha += reward;
        self.arms[arm_idx].beta += 1.0 - reward;
        Ok(())
    }

    /// Greedy "best arm so far" — the arm with the highest posterior
    /// mean. Use this for reporting; for the bandit's actual choice,
    /// call [`Self::select`].
    #[must_use]
    pub fn best_arm(&self) -> usize {
        let mut best = 0usize;
        let mut best_mean = f64::NEG_INFINITY;
        for (i, arm) in self.arms.iter().enumerate() {
            let m = arm.mean();
            if m > best_mean {
                best_mean = m;
                best = i;
            }
        }
        best
    }
}

/// Sample from Beta(α, β) using the ratio-of-gammas method:
/// `X = G(α) / (G(α) + G(β))`, where `G(k)` is a Gamma(k, 1) sample.
///
/// For α + β small (≤ 1) we'd want a specialized sampler; in practice
/// the bandit's arms always have α ≥ 1 + `observed_successes` ≥ 1, so
/// the Marsaglia-Tsang Gamma sampler is appropriate.
fn sample_beta<R: BanditRng>(alpha: f64, beta: f64, rng: &mut R) -> f64 {
    let g_a = sample_gamma(alpha, rng);
    let g_b = sample_gamma(beta, rng);
    g_a / (g_a + g_b)
}

/// Marsaglia-Tsang Gamma(shape, 1) sampler. For shape ≥ 1.
fn sample_gamma<R: BanditRng>(shape: f64, rng: &mut R) -> f64 {
    debug_assert!(shape > 0.0, "Gamma shape must be > 0; got {shape}");
    if shape < 1.0 {
        // Johnk's algorithm + boost: G(k) ~ G(k+1) * U^(1/k).
        let gamma_sample = sample_gamma(shape + 1.0, rng);
        let uniform_sample = rng.next_f64();
        return gamma_sample * uniform_sample.powf(1.0 / shape);
    }
    let shape_offset = shape - 1.0 / 3.0;
    let scale = 1.0 / (9.0 * shape_offset).sqrt();
    loop {
        // Standard normal via Box-Muller.
        let u1 = rng.next_f64().max(1e-300);
        let u2 = rng.next_f64();
        let normal_sample = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        let candidate_base = 1.0 + scale * normal_sample;
        if candidate_base <= 0.0 {
            continue;
        }
        let candidate = candidate_base * candidate_base * candidate_base;
        let acceptance_sample = rng.next_f64();
        if acceptance_sample < 1.0 - 0.0331 * normal_sample.powi(4) {
            return shape_offset * candidate;
        }
        if acceptance_sample.ln()
            < 0.5 * normal_sample * normal_sample
                + shape_offset * (1.0 - candidate + candidate.ln())
        {
            return shape_offset * candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_arms() {
        assert!(matches!(Bandit::new(0), Err(BanditError::NoArms)));
    }

    #[test]
    fn excessive_arms_rejected_before_allocation() {
        assert!(matches!(
            Bandit::new(usize::MAX),
            Err(BanditError::TooManyArms { .. })
        ));
    }

    #[test]
    fn fresh_bandit_uniform_arms() {
        let b = Bandit::new(3).unwrap();
        for arm in b.arms() {
            assert!((arm.alpha - 1.0).abs() < f64::EPSILON);
            assert!((arm.beta - 1.0).abs() < f64::EPSILON);
            assert!((arm.mean() - 0.5).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn update_records_reward() {
        let mut b = Bandit::new(3).unwrap();
        b.update(1, 1.0).unwrap();
        assert!((b.arms()[1].alpha - 2.0).abs() < f64::EPSILON);
        assert!((b.arms()[1].beta - 1.0).abs() < f64::EPSILON);
        b.update(1, 0.0).unwrap();
        assert!((b.arms()[1].alpha - 2.0).abs() < f64::EPSILON);
        assert!((b.arms()[1].beta - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn rejects_invalid_reward() {
        let mut b = Bandit::new(2).unwrap();
        assert!(matches!(
            b.update(0, -0.1),
            Err(BanditError::InvalidReward { .. })
        ));
        assert!(matches!(
            b.update(0, 1.5),
            Err(BanditError::InvalidReward { .. })
        ));
        assert!(matches!(
            b.update(0, f64::NAN),
            Err(BanditError::InvalidReward { .. })
        ));
        assert!(b.update(0, 0.0).is_ok());
        assert!(b.update(0, 1.0).is_ok());
        assert!(b.update(0, 0.5).is_ok());
    }

    #[test]
    fn rejects_arm_out_of_range() {
        let mut b = Bandit::new(3).unwrap();
        assert!(matches!(
            b.update(3, 0.5),
            Err(BanditError::ArmIndexOutOfRange { .. })
        ));
    }

    #[test]
    fn select_returns_valid_arm_index() {
        let b = Bandit::new(5).unwrap();
        let mut rng = BanditSeed::new(42);
        for _ in 0..100 {
            let idx = b.select(&mut rng);
            assert!(idx < 5);
        }
    }

    #[test]
    fn gamma_sampler_produces_positive_values() {
        let mut rng = BanditSeed::new(0xCAFE);
        for shape in [0.5_f64, 1.0, 2.0, 5.0, 10.0] {
            for _ in 0..50 {
                let g = sample_gamma(shape, &mut rng);
                assert!(g > 0.0, "shape={shape}: sample = {g}");
                assert!(g.is_finite());
            }
        }
    }

    #[test]
    fn beta_sampler_produces_values_in_unit_interval() {
        let mut rng = BanditSeed::new(0xBABE);
        for _ in 0..200 {
            let b = sample_beta(2.0, 3.0, &mut rng);
            assert!(b > 0.0 && b < 1.0);
        }
    }
}
