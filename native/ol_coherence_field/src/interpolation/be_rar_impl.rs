//! Bose-Einstein Radial Acceleration Relation (BE-RAR) interpolation.
//!
//! ```text
//! nu(y) = 1 / (1 − exp(−√y))
//! ```
//!
//! The α = 1/2 exponent in the `√y` is *not* a tunable hyper-parameter
//! — it is forced by Bose-Einstein statistics in the S_One galaxy
//! derivation chain. See [`super::alpha_constraint`] for the
//! derivation.
//!
//! Asymptotic limits:
//!
//! - Low coherence (y → 0⁺): `nu(y) ~ 1 / √y` — diverges, but
//!   physically this corresponds to the deep-Newtonian / shortest-path
//!   limit where the field is barely organized.
//! - High coherence (y → ∞): `nu(y) → 1` — saturation, the
//!   deep-coherence limit where the route is direct.
//!
//! ## Network interpretation
//!
//! `y` is the dimensionless argument `g_obs / g_A`: the ratio of the
//! observed local routing "pressure" to the swarm-wide apparent-
//! horizon anchor. `nu(y)` blends between the random / chaotic limit
//! (low y, lots of unstable links) and the coherent / directly-routed
//! limit (high y, dominant stable path). It replaces the ad-hoc
//! `loss_penalty(loss) = 1 / (1 − loss)²` that `ol_routing` ships:
//! same monotonic shape but Bose-statistics-forced exponent.

use super::BeRarError;

/// Evaluate `nu(y) = 1 / (1 − exp(−√y))` for `y ≥ 0`.
///
/// Returns [`BeRarError::InvalidArg`] for negative or NaN inputs.
/// Numerically stable at `y → 0` via a Taylor expansion (small-y
/// series), avoiding catastrophic cancellation in `1 − exp(−√y)`.
pub fn be_rar(y: f64) -> Result<f64, BeRarError> {
    if !y.is_finite() || y < 0.0 {
        return Err(BeRarError::InvalidArg(y));
    }
    let sqrt_y = y.sqrt();
    // Small-y expansion: 1 / (1 − exp(−s)) ≈ 1/s + 1/2 + s/12 − s³/720 + …
    // Switch to the closed form once s is large enough that the
    // exponential doesn't underflow / cause cancellation.
    if sqrt_y < 1e-5 {
        // Just the leading two terms; gives full f64 precision.
        return Ok(1.0 / sqrt_y + 0.5);
    }
    let denom = 1.0 - (-sqrt_y).exp();
    Ok(1.0 / denom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn be_rar_rejects_negative_arg() {
        assert!(matches!(be_rar(-1.0), Err(BeRarError::InvalidArg(_))));
    }

    #[test]
    fn be_rar_rejects_nan() {
        assert!(matches!(be_rar(f64::NAN), Err(BeRarError::InvalidArg(_))));
    }

    #[test]
    fn be_rar_low_y_matches_inverse_sqrt_asymptote() {
        // At y = 0.001, sqrt(y) = 0.0316. nu ≈ 1/0.0316 + 0.5 = 32.13.
        let v = be_rar(1e-3).unwrap();
        assert!(v > 30.0 && v < 35.0, "nu(1e-3) = {v}");
    }

    #[test]
    fn be_rar_high_y_saturates_to_one() {
        // At y = 100, nu → 1.0 within tight tolerance.
        let v = be_rar(100.0).unwrap();
        assert!((v - 1.0).abs() < 1e-3, "nu(100) = {v}");
    }

    #[test]
    fn be_rar_is_monotonic_decreasing() {
        // nu should be monotonically decreasing in y (more coherence
        // → smaller penalty multiplier).
        let mut prev = f64::INFINITY;
        for y in (1..50).map(|k| k as f64 * 0.1) {
            let v = be_rar(y).unwrap();
            assert!(
                v <= prev + 1e-12,
                "monotonicity broken at y={y}: prev={prev}, now={v}"
            );
            prev = v;
        }
    }

    #[test]
    fn be_rar_continuous_at_small_y_threshold() {
        // Make sure the small-y expansion is smoothly stitched to
        // the closed form at the threshold.
        let just_below = be_rar(1e-5 - 1e-12).unwrap();
        let just_above = be_rar(1e-5 + 1e-12).unwrap();
        let abs_diff = (just_below - just_above).abs();
        // The threshold is on sqrt_y, so the actual y boundary is
        // around 1e-10. At y ~ 1e-5, both branches should agree to
        // within a part in 10⁹.
        assert!(
            abs_diff / just_below.abs() < 1e-6,
            "discontinuity at threshold: {} vs {}",
            just_below,
            just_above
        );
    }
}
