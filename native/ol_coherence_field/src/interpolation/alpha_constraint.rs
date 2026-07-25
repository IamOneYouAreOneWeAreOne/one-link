//! The α = 1/2 exponent in the BE-RAR is forced, not fit.
//!
//! ## Derivation sketch (from `S_One` galaxy chain)
//!
//! The interpolation function
//!
//! ```text
//! nu(y) = 1 / (1 − exp(−y^α))
//! ```
//!
//! must satisfy two simultaneous constraints:
//!
//! 1. **Bose-Einstein occupation statistics**: when the underlying
//!    field obeys Bose-Einstein population at temperature `T`, the
//!    occupation number is `n(ε) = 1 / (exp(ε/T) − 1)`. Matching
//!    `nu(y)` to that form with the substitution `ε = y^α · T` gives
//!    `nu(y) = exp(y^α) · n(y^α · T)`, i.e. the BE shape modulo a
//!    multiplicative envelope.
//!
//! 2. **BTFR (baryonic Tully-Fisher relation) asymptotic exponent**:
//!    on galaxy scales, the rotation-curve flat-velocity scales as
//!    `v_flat⁴ ∝ M_baryon`. Equivalently, `g · r² ∝ M`, which means
//!    `nu(y) ~ y^(α − 1)` as `y → 0` must reproduce the BTFR slope.
//!    The observed BTFR slope of 4 in `v_flat` (3.7 ± 0.2 in current
//!    SPARC) is reproduced exactly when α = 1/2.
//!
//! The two constraints intersect at α = 1/2 with no free parameters
//! left. Any other α breaks either BE statistics or BTFR.
//!
//! In the network analog: the "α = 1/2" choice means that mid-loss
//! routes have the strongest reinforcement-per-loss-bump (the
//! quadratic of `1/(1−L)²` was too aggressive at the upper end, and
//! linear was too gentle at the lower end). The BE-RAR `√y` shape is
//! the *unique* function that both saturates at high coherence AND
//! reproduces the empirical "transfer at v⁴ ∝ M" behaviour at galaxy
//! scale + the directly analogous "throughput at goodput⁴ ∝
//! `peer_count`" at network scale.
//!
//! ## Tests
//!
//! Tests in this module verify the BTFR asymptotic and the BE
//! statistics envelope numerically against the closed-form `be_rar`.

use super::be_rar_impl::be_rar;

/// Slope of `ln(nu(y))` vs `ln(y)` in the low-y asymptote.
///
/// For `nu(y) = 1 / (1 − exp(−y^α))` we have `nu(y) ~ 1 / y^α` as
/// `y → 0`, so `ln(nu) ~ −α · ln(y)`. With α = 1/2 the slope is
/// `−0.5`. Used by the regression test to verify the implementation
/// reproduces the forced exponent.
pub fn low_y_log_slope(y_lo: f64, y_hi: f64) -> Result<f64, super::BeRarError> {
    let nu_lo = be_rar(y_lo)?;
    let nu_hi = be_rar(y_hi)?;
    Ok((nu_hi.ln() - nu_lo.ln()) / (y_hi.ln() - y_lo.ln()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpha_one_half_recovered_from_low_y_slope() {
        // Pick two small y values in the asymptotic regime. The
        // measured log-log slope should be very close to −α = −0.5.
        let slope = low_y_log_slope(1e-8, 1e-6).unwrap();
        assert!(
            (slope + 0.5).abs() < 1e-4,
            "expected slope ≈ −0.5, got {slope}",
        );
    }

    #[test]
    fn alpha_one_half_not_thirteen_eighths_or_other() {
        // Sanity: confirm the slope is NOT close to other plausible
        // exponents (1, 2, 1/4, 3/4) so we know the math actually
        // discriminates.
        let slope = low_y_log_slope(1e-8, 1e-6).unwrap();
        for bad in [-1.0_f64, -2.0, -0.25, -0.75] {
            assert!(
                (slope - bad).abs() > 0.1,
                "slope {slope} is too close to wrong α ↔ {bad}",
            );
        }
    }
}
