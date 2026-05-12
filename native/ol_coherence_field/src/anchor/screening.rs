//! Screening length `ell_screen = √(D / Γ)`.
//!
//! On galaxy scales, `D` and `Γ` are the reaction-diffusion
//! coefficients in the τ_c PDE; the screening length comes out to
//! `c / (√3 · H_0)` ≈ 4.4 Gpc — much larger than any galaxy radius,
//! so the field response is in the Poisson limit there.
//!
//! On the network, the same formula gives a screening length in graph-
//! hop units: how many hops a coherence perturbation can propagate
//! before damping wins. Calibration constants (D = info-mixing rate,
//! Γ = peer-churn rate) come from observed swarm metrics; see
//! [`super::super::calibration::one_link`].

/// Which regime the swarm sits in relative to the screening length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreeningRegime {
    /// `ell_screen ≫ graph_radius` — coherence response is long-range,
    /// reduces to graph-Poisson. Galaxy-side analog.
    Poisson,
    /// `ell_screen ~ graph_radius` — full Helmholtz regime, mixed
    /// response. Most production swarms live here.
    Helmholtz,
    /// `ell_screen ≪ graph_radius` — Yukawa-like exponential cutoff,
    /// response only reaches a small neighborhood.
    Yukawa,
}

/// Compute `ell_screen = √(D / Γ)`. Returns `None` for non-physical
/// inputs (`D ≤ 0` or `Γ ≤ 0`, since both must be strictly positive
/// for a finite screening length).
#[must_use]
pub fn screening_length(d: f64, gamma: f64) -> Option<f64> {
    if !(d > 0.0 && gamma > 0.0 && d.is_finite() && gamma.is_finite()) {
        return None;
    }
    Some((d / gamma).sqrt())
}

/// Classify the regime: compare the screening length against the
/// swarm's effective radius (typically `graph_diameter / 2` or the
/// mean shortest-path length).
///
/// Boundary rules:
///
/// - `ell_screen > 10 · graph_radius` → Poisson regime.
/// - `ell_screen < 0.1 · graph_radius` → Yukawa regime.
/// - Otherwise → Helmholtz regime.
///
/// The 10× cushion on each side keeps swarms that hover near a
/// boundary from oscillating between regimes; pick a regime and keep
/// it until the ratio changes by an order of magnitude.
#[must_use]
pub fn classify_regime(ell_screen: f64, graph_radius: f64) -> ScreeningRegime {
    if !ell_screen.is_finite() || !graph_radius.is_finite() || graph_radius <= 0.0 {
        return ScreeningRegime::Helmholtz; // safe default
    }
    let ratio = ell_screen / graph_radius;
    if ratio > 10.0 {
        ScreeningRegime::Poisson
    } else if ratio < 0.1 {
        ScreeningRegime::Yukawa
    } else {
        ScreeningRegime::Helmholtz
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screening_length_basic() {
        // D = 4, Γ = 1 → ell = 2.
        assert!((screening_length(4.0, 1.0).unwrap() - 2.0).abs() < 1e-12);
        // D = 1, Γ = 1 → ell = 1.
        assert!((screening_length(1.0, 1.0).unwrap() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn screening_length_rejects_non_physical() {
        assert_eq!(screening_length(-1.0, 1.0), None);
        assert_eq!(screening_length(1.0, -1.0), None);
        assert_eq!(screening_length(0.0, 1.0), None);
        assert_eq!(screening_length(1.0, 0.0), None);
        assert_eq!(screening_length(f64::NAN, 1.0), None);
    }

    #[test]
    fn regime_classification() {
        // Big screening length, small graph → Poisson.
        assert_eq!(classify_regime(1_000.0, 10.0), ScreeningRegime::Poisson);
        // Comparable → Helmholtz.
        assert_eq!(classify_regime(20.0, 10.0), ScreeningRegime::Helmholtz);
        // Tiny screening, big graph → Yukawa.
        assert_eq!(classify_regime(1.0, 100.0), ScreeningRegime::Yukawa);
    }

    #[test]
    fn regime_galaxy_analog_is_poisson() {
        // Cosmological numbers: ell_screen ≈ 4.4 Gpc, galaxy radius
        // ≈ 30 kpc. Ratio is enormous → Poisson regime, matching the
        // S_One galaxy derivation.
        let ell_gpc = 4_400.0; // Mpc
        let r_galaxy = 0.030; // Mpc (30 kpc)
        assert_eq!(classify_regime(ell_gpc, r_galaxy), ScreeningRegime::Poisson);
    }
}
