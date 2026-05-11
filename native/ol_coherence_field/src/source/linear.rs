//! Linear source `S ∝ ρ` — the reference baseline.
//!
//! ## Why this module exists
//!
//! The S_One galaxy chain proves a sharp **no-go theorem**: if the
//! source functional is linear in baryon density `ρ_b`, then the
//! coherence flux `g_coh` collapses to `g_coh ∝ g_bar`. Translation:
//! a purely density-linear source contributes *nothing new* beyond
//! what Newtonian gravity already provides.
//!
//! Network corollary: weighting peers linearly by 1/RTT (which is
//! what `ol_routing` ships today) is exactly the `S_b ∝ ρ_b` case at
//! network scale. Pure shortest-path-with-weights leaves all the real
//! gains on the table; you need a nonlinear source to escape.
//!
//! This module exists to (a) document the baseline, (b) provide the
//! regression-test reference that
//! `tests/linear_source_no_go.rs` checks against. **Don't use it in
//! production routing.**

use super::SourceError;

/// Linear source `S[i] = weight · density[i]`. Caller supplies the
/// scaling constant.
pub fn linear_source(density: &[f64], weight: f64) -> Result<Vec<f64>, SourceError> {
    if !weight.is_finite() || weight < 0.0 {
        return Err(SourceError::InvalidWeight(weight));
    }
    Ok(density.iter().map(|&d| weight * d).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_scales_uniformly() {
        let rho = vec![1.0, 2.0, 3.0, 4.0];
        let s = linear_source(&rho, 2.0).unwrap();
        assert_eq!(s, vec![2.0, 4.0, 6.0, 8.0]);
    }

    #[test]
    fn linear_rejects_negative_weight() {
        let rho = vec![1.0, 2.0];
        assert!(matches!(
            linear_source(&rho, -1.0),
            Err(SourceError::InvalidWeight(_))
        ));
    }
}
