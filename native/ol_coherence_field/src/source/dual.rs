//! Identity-sector dual sourcing: `S = α · ρ + β · |J|`.
//!
//! ## Why dual sourcing
//!
//! The S_One linear-source no-go theorem says a pure density-linear
//! `S = α · ρ` collapses the coherence flux to `g_coh ∝ g_bar`.
//! Escape requires the source to be nonlinear in observables OR to
//! carry an additional structural channel beyond density.
//!
//! The ONE Docs galaxy-synthesis identifies that additional channel:
//! the **identity sector** in the underlying field theory contains
//! both density-like and flux-like sourcing. At galaxy scale this
//! shows up as density + angular-momentum-flux dual sourcing; at
//! network scale, the analog is **chunks-held + chunks-moving**
//! (density + flux of data through each peer).
//!
//! ## Network mapping
//!
//! - `density[i]` = number of chunks currently held by peer `i`,
//!   normalised by the swarm's mean.
//! - `flux[i]` = recent chunks-per-second transfer rate at peer `i`,
//!   normalised by the swarm's mean.
//! - `alpha` = density weight (typical: 0.3–0.7).
//! - `beta` = flux weight (typical: 0.3–0.7).
//!
//! Both weights must be ≥ 0; both can be tuned per swarm by the
//! cross-domain calibration layer.

use super::SourceError;

/// Build the dual source vector `S[i] = α · ρ[i] + β · |J[i]|`.
///
/// `flux` is taken in absolute value because the direction of flow
/// doesn't change a peer's contribution to the coherence field — only
/// the magnitude of through-flow does.
pub fn identity_dual_source(
    density: &[f64],
    flux: &[f64],
    alpha: f64,
    beta: f64,
) -> Result<Vec<f64>, SourceError> {
    if density.len() != flux.len() {
        return Err(SourceError::LengthMismatch {
            expected: density.len(),
            got: flux.len(),
        });
    }
    if !alpha.is_finite() || alpha < 0.0 {
        return Err(SourceError::InvalidWeight(alpha));
    }
    if !beta.is_finite() || beta < 0.0 {
        return Err(SourceError::InvalidWeight(beta));
    }
    let out: Vec<f64> = density
        .iter()
        .zip(flux.iter())
        .map(|(&d, &j)| alpha * d + beta * j.abs())
        .collect();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_combines_density_and_flux() {
        let rho = vec![1.0, 0.0, 2.0];
        let j = vec![0.5, 1.0, -0.5];
        let s = identity_dual_source(&rho, &j, 0.5, 0.5).unwrap();
        // S[0] = 0.5*1 + 0.5*0.5 = 0.75
        // S[1] = 0.5*0 + 0.5*1.0 = 0.5
        // S[2] = 0.5*2 + 0.5*0.5 = 1.25  (|−0.5| = 0.5)
        assert!((s[0] - 0.75).abs() < 1e-12);
        assert!((s[1] - 0.5).abs() < 1e-12);
        assert!((s[2] - 1.25).abs() < 1e-12);
    }

    #[test]
    fn dual_rejects_length_mismatch() {
        assert!(matches!(
            identity_dual_source(&[1.0, 2.0], &[1.0], 0.5, 0.5),
            Err(SourceError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn dual_rejects_non_physical_weights() {
        assert!(matches!(
            identity_dual_source(&[1.0], &[1.0], -0.1, 0.5),
            Err(SourceError::InvalidWeight(_))
        ));
        assert!(matches!(
            identity_dual_source(&[1.0], &[1.0], 0.5, f64::INFINITY),
            Err(SourceError::InvalidWeight(_))
        ));
    }

    #[test]
    fn dual_is_strictly_richer_than_linear() {
        // If two peers have the same density but different flux, the
        // dual source distinguishes them. The linear source can't.
        let rho = vec![1.0, 1.0];
        let j = vec![0.0, 5.0];
        let dual = identity_dual_source(&rho, &j, 1.0, 1.0).unwrap();
        // The flux-rich peer has strictly higher source value.
        assert!(dual[1] > dual[0]);
    }
}
