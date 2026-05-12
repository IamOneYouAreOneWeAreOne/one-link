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

use super::{support_phase_kernel, SourceError, SupportPhaseConfig};

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

/// Composed production source: identity-sector dual sourcing **with
/// the support-phase boundary kernel applied**. Closes the
/// "transport + alignment + boundary" Phase E gate.
///
/// `c_support[i]` is the cumulative-support fraction at peer `i`
/// (defined in [`crate::source::support_phase_kernel`]). The boundary
/// kernel `k_phase = tanh((c0 − C_support) / w_phase)` is multiplied
/// pointwise with the dual source:
///
/// ```text
/// S[i] = k_phase[i] · (α · ρ[i] + β · |J[i]|)
/// ```
///
/// Core peers (low `C_support`) get a positive multiplier (boost);
/// edge peers (high `C_support`) get a negative multiplier (attenuate
/// or invert).
///
/// This is the **production composition** the daemon should use for
/// field-solve source terms, NOT the bare `identity_dual_source`.
/// The bare form is kept for the linear-source-no-go regression test
/// and for callers that pre-apply their own boundary weighting.
pub fn identity_dual_source_with_phase(
    density: &[f64],
    flux: &[f64],
    c_support: &[f64],
    alpha: f64,
    beta: f64,
    phase: SupportPhaseConfig,
) -> Result<Vec<f64>, SourceError> {
    if density.len() != c_support.len() {
        return Err(SourceError::LengthMismatch {
            expected: density.len(),
            got: c_support.len(),
        });
    }
    let dual = identity_dual_source(density, flux, alpha, beta)?;
    let k = support_phase_kernel(c_support, phase);
    debug_assert_eq!(dual.len(), k.len());
    let out: Vec<f64> = dual.iter().zip(k.iter()).map(|(&s, &kp)| s * kp).collect();
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

    #[test]
    fn dual_with_phase_modulates_core_vs_edge() {
        // Two peers with identical density+flux but different
        // support-phase positions. The kernel tanh((c0 − C_support)/w)
        // saturates to ≈+1 deep in the core and ≈−1 past the edge:
        //
        //   core peer (c_support=0.20):  k ≈ +1   → source preserved
        //   edge peer (c_support=0.95):  k ≈ −0.85 → source sign-flips
        //
        // So the "core peer is closer to bare than edge peer is" is
        // the production-meaningful check; the edge peer must
        // actually flip negative.
        let rho = vec![1.0, 1.0];
        let j = vec![0.5, 0.5];
        let c_support = vec![0.20, 0.95];
        let bare = identity_dual_source(&rho, &j, 0.5, 0.5).unwrap();
        let with_phase = identity_dual_source_with_phase(
            &rho,
            &j,
            &c_support,
            0.5,
            0.5,
            SupportPhaseConfig::default(),
        )
        .unwrap();
        // Core peer stays close to bare (kernel saturates near +1).
        assert!(
            (with_phase[0] - bare[0]).abs() < 0.01 * bare[0].abs() + 1e-6,
            "core peer should preserve sign + magnitude; got {:.6} vs bare {:.6}",
            with_phase[0],
            bare[0]
        );
        // Edge peer must sign-flip (kernel goes negative past c0).
        assert!(
            with_phase[1] < 0.0,
            "edge peer source must sign-flip past support boundary; got {:.6}",
            with_phase[1]
        );
        // Edge peer's |source| is smaller than core's |source| by the
        // |k_phase| ratio — verifies the modulation actually depends
        // on c_support and isn't accidentally a constant scale.
        assert!(with_phase[1].abs() < with_phase[0].abs());
    }

    #[test]
    fn dual_with_phase_rejects_c_support_length_mismatch() {
        let err = identity_dual_source_with_phase(
            &[1.0, 1.0],
            &[1.0, 1.0],
            &[0.5], // wrong length
            0.5,
            0.5,
            SupportPhaseConfig::default(),
        )
        .unwrap_err();
        assert!(matches!(err, SourceError::LengthMismatch { .. }));
    }
}
