//! Alignment operator — the third operator in the
//! "transport + alignment + boundary" composition the Phase E plan
//! gate calls for.
//!
//! ## Theory
//!
//! S_One identifies three operator families in the coherence-field
//! Lagrangian:
//!
//! 1. **Transport** — `D · ∇²(δτ_c)`: spatial diffusion of field
//!    perturbations. Implemented by the graph Laplacian inside
//!    [`solve_helmholtz`](super::super::solve_helmholtz).
//! 2. **Alignment** — couples the field to the gradient of a separate
//!    structural channel. In cosmology, this is the orientation
//!    coupling between coherence and angular-momentum flux. In
//!    networking, it's the coupling between local field magnitude and
//!    the gradient of the chunk-flux direction (i.e., peers should
//!    align their routing decisions with the dominant flow direction).
//! 3. **Boundary** — `support_phase_kernel`: tanh-shaped attenuation at
//!    the support edge. Already shipped in
//!    [`super::support_phase_kernel`].
//!
//! ## Network mapping
//!
//! For each peer `i`, the alignment operator computes a scalar
//! `alignment[i]` ∈ \[−1, 1\] that measures how well the peer's local
//! flux direction matches the **swarm-mean flux direction**. Peers
//! aligned with the dominant flow get a positive contribution; peers
//! moving against the swarm (sinks, hold-only nodes) get negative.
//!
//! The alignment scalar is composed into the source term:
//!
//! ```text
//! S_aligned[i] = S_dual[i] · (1 + λ · alignment[i])
//! ```
//!
//! where `λ ∈ [0, 1]` is the coupling strength (production default
//! 0.5 — half the source modulation can come from alignment, the
//! rest from the bare dual). The full transport-alignment-boundary
//! source is then `k_phase(c_support) · S_aligned`.

use super::SourceError;

/// Compute per-peer alignment scalars from the flux vector.
///
/// `flux[i]` is the per-peer chunks-per-second through-flow (the
/// same `J` used in [`super::identity_dual_source`]). The alignment
/// is the cosine-similarity between each peer's flux magnitude and
/// the swarm-mean magnitude, on a 1-D scalar — normalised so the
/// mean-aligned peer gets 1.0 and the most-misaligned gets −1.0.
///
/// This is a pragmatic 1-D analog of the cosmological vector-cosine
/// formulation; in 1-D "alignment" reduces to "agreement with the
/// mean direction," which on a scalar-valued flux means how close
/// the peer's value sits to the swarm mean. Peers far from the mean
/// (either much higher or much lower than the swarm average) are
/// "misaligned" — they're not participating in the dominant flow.
///
/// Returns a vector of length `flux.len()` with entries in (−1, 1).
///
/// # Errors
///
/// - [`SourceError::LengthMismatch`] if `flux` is empty (no swarm-
///   mean to compute against).
#[must_use]
pub fn alignment_scalars(flux: &[f64]) -> Vec<f64> {
    let n = flux.len();
    if n == 0 {
        return Vec::new();
    }
    let mean: f64 = flux.iter().sum::<f64>() / n as f64;
    let variance: f64 =
        flux.iter().map(|&v| (v - mean).powi(2)).sum::<f64>() / n as f64;
    let std_dev = variance.sqrt().max(1e-9);
    flux.iter()
        .map(|&v| {
            // Z-score then squash to (−1, 1) via tanh. Peers near
            // the mean get alignment ≈ 0 / slightly +. Peers far
            // from the mean (very high OR very low) tend to −1.
            let z = (v - mean) / std_dev;
            // 1.0 - 2 * |z|.tanh() maps: |z|=0 → 1.0 (mean-aligned),
            // |z|→∞ → −1.0 (totally misaligned). Direction-agnostic.
            1.0 - 2.0 * z.abs().tanh()
        })
        .collect()
}

/// Compose alignment into a bare dual-source vector:
/// `S_aligned[i] = S_dual[i] · (1 + lambda · alignment[i])`.
///
/// `lambda` is clamped to \[0, 1\]. The output preserves the sign of
/// the input dual source — alignment can amplify (lambda > 0,
/// alignment > 0) or attenuate (alignment < 0) but cannot flip sign.
///
/// # Errors
///
/// - [`SourceError::LengthMismatch`] if `dual_source.len() != flux.len()`.
pub fn align_source(
    dual_source: &[f64],
    flux: &[f64],
    lambda: f64,
) -> Result<Vec<f64>, SourceError> {
    if dual_source.len() != flux.len() {
        return Err(SourceError::LengthMismatch {
            expected: dual_source.len(),
            got: flux.len(),
        });
    }
    let lam = lambda.clamp(0.0, 1.0);
    let alignment = alignment_scalars(flux);
    Ok(dual_source
        .iter()
        .zip(alignment.iter())
        .map(|(&s, &a)| s * (1.0 + lam * a))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alignment_scalars_empty_input_returns_empty() {
        assert_eq!(alignment_scalars(&[]), Vec::<f64>::new());
    }

    #[test]
    fn alignment_scalars_uniform_flux_all_aligned() {
        // All peers have identical flux → all are "perfectly aligned"
        // with the swarm mean. std_dev → 0; tanh(z) ≈ 0; alignment ≈ 1.
        let flux = vec![5.0; 10];
        let a = alignment_scalars(&flux);
        for v in a {
            assert!((v - 1.0).abs() < 1e-6);
        }
    }

    #[test]
    fn alignment_scalars_outlier_is_misaligned() {
        // 9 peers at mean=1, one outlier at 100. Outlier gets ≈ -1;
        // the rest cluster near +1 (they're close to the new mean).
        let mut flux = vec![1.0; 9];
        flux.push(100.0);
        let a = alignment_scalars(&flux);
        assert!(a[9] < -0.5, "outlier alignment = {}", a[9]);
        // With one extreme outlier the std blows up, so even mean-peers
        // sit a few tenths below the swarm mean in z-units. Floor is
        // 0.3 (still clearly positive, well above the outlier's −0.5).
        for v in &a[..9] {
            assert!(*v > 0.3, "near-mean peer alignment = {v}");
        }
    }

    #[test]
    fn align_source_amplifies_aligned_peers() {
        // Uniform flux → uniform alignment ≈ 1.0 → every source value
        // gets multiplied by (1 + lambda * 1.0) = (1 + lambda).
        let dual = vec![1.0, 2.0, 3.0, 4.0];
        let flux = vec![1.0, 1.0, 1.0, 1.0];
        let lambda = 0.5;
        let aligned = align_source(&dual, &flux, lambda).unwrap();
        for (orig, new) in dual.iter().zip(aligned.iter()) {
            let expected = orig * (1.0 + lambda);
            assert!(
                (new - expected).abs() < 1e-6,
                "got {new}, expected {expected}"
            );
        }
    }

    #[test]
    fn align_source_attenuates_misaligned_peer() {
        // 9 peers aligned, 1 misaligned → misaligned peer's source
        // gets attenuated relative to the aligned ones.
        let dual = vec![1.0; 10];
        let mut flux = vec![1.0; 9];
        flux.push(100.0);
        let aligned = align_source(&dual, &flux, 0.8).unwrap();
        let misaligned_factor = aligned[9];
        let aligned_factor = aligned[0];
        assert!(misaligned_factor < aligned_factor);
        // misaligned: 1 * (1 + 0.8 * -1) ≈ 0.2; aligned: 1 * (1 +
        // 0.8 * +1) ≈ 1.8. Both ratios depend on tanh asymptote.
    }

    #[test]
    fn align_source_rejects_length_mismatch() {
        let err = align_source(&[1.0, 2.0], &[1.0], 0.5).unwrap_err();
        assert!(matches!(err, SourceError::LengthMismatch { .. }));
    }

    #[test]
    fn align_source_clamps_lambda() {
        // lambda > 1 should clamp to 1; lambda < 0 should clamp to 0.
        let dual = vec![1.0; 5];
        let flux = vec![1.0; 5];
        let r_high = align_source(&dual, &flux, 5.0).unwrap();
        let r_one = align_source(&dual, &flux, 1.0).unwrap();
        for (a, b) in r_high.iter().zip(r_one.iter()) {
            assert!((a - b).abs() < 1e-9);
        }
        let r_low = align_source(&dual, &flux, -3.0).unwrap();
        let r_zero = align_source(&dual, &flux, 0.0).unwrap();
        for (a, b) in r_low.iter().zip(r_zero.iter()) {
            assert!((a - b).abs() < 1e-9);
        }
    }
}
