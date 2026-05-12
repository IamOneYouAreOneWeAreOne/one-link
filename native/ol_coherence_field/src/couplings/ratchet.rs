//! τ_c × Double-Ratchet rotation coupling.
//!
//! Standard Double-Ratchet rotates keys per message, with a fixed
//! cadence chosen at protocol-design time. The coherence-field
//! coupling makes the cadence a *function of network physics*:
//! peers in low-coherence wells (lossy / churning / central /
//! adversarially-positioned) rotate ratchet keys MORE frequently
//! per byte than peers in high-coherence neighbourhoods. The
//! compromise window for any leaked key scales with the physical
//! fragility of the route at that moment.
//!
//! This is crypto strength as a *function* of network coherence —
//! not a fixed knob.
//!
//! ## Mapping
//!
//! - Baseline rotation rate: 1 per N bytes (chosen by `ol_ratchet`).
//! - Coupling multiplier `μ(δτ_c) ∈ [1, μ_max]`: peers with high field
//!   get μ = 1 (no extra rotation), peers with low field get μ
//!   approaching μ_max (rotation happens μ_max× faster).
//!
//! - μ(field) = 1 + (μ_max − 1) · (1 − normalised_field)^p
//!
//! where `p` controls how sharply the multiplier ramps up as
//! coherence degrades. p = 2 (quadratic) is the production default
//! — moderate amplification, doesn't blow up at slight coherence
//! drops.

/// Recommended rotation cadence for a single peer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RotationCadence {
    /// Peer index this cadence applies to.
    pub peer: usize,
    /// Multiplier on the baseline rotation rate (≥ 1). 1.0 = unchanged.
    pub multiplier: f64,
    /// Recommended bytes-between-rotations: `baseline_bytes /
    /// multiplier`. Daemon should rotate after this many bytes sent
    /// to / received from this peer.
    pub bytes_between_rotations: u64,
}

/// Compute per-peer ratchet rotation multipliers from the field.
///
/// `field` is the recovered δτ_c at every peer. `mu_max` is the
/// rotation-rate cap (typical: 4–10×; values above 10× exhaust
/// ratchet-state budget). `power` is the contrast exponent (p in the
/// `(1 − norm)^p` term).
///
/// Returns one cadence per peer in input order.
#[must_use]
pub fn rotation_cadence_multiplier(
    field: &[f64],
    baseline_bytes: u64,
    mu_max: f64,
    power: f64,
) -> Vec<RotationCadence> {
    if field.is_empty() {
        return Vec::new();
    }
    let f_min = field.iter().cloned().fold(f64::INFINITY, f64::min);
    let f_max = field.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let span = (f_max - f_min).max(1e-9);
    let mu_max = mu_max.max(1.0);
    let power = power.max(0.0);

    field
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            // Normalised coherence in [0, 1]. 1 = best in swarm.
            let n = ((v - f_min) / span).clamp(0.0, 1.0);
            // Deficit raised to power; multiplier grows with deficit.
            let deficit = (1.0 - n).powf(power);
            let multiplier = 1.0 + (mu_max - 1.0) * deficit;
            let bytes = ((baseline_bytes as f64) / multiplier) as u64;
            RotationCadence {
                peer: i,
                multiplier,
                bytes_between_rotations: bytes.max(1),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highest_field_peer_gets_baseline_cadence() {
        let field = vec![0.1, 0.5, 1.0];
        let c = rotation_cadence_multiplier(&field, 1_000_000, 4.0, 2.0);
        // Best peer (index 2, highest field) → multiplier ≈ 1.
        assert!((c[2].multiplier - 1.0).abs() < 1e-9);
        assert_eq!(c[2].bytes_between_rotations, 1_000_000);
    }

    #[test]
    fn lowest_field_peer_gets_max_rotation() {
        let field = vec![0.1, 0.5, 1.0];
        let c = rotation_cadence_multiplier(&field, 1_000_000, 4.0, 2.0);
        // Worst peer (index 0, lowest field) → multiplier = mu_max.
        assert!((c[0].multiplier - 4.0).abs() < 1e-9);
        // Bytes-between = baseline / 4 = 250_000.
        assert_eq!(c[0].bytes_between_rotations, 250_000);
    }

    #[test]
    fn quadratic_power_gives_strong_contrast() {
        // Mid-coherence peer (norm = 0.5) at p = 2 should have
        // multiplier = 1 + 3 * (1 - 0.5)^2 = 1 + 3 * 0.25 = 1.75.
        let field = vec![0.0, 0.5, 1.0];
        let c = rotation_cadence_multiplier(&field, 100, 4.0, 2.0);
        assert!(
            (c[1].multiplier - 1.75).abs() < 1e-9,
            "got {}",
            c[1].multiplier
        );
    }

    #[test]
    fn linear_power_gives_proportional_contrast() {
        let field = vec![0.0, 0.5, 1.0];
        let c = rotation_cadence_multiplier(&field, 100, 4.0, 1.0);
        // mid-peer at p = 1: 1 + 3 * 0.5 = 2.5
        assert!((c[1].multiplier - 2.5).abs() < 1e-9);
    }

    #[test]
    fn mu_max_clamped_to_at_least_one() {
        let field = vec![0.0, 1.0];
        let c = rotation_cadence_multiplier(&field, 100, 0.5, 2.0);
        // mu_max < 1 is non-physical (would reduce rotation rate).
        // Should be clamped to 1.
        for cad in &c {
            assert!(cad.multiplier >= 1.0);
        }
    }

    #[test]
    fn bytes_between_never_zero() {
        // Extreme low field + huge mu_max could push bytes
        // negative or zero — should saturate at 1.
        let field = vec![0.0; 5];
        let c = rotation_cadence_multiplier(&field, 1, 1000.0, 2.0);
        for cad in &c {
            assert!(cad.bytes_between_rotations >= 1);
        }
    }
}
