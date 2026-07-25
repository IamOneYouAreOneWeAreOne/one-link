//! `τ_c` × Double-Ratchet rotation coupling.
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
//!   approaching `μ_max` (rotation happens `μ_max`× faster).
//!
//! - `μ(field) = 1 + (μ_max − 1) · (1 − normalised_field)^p`
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
/// `field` is the recovered `δτ_c` at every peer. `mu_max` is the
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
    let f_min = field.iter().copied().fold(f64::INFINITY, f64::min);
    let f_max = field.iter().copied().fold(f64::NEG_INFINITY, f64::max);
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
            let bytes = floor_u64_div_f64(baseline_bytes, multiplier);
            RotationCadence {
                peer: i,
                multiplier,
                bytes_between_rotations: bytes.max(1),
            }
        })
        .collect()
}

/// Divide an integer byte budget by a finite binary64 multiplier without
/// routing the integer through a lossy `u64 -> f64 -> u64` round trip.
///
/// Every production multiplier is at least one. Non-finite or otherwise
/// invalid values produce zero, matching Rust's saturating float-to-unsigned
/// conversion at the old call site; the caller then enforces its one-byte
/// minimum.
fn floor_u64_div_f64(dividend: u64, divisor: f64) -> u64 {
    const FRACTION_BITS: i32 = 52;
    const EXPONENT_BIAS: i32 = 1023;
    const FRACTION_MASK: u64 = (1_u64 << 52) - 1;

    if !divisor.is_finite() || divisor < 1.0 {
        return 0;
    }

    let bits = divisor.to_bits();
    let biased_exponent =
        i32::try_from((bits >> 52) & 0x7ff).expect("an 11-bit binary64 exponent always fits i32");
    let exponent = biased_exponent - EXPONENT_BIAS;
    debug_assert!(
        exponent >= 0,
        "a finite divisor >= 1 has a non-negative exponent"
    );
    let significand = (1_u64 << 52) | (bits & FRACTION_MASK);

    let quotient = if exponent <= FRACTION_BITS {
        let shift = u32::try_from(FRACTION_BITS - exponent)
            .expect("non-negative binary64 scaling shift fits u32");
        (u128::from(dividend) << shift) / u128::from(significand)
    } else if exponent >= 64 {
        0
    } else {
        let shift = u32::try_from(exponent - FRACTION_BITS)
            .expect("non-negative binary64 scaling shift fits u32");
        u128::from(dividend) / (u128::from(significand) << shift)
    };

    u64::try_from(quotient).expect("division by a value >= 1 cannot exceed the dividend")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_integer_division_handles_full_u64_domain() {
        assert_eq!(floor_u64_div_f64(1_000_000, 1.0), 1_000_000);
        assert_eq!(floor_u64_div_f64(1_000_000, 4.0), 250_000);
        assert_eq!(floor_u64_div_f64(1_000_000, 1.5), 666_666);
        assert_eq!(floor_u64_div_f64(u64::MAX, 1.0), u64::MAX);
        assert_eq!(floor_u64_div_f64(u64::MAX, 2.0), u64::MAX / 2);
        assert_eq!(floor_u64_div_f64(u64::MAX, f64::INFINITY), 0);
        assert_eq!(floor_u64_div_f64(u64::MAX, f64::NAN), 0);
    }

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
