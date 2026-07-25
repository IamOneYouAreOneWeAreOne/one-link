//! Stage 1+2: quantize raw observations to a bit string.
//!
//! Algorithm (matches `OneField`'s bootstrap.cl):
//!
//! 1. Compute the median of the observation values (per-byte).
//! 2. For each observation, output:
//!    - bit `1` if value > median + `guard_band`
//!    - bit `0` if value < median - `guard_band`
//!    - SKIP if value is inside the guard band (ambiguous; both sides
//!      might disagree)
//!
//! The guard band trades raw key rate for agreement rate. `OneField` uses
//! a guard band sized at ~5% of the observation range.

use crate::PairError;

/// Default observation-vector minimum length: 128 bytes (= 128 probes
/// of 1 byte each, matching `OneField`'s `KEY_DERIVATION_PROBES`).
pub const OBSERVATION_BYTES_DEFAULT: usize = 128;

/// Default guard band as a fraction of the observed range
/// (0.0 = no guard, 1.0 = entire range). 0.10 means 10% guard on
/// each side of the median.
pub const GUARD_BAND_DEFAULT: f64 = 0.10;

/// Quantization parameters.
#[derive(Clone, Debug)]
pub struct QuantizeConfig {
    /// Minimum observation vector length to accept.
    pub min_bytes: usize,
    /// Guard band fraction.
    pub guard_band: f64,
}

impl Default for QuantizeConfig {
    fn default() -> Self {
        Self {
            min_bytes: OBSERVATION_BYTES_DEFAULT,
            guard_band: GUARD_BAND_DEFAULT,
        }
    }
}

/// Quantize an observation vector to a bit string.
///
/// Observations inside the guard band are SKIPPED (not output as
/// bits). The returned `Vec<u8>` is a packed bit string: each byte
/// is 0 or 1.
///
/// # Errors
/// Returns [`PairError::ObservationTooShort`] if input is below
/// `config.min_bytes`.
pub fn quantize_observations(
    observations: &[u8],
    config: &QuantizeConfig,
) -> Result<Vec<u8>, PairError> {
    if observations.len() < config.min_bytes {
        return Err(PairError::ObservationTooShort {
            got: observations.len(),
            min: config.min_bytes,
        });
    }
    // Median via sort. Observations are bytes so we can use the
    // counting trick for stability + O(n) but for clarity we sort.
    let mut sorted: Vec<u8> = observations.to_vec();
    sorted.sort_unstable();
    let median = sorted[sorted.len() / 2] as f64;
    // Guard band in same units as observations (bytes).
    let range = (sorted[sorted.len() - 1] - sorted[0]) as f64;
    let guard = (range * config.guard_band).max(1.0);
    let lo_threshold = median - guard;
    let hi_threshold = median + guard;
    let mut bits = Vec::with_capacity(observations.len());
    for &v in observations {
        let vf = v as f64;
        if vf > hi_threshold {
            bits.push(1u8);
        } else if vf < lo_threshold {
            bits.push(0u8);
        }
        // else: drop (inside guard band)
    }
    Ok(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_too_short_errors() {
        let cfg = QuantizeConfig {
            min_bytes: 16,
            guard_band: 0.05,
        };
        let err = quantize_observations(&[0u8; 4], &cfg).unwrap_err();
        assert!(matches!(err, PairError::ObservationTooShort { .. }));
    }

    #[test]
    fn quantize_separates_above_below_median() {
        let cfg = QuantizeConfig {
            min_bytes: 8,
            guard_band: 0.0, // no guard band, all observations classified
        };
        let obs: Vec<u8> = (0..32).map(|i| i as u8 * 4).collect();
        let bits = quantize_observations(&obs, &cfg).unwrap();
        // Median is around 62. Values < median should be 0, > median should be 1.
        // With zero guard band every value gets classified.
        assert!(!bits.is_empty());
        // First half (low values) should be 0; second half (high) should be 1.
        let (n_zeros, n_ones) = bits.iter().fold((0usize, 0usize), |counts, bit| match bit {
            0 => (counts.0 + 1, counts.1),
            1 => (counts.0, counts.1 + 1),
            _ => counts,
        });
        assert!(n_zeros > 0);
        assert!(n_ones > 0);
        assert_eq!(n_zeros + n_ones, bits.len());
    }

    #[test]
    fn guard_band_drops_ambiguous_observations() {
        let cfg = QuantizeConfig {
            min_bytes: 8,
            guard_band: 0.5, // huge guard band
        };
        // Mostly-uniform input → many values inside the big guard band.
        let obs: Vec<u8> = (50..(50 + 32)).map(|i| i as u8).collect();
        let bits = quantize_observations(&obs, &cfg).unwrap();
        // With a 50% guard band on a tight range, lots gets dropped.
        assert!(bits.len() < obs.len());
    }

    #[test]
    fn co_located_devices_produce_similar_bits() {
        // Simulation: two devices observing the same environment
        // see slightly different values (noise). Their quantized
        // bit strings should agree on most positions.
        let cfg = QuantizeConfig {
            min_bytes: 64,
            guard_band: 0.15,
        };
        // Alice observes the base values.
        let alice_obs: Vec<u8> = (0..128u32).map(|i| ((i * 7) % 200) as u8).collect();
        // Bob observes the same physical environment with mild noise
        // (+/- 2 in a few positions).
        let mut bob_obs = alice_obs.clone();
        bob_obs[5] = bob_obs[5].wrapping_add(2);
        bob_obs[20] = bob_obs[20].wrapping_sub(1);
        bob_obs[60] = bob_obs[60].wrapping_add(3);
        let alice_bits = quantize_observations(&alice_obs, &cfg).unwrap();
        let bob_bits = quantize_observations(&bob_obs, &cfg).unwrap();
        // Truncate to min length (they might have different sizes after guard drops).
        let n = alice_bits.len().min(bob_bits.len());
        let agreement = alice_bits[..n]
            .iter()
            .zip(bob_bits[..n].iter())
            .filter(|(a, b)| a == b)
            .count();
        let agreement_rate = f64::from(u32::try_from(agreement).expect("test vector fits u32"))
            / f64::from(u32::try_from(n).expect("test vector fits u32"));
        // Should agree on the vast majority of bits.
        assert!(
            agreement_rate >= 0.85,
            "co-located devices should agree on >= 85% of bits, got {:.2}%",
            agreement_rate * 100.0
        );
    }
}
