//! Robust Soliton Distribution (Luby 2002) for LT codes.
//!
//! Computes Ω(d) — the probability of selecting degree d when encoding
//! a single LT symbol — as a function of:
//!
//! - **K**: source-symbol count
//! - **c**: free knob, typically 0.03-0.2; smaller = lower overhead at
//!   the cost of failure rate. We use **c = 0.03**.
//! - **δ**: target decoding failure probability. We use **δ = 0.05**.
//!
//! Both `c` and `δ` are fixed for Phase B v1 per ADR-0015 to keep the
//! wire format simple — the receiver re-derives the same CDF from K.
//!
//! ## Reference
//!
//! Luby, "LT Codes," FOCS 2002. The classic K-dependent distribution.

use crate::rng::SplitMix64;

/// Phase B v1 LT codes free knob (Luby's `c`).
pub const C: f64 = 0.03;

/// Phase B v1 LT codes target failure probability (Luby's `δ`).
pub const DELTA: f64 = 0.05;

/// Compute the Robust Soliton CDF for K source symbols. Returns a
/// `Vec<f64>` of length K, where `cdf[d-1]` is the cumulative probability
/// up to and including degree `d`.
#[must_use]
pub fn robust_soliton_cdf(k: u32) -> Vec<f64> {
    let k_f = f64::from(k);
    // R = c * ln(K/δ) * sqrt(K)
    let r = C * (k_f / DELTA).ln() * k_f.sqrt();
    let r_int = r.round().max(1.0) as u32;
    let r_int = r_int.min(k); // cap

    // Compute (ρ + τ) per degree, then normalize.
    let mut weights = vec![0.0f64; k as usize];
    for d in 1..=k {
        let i = (d - 1) as usize;
        // ρ(d)
        let rho = if d == 1 {
            1.0 / k_f
        } else {
            1.0 / (f64::from(d) * f64::from(d - 1))
        };
        // τ(d)
        let tau = if d < r_int {
            r / (f64::from(d) * k_f)
        } else if d == r_int {
            r * (r / DELTA).ln() / k_f
        } else {
            0.0
        };
        weights[i] = rho + tau;
    }
    // Normalize.
    let z: f64 = weights.iter().sum();
    for w in &mut weights {
        *w /= z;
    }
    // Convert to CDF.
    let mut cdf = vec![0.0f64; k as usize];
    let mut acc = 0.0f64;
    for (i, w) in weights.iter().enumerate() {
        acc += *w;
        cdf[i] = acc;
    }
    // Clamp the last entry to 1.0 to absorb float rounding.
    if let Some(last) = cdf.last_mut() {
        *last = 1.0;
    }
    cdf
}

/// Sample a degree from the Robust Soliton CDF using `rng`.
#[must_use]
pub fn sample_degree(cdf: &[f64], rng: &mut SplitMix64) -> u32 {
    let u = rng.next_f64_01();
    // Linear scan — K is small (≤ 256) so binary search is overkill.
    for (i, &c) in cdf.iter().enumerate() {
        if u <= c {
            return (i + 1) as u32;
        }
    }
    // Float overflow safety: return max degree.
    cdf.len() as u32
}

/// Sample `d` distinct source-symbol indices in `[0, k)` using `rng`.
///
/// For `d` close to `k`, uses reservoir-style sampling without replacement
/// to avoid quadratic retry. For `d` small, uses Floyd's algorithm with
/// a small `HashSet`.
#[must_use]
pub fn sample_neighbors(k: u32, d: u32, rng: &mut SplitMix64) -> Vec<u32> {
    let d = d.min(k);
    let mut chosen = std::collections::BTreeSet::new();
    // Floyd's algorithm: O(d) draws even when d ≈ k.
    for j in (k - d)..k {
        let r = rng.next_u32_below(j + 1);
        if chosen.contains(&r) {
            chosen.insert(j);
        } else {
            chosen.insert(r);
        }
    }
    chosen.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdf_is_monotone_nondecreasing() {
        for k in [8u32, 16, 64, 256] {
            let cdf = robust_soliton_cdf(k);
            assert_eq!(cdf.len(), k as usize);
            for w in cdf.windows(2) {
                assert!(w[0] <= w[1] + 1e-9);
            }
            assert!((cdf.last().unwrap() - 1.0).abs() < 1e-9);
        }
    }

    #[test]
    fn cdf_emphasizes_low_degrees() {
        // For K=64, expect ~half the mass to land at d ≤ ~8 (sqrt(K) area).
        let cdf = robust_soliton_cdf(64);
        let cdf_at_8 = cdf[7];
        assert!(
            cdf_at_8 > 0.5,
            "expected >50% mass at d ≤ 8, got {cdf_at_8}"
        );
    }

    #[test]
    fn sample_degree_within_range() {
        let cdf = robust_soliton_cdf(64);
        let mut rng = SplitMix64::new(0xCAFE);
        for _ in 0..10_000 {
            let d = sample_degree(&cdf, &mut rng);
            assert!((1..=64).contains(&d));
        }
    }

    #[test]
    fn neighbors_distinct_within_range() {
        let mut rng = SplitMix64::new(0xDEAD);
        for d in [1u32, 4, 10, 32, 64] {
            let n = sample_neighbors(64, d, &mut rng);
            assert_eq!(n.len(), d as usize);
            for &i in &n {
                assert!(i < 64);
            }
            // Distinctness (set semantics).
            let s: std::collections::HashSet<_> = n.iter().copied().collect();
            assert_eq!(s.len(), d as usize);
        }
    }

    #[test]
    fn determinism_for_same_seed() {
        let cdf = robust_soliton_cdf(64);
        let mut r1 = SplitMix64::new(123);
        let mut r2 = SplitMix64::new(123);
        let seq1: Vec<u32> = (0..100).map(|_| sample_degree(&cdf, &mut r1)).collect();
        let seq2: Vec<u32> = (0..100).map(|_| sample_degree(&cdf, &mut r2)).collect();
        assert_eq!(seq1, seq2);
    }
}
