//! Bloom filter sizing math per [ADR-0011](../../../docs/decisions/0011-bloom-transfer-init.md).
//!
//! For `n` elements and target false-positive rate `p`:
//!
//! ```text
//! m_bits = -(n × ln(p)) / (ln(2)²)
//! k       = (m_bits / n) × ln(2)
//! ```
//!
//! Phase B target: `p = 0.01` (1% FP rate, 7 hash functions, ~9.6 bits/key).

/// Compute the optimal `m_bits` (filter size) for `n` elements at
/// target FP rate `p`.
///
/// Returns at least 8 bits (one byte) even for `n == 0`, so callers get
/// a valid empty filter rather than a zero-sized one.
#[must_use]
pub fn optimal_m_bits(n: usize, p: f64) -> u32 {
    if n == 0 {
        return 8;
    }
    let p = p.clamp(1e-10, 0.999);
    let raw = -(usize_as_f64(n) * p.ln()) / (std::f64::consts::LN_2 * std::f64::consts::LN_2);
    // Round up; minimum 8 bits.
    ceil_f64_to_u32_saturating(raw.max(8.0))
}

/// Compute the optimal number of hash functions `k` for `m_bits` over
/// `n` elements.
///
/// Caps k at 32 to bound the worst-case insert/query cost.
#[must_use]
pub fn optimal_k(n: usize, m_bits: u32) -> u32 {
    if n == 0 {
        return 1;
    }
    let raw = (f64::from(m_bits) / usize_as_f64(n)) * std::f64::consts::LN_2;
    ceil_f64_to_u32_saturating(raw.round().clamp(1.0, 32.0))
}

/// Convert a pointer-sized count to `f64` without an unchecked precision-
/// losing cast. Splitting at 32 bits makes the intentional IEEE-754 rounding
/// explicit while preserving the full magnitude on 64-bit targets.
fn usize_as_f64(value: usize) -> f64 {
    let value = u64::try_from(value).unwrap_or(u64::MAX);
    let high = u32::try_from(value >> 32).expect("shifted high half fits in u32");
    let low = u32::try_from(value & u64::from(u32::MAX)).expect("masked low half fits in u32");
    f64::from(high).mul_add(4_294_967_296.0, f64::from(low))
}

/// Return `ceil(value)` as a saturating `u32` without relying on Rust's
/// implicit float-to-integer saturation rules.
fn ceil_f64_to_u32_saturating(value: f64) -> u32 {
    if !value.is_finite() || value >= f64::from(u32::MAX) {
        return u32::MAX;
    }
    if value <= 0.0 {
        return 0;
    }

    let target = value.ceil();
    let mut low = 0_u32;
    let mut high = u32::MAX;
    while low < high {
        let midpoint = low + (high - low) / 2;
        if f64::from(midpoint) < target {
            low = midpoint.saturating_add(1);
        } else {
            high = midpoint;
        }
    }
    low
}

/// Target false-positive rate Phase B v1 chooses by default.
pub const DEFAULT_TARGET_FP_RATE: f64 = 0.01;

/// Convenience: returns [`DEFAULT_TARGET_FP_RATE`] for callers that
/// want the configured value rather than hardcoding the number.
#[inline]
#[must_use]
pub fn target_fp_rate() -> f64 {
    DEFAULT_TARGET_FP_RATE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_n_yields_minimum_size() {
        // n=0 should still produce a valid (1-byte) filter.
        assert_eq!(optimal_m_bits(0, 0.01), 8);
        assert_eq!(optimal_k(0, 8), 1);
    }

    #[test]
    fn standard_sizing_matches_adr() {
        // Per ADR-0011 examples (rounded to ceil + 8-bit minimum).
        // n=1024 at p=0.01 → m ≈ 9816 bits.
        let m = optimal_m_bits(1024, 0.01);
        assert!((9816..=9825).contains(&m), "got {m}");
        // k ≈ 7.
        let k = optimal_k(1024, m);
        assert_eq!(k, 7, "expected ~7 hash funcs, got {k}");
    }

    #[test]
    fn larger_n_scales_linearly() {
        let baseline_bits = optimal_m_bits(1024, 0.01);
        let medium_bits = optimal_m_bits(16 * 1024, 0.01);
        let large_bits = optimal_m_bits(256 * 1024, 0.01);
        // m grows linearly with n.
        let ratio_a = f64::from(medium_bits) / f64::from(baseline_bits);
        let ratio_b = f64::from(large_bits) / f64::from(medium_bits);
        // 16x and 16x respectively, with rounding tolerance.
        assert!((ratio_a - 16.0).abs() < 0.1, "ratio={ratio_a}");
        assert!((ratio_b - 16.0).abs() < 0.1, "ratio={ratio_b}");
    }

    #[test]
    fn k_is_clamped_to_32() {
        // Pathological input: n=1, m=10000 → k would be ~6900.
        let k = optimal_k(1, 10_000);
        assert_eq!(k, 32);
    }

    #[test]
    fn tighter_p_means_more_bits() {
        let m_lax = optimal_m_bits(1024, 0.10);
        let m_strict = optimal_m_bits(1024, 0.001);
        assert!(m_strict > m_lax);
    }
}
