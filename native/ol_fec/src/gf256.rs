//! GF(2^8) arithmetic — the Rijndael / AES field.
//!
//! Elements are bytes; addition is XOR. Multiplication is polynomial
//! multiplication modulo the irreducible polynomial
//! `x^8 + x^4 + x^3 + x + 1` (0x11B). We precompute log/exp tables
//! using the primitive root `g = 0x03`:
//!
//! - [`LOG`]: `LOG[a] = i` iff `g^i = a` (defined for `a != 0`).
//! - [`EXP`]: `EXP[i] = g^i`, extended to 510 entries so wraparound
//!   `(log_a + log_b) % 255` can be avoided with a single index.
//!
//! Per-op cost: ~3 scalar cycles (two table loads + one add). Fast
//! enough that the engine's RS encode is bandwidth-bound on the XOR
//! pass, not the multiply.

/// Number of elements in GF(2^8).
pub const FIELD_SIZE: usize = 256;

/// Multiplicative order of GF(2^8) — the field minus the additive
/// identity. `LOG[a]` is in `0..255` for `a != 0`.
pub const FIELD_ORDER: usize = 255;

/// Primitive root used to build the log/exp tables. `0x03` is the
/// smallest primitive root for the Rijndael irreducible polynomial.
pub const PRIMITIVE_ROOT: u8 = 0x03;

/// Irreducible polynomial of GF(2^8) used by AES + this codec:
/// `x^8 + x^4 + x^3 + x + 1`. Reduction is done lazily via the
/// precomputed `EXP` table.
pub const IRREDUCIBLE_POLY: u16 = 0x11B;

/// Discrete-log table: `LOG[a] = i` such that `g^i = a` for `a in 1..256`.
/// `LOG[0]` is unused (logarithm of zero is undefined).
pub static LOG: [u8; FIELD_SIZE] = {
    let mut log = [0u8; FIELD_SIZE];
    let mut x: u16 = 1;
    let mut i: usize = 0;
    while i < FIELD_ORDER {
        // SAFETY: x ∈ 1..256, indexing is in bounds.
        log[x as usize] = i.to_le_bytes()[0];
        x = mul_no_table(x, PRIMITIVE_ROOT as u16);
        i += 1;
    }
    log
};

/// Exponentiation table, double-sized so multiplication doesn't need
/// `% 255`. `EXP[i] = g^(i % 255)` for `i in 0..510`.
pub static EXP: [u8; 2 * FIELD_ORDER] = {
    let mut exp = [0u8; 2 * FIELD_ORDER];
    let mut x: u16 = 1;
    let mut i: usize = 0;
    while i < FIELD_ORDER {
        let x_byte = x.to_le_bytes()[0];
        exp[i] = x_byte;
        exp[i + FIELD_ORDER] = x_byte;
        x = mul_no_table(x, PRIMITIVE_ROOT as u16);
        i += 1;
    }
    exp
};

/// Polynomial multiplication mod [`IRREDUCIBLE_POLY`]. Used at
/// compile-time to build [`LOG`] and [`EXP`]; not on the hot path.
const fn mul_no_table(a: u16, b: u16) -> u16 {
    let mut result: u16 = 0;
    let mut aa = a;
    let mut bb = b;
    let mut i = 0;
    while i < 8 {
        if (bb & 1) != 0 {
            result ^= aa;
        }
        let high_bit = aa & 0x80;
        aa <<= 1;
        if high_bit != 0 {
            aa ^= IRREDUCIBLE_POLY;
        }
        bb >>= 1;
        i += 1;
    }
    result & 0xFF
}

/// GF(2^8) multiplication via table lookup. ~3 cycles scalar.
#[inline]
#[must_use]
pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let la = LOG[a as usize] as usize;
    let lb = LOG[b as usize] as usize;
    // Safe because la + lb ≤ 254 + 254 = 508 < 510.
    EXP[la + lb]
}

/// GF(2^8) addition is XOR. Inline for clarity at call sites.
#[inline]
#[must_use]
pub const fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiplicative inverse: `inv(a) * a = 1`, or `None` for zero.
#[inline]
#[must_use]
pub fn inv(a: u8) -> Option<u8> {
    if a == 0 {
        return None;
    }
    let la = LOG[a as usize] as usize;
    // 255 - la is in 1..=254, well-defined index.
    Some(EXP[FIELD_ORDER - la])
}

/// Division: `a / b = a * inv(b)`, or `None` for a zero divisor.
#[inline]
#[must_use]
pub fn div(a: u8, b: u8) -> Option<u8> {
    if b == 0 {
        return None;
    }
    if a == 0 {
        return Some(0);
    }
    let la = LOG[a as usize] as usize;
    let lb = LOG[b as usize] as usize;
    // la in 0..255, lb in 0..255; la + 255 - lb in 0..509.
    Some(EXP[la + FIELD_ORDER - lb])
}

/// In-place fused multiply-add over a byte slice:
/// `dest[i] = dest[i] + coeff * src[i]` for `i in 0..src.len()`.
///
/// This is the hot inner loop of Reed-Solomon encoding and decoding.
/// Dispatches to a SIMD-accelerated path when available; falls back
/// to the scalar table-lookup path otherwise. Both paths are
/// **byte-identical** in output (property-tested).
///
/// **`x86_64` SSSE3 path**: uses PSHUFB to do 16 GF(2^8) multiplications
/// per instruction via the 4-bit-by-4-bit decomposition
/// (Plank-Greenan-Miller 2013). Two 16-entry tables (high-nibble +
/// low-nibble of the multiplication result) are precomputed per
/// coefficient and held in SSE registers. ~5-7× faster than scalar.
///
/// **Scalar fallback**: per-coefficient 256-entry multiplication table
/// (the "Klauspost trick"). Amortizes log/exp lookups across the shard.
#[inline]
pub fn fma_into(dest: &mut [u8], src: &[u8], coeff: u8) -> Result<(), crate::FecError> {
    if dest.len() != src.len() {
        return Err(crate::FecError::InconsistentShardLen {
            expected: dest.len(),
            len: src.len(),
        });
    }
    if coeff == 0 {
        return Ok(());
    }
    if coeff == 1 {
        // Fast path: addition (XOR) only, no multiply. Uses the same
        // word-wide XOR helper as ol_fountain when available; for now
        // a tight byte loop is what the autovectorizer handles well.
        for (d, s) in dest.iter_mut().zip(src.iter()) {
            *d ^= *s;
        }
        return Ok(());
    }

    // Runtime SIMD dispatch.
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("ssse3") {
            // SAFETY: feature-detected at runtime.
            unsafe {
                fma_into_ssse3(dest, src, coeff);
            }
            return Ok(());
        }
    }
    fma_into_scalar(dest, src, coeff)
}

/// Scalar fallback: per-coefficient 256-entry table lookup.
#[inline]
pub fn fma_into_scalar(dest: &mut [u8], src: &[u8], coeff: u8) -> Result<(), crate::FecError> {
    if dest.len() != src.len() {
        return Err(crate::FecError::InconsistentShardLen {
            expected: dest.len(),
            len: src.len(),
        });
    }
    if coeff == 0 {
        return Ok(());
    }
    if coeff == 1 {
        for (d, s) in dest.iter_mut().zip(src.iter()) {
            *d ^= *s;
        }
        return Ok(());
    }
    let mut mul_table = [0u8; FIELD_SIZE];
    let lc = LOG[coeff as usize] as usize;
    mul_table[0] = 0;
    for x in 1..FIELD_SIZE {
        let lx = LOG[x] as usize;
        mul_table[x] = EXP[lc + lx];
    }
    for (d, s) in dest.iter_mut().zip(src.iter()) {
        *d ^= mul_table[*s as usize];
    }
    Ok(())
}

/// SSSE3 PSHUFB path. Splits each source byte into high + low nibbles,
/// precomputes the two 16-byte multiplication tables for `coeff`, and
/// processes 16 bytes per iteration via `_mm_shuffle_epi8`.
///
/// # Safety
///
/// Caller must verify SSSE3 is available before calling (we check via
/// `is_x86_feature_detected!("ssse3")` in `fma_into`).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "ssse3")]
unsafe fn fma_into_ssse3(dest: &mut [u8], src: &[u8], coeff: u8) {
    use std::arch::x86_64::{
        __m128i, _mm_and_si128, _mm_set1_epi8, _mm_shuffle_epi8, _mm_srli_epi64, _mm_xor_si128,
    };

    debug_assert_eq!(dest.len(), src.len());

    // Precompute two 16-byte tables: low_table[i] = coeff * i,
    // high_table[i] = coeff * (i << 4). Together they let us compute
    // coeff * b = low_table[b & 0x0F] ^ high_table[b >> 4] for any
    // byte b, vectorized 16-wide via PSHUFB.
    let mut low_table = [0u8; 16];
    let mut high_table = [0u8; 16];
    for nibble in 0u8..16 {
        let index = usize::from(nibble);
        low_table[index] = mul(coeff, nibble);
        high_table[index] = mul(coeff, nibble << 4);
    }

    // SAFETY: all SSSE3 intrinsics + pointer arithmetic below are
    // guarded by:
    //  - This function's `target_feature = "ssse3"` (caller verified).
    //  - Loop bound `n16 = n & !15` keeps loads + stores within
    //    `[src.as_ptr()..src.as_ptr() + n)` and the mirrored dest range.
    //  - The tail loop does byte-wise scalar access.
    unsafe {
        let low_v = std::mem::transmute::<[u8; 16], __m128i>(low_table);
        let high_v = std::mem::transmute::<[u8; 16], __m128i>(high_table);
        let mask_nibble = _mm_set1_epi8(0x0F);

        let n = src.len();
        let n16 = n & !15;
        let mut i = 0usize;
        while i < n16 {
            let src_bytes: [u8; 16] = src[i..i + 16]
                .try_into()
                .expect("vector loop always has 16 source bytes");
            let s = std::mem::transmute::<[u8; 16], __m128i>(src_bytes);
            let low_nibbles = _mm_and_si128(s, mask_nibble);
            // Right-shift each byte 4 bits to get high nibbles.
            // `_mm_srli_epi64` shifts the *whole 64-bit lane*, so bytes
            // leak across boundaries; we mask off the leakage with
            // `& 0x0F` again.
            let high_nibbles = _mm_and_si128(_mm_srli_epi64(s, 4), mask_nibble);
            let low_result = _mm_shuffle_epi8(low_v, low_nibbles);
            let high_result = _mm_shuffle_epi8(high_v, high_nibbles);
            let product = _mm_xor_si128(low_result, high_result);
            let dest_bytes: [u8; 16] = dest[i..i + 16]
                .try_into()
                .expect("vector loop always has 16 destination bytes");
            let d = std::mem::transmute::<[u8; 16], __m128i>(dest_bytes);
            let d_xor = _mm_xor_si128(d, product);
            let output = std::mem::transmute::<__m128i, [u8; 16]>(d_xor);
            dest[i..i + 16].copy_from_slice(&output);
            i += 16;
        }
        // Scalar tail for the last 0..15 bytes.
        while i < n {
            let s_byte = src[i];
            let low = low_table[(s_byte & 0x0F) as usize];
            let high = high_table[((s_byte >> 4) & 0x0F) as usize];
            dest[i] ^= low ^ high;
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_is_xor() {
        assert_eq!(add(0x42, 0xAB), 0x42 ^ 0xAB);
        assert_eq!(add(0, 0), 0);
        assert_eq!(add(0xFF, 0xFF), 0);
    }

    #[test]
    fn mul_by_zero_is_zero() {
        for x in 0u8..=255 {
            assert_eq!(mul(x, 0), 0);
            assert_eq!(mul(0, x), 0);
        }
    }

    #[test]
    fn mul_by_one_is_identity() {
        for x in 0u8..=255 {
            assert_eq!(mul(x, 1), x);
            assert_eq!(mul(1, x), x);
        }
    }

    #[test]
    fn inv_is_multiplicative_inverse() {
        for x in 1u8..=255 {
            let i = inv(x).unwrap();
            assert_eq!(mul(x, i), 1, "inv({x:#x}) failed");
        }
    }

    #[test]
    fn zero_inverse_and_zero_divisor_are_rejected_without_panicking() {
        assert_eq!(inv(0), None);
        assert_eq!(div(1, 0), None);
        assert_eq!(div(0, 0), None);
    }

    #[test]
    fn div_is_inverse_of_mul() {
        for a in 0u8..=255 {
            for b in 1u8..=255 {
                let q = div(a, b).unwrap();
                let r = mul(q, b);
                assert_eq!(
                    r, a,
                    "div({a:#x}, {b:#x}) = {q:#x} but {q:#x}*{b:#x} = {r:#x}"
                );
            }
        }
    }

    #[test]
    fn mul_is_associative_commutative() {
        // Spot-check; full quadratic-table verification at 256^3 ≈ 16M ops
        // is the property-test scope.
        let trios: [(u8, u8, u8); 5] = [
            (0x02, 0x03, 0x05),
            (0x42, 0x77, 0xAB),
            (0xFF, 0x01, 0xCD),
            (0x10, 0x20, 0x30),
            (0x80, 0x80, 0x80),
        ];
        for (a, b, c) in trios {
            assert_eq!(mul(a, b), mul(b, a));
            assert_eq!(mul(mul(a, b), c), mul(a, mul(b, c)));
        }
    }

    #[test]
    fn fma_zero_coefficient_is_noop() {
        let original = vec![0x42u8; 100];
        let mut dest = original.clone();
        let src = vec![0xCDu8; 100];
        fma_into(&mut dest, &src, 0).unwrap();
        assert_eq!(dest, original);
    }

    #[test]
    fn fma_one_coefficient_is_xor() {
        let mut dest = vec![0u8; 32];
        let src: Vec<u8> = (0u8..32).collect();
        fma_into(&mut dest, &src, 1).unwrap();
        assert_eq!(dest, src);
        fma_into(&mut dest, &src, 1).unwrap();
        assert_eq!(dest, vec![0u8; 32]); // XOR with self = zero
    }

    #[test]
    fn fma_general_matches_byte_by_byte_mul() {
        let mut dest = vec![0u8; 256];
        let src: Vec<u8> = (0u8..=255).collect();
        let coeff = 0xAB;
        fma_into(&mut dest, &src, coeff).unwrap();
        for i in 0..256 {
            assert_eq!(dest[i], mul(coeff, src[i]));
        }
    }

    #[test]
    fn fma_rejects_mismatched_lengths_before_simd_access() {
        let mut dest = [0u8; 32];
        let src = [0u8; 31];
        assert!(matches!(
            fma_into(&mut dest, &src, 7),
            Err(crate::FecError::InconsistentShardLen { .. })
        ));
    }

    /// SIMD path (when available) MUST produce byte-identical output
    /// vs the scalar path across every coefficient + many input shapes.
    /// This guards against the SSSE3 PSHUFB implementation drifting from
    /// the canonical scalar reference.
    #[test]
    fn simd_matches_scalar_across_all_coefficients_and_sizes() {
        // Cover lengths that exercise the 16-byte SIMD lane + scalar tail.
        let lengths = [
            0usize, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 127, 128, 1023, 1024, 1025,
        ];
        // Use a deterministic source pattern.
        let src_base: Vec<u8> = (0..1025u32)
            .map(|i| (i.wrapping_mul(31) & 0xFF) as u8)
            .collect();
        for &len in &lengths {
            let src = &src_base[..len];
            for coeff in 0u8..=255 {
                let mut dest_simd = vec![0xAAu8; len];
                let mut dest_scalar = vec![0xAAu8; len];
                fma_into(&mut dest_simd, src, coeff).unwrap();
                fma_into_scalar(&mut dest_scalar, src, coeff).unwrap();
                assert_eq!(
                    dest_simd, dest_scalar,
                    "SIMD ≠ scalar at len={len} coeff={coeff:#x}"
                );
            }
        }
    }
}
