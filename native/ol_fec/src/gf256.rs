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
        log[x as usize] = i as u8;
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
        exp[i] = x as u8;
        exp[i + FIELD_ORDER] = x as u8;
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

/// Multiplicative inverse: `inv(a) * a = 1`. Panics for `a == 0`.
#[inline]
#[must_use]
pub fn inv(a: u8) -> u8 {
    assert!(a != 0, "GF(2^8) zero has no multiplicative inverse");
    let la = LOG[a as usize] as usize;
    // 255 - la is in 1..=254, well-defined index.
    EXP[FIELD_ORDER - la]
}

/// Division: `a / b = a * inv(b)`. Panics for `b == 0`.
#[inline]
#[must_use]
pub fn div(a: u8, b: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    assert!(b != 0, "GF(2^8) division by zero");
    let la = LOG[a as usize] as usize;
    let lb = LOG[b as usize] as usize;
    // la in 0..255, lb in 0..255; la + 255 - lb in 0..509.
    EXP[la + FIELD_ORDER - lb]
}

/// In-place fused multiply-add over a byte slice:
/// `dest[i] = dest[i] + coeff * src[i]` for `i in 0..src.len()`.
///
/// This is the hot inner loop of Reed-Solomon encoding and decoding.
/// We pre-build a per-coefficient 256-entry multiplication table
/// (the "Klauspost trick" without SIMD) to amortize the log/exp lookups
/// across the whole shard — one table per row of the encoding matrix.
#[inline]
pub fn fma_into(dest: &mut [u8], src: &[u8], coeff: u8) {
    debug_assert_eq!(dest.len(), src.len());
    if coeff == 0 {
        return;
    }
    if coeff == 1 {
        // Fast path: addition (XOR) only, no multiply.
        for (d, s) in dest.iter_mut().zip(src.iter()) {
            *d ^= *s;
        }
        return;
    }
    // Build a 256-entry table: mul_table[x] = coeff * x for x in 0..256.
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
            let i = inv(x);
            assert_eq!(mul(x, i), 1, "inv({x:#x}) failed");
        }
    }

    #[test]
    fn div_is_inverse_of_mul() {
        for a in 0u8..=255 {
            for b in 1u8..=255 {
                let q = div(a, b);
                let r = mul(q, b);
                assert_eq!(r, a, "div({a:#x}, {b:#x}) = {q:#x} but {q:#x}*{b:#x} = {r:#x}");
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
        fma_into(&mut dest, &src, 0);
        assert_eq!(dest, original);
    }

    #[test]
    fn fma_one_coefficient_is_xor() {
        let mut dest = vec![0u8; 32];
        let src: Vec<u8> = (0..32).map(|i| i as u8).collect();
        fma_into(&mut dest, &src, 1);
        assert_eq!(dest, src);
        fma_into(&mut dest, &src, 1);
        assert_eq!(dest, vec![0u8; 32]); // XOR with self = zero
    }

    #[test]
    fn fma_general_matches_byte_by_byte_mul() {
        let mut dest = vec![0u8; 256];
        let src: Vec<u8> = (0u8..=255).collect();
        let coeff = 0xAB;
        fma_into(&mut dest, &src, coeff);
        for i in 0..256 {
            assert_eq!(dest[i], mul(coeff, src[i]));
        }
    }
}
