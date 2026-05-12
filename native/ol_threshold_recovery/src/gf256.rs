//! Constant-time GF(2^8) arithmetic using the AES primitive polynomial
//! x^8 + x^4 + x^3 + x + 1 = 0x11B.
//!
//! Direct port of `OneField/onefield/privacy/sharding.cl` SECTION 1.
//! Identical bit-pattern outputs so encoded shares interoperate with
//! the OneField mesh nodes byte-for-byte.

/// GF(2^8) primitive polynomial (AES standard). Low byte 0x1B is what
/// gets XORed during the reduce step after a left-shift overflow.
pub const GF_PRIMITIVE: u32 = 0x11B;

/// GF(2^8) addition is XOR (characteristic 2).
#[inline]
#[must_use]
pub const fn gf_add(a: u32, b: u32) -> u32 {
    (a ^ b) & 0xFF
}

/// GF(2^8) subtraction equals addition (characteristic 2).
#[inline]
#[must_use]
pub const fn gf_sub(a: u32, b: u32) -> u32 {
    (a ^ b) & 0xFF
}

/// GF(2^8) multiplication via Russian-peasant shift-and-reduce.
/// Constant-time wrt operand values: branch-free, fixed 8 iterations,
/// uses masked XOR instead of `if y_lsb { ... }`.
#[inline]
#[must_use]
pub const fn gf_mul(a: u32, b: u32) -> u32 {
    let mut x: u32 = a & 0xFF;
    let mut y: u32 = b & 0xFF;
    let mut r: u32 = 0;
    let mut i: u32 = 0;
    while i < 8 {
        let y_lsb = y & 1;
        // Mask is 0 or 0xFFFFFFFF; constant-time conditional XOR.
        let mask = 0u32.wrapping_sub(y_lsb);
        r ^= x & mask;
        let x_msb = x & 0x80;
        x = (x << 1) & 0xFF;
        let reduce_mask = 0u32.wrapping_sub(x_msb >> 7);
        x ^= reduce_mask & 0x1B;
        y >>= 1;
        i += 1;
    }
    r & 0xFF
}

/// GF(2^8) power: a^e via square-and-multiply. Not constant-time wrt e
/// (e is typically the public exponent 254 in [`gf_inv`] so this is fine).
#[inline]
#[must_use]
pub const fn gf_pow(base: u32, exp: u32) -> u32 {
    let mut b = base & 0xFF;
    let mut e = exp;
    let mut r: u32 = 1;
    while e > 0 {
        if e & 1 == 1 {
            r = gf_mul(r, b);
        }
        b = gf_mul(b, b);
        e >>= 1;
    }
    r
}

/// GF(2^8) multiplicative inverse via Fermat: a^(2^8 - 2) = a^254.
/// Returns 0 for input 0 (undefined; caller must avoid by construction).
#[inline]
#[must_use]
pub const fn gf_inv(a: u32) -> u32 {
    if (a & 0xFF) == 0 {
        0
    } else {
        gf_pow(a, 254)
    }
}

/// GF(2^8) division a / b = a * b^{-1}. Returns 0 when b == 0.
#[inline]
#[must_use]
pub const fn gf_div(a: u32, b: u32) -> u32 {
    if (b & 0xFF) == 0 {
        0
    } else {
        gf_mul(a, gf_inv(b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additive_identity() {
        assert_eq!(gf_add(0x57, 0), 0x57);
    }

    #[test]
    fn self_inverse_under_add() {
        assert_eq!(gf_add(0x57, 0x57), 0);
    }

    #[test]
    fn multiplicative_identity() {
        assert_eq!(gf_mul(0x57, 1), 0x57);
    }

    #[test]
    fn zero_annihilation() {
        assert_eq!(gf_mul(0x57, 0), 0);
    }

    #[test]
    fn aes_vector() {
        // Standard AES test vector: 0x57 * 0x83 = 0xC1.
        assert_eq!(gf_mul(0x57, 0x83), 0xC1);
    }

    #[test]
    fn inverse_roundtrip_every_nonzero() {
        for a in 1u32..256 {
            let inv = gf_inv(a);
            assert_eq!(gf_mul(a, inv), 1, "a={a}");
        }
    }

    #[test]
    fn pow_consistency() {
        // 3^2 in GF(2^8): (x+1)*(x+1) = x^2 + 1 = 5.
        assert_eq!(gf_pow(3, 2), 5);
        // a^0 = 1, a^1 = a.
        assert_eq!(gf_pow(0x42, 0), 1);
        assert_eq!(gf_pow(0x42, 1), 0x42);
    }

    #[test]
    fn division_roundtrip() {
        for a in 0u32..256 {
            for b in 1u32..256 {
                let q = gf_div(a, b);
                assert_eq!(gf_mul(q, b), a, "a={a} b={b}");
            }
        }
    }
}
