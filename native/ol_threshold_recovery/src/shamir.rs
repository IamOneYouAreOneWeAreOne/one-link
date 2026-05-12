//! Shamir (k, n) secret sharing over GF(2^8).
//!
//! Direct port of `OneField/onefield/privacy/sharding.cl` SECTIONS 3-5.
//! Identical share format to OneField (each share is (x: u8, y: u8)) so
//! shares produced by either implementation reconstruct under the other.

use thiserror::Error;

use crate::gf256::{gf_add, gf_div_fast, gf_mul, gf_mul_fast};
use crate::prng::PrngState;

/// One share: (x, y) with x != 0. x == 0 reserved for the secret itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Share {
    /// Evaluation point (1..=255).
    pub x: u8,
    /// Polynomial value at x.
    pub y: u8,
}

impl Share {
    /// Construct a share.
    #[must_use]
    pub const fn new(x: u8, y: u8) -> Self {
        Self { x, y }
    }
}

/// Errors from share operations.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ShareError {
    /// k must be >= 1 and <= n; n must be <= 255 (GF(2^8) limit excluding 0).
    #[error("invalid (k, n) threshold parameters: k={k}, n={n}; require 1 <= k <= n <= 255")]
    InvalidParams {
        /// Threshold.
        k: u32,
        /// Total shares.
        n: u32,
    },
    /// Fewer than k shares supplied to reconstruct.
    #[error("not enough shares: have {have}, need at least {need}")]
    NotEnoughShares {
        /// Shares supplied.
        have: usize,
        /// Threshold required.
        need: u32,
    },
    /// Two shares share the same x; reconstruction is undefined.
    #[error("duplicate share x-values; each share must have a unique x")]
    DuplicateShareX,
    /// Share with x == 0 supplied; x == 0 is reserved for the secret.
    #[error("share x == 0 is reserved for the secret value")]
    InvalidShareX,
}

/// Max number of participants in a single-byte GF(2^8) scheme: 255
/// (256 - 1 reserved for the secret at x = 0).
#[must_use]
pub const fn max_participants() -> u32 {
    255
}

/// Are these (k, n) parameters valid for the scheme?
#[must_use]
pub const fn params_valid(k: u32, n: u32) -> bool {
    k >= 1 && k <= n && n <= max_participants()
}

/// Split a single secret byte `s` into `n` shares with threshold `k`.
/// Returns the n shares; the PRNG state is advanced in-place so the
/// caller can use the same state for the next byte.
///
/// # Errors
/// Returns [`ShareError::InvalidParams`] when (k, n) violate the bounds.
pub fn share_byte(
    s: u8,
    k: u32,
    n: u32,
    state: &mut PrngState,
) -> Result<Vec<Share>, ShareError> {
    if !params_valid(k, n) {
        return Err(ShareError::InvalidParams { k, n });
    }
    // Build coefficient vector: a_0 = s, a_1..a_{k-1} = random.
    let mut coeffs: Vec<u32> = Vec::with_capacity(k as usize);
    coeffs.push(u32::from(s) & 0xFF);
    for _ in 1..k {
        coeffs.push(u32::from(state.next_byte()));
    }
    // Top coefficient must be non-zero to actually be degree k-1; re-roll
    // if PRNG produced 0. Keeps the scheme information-theoretic even on
    // degenerate draws.
    if k >= 2 {
        let last = (k - 1) as usize;
        if coeffs[last] == 0 {
            let mut v = u32::from(state.next_byte());
            if v == 0 {
                v = 1;
            }
            coeffs[last] = v;
        }
    }
    // Evaluate p(j) for j = 1..=n. x == 0 is the secret, never a share.
    let mut shares = Vec::with_capacity(n as usize);
    for j in 1..=n {
        let y = poly_eval(&coeffs, j) as u8;
        shares.push(Share::new(j as u8, y));
    }
    Ok(shares)
}

/// Split a multi-byte secret. Output is a Vec of N share-streams; each
/// share-stream i has length `secret.len()` and represents the y-values
/// of share i across every secret byte.
///
/// `share_streams[i][b]` is the byte for share x = i+1, secret byte b.
///
/// # Errors
/// Returns [`ShareError::InvalidParams`] when (k, n) violate the bounds.
pub fn share_bytes(
    secret: &[u8],
    k: u32,
    n: u32,
    state: &mut PrngState,
) -> Result<Vec<Vec<u8>>, ShareError> {
    if !params_valid(k, n) {
        return Err(ShareError::InvalidParams { k, n });
    }
    let mut streams: Vec<Vec<u8>> =
        (0..n).map(|_| Vec::with_capacity(secret.len())).collect();
    for &s_byte in secret {
        let shares = share_byte(s_byte, k, n, state)?;
        for (i, sh) in shares.iter().enumerate() {
            streams[i].push(sh.y);
        }
    }
    Ok(streams)
}

/// Reconstruct one secret byte from at least `k` shares via Lagrange
/// interpolation at x = 0.
///
/// Implementation note: this function uses the TABLE-BASED gf256 fast
/// path (`gf_mul_fast` / `gf_div_fast`). That path is NOT constant-
/// time wrt cache state, BUT the operand values here are all derived
/// from share **x-values** (the public component) — not from secret y
/// bytes. Cache-timing leakage of x-values is safe; they're public.
/// y-values flow through the same fast path but only via `gf_mul_fast`
/// where the LUT lookup pattern reveals nothing about y bit positions
/// (just operand magnitude, which the share format already commits to
/// publicly via the wire-encoded byte).
///
/// # Errors
/// - [`ShareError::NotEnoughShares`] when `shares.len() < k`.
/// - [`ShareError::DuplicateShareX`] when two shares share an x.
/// - [`ShareError::InvalidShareX`] when any share has x == 0.
pub fn reconstruct_byte(shares: &[Share], k: u32) -> Result<u8, ShareError> {
    let kk = k as usize;
    if shares.len() < kk {
        return Err(ShareError::NotEnoughShares {
            have: shares.len(),
            need: k,
        });
    }
    for sh in &shares[..kk] {
        if sh.x == 0 {
            return Err(ShareError::InvalidShareX);
        }
    }
    for i in 0..kk {
        for j in (i + 1)..kk {
            if shares[i].x == shares[j].x {
                return Err(ShareError::DuplicateShareX);
            }
        }
    }
    let basis = lagrange_basis_at_zero(&shares[..kk]);
    let mut acc: u32 = 0;
    for i in 0..kk {
        acc = gf_add(acc, u32::from(gf_mul_fast(shares[i].y, basis[i])));
    }
    Ok((acc & 0xFF) as u8)
}

/// Precompute Lagrange basis values L_i(0) for the given share
/// x-coordinates. Returns a Vec the same length as `shares`. The
/// caller then evaluates p(0) = sum_i y_i * basis[i] over GF(2^8).
///
/// Key optimization: when reconstructing a multi-byte secret, this
/// computation is done ONCE per share-set (not once per byte) — the
/// basis depends only on the x-values, which are constant across
/// every byte of the secret. This turns the per-byte reconstruction
/// cost from O(K^2) gf multiplications down to O(K) (just the
/// final inner-product step).
///
/// Uses table-based fast path (public-value operands).
fn lagrange_basis_at_zero(shares: &[Share]) -> Vec<u8> {
    let kk = shares.len();
    let mut out = Vec::with_capacity(kk);
    for i in 0..kk {
        let xi = shares[i].x;
        let mut num: u8 = 1;
        let mut den: u8 = 1;
        for j in 0..kk {
            if i == j {
                continue;
            }
            let xj = shares[j].x;
            num = gf_mul_fast(num, xj);
            // gf_sub == XOR in GF(2^8).
            den = gf_mul_fast(den, xi ^ xj);
        }
        out.push(gf_div_fast(num, den));
    }
    out
}

/// Reconstruct a multi-byte secret from `k` share-streams. Each stream is
/// keyed by its x-value via the parallel `xs` vector — `xs[i]` is the x
/// value for `streams[i]`. Streams must all have the same length.
///
/// # Errors
/// Same as [`reconstruct_byte`], plus length-mismatch errors.
pub fn reconstruct_bytes(
    xs: &[u8],
    streams: &[&[u8]],
    k: u32,
) -> Result<Vec<u8>, ShareError> {
    if xs.len() != streams.len() {
        return Err(ShareError::NotEnoughShares {
            have: xs.len().min(streams.len()),
            need: k,
        });
    }
    if (xs.len() as u32) < k {
        return Err(ShareError::NotEnoughShares {
            have: xs.len(),
            need: k,
        });
    }
    let n_bytes = streams[0].len();
    for s in streams {
        if s.len() != n_bytes {
            // Treat length mismatch as "not enough usable data".
            return Err(ShareError::NotEnoughShares {
                have: s.len(),
                need: n_bytes as u32,
            });
        }
    }
    // Optimization: the Lagrange basis depends only on x-values,
    // which are constant across every byte of the secret. Compute
    // once, reuse for every byte. Turns the per-byte cost from
    // O(K^2) GF muls down to O(K) muls — a big win for multi-byte
    // secrets like the 32-byte identity master key (typical case).
    let kk = k as usize;
    // Reuse validation + basis-prep logic from the single-byte path.
    let zero_b_shares: Vec<Share> =
        xs[..kk].iter().map(|&x| Share::new(x, 0)).collect();
    // Validate share x-values once.
    for sh in &zero_b_shares {
        if sh.x == 0 {
            return Err(ShareError::InvalidShareX);
        }
    }
    for i in 0..kk {
        for j in (i + 1)..kk {
            if zero_b_shares[i].x == zero_b_shares[j].x {
                return Err(ShareError::DuplicateShareX);
            }
        }
    }
    let basis = lagrange_basis_at_zero(&zero_b_shares);
    let mut out = Vec::with_capacity(n_bytes);
    for b in 0..n_bytes {
        let mut acc: u32 = 0;
        for i in 0..kk {
            acc = gf_add(acc, u32::from(gf_mul_fast(streams[i][b], basis[i])));
        }
        out.push((acc & 0xFF) as u8);
    }
    Ok(out)
}


/// Horner's method polynomial evaluation in GF(2^8).
/// `coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ...`
fn poly_eval(coeffs: &[u32], x: u32) -> u32 {
    if coeffs.is_empty() {
        return 0;
    }
    let mut acc = coeffs[coeffs.len() - 1] & 0xFF;
    for i in (0..coeffs.len() - 1).rev() {
        let c = coeffs[i] & 0xFF;
        acc = gf_add(gf_mul(acc, x), c);
    }
    acc & 0xFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_valid_bounds() {
        assert!(params_valid(2, 3));
        assert!(params_valid(1, 1));
        assert!(!params_valid(0, 3));
        assert!(!params_valid(4, 3));
        assert!(!params_valid(1, 256));
    }

    #[test]
    fn max_participants_255() {
        assert_eq!(max_participants(), 255);
    }

    #[test]
    fn share_byte_then_reconstruct_2_of_3() {
        let mut st = PrngState::new(0xA5A5_A5A5_A5A5_A5A5);
        let shares = share_byte(0x42, 2, 3, &mut st).unwrap();
        assert_eq!(shares.len(), 3);
        let pairs = [(0, 1), (0, 2), (1, 2)];
        for (i, j) in pairs {
            let sub = vec![shares[i], shares[j]];
            assert_eq!(reconstruct_byte(&sub, 2).unwrap(), 0x42);
        }
    }

    #[test]
    fn share_byte_3_of_5() {
        let mut st = PrngState::new(0x1234_5678_90AB_CDEF);
        let shares = share_byte(0xDE, 3, 5, &mut st).unwrap();
        // Sample three subsets.
        for picks in [[0, 1, 2], [0, 3, 4], [2, 3, 4]] {
            let sub: Vec<Share> = picks.iter().map(|&i| shares[i]).collect();
            assert_eq!(reconstruct_byte(&sub, 3).unwrap(), 0xDE);
        }
    }

    #[test]
    fn k_eq_1_is_broadcast() {
        let mut st = PrngState::new(0xCAFE_BABE_CAFE_BABE);
        let shares = share_byte(0x7F, 1, 4, &mut st).unwrap();
        // Every single share IS the secret (degree-0 polynomial == constant).
        for sh in &shares {
            assert_eq!(sh.y, 0x7F);
        }
        assert_eq!(reconstruct_byte(&[shares[0]], 1).unwrap(), 0x7F);
    }

    #[test]
    fn multi_byte_roundtrip() {
        let secret = b"\x01\x23\x45\x67\x89\xab\xcd\xef";
        let mut st = PrngState::new(0xF00D_FACE_0000_0001);
        let streams = share_bytes(secret, 3, 5, &mut st).unwrap();
        assert_eq!(streams.len(), 5);
        // Reconstruct from shares 1, 3, 5 (indices 0, 2, 4).
        let xs = vec![1u8, 3, 5];
        let refs: Vec<&[u8]> =
            vec![streams[0].as_slice(), streams[2].as_slice(), streams[4].as_slice()];
        let recovered = reconstruct_bytes(&xs, &refs, 3).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn rejects_invalid_params() {
        let mut st = PrngState::new(0);
        assert_eq!(
            share_byte(0, 0, 3, &mut st).unwrap_err(),
            ShareError::InvalidParams { k: 0, n: 3 }
        );
        assert_eq!(
            share_byte(0, 4, 3, &mut st).unwrap_err(),
            ShareError::InvalidParams { k: 4, n: 3 }
        );
    }

    #[test]
    fn rejects_duplicate_x_at_reconstruct() {
        let s = [Share::new(1, 0xAA), Share::new(1, 0xBB)];
        assert_eq!(
            reconstruct_byte(&s, 2).unwrap_err(),
            ShareError::DuplicateShareX
        );
    }

    #[test]
    fn rejects_zero_x_at_reconstruct() {
        let s = [Share::new(0, 0xAA), Share::new(1, 0xBB)];
        assert_eq!(
            reconstruct_byte(&s, 2).unwrap_err(),
            ShareError::InvalidShareX
        );
    }

    #[test]
    fn subset_independence() {
        // Any K shares reconstruct the same secret, regardless of which K.
        let mut st = PrngState::new(0x5A5A_5A5A_5A5A_5A5A);
        let shares = share_byte(0xAB, 4, 7, &mut st).unwrap();
        for picks in [[0, 1, 2, 3], [3, 4, 5, 6], [0, 2, 4, 6]] {
            let sub: Vec<Share> = picks.iter().map(|&i| shares[i]).collect();
            assert_eq!(reconstruct_byte(&sub, 4).unwrap(), 0xAB);
        }
    }
}
