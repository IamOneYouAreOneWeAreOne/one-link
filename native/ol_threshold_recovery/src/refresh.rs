//! Proactive Secret Sharing (Herzberg-Jarecki-Krawczyk 1995).
//!
//! Generate a "zero-polynomial" q(x) with q(0) = 0 of the same degree as
//! the secret polynomial, then add q(x_i) to each share. Reconstruction
//! at x = 0 still yields S because q(0) = 0, but the shares are now
//! fresh: an adversary holding K-1 old shares gains nothing by combining
//! with K-1 new shares (they lie on different polynomials).
//!
//! Direct port of `OneField/onefield/privacy/sharding.cl` SECTION 6.
//!
//! For the Coherence Mesh: callers run a refresh tick periodically (say,
//! daily) on every share-holder so static breach of N cloud-backed shares
//! becomes time-limited.

use crate::gf256::gf_add;
use crate::prng::PrngState;
use crate::shamir::{share_byte, share_bytes, Share, ShareError};

/// Generate share-set of the zero secret. The constant term is 0; degrees
/// 1..k-1 are random. Adding these point-by-point to existing shares
/// refreshes them without changing the encoded secret.
///
/// # Errors
/// Inherits [`ShareError::InvalidParams`] when (k, n) violate the bounds.
pub fn zero_polynomial_byte(
    k: u32,
    n: u32,
    state: &mut PrngState,
) -> Result<Vec<Share>, ShareError> {
    share_byte(0, k, n, state)
}

/// Apply a one-byte refresh: `out[i].y = in[i].y XOR delta[i].y`.
/// `in_shares` and `delta_shares` must be aligned by x; this function
/// trusts the caller to construct them with matching x sequences (both
/// produced by share_byte / zero_polynomial_byte at the same n).
///
/// # Panics
/// Debug-asserts that the x-values match. In release mode the function
/// silently uses `in_shares[i].x` and is robust to the mismatch.
#[must_use]
pub fn refresh_byte(in_shares: &[Share], delta_shares: &[Share]) -> Vec<Share> {
    debug_assert_eq!(
        in_shares.len(),
        delta_shares.len(),
        "refresh requires aligned share-sets"
    );
    let n = in_shares.len().min(delta_shares.len());
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        debug_assert_eq!(in_shares[i].x, delta_shares[i].x);
        let new_y = gf_add(
            u32::from(in_shares[i].y),
            u32::from(delta_shares[i].y),
        ) as u8;
        out.push(Share::new(in_shares[i].x, new_y));
    }
    out
}

/// Multi-byte refresh: generates a fresh zero-share set per byte and
/// applies it. Returns the refreshed share-streams.
///
/// # Errors
/// Inherits [`ShareError::InvalidParams`] when (k, n) violate the bounds.
pub fn refresh_bytes(
    in_streams: &[Vec<u8>],
    k: u32,
    n: u32,
    state: &mut PrngState,
) -> Result<Vec<Vec<u8>>, ShareError> {
    if in_streams.is_empty() {
        return Ok(Vec::new());
    }
    let n_bytes = in_streams[0].len();
    // Generate a zero-secret share-set spanning `n_bytes` bytes.
    let zero_secret = vec![0u8; n_bytes];
    let zero_streams = share_bytes(&zero_secret, k, n, state)?;
    debug_assert_eq!(zero_streams.len(), in_streams.len());
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(in_streams.len());
    for (orig, delta) in in_streams.iter().zip(zero_streams.iter()) {
        let mut refreshed = Vec::with_capacity(orig.len());
        for (a, b) in orig.iter().zip(delta.iter()) {
            refreshed.push((u32::from(*a) ^ u32::from(*b)) as u8);
        }
        out.push(refreshed);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir::reconstruct_byte;

    #[test]
    fn refresh_preserves_secret_byte() {
        let mut st = PrngState::new(0x1111_2222_3333_4444);
        let secret = 0x99u8;
        let shares = share_byte(secret, 3, 5, &mut st).unwrap();
        let zero = zero_polynomial_byte(3, 5, &mut st).unwrap();
        let refreshed = refresh_byte(&shares, &zero);
        // Old K-of-N reconstruct still works.
        let old_three: Vec<Share> = shares.iter().take(3).copied().collect();
        assert_eq!(reconstruct_byte(&old_three, 3).unwrap(), secret);
        // Refreshed K-of-N reconstructs the same secret.
        let new_three: Vec<Share> =
            refreshed.iter().take(3).copied().collect();
        assert_eq!(reconstruct_byte(&new_three, 3).unwrap(), secret);
    }

    #[test]
    fn refresh_changes_at_least_one_share() {
        let mut st = PrngState::new(0x1111_2222_3333_4444);
        let shares = share_byte(0x42, 3, 5, &mut st).unwrap();
        let zero = zero_polynomial_byte(3, 5, &mut st).unwrap();
        let refreshed = refresh_byte(&shares, &zero);
        // At least one share's y MUST differ (zero polynomial isn't
        // identically zero for non-trivial k).
        let any_changed = shares.iter().zip(refreshed.iter()).any(|(a, b)| a.y != b.y);
        assert!(any_changed);
    }

    #[test]
    fn refresh_multi_byte_preserves_secret() {
        let mut st = PrngState::new(0xDEAD_BEEF_CAFE_F00D);
        let secret = b"hello, mesh";
        let streams = share_bytes(secret, 3, 5, &mut st).unwrap();
        let refreshed = refresh_bytes(&streams, 3, 5, &mut st).unwrap();
        // Reconstruct old + refreshed; both yield the same secret.
        use crate::shamir::reconstruct_bytes;
        let xs = vec![1u8, 2, 3];
        let old_refs: Vec<&[u8]> =
            streams[..3].iter().map(Vec::as_slice).collect();
        let new_refs: Vec<&[u8]> =
            refreshed[..3].iter().map(Vec::as_slice).collect();
        let recovered_old = reconstruct_bytes(&xs, &old_refs, 3).unwrap();
        let recovered_new = reconstruct_bytes(&xs, &new_refs, 3).unwrap();
        assert_eq!(recovered_old, secret);
        assert_eq!(recovered_new, secret);
    }
}
