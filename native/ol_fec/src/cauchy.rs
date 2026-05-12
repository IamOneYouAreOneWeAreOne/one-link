//! Cauchy matrix construction over GF(2^8).
//!
//! Per ADR-0016: any submatrix of a Cauchy matrix over GF(2^8) is
//! invertible. That's the defining property — every `(k, m)`
//! configuration we instantiate has the **always-decodable** guarantee
//! for any `k`-shard subset of the `k+m` produced shards.
//!
//! ## Construction
//!
//! Pick two disjoint sets of GF(2^8) elements `X = {x_0..x_{m-1}}` and
//! `Y = {y_0..y_{k-1}}` with all `x_i + y_j != 0` (since `+` is XOR in
//! GF(2^8), this means `x_i != y_j`).
//!
//! The Cauchy matrix entry at row `i`, column `j` is
//! `C[i][j] = 1 / (x_i + y_j) = 1 / (x_i ^ y_j)`.
//!
//! For our systematic encoder we then prepend the `k × k` identity to
//! get the full `(k+m) × k` generator matrix `G`:
//!
//! ```text
//! G = [ I_k       ]   ← rows 0..k:   data shards (identity)
//!     [ C_(m,k)   ]   ← rows k..k+m: parity shards
//! ```
//!
//! ## Choice of x_i, y_j
//!
//! We use the disjoint sets `Y = {0, 1, 2, ..., k-1}` and
//! `X = {k, k+1, ..., k+m-1}`. With `k + m ≤ 255` (per ADR-0016
//! limit), these sets fit in the field and are pairwise distinct.

use crate::error::FecError;
use crate::gf256::{div, mul};

/// A pre-built systematic generator matrix: `(k + m) × k` over GF(2^8).
///
/// Rows 0..k are the identity (data shards copy through unchanged).
/// Rows k..(k+m) are the Cauchy matrix `C` that produces the parity
/// shards. We store only the parity rows; the identity is implicit.
#[derive(Debug, Clone)]
pub struct CauchyMatrix {
    k: usize,
    m: usize,
    /// `m × k` parity coefficients. `parity[i][j]` = coefficient of
    /// data shard `j` contributing to parity shard `i`.
    parity: Vec<Vec<u8>>,
}

impl CauchyMatrix {
    /// Build a systematic Cauchy matrix for `(k, m)`.
    ///
    /// # Errors
    ///
    /// - [`FecError::InvalidParameters`] if `k == 0` or `m == 0` or
    ///   `k + m > 255`.
    pub fn new(k: usize, m: usize) -> Result<Self, FecError> {
        if k == 0 || m == 0 || k + m > 255 {
            return Err(FecError::InvalidParameters { k, m });
        }
        let mut parity = Vec::with_capacity(m);
        for i in 0..m {
            let mut row = Vec::with_capacity(k);
            for j in 0..k {
                // x_i = k + i; y_j = j. Both fit in u8.
                let x_i = (k + i) as u8;
                let y_j = j as u8;
                // x_i + y_j = x_i ^ y_j (GF(2^8)). Guaranteed non-zero
                // because x_i != y_j (disjoint sets).
                let denom = x_i ^ y_j;
                debug_assert!(denom != 0);
                row.push(div(1, denom));
            }
            parity.push(row);
        }
        Ok(Self { k, m, parity })
    }

    /// Number of data shards.
    #[inline]
    #[must_use]
    pub fn k(&self) -> usize {
        self.k
    }

    /// Number of parity shards.
    #[inline]
    #[must_use]
    pub fn m(&self) -> usize {
        self.m
    }

    /// Total shards = `k + m`.
    #[inline]
    #[must_use]
    pub fn total(&self) -> usize {
        self.k + self.m
    }

    /// Borrow the parity coefficient row for parity shard `i`. Length
    /// is `k`. Panics if `i >= m`.
    #[inline]
    #[must_use]
    pub fn parity_row(&self, i: usize) -> &[u8] {
        &self.parity[i]
    }

    /// Build the full systematic generator matrix as a flat `(k+m) × k`
    /// `Vec<Vec<u8>>`. Used by the decoder to pick the row subset
    /// matching the received shard indices.
    #[must_use]
    pub fn generator(&self) -> Vec<Vec<u8>> {
        let mut g = Vec::with_capacity(self.total());
        // Identity rows.
        for j in 0..self.k {
            let mut row = vec![0u8; self.k];
            row[j] = 1;
            g.push(row);
        }
        // Parity rows.
        for row in &self.parity {
            g.push(row.clone());
        }
        g
    }
}

/// Invert a `k × k` matrix over GF(2^8) via Gauss-Jordan elimination.
///
/// Used by [`crate::decoder`] to solve for the original data when given
/// any `k` of the `k + m` shards.
///
/// Returns the inverse matrix. The input is consumed in place to save
/// the allocation; caller passes a freshly-built copy.
///
/// # Errors
///
/// Returns `None` if the matrix is singular (cannot be inverted). For
/// matrices drawn from a Cauchy generator, this case is impossible by
/// construction — every `k × k` submatrix is invertible.
#[must_use]
pub fn invert(mut m: Vec<Vec<u8>>) -> Option<Vec<Vec<u8>>> {
    let n = m.len();
    if n == 0 || m.iter().any(|r| r.len() != n) {
        return None;
    }
    // Augment with identity.
    for i in 0..n {
        let mut id = vec![0u8; n];
        id[i] = 1;
        m[i].extend_from_slice(&id);
    }
    // Forward elimination + back substitution in one Gauss-Jordan pass.
    for col in 0..n {
        // Find a pivot row in `col..n`.
        let mut pivot = None;
        for r in col..n {
            if m[r][col] != 0 {
                pivot = Some(r);
                break;
            }
        }
        let pivot = pivot?;
        m.swap(col, pivot);
        // Normalize pivot row so `m[col][col] = 1`.
        let pivot_val = m[col][col];
        let pivot_inv = crate::gf256::inv(pivot_val);
        for v in &mut m[col] {
            *v = mul(*v, pivot_inv);
        }
        // Eliminate other rows.
        for r in 0..n {
            if r == col {
                continue;
            }
            let factor = m[r][col];
            if factor == 0 {
                continue;
            }
            // Subtract `factor * m[col]` from m[r]; subtraction = XOR.
            for c in 0..2 * n {
                let v = mul(factor, m[col][c]);
                m[r][c] ^= v;
            }
        }
    }
    // Strip the original-left half; return the right half = inverse.
    let mut inv = Vec::with_capacity(n);
    for row in m {
        inv.push(row[n..].to_vec());
    }
    Some(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_k_or_m() {
        assert!(CauchyMatrix::new(0, 4).is_err());
        assert!(CauchyMatrix::new(10, 0).is_err());
    }

    #[test]
    fn rejects_total_exceeding_field() {
        assert!(CauchyMatrix::new(200, 100).is_err()); // 300 > 255
                                                       // k + m must be ≤ 255.
        assert!(CauchyMatrix::new(128, 127).is_ok()); // 255 — boundary OK
        assert!(CauchyMatrix::new(128, 128).is_err()); // 256 — boundary fails
        assert!(CauchyMatrix::new(255, 1).is_err()); // 256 — fails
        assert!(CauchyMatrix::new(254, 1).is_ok()); // 255 — OK
    }

    #[test]
    fn standard_rs_10_4_constructs() {
        let c = CauchyMatrix::new(10, 4).unwrap();
        assert_eq!(c.k(), 10);
        assert_eq!(c.m(), 4);
        assert_eq!(c.total(), 14);
        // Parity entries are all nonzero (any zero would mean a
        // collision in (x_i ^ y_j) which can't happen with our scheme).
        for i in 0..4 {
            for &v in c.parity_row(i) {
                assert!(v != 0, "parity[{i}] has a zero entry");
            }
        }
    }

    #[test]
    fn identity_inversion() {
        let id: Vec<Vec<u8>> = (0..4)
            .map(|i| {
                let mut row = vec![0u8; 4];
                row[i] = 1;
                row
            })
            .collect();
        let inv = invert(id.clone()).unwrap();
        assert_eq!(inv, id, "inverse of I is I");
    }

    #[test]
    fn cauchy_submatrix_always_invertible() {
        // For k=10, m=4: pick any 10 of the 14 rows and confirm the
        // resulting 10x10 submatrix is invertible.
        let c = CauchyMatrix::new(10, 4).unwrap();
        let gen = c.generator();
        // 14 choose 10 = 1001 subsets; enumerate via bitmask.
        let n = 14;
        let k = 10;
        let mut bits: u64 = (1 << k) - 1;
        let limit = 1u64 << n;
        let mut tested = 0;
        while bits < limit {
            // Build the submatrix of `gen` for the rows whose bit is set.
            let mut sub: Vec<Vec<u8>> = Vec::with_capacity(k);
            for r in 0..n {
                if (bits >> r) & 1 == 1 {
                    sub.push(gen[r].clone());
                }
            }
            assert_eq!(sub.len(), k);
            assert!(
                invert(sub).is_some(),
                "submatrix bits={bits:b} not invertible"
            );
            tested += 1;
            // Gosper's hack: next bitmask with same popcount.
            let c2 = bits & bits.wrapping_neg();
            let r2 = bits + c2;
            bits = (((r2 ^ bits) >> 2) / c2) | r2;
        }
        assert_eq!(tested, 1001, "expected 1001 subsets, tested {tested}");
    }
}
