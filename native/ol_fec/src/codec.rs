//! Reed-Solomon codec: systematic encode + erasure decode.

use crate::cauchy::{invert, CauchyMatrix};
use crate::error::FecError;
use crate::gf256::fma_into;

/// Reed-Solomon Codec over GF(2^8) using a Cauchy systematic matrix.
///
/// One codec instance is built per `(k, m)` configuration and reused
/// across many encode/decode calls — the matrix is precomputed.
#[derive(Debug, Clone)]
pub struct Codec {
    cauchy: CauchyMatrix,
}

impl Codec {
    /// Build a codec for `(k, m)`: `k` data shards plus `m` parity
    /// shards, recoverable from any `k` of the `k + m`.
    ///
    /// # Errors
    ///
    /// [`FecError::InvalidParameters`] if `k == 0`, `m == 0`, or
    /// `k + m > 255`.
    pub fn new(k: usize, m: usize) -> Result<Self, FecError> {
        Ok(Self {
            cauchy: CauchyMatrix::new(k, m)?,
        })
    }

    /// Data-shard count.
    #[inline]
    #[must_use]
    pub fn k(&self) -> usize {
        self.cauchy.k()
    }

    /// Parity-shard count.
    #[inline]
    #[must_use]
    pub fn m(&self) -> usize {
        self.cauchy.m()
    }

    /// Total-shard count = `k + m`.
    #[inline]
    #[must_use]
    pub fn total_shards(&self) -> usize {
        self.cauchy.total()
    }

    /// Encode `data` (k equal-length shards) into the m parity shards.
    /// The data shards themselves are the FIRST k of the (k + m) total
    /// shards (systematic), so callers don't need to copy them here.
    ///
    /// # Errors
    ///
    /// - [`FecError::DataShardCount`] if `data.len() != k`.
    /// - [`FecError::InconsistentShardLen`] if shards aren't equal length.
    pub fn encode(&self, data: &[&[u8]]) -> Result<Vec<Vec<u8>>, FecError> {
        if data.len() != self.k() {
            return Err(FecError::DataShardCount {
                expected: self.k(),
                got: data.len(),
            });
        }
        let shard_len = data[0].len();
        for (i, d) in data.iter().enumerate() {
            if d.len() != shard_len {
                return Err(FecError::InconsistentShardLen {
                    expected: shard_len,
                    len: d.len(),
                });
            }
            let _ = i;
        }
        let mut parity: Vec<Vec<u8>> = (0..self.m()).map(|_| vec![0u8; shard_len]).collect();
        for (i, parity_shard) in parity.iter_mut().enumerate() {
            let row = self.cauchy.parity_row(i);
            for (j, &coeff) in row.iter().enumerate() {
                fma_into(parity_shard, data[j], coeff);
            }
        }
        Ok(parity)
    }

    /// Decode the original `k` data shards from any `k` of the
    /// `k + m` shards.
    ///
    /// `present` has length `k + m`; `present[i]` is `Some(&[u8])` if
    /// shard `i` was received, `None` if it's missing. At least `k`
    /// entries must be `Some`. All present shards must be equal length.
    ///
    /// # Errors
    ///
    /// - [`FecError::PresentSlotCount`] if `present.len() != k + m`.
    /// - [`FecError::InsufficientShards`] if fewer than `k` shards
    ///   are present.
    /// - [`FecError::InconsistentShardLen`] if present shards aren't
    ///   all the same length.
    pub fn decode(&self, present: &[Option<&[u8]>]) -> Result<Vec<Vec<u8>>, FecError> {
        let total = self.total_shards();
        if present.len() != total {
            return Err(FecError::PresentSlotCount {
                expected: total,
                got: present.len(),
            });
        }
        // Collect indices of present shards.
        let mut indices = Vec::with_capacity(total);
        let mut shard_len: Option<usize> = None;
        for (i, slot) in present.iter().enumerate() {
            if let Some(s) = slot {
                match shard_len {
                    None => shard_len = Some(s.len()),
                    Some(len) if len == s.len() => {}
                    Some(len) => {
                        return Err(FecError::InconsistentShardLen {
                            expected: len,
                            len: s.len(),
                        });
                    }
                }
                indices.push(i);
            }
        }
        if indices.len() < self.k() {
            return Err(FecError::InsufficientShards {
                needed: self.k(),
                got: indices.len(),
            });
        }
        // Use the first k present shards.
        indices.truncate(self.k());
        let shard_len = shard_len.expect("at least one present shard");

        // Fast path: all k data shards (indices 0..k) are present —
        // no recovery needed.
        if indices.iter().enumerate().all(|(i, &idx)| idx == i) {
            return Ok((0..self.k())
                .map(|i| present[i].expect("present").to_vec())
                .collect());
        }

        // Build the k × k submatrix of the generator matrix
        // corresponding to the chosen indices.
        let gen = self.cauchy.generator();
        let sub: Vec<Vec<u8>> = indices.iter().map(|&i| gen[i].clone()).collect();
        let inv =
            invert(sub).expect("Cauchy submatrices are always invertible");

        // Decode: data = inv * recv_data (matrix-vector across shards).
        let mut data: Vec<Vec<u8>> = (0..self.k()).map(|_| vec![0u8; shard_len]).collect();
        for (out_row, inv_row) in data.iter_mut().zip(inv.iter()) {
            for (j, &coeff) in inv_row.iter().enumerate() {
                fma_into(out_row, present[indices[j]].expect("indexed present"), coeff);
            }
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    #[test]
    fn rs_10_4_round_trip_fresh() {
        let codec = Codec::new(10, 4).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let shard_len = 1024;
        let data: Vec<Vec<u8>> = (0..10)
            .map(|_| (0..shard_len).map(|_| rng.r#gen::<u8>()).collect())
            .collect();
        let data_refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
        let parity = codec.encode(&data_refs).unwrap();
        assert_eq!(parity.len(), 4);
        for p in &parity {
            assert_eq!(p.len(), shard_len);
        }

        // Decode with all data present.
        let mut present: Vec<Option<&[u8]>> = data.iter().map(|d| Some(d.as_slice())).collect();
        for p in &parity {
            present.push(Some(p.as_slice()));
        }
        let decoded = codec.decode(&present).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn rs_10_4_recovers_from_any_4_erasures() {
        let codec = Codec::new(10, 4).unwrap();
        let mut rng = StdRng::seed_from_u64(0xCAFE);
        let shard_len = 256;
        let data: Vec<Vec<u8>> = (0..10)
            .map(|_| (0..shard_len).map(|_| rng.r#gen::<u8>()).collect())
            .collect();
        let data_refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
        let parity = codec.encode(&data_refs).unwrap();

        // Drop 4 specific shards: 0, 5, 11, 13 (mix of data + parity).
        let mut present: Vec<Option<&[u8]>> = Vec::with_capacity(14);
        for (i, d) in data.iter().enumerate() {
            if i == 0 || i == 5 {
                present.push(None);
            } else {
                present.push(Some(d.as_slice()));
            }
        }
        for (i, p) in parity.iter().enumerate() {
            // shards 10..14 are parity 0..4; we drop 11 (=parity 1) and 13 (=parity 3).
            if i == 1 || i == 3 {
                present.push(None);
            } else {
                present.push(Some(p.as_slice()));
            }
        }
        assert_eq!(present.iter().filter(|o| o.is_some()).count(), 10);
        let decoded = codec.decode(&present).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn rejects_too_few_present() {
        let codec = Codec::new(10, 4).unwrap();
        let present: Vec<Option<&[u8]>> = vec![None; 14];
        let result = codec.decode(&present);
        assert!(matches!(result, Err(FecError::InsufficientShards { .. })));
    }

    #[test]
    fn rejects_data_shard_count_mismatch() {
        let codec = Codec::new(5, 2).unwrap();
        let buf = vec![0u8; 32];
        let data: Vec<&[u8]> = vec![&buf[..]; 4]; // 4 shards, expected 5
        let result = codec.encode(&data);
        assert!(matches!(result, Err(FecError::DataShardCount { .. })));
    }

    #[test]
    fn rejects_unequal_shard_lengths() {
        let codec = Codec::new(3, 2).unwrap();
        let a = vec![0u8; 32];
        let b = vec![0u8; 64];
        let c = vec![0u8; 32];
        let data: Vec<&[u8]> = vec![&a[..], &b[..], &c[..]];
        let result = codec.encode(&data);
        assert!(matches!(result, Err(FecError::InconsistentShardLen { .. })));
    }
}
