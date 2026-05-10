//! LT encoder: takes a source buffer + symbol_len; produces one encoded
//! symbol per call.

use crate::distribution::{robust_soliton_cdf, sample_degree, sample_neighbors};
use crate::error::FountainError;
use crate::rng::SplitMix64;

/// LT encoder over a fixed source buffer.
///
/// Constructed once per chunk; `encode_symbol(symbol_id)` returns one
/// XORed payload of length `symbol_len`. Senders typically call this
/// in a monotonic loop until the receiver signals decode complete.
pub struct LtEncoder<'a> {
    source: &'a [u8],
    k: u32,
    symbol_len: usize,
    cdf: Vec<f64>,
    /// Padding for the last source symbol when `source.len() % symbol_len != 0`.
    /// Owned so `encode_symbol` can return a slice into either `source`
    /// or this padding buffer.
    last_padded: Option<Vec<u8>>,
}

impl<'a> std::fmt::Debug for LtEncoder<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LtEncoder")
            .field("k", &self.k)
            .field("symbol_len", &self.symbol_len)
            .field("source_len", &self.source.len())
            .finish()
    }
}

impl<'a> LtEncoder<'a> {
    /// Build an encoder over `source` with `symbol_len`-byte symbols.
    ///
    /// `k` is derived as `ceil(source.len() / symbol_len)`. The last
    /// source symbol is zero-padded if `source.len() % symbol_len != 0`.
    ///
    /// # Errors
    ///
    /// - [`FountainError::InvalidSymbolLen`] if `symbol_len == 0`.
    /// - [`FountainError::EmptySource`] if `source` is empty.
    pub fn new(source: &'a [u8], symbol_len: usize) -> Result<Self, FountainError> {
        if symbol_len == 0 {
            return Err(FountainError::InvalidSymbolLen("must be > 0"));
        }
        if source.is_empty() {
            return Err(FountainError::EmptySource);
        }
        let k = ((source.len() + symbol_len - 1) / symbol_len) as u32;
        let last_padded = if source.len() % symbol_len != 0 {
            let mut buf = vec![0u8; symbol_len];
            let tail_start = (k as usize - 1) * symbol_len;
            let tail_len = source.len() - tail_start;
            buf[..tail_len].copy_from_slice(&source[tail_start..]);
            Some(buf)
        } else {
            None
        };
        let cdf = robust_soliton_cdf(k);
        Ok(Self {
            source,
            k,
            symbol_len,
            cdf,
            last_padded,
        })
    }

    /// Source-symbol count.
    #[inline]
    #[must_use]
    pub fn k(&self) -> u32 {
        self.k
    }

    /// Symbol length in bytes.
    #[inline]
    #[must_use]
    pub fn symbol_len(&self) -> usize {
        self.symbol_len
    }

    /// Original source length in bytes (pre-padding).
    #[inline]
    #[must_use]
    pub fn source_len(&self) -> usize {
        self.source.len()
    }

    /// Borrow source symbol `i`. Returns the padded slice for the last
    /// symbol if the source isn't an exact multiple of `symbol_len`.
    fn source_symbol(&self, i: u32) -> &[u8] {
        let i_us = i as usize;
        let last = (self.k - 1) as usize;
        if i_us == last {
            if let Some(buf) = &self.last_padded {
                return buf.as_slice();
            }
        }
        let start = i_us * self.symbol_len;
        &self.source[start..start + self.symbol_len]
    }

    /// Encode one symbol with the given `symbol_id`. Returns the XORed
    /// payload of length `symbol_len`.
    #[must_use]
    pub fn encode_symbol(&self, symbol_id: u32) -> Vec<u8> {
        let mut rng = SplitMix64::for_symbol(self.k, symbol_id);
        let d = sample_degree(&self.cdf, &mut rng);
        let neighbors = sample_neighbors(self.k, d, &mut rng);
        // XOR the chosen source symbols.
        let mut out = vec![0u8; self.symbol_len];
        for n in &neighbors {
            let src = self.source_symbol(*n);
            for (o, s) in out.iter_mut().zip(src.iter()) {
                *o ^= *s;
            }
        }
        out
    }

    /// Convenience: re-derive the neighbor set for a given symbol_id
    /// without producing the payload. Useful for tests / diagnostics.
    #[must_use]
    pub fn neighbors_for(&self, symbol_id: u32) -> Vec<u32> {
        let mut rng = SplitMix64::for_symbol(self.k, symbol_id);
        let d = sample_degree(&self.cdf, &mut rng);
        sample_neighbors(self.k, d, &mut rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_source_rejected() {
        let r = LtEncoder::new(&[], 1024);
        assert!(matches!(r, Err(FountainError::EmptySource)));
    }

    #[test]
    fn zero_symbol_len_rejected() {
        let r = LtEncoder::new(&[1u8], 0);
        assert!(matches!(r, Err(FountainError::InvalidSymbolLen(_))));
    }

    #[test]
    fn k_computed_correctly() {
        let buf = vec![0xABu8; 4096];
        let enc = LtEncoder::new(&buf, 1024).unwrap();
        assert_eq!(enc.k(), 4);
    }

    #[test]
    fn k_rounds_up_with_padding() {
        let buf = vec![0xCDu8; 4097];
        let enc = LtEncoder::new(&buf, 1024).unwrap();
        assert_eq!(enc.k(), 5);
        assert_eq!(enc.source_len(), 4097);
    }

    #[test]
    fn deterministic_encoding() {
        let buf = vec![0xDEu8; 4096];
        let enc = LtEncoder::new(&buf, 1024).unwrap();
        let a = enc.encode_symbol(123);
        let b = enc.encode_symbol(123);
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_symbol_ids_produce_distinct_payloads() {
        // Build a buffer where every source symbol is unique (so XOR
        // outputs are non-trivially distinct).
        let mut buf = vec![0u8; 4096];
        for (i, b) in buf.iter_mut().enumerate() {
            // Use a non-byte-periodic mixer so each 1024-byte symbol
            // differs from the next.
            *b = ((i as u32).wrapping_mul(0x9E3779B9) ^ (i as u32 >> 11)) as u8;
        }
        let enc = LtEncoder::new(&buf, 1024).unwrap();
        let mut distinct = 0;
        let mut prev = enc.encode_symbol(0);
        for sid in 1u32..20 {
            let p = enc.encode_symbol(sid);
            if p != prev {
                distinct += 1;
            }
            prev = p;
        }
        // Expect the majority (≥12 of 19) of adjacent pairs to be
        // distinct. With K=4 and the Robust Soliton distribution
        // heavily weighting degree=1, collisions on consecutive small
        // K are not vanishingly rare; we just want to confirm that the
        // encoder isn't always producing the same payload.
        assert!(
            distinct >= 12,
            "expected mostly-distinct adjacent encodings, got {distinct}"
        );
    }
}
