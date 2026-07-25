//! LT encoder: takes a source buffer + `symbol_len`; produces one encoded
//! symbol per call.

use std::borrow::Cow;

use crate::decoder::{MAX_SOURCE_BYTES, MAX_SOURCE_SYMBOLS_PER_CHUNK, MAX_SYMBOL_LEN};
use crate::distribution::{robust_soliton_cdf, sample_degree, sample_neighbors};
use crate::error::FountainError;
use crate::rng::SplitMix64;
use crate::xor::xor_into;

/// LT encoder over a fixed source buffer.
///
/// Constructed once per chunk; `encode_symbol(symbol_id)` returns one
/// `XORed` payload of length `symbol_len`. Senders typically call this
/// in a monotonic loop until the receiver signals decode complete.
pub struct LtEncoder<'a> {
    source: Cow<'a, [u8]>,
    k: u32,
    symbol_len: usize,
    cdf: Vec<f64>,
    /// Padding for the last source symbol when `source.len() % symbol_len != 0`.
    /// Owned so `encode_symbol` can return a slice into either `source`
    /// or this padding buffer.
    last_padded: Option<Vec<u8>>,
}

impl std::fmt::Debug for LtEncoder<'_> {
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
        Self::from_cow(Cow::Borrowed(source), symbol_len)
    }

    /// Build an encoder which owns its source bytes. This is the
    /// efficient FFI shape: the robust-soliton CDF and final-symbol
    /// padding are computed once, then reused across every
    /// `encode_symbol` call.
    pub fn from_owned(
        source: Vec<u8>,
        symbol_len: usize,
    ) -> Result<LtEncoder<'static>, FountainError> {
        LtEncoder::from_cow(Cow::Owned(source), symbol_len)
    }

    fn from_cow(source: Cow<'a, [u8]>, symbol_len: usize) -> Result<Self, FountainError> {
        if symbol_len == 0 {
            return Err(FountainError::InvalidSymbolLen("must be > 0"));
        }
        if symbol_len > MAX_SYMBOL_LEN {
            return Err(FountainError::InvalidSymbolLen(
                "must be in 1..=MAX_SYMBOL_LEN",
            ));
        }
        if source.is_empty() {
            return Err(FountainError::EmptySource);
        }
        if source.len() > MAX_SOURCE_BYTES {
            return Err(FountainError::SourceTooLarge {
                got: source.len(),
                max: MAX_SOURCE_BYTES,
            });
        }
        let k_usize = source.len().div_ceil(symbol_len);
        let k = u32::try_from(k_usize).map_err(|_| FountainError::InvalidSourceSymbolCount {
            got: u32::MAX,
            max: MAX_SOURCE_SYMBOLS_PER_CHUNK,
        })?;
        if k > MAX_SOURCE_SYMBOLS_PER_CHUNK {
            return Err(FountainError::InvalidSourceSymbolCount {
                got: k,
                max: MAX_SOURCE_SYMBOLS_PER_CHUNK,
            });
        }
        let last_padded = if source.len().is_multiple_of(symbol_len) {
            None
        } else {
            let mut buf = vec![0u8; symbol_len];
            let tail_start = (k as usize - 1) * symbol_len;
            let tail_len = source.len() - tail_start;
            buf[..tail_len].copy_from_slice(&source[tail_start..]);
            Some(buf)
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

    /// Encode one symbol with the given `symbol_id`. Returns the `XORed`
    /// payload of length `symbol_len`.
    #[must_use]
    pub fn encode_symbol(&self, symbol_id: u32) -> Vec<u8> {
        let mut rng = SplitMix64::for_symbol(self.k, symbol_id);
        let d = sample_degree(&self.cdf, &mut rng);
        let neighbors = sample_neighbors(self.k, d, &mut rng);
        // First neighbor: clone directly into the output buffer (skips
        // a zero-fill + first XOR-against-zero, which is the dominant
        // cost at degree=1 under Robust Soliton).
        let mut iter = neighbors.iter();
        let first = *iter.next().expect("sample_neighbors yields ≥ 1");
        let mut out = self.source_symbol(first).to_vec();
        // Remaining neighbors: word-wide XOR into `out`.
        for n in iter {
            let lengths_match = xor_into(&mut out, self.source_symbol(*n));
            debug_assert!(lengths_match, "encoder source-symbol invariant");
        }
        out
    }

    /// Convenience: re-derive the neighbor set for a given `symbol_id`
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
    fn rejects_resource_exhaustion_shapes() {
        let too_many_symbols = vec![0u8; MAX_SOURCE_SYMBOLS_PER_CHUNK as usize + 1];
        assert!(matches!(
            LtEncoder::new(&too_many_symbols, 1),
            Err(FountainError::InvalidSourceSymbolCount { .. })
        ));
        let too_large = vec![0u8; MAX_SOURCE_BYTES + 1];
        assert!(matches!(
            LtEncoder::new(&too_large, 1024),
            Err(FountainError::SourceTooLarge { .. })
        ));
    }

    #[test]
    fn owned_encoder_matches_borrowed_encoder() {
        let source = vec![0xA5; 64 * 1024];
        let borrowed = LtEncoder::new(&source, 1024).unwrap();
        let owned = LtEncoder::from_owned(source.clone(), 1024).unwrap();
        for symbol_id in [0, 1, 17, 1023, u32::MAX] {
            assert_eq!(
                borrowed.encode_symbol(symbol_id),
                owned.encode_symbol(symbol_id)
            );
        }
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
            let index = u32::try_from(i).expect("test buffer index fits in u32");
            let mixed = index.wrapping_mul(0x9E37_79B9) ^ (index >> 11);
            *b = u8::try_from(mixed & 0xFF).expect("masked mixer output fits in u8");
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
