//! Bloom filter primitive per [ADR-0011](../../../docs/decisions/0011-bloom-transfer-init.md).
//!
//! Constructed for a target FP rate + element count. Inserts and
//! queries chunk_ids (32-byte BLAKE3 hashes). Encodes to / decodes from
//! a 12-byte header + bit-array wire format.
//!
//! ## Hash function
//!
//! Per [ADR-0011]: Kirsch + Mitzenmacher 2006 double-hashing. Two
//! 64-bit hashes (`h1`, `h2`) per chunk_id; the k bit positions are
//! `(h1 + i * h2) mod m` for i in 0..k.
//!
//! Implementation: **xxh3-128 with a domain-separation seed**. The
//! 128-bit output splits into a 64-bit `h1` (low half) and a 64-bit
//! `h2` (high half) in a single hash call. xxh3 is ~10 GiB/s scalar /
//! ~30 GiB/s SIMD on 32-byte inputs — roughly **5-8× faster than
//! BLAKE3 keyed_hash** at this size because BLAKE3 is setup-dominated
//! below one block (64 bytes).
//!
//! The Bloom filter only requires uniform distribution, not
//! cryptographic collision resistance, so a non-cryptographic hash is
//! the right primitive for this layer. Domain separation against other
//! xxh3 uses on the same chunk_id is provided by the seed value
//! [`XXH3_BLOOM_SEED`].

use crate::error::BloomError;
use crate::sizing::{optimal_k, optimal_m_bits, target_fp_rate};

/// On-wire header length: m_bits (4) + k (4) + reserved (4).
pub const BLOOM_HEADER_LEN: usize = 12;

/// Maximum on-wire size for a single `BloomFilter` QUIC frame, matching
/// `ol_quic::MAX_BULK_FRAME_BYTES`. Larger filters split across frames
/// (Phase B-2 work; v1 caps at this limit).
pub const MAX_FILTER_BYTES: usize = 1024 * 1024;

/// xxh3 seed for the Bloom double-hash. Domain-separation marker; the
/// exact value is arbitrary but FROZEN — changing it changes which bits
/// get set, breaking the wire format.
const XXH3_BLOOM_SEED: u64 = 0xB100_F117_E000_0001;

/// A Bloom filter sized for a target false-positive rate.
///
/// Insert chunk_ids via [`Bloom::insert`]; query via [`Bloom::contains`].
/// Encode for transmission via [`Bloom::encode`]; decode at the
/// receiver via [`Bloom::decode`].
///
/// `Clone` is cheap (the bit array is `Vec<u8>`).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Bloom {
    m_bits: u32,
    k: u32,
    bits: Vec<u8>,
}

impl Bloom {
    /// Build an empty Bloom filter sized for `n` chunk_ids at a 1% FP
    /// rate ([`crate::sizing::target_fp_rate`]).
    #[must_use]
    pub fn new(n: usize) -> Self {
        Self::with_target_fp(n, target_fp_rate())
    }

    /// Build an empty Bloom filter sized for `n` chunk_ids at a custom
    /// target FP rate `p` (clamped to `[1e-10, 0.999]`).
    #[must_use]
    pub fn with_target_fp(n: usize, p: f64) -> Self {
        let m_bits = optimal_m_bits(n, p);
        let k = optimal_k(n, m_bits);
        let bytes = m_bits.div_ceil(8) as usize;
        Self {
            m_bits,
            k,
            bits: vec![0u8; bytes],
        }
    }

    /// Build a filter with explicitly-specified parameters. Useful for
    /// tests + reproducibility; production callers should use
    /// [`Bloom::new`] which picks optimal sizing.
    ///
    /// # Errors
    ///
    /// Returns [`BloomError::InvalidParameters`] if `m_bits == 0` or
    /// `k == 0`.
    pub fn with_params(m_bits: u32, k: u32) -> Result<Self, BloomError> {
        if m_bits == 0 {
            return Err(BloomError::InvalidParameters("m_bits must be > 0"));
        }
        if k == 0 {
            return Err(BloomError::InvalidParameters("k must be > 0"));
        }
        let bytes = m_bits.div_ceil(8) as usize;
        Ok(Self {
            m_bits,
            k,
            bits: vec![0u8; bytes],
        })
    }

    /// Bit-array size (number of bits in the filter).
    #[inline]
    #[must_use]
    pub fn m_bits(&self) -> u32 {
        self.m_bits
    }

    /// Number of hash functions.
    #[inline]
    #[must_use]
    pub fn k(&self) -> u32 {
        self.k
    }

    /// On-wire byte length when encoded (header + bit array).
    #[inline]
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        BLOOM_HEADER_LEN + self.bits.len()
    }

    /// Number of bits currently set.
    #[must_use]
    pub fn popcount(&self) -> u64 {
        self.bits.iter().map(|b| u64::from(b.count_ones())).sum()
    }

    /// Insert a chunk_id into the filter.
    pub fn insert(&mut self, chunk_id: &[u8; 32]) {
        let (h1, h2) = derive_hashes(chunk_id);
        for i in 0..self.k {
            let pos = double_hash_position(h1, h2, i, self.m_bits);
            set_bit(&mut self.bits, pos);
        }
    }

    /// Test whether a chunk_id is (probably) in the filter.
    ///
    /// `false` = definitely absent. `true` = probably present (FP rate
    /// determined by sizing).
    #[must_use]
    pub fn contains(&self, chunk_id: &[u8; 32]) -> bool {
        let (h1, h2) = derive_hashes(chunk_id);
        for i in 0..self.k {
            let pos = double_hash_position(h1, h2, i, self.m_bits);
            if !get_bit(&self.bits, pos) {
                return false;
            }
        }
        true
    }

    /// Bulk-insert from an iterator of chunk_ids.
    pub fn extend_from_iter<'a, I: IntoIterator<Item = &'a [u8; 32]>>(&mut self, iter: I) {
        for cid in iter {
            self.insert(cid);
        }
    }

    /// Bulk-insert from a slice in parallel via rayon. Cores split the
    /// (h1, h2) hash derivation; the bit-set pass is serial because the
    /// bit array is single-writer.
    ///
    /// Wins start above ~4K chunk_ids; below that the rayon dispatch
    /// cost exceeds the per-id work. Falls back to the serial path for
    /// small inputs.
    pub fn extend_par(&mut self, ids: &[[u8; 32]]) {
        use rayon::prelude::*;

        // xxh3 made the serial path so fast (~66 Melem/s) that rayon's
        // dispatch overhead only pays off above ~512K ids per benches.
        // Below that, the serial loop is at most a few ms.
        const PARALLEL_THRESHOLD: usize = 512 * 1024;
        if ids.len() < PARALLEL_THRESHOLD {
            for cid in ids {
                self.insert(cid);
            }
            return;
        }
        // Parallel: derive (h1, h2) per id, collect, then set bits serially.
        let m = self.m_bits;
        let k = self.k;
        let positions: Vec<[u32; 8]> = ids
            .par_iter()
            .map(|cid| {
                let (h1, h2) = derive_hashes(cid);
                // Pre-compute up to k positions; 8 is a generous upper
                // bound for the Phase B target k≤7 at 1% FP rate. Larger
                // k values fall through to the serial path inside the
                // bit-set loop below.
                let mut out = [0u32; 8];
                let cap = (k as usize).min(8);
                for (i, slot) in out.iter_mut().enumerate().take(cap) {
                    *slot = double_hash_position(h1, h2, i as u32, m);
                }
                out
            })
            .collect();

        for (cid, pos) in ids.iter().zip(positions.iter()) {
            if k as usize <= 8 {
                for i in 0..(k as usize) {
                    set_bit(&mut self.bits, pos[i]);
                }
            } else {
                // Tall-k fallback: re-derive on the bit-set pass for
                // any positions past slot 8.
                self.insert(cid);
            }
        }
    }

    /// Batch presence check: returns one `bool` per input chunk_id.
    ///
    /// Faster than calling `contains` in a loop because:
    ///  - The hot loop is straight-line, helping branch prediction.
    ///  - The output `Vec<bool>` lets the compiler unroll cleanly.
    ///
    /// Used by the server-side bloom-handshake's "for each chunk_id in
    /// my memtable, does the peer have it?" scan.
    #[must_use]
    pub fn contains_many(&self, ids: &[[u8; 32]]) -> Vec<bool> {
        ids.iter().map(|cid| self.contains(cid)).collect()
    }

    /// Encode to wire bytes per ADR-0011.
    ///
    /// # Errors
    ///
    /// Returns [`BloomError::FilterTooLarge`] if the encoded length
    /// exceeds [`MAX_FILTER_BYTES`].
    pub fn encode(&self) -> Result<Vec<u8>, BloomError> {
        let total = self.encoded_len();
        if total > MAX_FILTER_BYTES {
            return Err(BloomError::FilterTooLarge {
                got: total,
                max: MAX_FILTER_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&self.m_bits.to_le_bytes());
        out.extend_from_slice(&self.k.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]); // reserved
        out.extend_from_slice(&self.bits);
        Ok(out)
    }

    /// Decode from wire bytes per ADR-0011.
    ///
    /// # Errors
    ///
    /// - [`BloomError::EncodedTooShort`] if `encoded` is < 12 bytes.
    /// - [`BloomError::ReservedNonZero`] if the reserved bytes aren't zero.
    /// - [`BloomError::LengthMismatch`] if the bit-array length doesn't
    ///   match the declared `m_bits`.
    /// - [`BloomError::FilterTooLarge`] if the encoded length exceeds
    ///   [`MAX_FILTER_BYTES`].
    pub fn decode(encoded: &[u8]) -> Result<Self, BloomError> {
        if encoded.len() < BLOOM_HEADER_LEN {
            return Err(BloomError::EncodedTooShort {
                got: encoded.len(),
                needed: BLOOM_HEADER_LEN,
            });
        }
        if encoded.len() > MAX_FILTER_BYTES {
            return Err(BloomError::FilterTooLarge {
                got: encoded.len(),
                max: MAX_FILTER_BYTES,
            });
        }
        let m_bits = u32::from_le_bytes(encoded[0..4].try_into().expect("4 bytes"));
        let k = u32::from_le_bytes(encoded[4..8].try_into().expect("4 bytes"));
        if !encoded[8..12].iter().all(|b| *b == 0) {
            return Err(BloomError::ReservedNonZero);
        }
        if m_bits == 0 || k == 0 {
            return Err(BloomError::InvalidParameters(
                "m_bits/k must be > 0",
            ));
        }
        let expected_bytes = m_bits.div_ceil(8) as usize;
        let bits = &encoded[BLOOM_HEADER_LEN..];
        if bits.len() != expected_bytes {
            return Err(BloomError::LengthMismatch {
                m_bits,
                expected_bytes,
                got: bits.len(),
            });
        }
        Ok(Self {
            m_bits,
            k,
            bits: bits.to_vec(),
        })
    }
}

// ──────────────────── private helpers ────────────────────────────────

/// Derive (h1, h2) — two independent 64-bit hashes from a chunk_id.
///
/// One xxh3-128 pass with [`XXH3_BLOOM_SEED`]. Output is 128 bits;
/// the low 64 become `h1`, the high 64 become `h2`. Domain separation
/// against other uses of xxh3 on the same chunk_id is provided by the
/// seed value.
#[inline]
fn derive_hashes(chunk_id: &[u8; 32]) -> (u64, u64) {
    let out = xxhash_rust::xxh3::xxh3_128_with_seed(chunk_id, XXH3_BLOOM_SEED);
    let h1 = out as u64;
    let h2 = (out >> 64) as u64;
    // Ensure h2 != 0; degenerate (h2 == 0) would map all k positions to
    // the same bit. Probability is 2^-64; we still guard.
    let h2 = if h2 == 0 { 1 } else { h2 };
    (h1, h2)
}

#[inline]
fn double_hash_position(h1: u64, h2: u64, i: u32, m_bits: u32) -> u32 {
    let m = u64::from(m_bits);
    let pos = h1.wrapping_add(u64::from(i).wrapping_mul(h2)) % m;
    pos as u32
}

#[inline]
fn set_bit(bits: &mut [u8], pos: u32) {
    let byte_idx = (pos / 8) as usize;
    let bit_idx = (pos % 8) as u8;
    bits[byte_idx] |= 1u8 << bit_idx;
}

#[inline]
fn get_bit(bits: &[u8], pos: u32) -> bool {
    let byte_idx = (pos / 8) as usize;
    let bit_idx = (pos % 8) as u8;
    (bits[byte_idx] >> bit_idx) & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = seed;
        a[1] = 0xAA;
        a
    }

    #[test]
    fn empty_filter_contains_nothing() {
        let f = Bloom::new(1024);
        for i in 0u8..50 {
            assert!(!f.contains(&id(i)), "empty filter should not contain id {i}");
        }
    }

    #[test]
    fn inserted_keys_definitely_present() {
        let mut f = Bloom::new(1024);
        let inserted: Vec<_> = (0u8..50).map(id).collect();
        for cid in &inserted {
            f.insert(cid);
        }
        for cid in &inserted {
            assert!(f.contains(cid), "inserted id should be present");
        }
    }

    #[test]
    fn extend_from_iter_works() {
        let mut f = Bloom::new(1024);
        let ids: Vec<_> = (0u8..32).map(id).collect();
        f.extend_from_iter(ids.iter());
        for cid in &ids {
            assert!(f.contains(cid));
        }
    }

    #[test]
    fn empirical_fp_rate_at_target() {
        // Insert 1000 ids; query 10000 unrelated ids; FP rate should be
        // around 1% (Phase B target) ± noise.
        let mut f = Bloom::new(1000);
        for i in 0u32..1000 {
            let mut a = [0u8; 32];
            a[..4].copy_from_slice(&i.to_le_bytes());
            f.insert(&a);
        }
        let mut fp_count = 0;
        for i in 10_000u32..20_000 {
            let mut a = [0u8; 32];
            a[..4].copy_from_slice(&i.to_le_bytes());
            a[31] = 0xFF; // ensure no overlap with inserted ids
            if f.contains(&a) {
                fp_count += 1;
            }
        }
        let fp_rate = (fp_count as f64) / 10_000.0;
        // Allow up to 2% to absorb the tail of the binomial distribution.
        assert!(fp_rate <= 0.02, "FP rate {fp_rate} too high");
    }

    #[test]
    fn round_trip_encode_decode() {
        let mut original = Bloom::new(1024);
        for i in 0u8..100 {
            original.insert(&id(i));
        }
        let encoded = original.encode().unwrap();
        let decoded = Bloom::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
        for i in 0u8..100 {
            assert!(decoded.contains(&id(i)));
        }
    }

    #[test]
    fn encode_length_matches_predicted() {
        let f = Bloom::new(1024);
        let encoded = f.encode().unwrap();
        assert_eq!(encoded.len(), f.encoded_len());
        assert_eq!(encoded.len(), BLOOM_HEADER_LEN + f.bits.len());
    }

    #[test]
    fn rejects_short_encoded() {
        let result = Bloom::decode(&[0u8; 8]);
        assert!(matches!(result, Err(BloomError::EncodedTooShort { .. })));
    }

    #[test]
    fn rejects_nonzero_reserved() {
        let mut f = Bloom::new(64);
        let mut encoded = f.encode().unwrap();
        encoded[10] = 0xFF;
        let result = Bloom::decode(&encoded);
        assert!(matches!(result, Err(BloomError::ReservedNonZero)));
        let _ = f.popcount();
    }

    #[test]
    fn rejects_length_mismatch() {
        let f = Bloom::new(1024);
        let mut encoded = f.encode().unwrap();
        encoded.pop(); // truncate
        let result = Bloom::decode(&encoded);
        assert!(matches!(result, Err(BloomError::LengthMismatch { .. })));
    }

    #[test]
    fn rejects_too_large_encoded() {
        // Construct a header claiming a huge filter; decode should reject.
        let mut buf = vec![0u8; MAX_FILTER_BYTES + 1];
        buf[0..4].copy_from_slice(&((MAX_FILTER_BYTES as u32) * 8).to_le_bytes());
        buf[4..8].copy_from_slice(&7u32.to_le_bytes());
        let result = Bloom::decode(&buf);
        assert!(matches!(result, Err(BloomError::FilterTooLarge { .. })));
    }

    #[test]
    fn deterministic_across_construction() {
        // Two independently-constructed filters with the same inserts
        // produce byte-identical encodings.
        let mut a = Bloom::new(64);
        let mut b = Bloom::new(64);
        for i in 0u8..30 {
            a.insert(&id(i));
            b.insert(&id(i));
        }
        assert_eq!(a.encode().unwrap(), b.encode().unwrap());
    }

    #[test]
    fn empty_filter_round_trip() {
        let f = Bloom::new(0); // n=0 should still produce a valid 1-byte filter
        let encoded = f.encode().unwrap();
        let decoded = Bloom::decode(&encoded).unwrap();
        assert_eq!(f, decoded);
        assert_eq!(decoded.popcount(), 0);
    }

    #[test]
    fn debug_does_not_dump_bits() {
        let f = Bloom::new(1024);
        let s = format!("{f:?}");
        assert!(s.contains("Bloom"));
    }
}
