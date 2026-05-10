//! LT decoder: belief-propagation reconstruction of source symbols from
//! a stream of encoded packets.
//!
//! Algorithm (standard LT decoding):
//!
//! 1. Each incoming encoded symbol is stored with its (deterministic)
//!    neighbor set computed from `(k, symbol_id)`.
//! 2. If any encoded symbol has exactly one *unresolved* neighbor, that
//!    neighbor is recovered: source[n] = encoded XOR XOR(all-other-resolved-neighbors).
//! 3. Once a source is resolved, every encoded symbol whose neighbor
//!    set includes it XORs it out + drops it from its neighbor set.
//! 4. Repeat until no degree-1 encoded symbols exist or all sources
//!    are resolved.
//!
//! This is O((K + N) × d_avg) per ingest in the worst case, where N is
//! the number of encoded symbols held. For K ≤ 256 and d_avg ≈ 4, this
//! is microseconds per ingest.

use std::collections::{HashMap, VecDeque};

use crate::distribution::{robust_soliton_cdf, sample_degree, sample_neighbors};
use crate::error::FountainError;
use crate::rng::SplitMix64;

/// Maximum encoded-symbol count the decoder will hold per chunk. Caps
/// memory at K * symbol_len * MAX_ENCODED_PER_CHUNK / K = symbol_len *
/// MAX_ENCODED_PER_CHUNK bytes ≈ 1 MiB for symbol_len=1024.
pub const MAX_ENCODED_PER_CHUNK: u32 = 1024;

/// Per-packet state inside the decoder: payload + remaining-unresolved
/// neighbors. As neighbors are recovered they get XORed out of `payload`
/// and removed from `neighbors`.
struct PendingPacket {
    payload: Vec<u8>,
    neighbors: Vec<u32>,
}

/// LT decoder for a single chunk.
pub struct LtDecoder {
    k: u32,
    symbol_len: usize,
    source_len: usize,
    /// Resolved source symbols. `None` until decoded.
    sources: Vec<Option<Vec<u8>>>,
    /// Pending encoded packets keyed by symbol_id (so duplicates are
    /// dropped silently).
    pending: HashMap<u32, PendingPacket>,
    /// Reverse index: source-symbol index → set of symbol_ids whose
    /// neighbor sets currently include it. Used for fast propagation.
    inverse: HashMap<u32, std::collections::BTreeSet<u32>>,
    /// Queue of packets currently at degree-1, ready to resolve. We
    /// push to the back on ingest / cascade and pop from the front in
    /// propagate. This converts the O(pending) linear scan in the
    /// classical decoder to O(1) amortized per resolution.
    degree1_queue: VecDeque<u32>,
    /// Number of source symbols resolved so far.
    resolved: u32,
    /// Degree CDF cached.
    cdf: Vec<f64>,
}

impl std::fmt::Debug for LtDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LtDecoder")
            .field("k", &self.k)
            .field("resolved", &self.resolved)
            .field("pending", &self.pending.len())
            .finish()
    }
}

impl LtDecoder {
    /// Build a decoder for a chunk with `k` source symbols, each of
    /// length `symbol_len`, encoding an original source of `source_len`
    /// bytes (≤ `k * symbol_len`).
    ///
    /// # Errors
    ///
    /// [`FountainError::InvalidSymbolLen`] if `symbol_len == 0`.
    pub fn new(k: u32, symbol_len: usize, source_len: usize) -> Result<Self, FountainError> {
        if symbol_len == 0 {
            return Err(FountainError::InvalidSymbolLen("must be > 0"));
        }
        if source_len > (k as usize) * symbol_len {
            return Err(FountainError::InvalidSymbolLen(
                "source_len > k * symbol_len",
            ));
        }
        Ok(Self {
            k,
            symbol_len,
            source_len,
            sources: vec![None; k as usize],
            pending: HashMap::new(),
            inverse: HashMap::new(),
            degree1_queue: VecDeque::new(),
            resolved: 0,
            cdf: robust_soliton_cdf(k),
        })
    }

    /// K (source-symbol count).
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

    /// Number of source symbols resolved so far.
    #[inline]
    #[must_use]
    pub fn resolved_count(&self) -> u32 {
        self.resolved
    }

    /// True iff all K source symbols are resolved.
    #[inline]
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.resolved == self.k
    }

    /// Ingest one encoded packet. Returns `Ok(true)` when this packet
    /// completed the decode; `Ok(false)` otherwise.
    ///
    /// # Errors
    ///
    /// - [`FountainError::SymbolLenMismatch`] if `payload.len() !=
    ///   symbol_len`.
    /// - [`FountainError::SymbolIdOverflow`] if `symbol_id >=
    ///   MAX_ENCODED_PER_CHUNK`.
    pub fn ingest(&mut self, symbol_id: u32, payload: &[u8]) -> Result<bool, FountainError> {
        if self.is_complete() {
            return Ok(true);
        }
        if payload.len() != self.symbol_len {
            return Err(FountainError::SymbolLenMismatch {
                expected: self.symbol_len,
                got: payload.len(),
            });
        }
        if symbol_id >= MAX_ENCODED_PER_CHUNK {
            return Err(FountainError::SymbolIdOverflow {
                got: symbol_id,
                max: MAX_ENCODED_PER_CHUNK,
            });
        }
        if self.pending.contains_key(&symbol_id) {
            // Duplicate; drop.
            return Ok(self.is_complete());
        }

        let mut rng = SplitMix64::for_symbol(self.k, symbol_id);
        let d = sample_degree(&self.cdf, &mut rng);
        let neighbors = sample_neighbors(self.k, d, &mut rng);

        // Pre-XOR any already-resolved neighbors out of the payload.
        let mut working_payload = payload.to_vec();
        let mut unresolved = Vec::with_capacity(neighbors.len());
        for n in &neighbors {
            if let Some(src) = &self.sources[*n as usize] {
                for (o, s) in working_payload.iter_mut().zip(src.iter()) {
                    *o ^= *s;
                }
            } else {
                unresolved.push(*n);
            }
        }

        // If after pre-resolution the packet has 0 unresolved neighbors,
        // it's redundant; drop it.
        if unresolved.is_empty() {
            return Ok(self.is_complete());
        }

        // Insert pending + update reverse index.
        for n in &unresolved {
            self.inverse
                .entry(*n)
                .or_insert_with(std::collections::BTreeSet::new)
                .insert(symbol_id);
        }
        let neighbor_count = unresolved.len();
        self.pending.insert(
            symbol_id,
            PendingPacket {
                payload: working_payload,
                neighbors: unresolved,
            },
        );
        if neighbor_count == 1 {
            self.degree1_queue.push_back(symbol_id);
        }

        // Propagate any degree-1 packets.
        self.propagate();
        Ok(self.is_complete())
    }

    /// Belief-propagation pass: drain the degree-1 queue, resolving the
    /// referenced source for each and cascading into dependents. New
    /// degree-1 packets discovered during cascade are pushed to the
    /// queue and picked up in the same drain.
    ///
    /// Complexity: O(N_resolved × d_avg × symbol_len) where N_resolved
    /// is at most K. The previous implementation scanned all pending
    /// packets per resolution (O(K × pending)) — this version is
    /// O(K × d_avg).
    fn propagate(&mut self) {
        while let Some(sid) = self.degree1_queue.pop_front() {
            // Stale entry — the packet may have been resolved (and
            // removed) via cascade since it was queued, or its degree
            // may no longer be 1 (a cascade XOR'd in extra neighbors,
            // which never happens in LT codes, but be defensive).
            let pkt = match self.pending.remove(&sid) {
                Some(p) if p.neighbors.len() == 1 => p,
                Some(p) => {
                    self.pending.insert(sid, p);
                    continue;
                }
                None => continue,
            };
            let target = pkt.neighbors[0];
            // pkt.payload IS source[target].
            self.sources[target as usize] = Some(pkt.payload.clone());
            self.resolved += 1;
            let dependents = self.inverse.remove(&target).unwrap_or_default();
            for dep_sid in dependents {
                if dep_sid == sid {
                    continue;
                }
                if let Some(dep) = self.pending.get_mut(&dep_sid) {
                    if let Some(pos) = dep.neighbors.iter().position(|n| *n == target) {
                        dep.neighbors.remove(pos);
                        for (o, s) in dep.payload.iter_mut().zip(pkt.payload.iter()) {
                            *o ^= *s;
                        }
                        if dep.neighbors.len() == 1 {
                            self.degree1_queue.push_back(dep_sid);
                        }
                    }
                }
            }
            if self.is_complete() {
                self.degree1_queue.clear();
                break;
            }
        }
    }

    /// Consume the decoder + return the reconstructed source bytes.
    ///
    /// # Errors
    ///
    /// [`FountainError::IncompleteDecode`] if not all K sources have
    /// been resolved.
    pub fn finish(self) -> Result<Vec<u8>, FountainError> {
        if !self.is_complete() {
            return Err(FountainError::IncompleteDecode {
                resolved: self.resolved,
                k: self.k,
            });
        }
        let mut out = Vec::with_capacity(self.source_len);
        for i in 0..self.k as usize {
            let s = self.sources[i].as_ref().expect("resolved");
            out.extend_from_slice(s);
        }
        out.truncate(self.source_len);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::LtEncoder;

    fn deterministic_buf(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| ((i as u32).wrapping_mul(0x9E3779B9) ^ u32::from(seed)) as u8)
            .collect()
    }

    #[test]
    fn round_trip_small_k() {
        let buf = deterministic_buf(0x42, 8 * 1024);
        let enc = LtEncoder::new(&buf, 1024).unwrap();
        let mut dec = LtDecoder::new(enc.k(), 1024, buf.len()).unwrap();
        for sid in 0u32..200 {
            let payload = enc.encode_symbol(sid);
            if dec.ingest(sid, &payload).unwrap() {
                break;
            }
        }
        assert!(dec.is_complete());
        let recovered = dec.finish().unwrap();
        assert_eq!(recovered, buf);
    }

    #[test]
    fn round_trip_k_64() {
        let buf = deterministic_buf(0xAA, 64 * 1024);
        let enc = LtEncoder::new(&buf, 1024).unwrap();
        let mut dec = LtDecoder::new(enc.k(), 1024, buf.len()).unwrap();
        for sid in 0u32..400 {
            let payload = enc.encode_symbol(sid);
            if dec.ingest(sid, &payload).unwrap() {
                break;
            }
        }
        assert!(dec.is_complete(), "decoder did not complete at sid=400");
        let recovered = dec.finish().unwrap();
        assert_eq!(recovered, buf);
    }

    #[test]
    fn round_trip_unaligned_size() {
        // 8200 bytes = 8 full symbols + 8 padding bytes.
        let buf = deterministic_buf(0xCC, 8200);
        let enc = LtEncoder::new(&buf, 1024).unwrap();
        assert_eq!(enc.k(), 9);
        let mut dec = LtDecoder::new(enc.k(), 1024, buf.len()).unwrap();
        for sid in 0u32..300 {
            let payload = enc.encode_symbol(sid);
            if dec.ingest(sid, &payload).unwrap() {
                break;
            }
        }
        assert!(dec.is_complete());
        let recovered = dec.finish().unwrap();
        assert_eq!(recovered.len(), 8200);
        assert_eq!(recovered, buf);
    }

    #[test]
    fn duplicate_packets_handled() {
        let buf = deterministic_buf(0x11, 8 * 1024);
        let enc = LtEncoder::new(&buf, 1024).unwrap();
        let mut dec = LtDecoder::new(enc.k(), 1024, buf.len()).unwrap();
        // Ingest the same packet 10 times.
        let p = enc.encode_symbol(7);
        for _ in 0..10 {
            let _ = dec.ingest(7, &p).unwrap();
        }
        // Then deliver fresh packets until decode completes.
        for sid in 0u32..200 {
            if dec.ingest(sid, &enc.encode_symbol(sid)).unwrap() {
                break;
            }
        }
        assert!(dec.is_complete());
    }

    #[test]
    fn rejects_wrong_symbol_len() {
        let mut dec = LtDecoder::new(8, 1024, 8 * 1024).unwrap();
        let bad = vec![0u8; 512];
        let r = dec.ingest(0, &bad);
        assert!(matches!(r, Err(FountainError::SymbolLenMismatch { .. })));
    }

    #[test]
    fn rejects_symbol_id_overflow() {
        let mut dec = LtDecoder::new(8, 1024, 8 * 1024).unwrap();
        let bad = vec![0u8; 1024];
        let r = dec.ingest(MAX_ENCODED_PER_CHUNK + 100, &bad);
        assert!(matches!(r, Err(FountainError::SymbolIdOverflow { .. })));
    }

    #[test]
    fn finish_on_incomplete_fails() {
        let dec = LtDecoder::new(8, 1024, 8 * 1024).unwrap();
        let r = dec.finish();
        assert!(matches!(r, Err(FountainError::IncompleteDecode { .. })));
    }
}
