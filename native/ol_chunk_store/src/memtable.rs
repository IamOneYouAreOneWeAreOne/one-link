//! `Memtable` — in-memory chunk_id → location index with a Bloom filter
//! front for sub-microsecond presence checks.
//!
//! Per [ADR-0003](../../../docs/decisions/0003-on-disk-format.md) the
//! Bloom filter sits in front of the LSM SST files; while we don't
//! persist SSTs in Phase A1 (rebuilt from the chunk_log on every boot),
//! we still expose the bloom interface so the higher layers can use it
//! the same way Phase B's flushed SSTs will.
//!
//! Bloom parameters:
//! - 10 bits per chunk_id (~1% false-positive rate)
//! - SipHash-1-3 (the `bloomfilter` crate's default) — deterministic
//!   under a fixed seed, hardware-friendly
//! - Capacity grows with the chunk count via re-allocation when the
//!   load factor exceeds 0.7 (Phase B optimization will switch to a
//!   scalable bloom; A1 uses a single right-sized table).
//!
//! Determinism: insertion order does not affect lookup outcomes
//! (the bloom is order-independent; the hashmap returns deterministic
//! values for any key).

use std::collections::HashMap;

use bloomfilter::Bloom;

use crate::location::ChunkLocation;

/// Default expected chunk count when the memtable has no prior estimate.
/// 64K chunks ≈ 4 GiB at the 64 KiB ADR-0001 mean — generous default
/// that doesn't waste memory on empty stores.
const DEFAULT_BLOOM_CAPACITY: usize = 64 * 1024;

/// In-memory chunk_id → ChunkLocation index.
///
/// Maintained by [`crate::store::ChunkStore`] across the chunk_log
/// replay and live writes. Lookups go through the Bloom filter first so
/// negative answers cost ~100 ns; positive bloom hits go to the
/// hashmap for the actual location.
pub struct Memtable {
    /// chunk_id → location.
    map: HashMap<[u8; 32], ChunkLocation>,
    /// Presence-only bloom for fast negative lookups.
    bloom: Bloom<[u8; 32]>,
}

impl std::fmt::Debug for Memtable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Memtable")
            .field("len", &self.map.len())
            .finish()
    }
}

impl Default for Memtable {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_BLOOM_CAPACITY)
    }
}

impl Memtable {
    /// Create a memtable sized for the given expected chunk count.
    /// The bloom filter is computed for ~1% false-positive rate.
    #[must_use]
    pub fn with_capacity(expected_chunks: usize) -> Self {
        // bloomfilter::Bloom needs at least 1 bit. Clamp.
        let n = expected_chunks.max(8);
        // 1% FP rate → ~10 bits/key, ~7 hash functions.
        let bloom = Bloom::new_for_fp_rate(n, 0.01).expect("bloom params valid");
        Self {
            map: HashMap::with_capacity(n),
            bloom,
        }
    }

    /// Number of chunks indexed.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True iff the memtable has no chunks.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Insert a chunk_id → location pair. Updates both the hashmap and
    /// the bloom.
    pub fn insert(&mut self, chunk_id: [u8; 32], location: ChunkLocation) {
        self.bloom.set(&chunk_id);
        self.map.insert(chunk_id, location);
    }

    /// Bloom-only presence check. Returns `false` only when the chunk
    /// is *definitely* absent; `true` may be a false positive.
    #[inline]
    #[must_use]
    pub fn bloom_check(&self, chunk_id: &[u8; 32]) -> bool {
        self.bloom.check(chunk_id)
    }

    /// Authoritative presence check (bloom + hashmap).
    #[inline]
    #[must_use]
    pub fn contains(&self, chunk_id: &[u8; 32]) -> bool {
        self.bloom.check(chunk_id) && self.map.contains_key(chunk_id)
    }

    /// Look up a location. Returns `None` if absent.
    #[inline]
    #[must_use]
    pub fn get(&self, chunk_id: &[u8; 32]) -> Option<&ChunkLocation> {
        if !self.bloom.check(chunk_id) {
            return None;
        }
        self.map.get(chunk_id)
    }

    /// Remove a chunk_id from the index. Note: the bloom filter cannot
    /// "unset" a key; later bloom_check() may still return true (false
    /// positive). The hashmap is the source of truth for definitive
    /// presence.
    pub fn remove(&mut self, chunk_id: &[u8; 32]) -> Option<ChunkLocation> {
        self.map.remove(chunk_id)
    }

    /// Iterate (chunk_id, location) pairs. Order is HashMap iteration
    /// order — non-deterministic; callers that need order must sort.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 32], &ChunkLocation)> {
        self.map.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stripe::StripeDescriptor;

    fn loc(file_id: u64, offset: u64) -> ChunkLocation {
        ChunkLocation {
            file_id,
            wal_offset: offset,
            length_plaintext: 64 * 1024,
            length_ciphertext: 64 * 1024 + 64,
            ratchet_key_id: [0u8; 16],
            stripe_descriptor: StripeDescriptor::NONE,
        }
    }

    fn id(b: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = b;
        a
    }

    #[test]
    fn empty_memtable() {
        let m = Memtable::with_capacity(16);
        assert_eq!(m.len(), 0);
        assert!(m.is_empty());
        assert!(!m.contains(&id(1)));
        assert!(m.get(&id(1)).is_none());
    }

    #[test]
    fn insert_and_get() {
        let mut m = Memtable::with_capacity(16);
        m.insert(id(1), loc(1, 64));
        m.insert(id(2), loc(1, 200));
        assert_eq!(m.len(), 2);
        assert!(m.contains(&id(1)));
        assert!(m.contains(&id(2)));
        assert!(!m.contains(&id(99)));
        let got = m.get(&id(1)).unwrap();
        assert_eq!(got.file_id, 1);
        assert_eq!(got.wal_offset, 64);
    }

    #[test]
    fn bloom_eliminates_definite_absence() {
        let mut m = Memtable::with_capacity(1024);
        for i in 0u8..50 {
            m.insert(id(i), loc(1, 100 + u64::from(i)));
        }
        // For chunk_ids never inserted, bloom_check should be mostly
        // false (some false positives expected at <2% rate).
        let mut definite_absences = 0;
        for i in 100u8..255 {
            if !m.bloom_check(&id(i)) {
                definite_absences += 1;
            }
        }
        // Expect the vast majority to be definite absences.
        assert!(
            definite_absences > 100,
            "expected most never-inserted ids to be bloom-rejected, got {definite_absences}"
        );
    }

    #[test]
    fn remove_works() {
        let mut m = Memtable::with_capacity(16);
        m.insert(id(1), loc(1, 64));
        let removed = m.remove(&id(1));
        assert!(removed.is_some());
        assert!(!m.contains(&id(1)));
    }

    #[test]
    fn iter_visits_all() {
        let mut m = Memtable::with_capacity(16);
        for i in 0u8..10 {
            m.insert(id(i), loc(1, u64::from(i)));
        }
        let count = m.iter().count();
        assert_eq!(count, 10);
    }

    #[test]
    fn debug_does_not_panic() {
        let m = Memtable::with_capacity(16);
        let s = format!("{:?}", m);
        assert!(s.contains("Memtable"));
    }
}
