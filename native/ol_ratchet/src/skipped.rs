//! Bounded skipped-key store.
//!
//! Receivers see chunks reordered (especially under fountain delivery
//! per ADR-0015). When chunk N arrives before chunk N-1, the receiver
//! advances the chain to step N+1 but stashes the unused key for step
//! N-1 in this store so it can decrypt N-1 when it arrives.
//!
//! Capacity is bounded to prevent a malicious peer from forcing us to
//! materialize unbounded key state.

use std::collections::{BTreeMap, VecDeque};

use crate::chain::MessageKey;
#[cfg(test)]
use crate::chain::MESSAGE_KEY_LEN;
use crate::error::RatchetError;

/// Default capacity. Tuned so that a moderately-out-of-order fountain
/// stream (up to ~1024 in-flight symbols per ADR-0015) can be buffered
/// without overflow.
pub const DEFAULT_SKIPPED_CAP: usize = 1024;

/// A bounded LRU buffer of `(step → message_key)` entries.
///
/// Keys are evicted in FIFO order on overflow — the oldest skipped key
/// drops when capacity is exceeded. Receivers should size this to
/// match the worst-case reordering window.
pub struct SkippedKeyStore {
    /// step → key. Use `BTreeMap` so iteration is in step-order (useful
    /// for diagnostics + deterministic ordering across platforms).
    map: BTreeMap<u64, MessageKey>,
    /// Insertion order so we can evict the oldest entry.
    order: VecDeque<u64>,
    cap: usize,
}

impl std::fmt::Debug for SkippedKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkippedKeyStore")
            .field("size", &self.map.len())
            .field("cap", &self.cap)
            .finish_non_exhaustive()
    }
}

impl Default for SkippedKeyStore {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_SKIPPED_CAP)
    }
}

impl SkippedKeyStore {
    /// Build a store with `cap` slots.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            map: BTreeMap::new(),
            order: VecDeque::with_capacity(cap),
            cap,
        }
    }

    /// Number of skipped keys currently held.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True iff empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Capacity.
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Store a key for `step`. Evicts the oldest entry if at capacity.
    ///
    /// # Errors
    ///
    /// [`RatchetError::SkippedStoreFull`] only if `cap == 0`. Normal
    /// overflow is handled silently via FIFO eviction.
    pub fn insert(&mut self, step: u64, key: MessageKey) -> Result<(), RatchetError> {
        if self.cap == 0 {
            return Err(RatchetError::SkippedStoreFull { cap: self.cap });
        }
        // If we're at cap and this step isn't already in the map, evict.
        if !self.map.contains_key(&step) && self.map.len() == self.cap {
            if let Some(oldest) = self.order.pop_front() {
                self.map.remove(&oldest);
            }
        }
        // Insert or overwrite.
        if !self.map.contains_key(&step) {
            self.order.push_back(step);
        }
        self.map.insert(step, key);
        Ok(())
    }

    /// Retrieve + remove the key for `step`. Returns the key (zeroized
    /// on drop unless the caller transfers ownership).
    ///
    /// # Errors
    ///
    /// [`RatchetError::SkippedKeyNotFound`] if no key for that step.
    pub fn take(&mut self, step: u64) -> Result<MessageKey, RatchetError> {
        let mk = self
            .map
            .remove(&step)
            .ok_or(RatchetError::SkippedKeyNotFound { step })?;
        if let Some(pos) = self.order.iter().position(|s| *s == step) {
            self.order.remove(pos);
        }
        Ok(mk)
    }

    /// Drop any keys older than `min_step` — used by the receiver to
    /// expire skipped keys that have aged out of relevance.
    pub fn drop_older_than(&mut self, min_step: u64) {
        let to_drop: Vec<u64> = self.map.range(..min_step).map(|(s, _)| *s).collect();
        for s in to_drop {
            self.map.remove(&s);
            if let Some(pos) = self.order.iter().position(|x| *x == s) {
                self.order.remove(pos);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn key(seed: u8) -> MessageKey {
        Zeroizing::new([seed; MESSAGE_KEY_LEN])
    }

    #[test]
    fn insert_and_take() {
        let mut s = SkippedKeyStore::with_capacity(8);
        s.insert(3, key(0xAA)).unwrap();
        s.insert(7, key(0xBB)).unwrap();
        assert_eq!(s.len(), 2);

        let mk = s.take(3).unwrap();
        assert_eq!(*mk, [0xAAu8; 32]);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn take_missing_returns_err() {
        let mut s = SkippedKeyStore::with_capacity(4);
        let r = s.take(42);
        assert!(matches!(r, Err(RatchetError::SkippedKeyNotFound { .. })));
    }

    #[test]
    fn fifo_eviction_on_overflow() {
        let mut s = SkippedKeyStore::with_capacity(3);
        for i in 0..5u8 {
            s.insert(u64::from(i), key(i)).unwrap();
        }
        // After 5 inserts with cap=3: should hold the LAST 3 (steps 2, 3, 4).
        assert_eq!(s.len(), 3);
        assert!(s.take(0).is_err());
        assert!(s.take(1).is_err());
        assert!(s.take(2).is_ok());
        assert!(s.take(3).is_ok());
        assert!(s.take(4).is_ok());
    }

    #[test]
    fn drop_older_than_removes_expired() {
        let mut s = SkippedKeyStore::with_capacity(16);
        for i in 0..10u8 {
            s.insert(u64::from(i), key(i)).unwrap();
        }
        s.drop_older_than(5);
        assert_eq!(s.len(), 5);
        for i in 0..5 {
            assert!(s.take(i).is_err());
        }
        for i in 5..10 {
            assert!(s.take(i).is_ok());
        }
    }

    #[test]
    fn zero_cap_rejects_insert() {
        let mut s = SkippedKeyStore::with_capacity(0);
        let r = s.insert(1, key(0));
        assert!(matches!(r, Err(RatchetError::SkippedStoreFull { .. })));
    }
}
