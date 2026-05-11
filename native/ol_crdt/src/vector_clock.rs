//! Vector clocks for causal ordering between replicas.

use std::collections::BTreeMap;

use crate::Lattice;

/// Stable identifier for a replica. The folder model uses 32-byte
/// BLAKE3 fingerprints of the device public key; here we keep it
/// generic so callers control the namespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReplicaId(pub [u8; 32]);

/// Vector clock: per-replica monotonic counter, sparse map.
///
/// Merge takes pointwise max; comparison is the standard partial order
/// (a ≤ b iff every coordinate of a is ≤ b's, with strictness somewhere).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VectorClock {
    pub(crate) counters: BTreeMap<ReplicaId, u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockOrder {
    Before,
    After,
    Equal,
    Concurrent,
}

impl VectorClock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Tick this replica's counter by one and return the new value.
    pub fn tick(&mut self, replica: &ReplicaId) -> u64 {
        let entry = self.counters.entry(replica.clone()).or_insert(0);
        *entry += 1;
        *entry
    }

    pub fn get(&self, replica: &ReplicaId) -> u64 {
        self.counters.get(replica).copied().unwrap_or(0)
    }

    /// Iterate (replica, counter) pairs in deterministic order. Used by
    /// the structural-hash function in the lattice-law acceptance gate.
    pub fn iter(&self) -> impl Iterator<Item = (&ReplicaId, &u64)> {
        self.counters.iter()
    }

    /// Causal comparison. Returns `Concurrent` if neither dominates.
    pub fn compare(&self, other: &Self) -> ClockOrder {
        let mut self_dominates = false;
        let mut other_dominates = false;

        let mut all_keys: std::collections::BTreeSet<&ReplicaId> = self.counters.keys().collect();
        all_keys.extend(other.counters.keys());

        for k in all_keys {
            let a = self.get(k);
            let b = other.get(k);
            if a > b {
                self_dominates = true;
            } else if b > a {
                other_dominates = true;
            }
            if self_dominates && other_dominates {
                return ClockOrder::Concurrent;
            }
        }
        match (self_dominates, other_dominates) {
            (false, false) => ClockOrder::Equal,
            (true, false) => ClockOrder::After,
            (false, true) => ClockOrder::Before,
            (true, true) => unreachable!("dominance flags exclusive above"),
        }
    }
}

impl Lattice for VectorClock {
    /// Pointwise max — the canonical CRDT merge for a vector clock.
    fn merge(&mut self, other: &Self) {
        for (rid, &v) in &other.counters {
            let entry = self.counters.entry(rid.clone()).or_insert(0);
            if v > *entry {
                *entry = v;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid(b: u8) -> ReplicaId {
        ReplicaId([b; 32])
    }

    #[test]
    fn tick_increments() {
        let mut vc = VectorClock::new();
        let a = rid(1);
        assert_eq!(vc.tick(&a), 1);
        assert_eq!(vc.tick(&a), 2);
        assert_eq!(vc.get(&a), 2);
    }

    #[test]
    fn merge_takes_pointwise_max() {
        let mut a = VectorClock::new();
        a.tick(&rid(1));
        a.tick(&rid(1));
        a.tick(&rid(2));

        let mut b = VectorClock::new();
        b.tick(&rid(1));
        b.tick(&rid(3));

        a.merge(&b);
        assert_eq!(a.get(&rid(1)), 2);
        assert_eq!(a.get(&rid(2)), 1);
        assert_eq!(a.get(&rid(3)), 1);
    }

    #[test]
    fn compare_before_after_equal() {
        let mut a = VectorClock::new();
        a.tick(&rid(1));
        let mut b = a.clone();
        assert_eq!(a.compare(&b), ClockOrder::Equal);

        b.tick(&rid(1));
        assert_eq!(a.compare(&b), ClockOrder::Before);
        assert_eq!(b.compare(&a), ClockOrder::After);
    }

    #[test]
    fn compare_concurrent() {
        let mut a = VectorClock::new();
        a.tick(&rid(1));
        let mut b = VectorClock::new();
        b.tick(&rid(2));
        assert_eq!(a.compare(&b), ClockOrder::Concurrent);
    }
}
