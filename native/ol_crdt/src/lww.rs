//! Last-Writer-Wins register.
//!
//! Holds a value plus a (timestamp, replica id) pair. Merge picks the
//! pair with the larger timestamp, breaking ties on replica id so the
//! merge is deterministic across all replicas (associative + idempotent
//! + commutative once ties are broken).

use crate::vector_clock::ReplicaId;
use crate::Lattice;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LwwRegister<V: Clone + PartialEq + Eq> {
    pub value: V,
    pub timestamp: u64,
    pub replica: ReplicaId,
}

impl<V: Clone + PartialEq + Eq> LwwRegister<V> {
    pub fn new(value: V, timestamp: u64, replica: ReplicaId) -> Self {
        Self {
            value,
            timestamp,
            replica,
        }
    }

    /// Returns true iff `other` should overwrite self.
    fn dominates(&self, other: &Self) -> bool {
        match other.timestamp.cmp(&self.timestamp) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => other.replica.0 > self.replica.0,
        }
    }
}

impl<V: Clone + PartialEq + Eq> Lattice for LwwRegister<V> {
    fn merge(&mut self, other: &Self) {
        if self.dominates(other) {
            *self = other.clone();
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
    fn higher_timestamp_wins() {
        let mut a = LwwRegister::new("v1", 1, rid(1));
        let b = LwwRegister::new("v2", 2, rid(2));
        a.merge(&b);
        assert_eq!(a.value, "v2");
    }

    #[test]
    fn tie_broken_by_replica_id() {
        let mut a = LwwRegister::new("v1", 5, rid(1));
        let b = LwwRegister::new("v2", 5, rid(2));
        a.merge(&b);
        assert_eq!(a.value, "v2");

        // Reverse merge produces the same answer (commutativity).
        let mut b2 = LwwRegister::new("v2", 5, rid(2));
        let a2 = LwwRegister::new("v1", 5, rid(1));
        b2.merge(&a2);
        assert_eq!(b2.value, "v2");
    }

    #[test]
    fn merge_is_idempotent() {
        let mut a = LwwRegister::new("v1", 1, rid(1));
        let snap = a.clone();
        a.merge(&snap);
        assert_eq!(a, snap);
    }
}
