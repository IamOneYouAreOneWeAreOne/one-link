//! Last-Writer-Wins register.
//!
//! Holds a value plus a (timestamp, replica id) pair. Merge picks the
//! pair with the larger timestamp; ties break on a BLAKE3 keyed hash
//! of `(replica || value-debug || timestamp)` so the merge is
//! deterministic across all replicas AND an adversary can't grind
//! a high replica id to win every concurrent edit (audit L10 May
//! 2026 — previously `other.replica.0 > self.replica.0` let an
//! attacker generate pubkeys until the BLAKE3 fingerprint started
//! with high bytes ≈ 2^32 work for a leading `0xFFFF_FFFF`).
//!
//! Tie-breaker hash inputs:
//! - The replica id (32 bytes)
//! - The Debug repr of the value (so the hash differs per concurrent
//!   edit; an attacker can't precompute a "always-high" replica id
//!   that wins regardless of value)
//! - The timestamp (8 bytes)
//!
//! Domain-tagged via BLAKE3 derive_key so this hash can't be confused
//! with any other in the workspace.

use crate::vector_clock::ReplicaId;
use crate::Lattice;

/// BLAKE3 derive_key context for the LWW tie-break hash. Bumping
/// this is a wire-incompatible change to the merge function — only
/// safe at a fresh-folder boundary.
const LWW_TIEBREAK_CONTEXT: &str = "ol-crdt-lww-tiebreak-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LwwRegister<V: Clone + PartialEq + Eq + core::fmt::Debug> {
    pub value: V,
    pub timestamp: u64,
    pub replica: ReplicaId,
}

impl<V: Clone + PartialEq + Eq + core::fmt::Debug> LwwRegister<V> {
    pub fn new(value: V, timestamp: u64, replica: ReplicaId) -> Self {
        Self {
            value,
            timestamp,
            replica,
        }
    }

    /// Audit L10 May 2026 — compute the tie-break hash. Combines
    /// the replica id with a value-derived component so an attacker
    /// can't grind a single high replica id that wins concurrent
    /// edits across all values. The value's Debug repr is the
    /// portable "value bytes" surface across generic V types.
    fn tiebreak_hash(&self) -> [u8; 32] {
        let mut buf: Vec<u8> = Vec::with_capacity(32 + 64);
        buf.extend_from_slice(&self.replica.0);
        // Hash the value's Debug repr — for the typical V types
        // we use (strings, ids) this captures the content. The
        // attacker can't precompute a winning replica id without
        // knowing the eventual value.
        let value_repr = format!("{:?}", self.value);
        buf.extend_from_slice(value_repr.as_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        blake3::derive_key(LWW_TIEBREAK_CONTEXT, &buf)
    }

    /// Returns true iff `other` should overwrite self.
    fn dominates(&self, other: &Self) -> bool {
        match other.timestamp.cmp(&self.timestamp) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => {
                // L10 tie-break — hash-derived rather than raw
                // replica.0 comparison.
                other.tiebreak_hash() > self.tiebreak_hash()
            }
        }
    }
}

impl<V: Clone + PartialEq + Eq + core::fmt::Debug> Lattice for LwwRegister<V> {
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
    fn tie_break_is_deterministic_and_commutative() {
        // L10 May 2026 — tie-break is now hash-derived, so the
        // exact winner depends on (replica, value, timestamp) all
        // mixed in. The contract we test: BOTH orderings of the
        // same merge inputs converge to the SAME value
        // (commutativity).
        let mut a = LwwRegister::new("v1", 5, rid(1));
        let b = LwwRegister::new("v2", 5, rid(2));
        a.merge(&b);
        let forward_winner = a.value;

        let mut b2 = LwwRegister::new("v2", 5, rid(2));
        let a2 = LwwRegister::new("v1", 5, rid(1));
        b2.merge(&a2);
        let reverse_winner = b2.value;

        assert_eq!(forward_winner, reverse_winner);
    }

    #[test]
    fn tie_break_not_solely_replica_id_dominated() {
        // L10 regression — even when one side's replica.0 is
        // all-0xFF (the maximum), the OTHER side can still win
        // because the tie-break hash mixes the value + timestamp
        // bytes. The attacker can't pre-pick a replica id that
        // wins regardless of value.
        // Find a value where low_replica wins over high_replica
        // — proves the high-replica attacker can't always win.
        let mut found_inversion = false;
        for value in ["a", "b", "c", "d", "e", "f", "g", "h"].iter() {
            let mut high = LwwRegister::new(*value, 5, rid(0xFF));
            let low = LwwRegister::new(*value, 5, rid(0x01));
            high.merge(&low);
            if high.replica == rid(0x01) {
                found_inversion = true;
                break;
            }
        }
        assert!(
            found_inversion,
            "high-replica should not win every tie-break — \
             grind-defeats-the-CRDT vector still open"
        );
    }

    #[test]
    fn merge_is_idempotent() {
        let mut a = LwwRegister::new("v1", 1, rid(1));
        let snap = a.clone();
        a.merge(&snap);
        assert_eq!(a, snap);
    }
}
