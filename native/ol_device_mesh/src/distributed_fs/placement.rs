//! Per-chunk placement index + under-replication detector.
//!
//! The placement index maps each [`super::ChunkHash`] to the set of
//! devices that currently claim to hold it. Higher layers store
//! this as a Layer-3 CRDT subtree (one entry per chunk) so it's
//! replicated across every device in the mesh.

use std::collections::{BTreeMap, BTreeSet};

use crate::subkey::DEVICE_ID_LEN;

use super::manifest::ChunkHash;
use super::policy::ErasurePolicy;

/// Placement entry for a single chunk. `device_ids` is the live
/// set; `last_attest_unix` is the latest wall-clock from any
/// holding device's attestation (used by higher-layer staleness
/// detection).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChunkPlacement {
    /// The chunk this entry describes.
    pub chunk_hash: ChunkHash,
    /// Set of devices that hold this chunk.
    pub device_ids: BTreeSet<[u8; DEVICE_ID_LEN]>,
    /// Latest wall-clock seconds across all holders' attestations.
    pub last_attest_unix: u64,
}

impl ChunkPlacement {
    /// Construct an empty placement for `chunk_hash`.
    #[must_use]
    pub const fn empty(chunk_hash: ChunkHash) -> Self {
        Self {
            chunk_hash,
            device_ids: BTreeSet::new(),
            last_attest_unix: 0,
        }
    }

    /// Record that `device_id` attested at `attest_unix`.
    pub fn add_holder(&mut self, device_id: [u8; DEVICE_ID_LEN], attest_unix: u64) {
        self.device_ids.insert(device_id);
        if attest_unix > self.last_attest_unix {
            self.last_attest_unix = attest_unix;
        }
    }

    /// Number of currently-known holders.
    #[must_use]
    pub fn holder_count(&self) -> usize {
        self.device_ids.len()
    }

    /// Does this chunk meet the policy's `min_devices_per_shard`
    /// rule?
    #[must_use]
    pub fn meets_policy(&self, policy: &ErasurePolicy) -> bool {
        self.holder_count() >= policy.min_devices_per_shard as usize
    }
}

/// Among the supplied placements, return the chunk hashes that fall
/// below the policy's durability rule.
#[must_use]
pub fn under_replicated<'a, I>(placements: I, policy: &ErasurePolicy) -> Vec<ChunkHash>
where
    I: IntoIterator<Item = &'a ChunkPlacement>,
{
    placements
        .into_iter()
        .filter(|p| !p.meets_policy(policy))
        .map(|p| p.chunk_hash)
        .collect()
}

/// Build a map from `device_id` to "chunk count currently held"
/// across a placement collection. Used by the repair planner to
/// pick the least-loaded device for the next assignment.
#[must_use]
pub fn device_load_map<'a, I>(placements: I) -> BTreeMap<[u8; DEVICE_ID_LEN], usize>
where
    I: IntoIterator<Item = &'a ChunkPlacement>,
{
    let mut load = BTreeMap::new();
    for p in placements {
        for d in &p.device_ids {
            *load.entry(*d).or_insert(0_usize) += 1;
        }
    }
    load
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> ChunkHash {
        [byte; 32]
    }
    fn d(byte: u8) -> [u8; DEVICE_ID_LEN] {
        [byte; DEVICE_ID_LEN]
    }

    #[test]
    fn empty_placement_does_not_meet_policy() {
        let p = ErasurePolicy::new(2, 1, 2).unwrap();
        let e = ChunkPlacement::empty(h(0x01));
        assert!(!e.meets_policy(&p));
    }

    #[test]
    fn add_holder_tracks_attest_max() {
        let mut p = ChunkPlacement::empty(h(0x01));
        p.add_holder(d(1), 100);
        assert_eq!(p.last_attest_unix, 100);
        p.add_holder(d(2), 50);
        assert_eq!(p.last_attest_unix, 100);
        p.add_holder(d(3), 200);
        assert_eq!(p.last_attest_unix, 200);
    }

    #[test]
    fn meets_policy_threshold() {
        let policy = ErasurePolicy::new(2, 1, 3).unwrap();
        let mut p = ChunkPlacement::empty(h(0x01));
        p.add_holder(d(1), 10);
        p.add_holder(d(2), 20);
        assert!(!p.meets_policy(&policy));
        p.add_holder(d(3), 30);
        assert!(p.meets_policy(&policy));
    }

    #[test]
    fn under_replicated_filters_correctly() {
        let policy = ErasurePolicy::new(2, 1, 2).unwrap();
        let mut a = ChunkPlacement::empty(h(0x01));
        a.add_holder(d(1), 1);
        let mut b = ChunkPlacement::empty(h(0x02));
        b.add_holder(d(1), 1);
        b.add_holder(d(2), 1);
        let mut c = ChunkPlacement::empty(h(0x03));
        c.add_holder(d(1), 1);
        c.add_holder(d(2), 1);
        c.add_holder(d(3), 1);
        let under = under_replicated([&a, &b, &c], &policy);
        assert_eq!(under, vec![h(0x01)]);
    }

    #[test]
    fn device_load_map_sums() {
        let mut a = ChunkPlacement::empty(h(0x01));
        a.add_holder(d(1), 1);
        a.add_holder(d(2), 1);
        let mut b = ChunkPlacement::empty(h(0x02));
        b.add_holder(d(1), 1);
        b.add_holder(d(3), 1);
        let load = device_load_map([&a, &b]);
        assert_eq!(load.get(&d(1)).copied().unwrap_or(0), 2);
        assert_eq!(load.get(&d(2)).copied().unwrap_or(0), 1);
        assert_eq!(load.get(&d(3)).copied().unwrap_or(0), 1);
    }
}
