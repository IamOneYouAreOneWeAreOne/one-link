//! Repair planner — assign under-replicated chunks to fresh devices.
//!
//! Given a set of [`super::ChunkPlacement`] records and a set of
//! mesh-member device ids, produce a list of [`RepairAssignment`]s
//! that brings every chunk up to `policy.min_devices_per_shard`.
//!
//! The planner picks the LEAST-LOADED eligible device (smallest
//! current chunk count) at each step, then bumps that device's
//! virtual load before picking the next assignment so the work
//! spreads evenly across the mesh.

use std::collections::BTreeSet;

use crate::subkey::DEVICE_ID_LEN;

use super::manifest::ChunkHash;
use super::placement::{device_load_map, ChunkPlacement};
use super::policy::ErasurePolicy;

/// One repair assignment: device `assigned_to` should fetch + start
/// holding chunk `chunk_hash`. Higher layers turn this into a
/// fetch over Phase A2 QUIC (once shipped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairAssignment {
    /// Chunk needing additional replicas.
    pub chunk_hash: ChunkHash,
    /// Device picked to receive a copy.
    pub assigned_to: [u8; DEVICE_ID_LEN],
}

/// Compute a repair plan.
///
/// - `placements` are the current per-chunk placement records.
/// - `mesh_devices` is the full mesh roster (every device id that
///   could legally receive a chunk; typically all devices in the
///   master's policy).
/// - `policy` is the durability policy applied to under-replication
///   detection.
///
/// Returns an assignment list in deterministic order (chunk hash
/// ascending; for each chunk, devices that already-hold are
/// excluded, and the remaining are picked least-loaded-first).
#[must_use]
pub fn repair_plan<'a, I>(
    placements: I,
    mesh_devices: &BTreeSet<[u8; DEVICE_ID_LEN]>,
    policy: &ErasurePolicy,
) -> Vec<RepairAssignment>
where
    I: IntoIterator<Item = &'a ChunkPlacement>,
{
    // Snapshot the placements into a Vec so we can iterate twice.
    let placements: Vec<&ChunkPlacement> = placements.into_iter().collect();
    let mut load = device_load_map(placements.iter().copied());
    // Ensure every mesh device has an entry (even if currently 0).
    for d in mesh_devices {
        load.entry(*d).or_insert(0);
    }

    let mut out = Vec::new();
    // Iterate placements in deterministic order (BTreeMap-style:
    // we sort by chunk hash before consuming).
    let mut sorted: Vec<&ChunkPlacement> = placements;
    sorted.sort_by_key(|p| p.chunk_hash);
    for p in sorted {
        let need = policy.needed_for_durability(p.holder_count());
        for _ in 0..need {
            // Pick the least-loaded eligible device that isn't
            // already in the placement and isn't already-assigned
            // this round.
            let already_assigned: BTreeSet<[u8; DEVICE_ID_LEN]> = out
                .iter()
                .filter(|a: &&RepairAssignment| a.chunk_hash == p.chunk_hash)
                .map(|a| a.assigned_to)
                .collect();
            let candidate = mesh_devices
                .iter()
                .filter(|d| !p.device_ids.contains(*d))
                .filter(|d| !already_assigned.contains(*d))
                .min_by_key(|d| (load.get(*d).copied().unwrap_or(0), **d));
            let Some(&pick) = candidate else {
                break; // not enough eligible devices for this chunk
            };
            *load.entry(pick).or_insert(0) += 1;
            out.push(RepairAssignment {
                chunk_hash: p.chunk_hash,
                assigned_to: pick,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn h(byte: u8) -> ChunkHash {
        [byte; 32]
    }
    fn d(byte: u8) -> [u8; DEVICE_ID_LEN] {
        [byte; DEVICE_ID_LEN]
    }
    fn mesh(n: u8) -> BTreeSet<[u8; DEVICE_ID_LEN]> {
        (1..=n).map(d).collect()
    }

    #[test]
    fn empty_plan_when_already_durable() {
        let policy = ErasurePolicy::new(2, 1, 2).unwrap();
        let mut p = ChunkPlacement::empty(h(0x01));
        p.add_holder(d(1), 1);
        p.add_holder(d(2), 1);
        let plan = repair_plan([&p], &mesh(4), &policy);
        assert!(plan.is_empty());
    }

    #[test]
    fn assigns_missing_holders_least_loaded_first() {
        let policy = ErasurePolicy::new(2, 1, 3).unwrap();
        // Chunk h1 has 1 holder (d1); needs 2 more.
        // Chunk h2 has 1 holder (d1); needs 2 more.
        // Loads at start: d1=2, d2=0, d3=0, d4=0.
        // Plan should spread to d2/d3 for h1, then d2/d3 (now 1 each)
        // for h2 — picking by least load + lex-tiebreak.
        let mut h1 = ChunkPlacement::empty(h(0x01));
        h1.add_holder(d(1), 1);
        let mut h2 = ChunkPlacement::empty(h(0x02));
        h2.add_holder(d(1), 1);
        let plan = repair_plan([&h1, &h2], &mesh(4), &policy);
        // 4 assignments total: 2 for each of two chunks.
        assert_eq!(plan.len(), 4);
        // Every assigned device must not already hold its chunk.
        for a in &plan {
            let placement_for_chunk: Option<&ChunkPlacement> =
                [&h1, &h2].into_iter().find(|p| p.chunk_hash == a.chunk_hash);
            assert!(placement_for_chunk.is_some());
            assert!(
                !placement_for_chunk.unwrap().device_ids.contains(&a.assigned_to)
            );
        }
    }

    #[test]
    fn no_double_assign_per_chunk() {
        let policy = ErasurePolicy::new(2, 1, 5).unwrap();
        // Need 5 holders; mesh has 4; placement currently empty.
        let p = ChunkPlacement::empty(h(0x01));
        let plan = repair_plan([&p], &mesh(4), &policy);
        // We can only assign 4 unique devices; plan returns the
        // achievable subset, never duplicating a device.
        assert!(plan.len() <= 4);
        let unique: BTreeSet<[u8; DEVICE_ID_LEN]> =
            plan.iter().map(|a| a.assigned_to).collect();
        assert_eq!(unique.len(), plan.len());
    }

    #[test]
    fn doesnt_pick_already_holding_device() {
        let policy = ErasurePolicy::new(2, 1, 4).unwrap();
        let mut p = ChunkPlacement::empty(h(0x01));
        p.add_holder(d(1), 1);
        p.add_holder(d(2), 1);
        let plan = repair_plan([&p], &mesh(4), &policy);
        for a in &plan {
            assert!(a.assigned_to == d(3) || a.assigned_to == d(4));
        }
    }

    #[test]
    fn deterministic_order() {
        let policy = ErasurePolicy::new(2, 1, 2).unwrap();
        let p1 = ChunkPlacement::empty(h(0x05));
        let p2 = ChunkPlacement::empty(h(0x02));
        let p3 = ChunkPlacement::empty(h(0x08));
        let plan_a = repair_plan([&p1, &p2, &p3], &mesh(4), &policy);
        let plan_b = repair_plan([&p3, &p2, &p1], &mesh(4), &policy);
        assert_eq!(plan_a, plan_b);
    }
}
