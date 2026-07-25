//! Receiver-side transfer progress tracker.
//!
//! Holds the state of an in-progress fan-out fetch:
//! - which chunks have completed,
//! - which are currently in-flight from each source,
//! - which are still pending.
//!
//! Signals completion as soon as `≥ k_total` distinct shards have
//! arrived (where `k_total = n_stripes * policy.k`), so a fast
//! subset of sources can finish the transfer without waiting on
//! slow ones — the fountain-code property.

use std::collections::{BTreeMap, BTreeSet};

use crate::distributed_fs::{ChunkHash, FileManifest};
use crate::subkey::DEVICE_ID_LEN;

use super::plan::FanOutPlan;

/// Per-transfer tracker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferProgress {
    /// File the transfer targets.
    pub file_id: crate::distributed_fs::FileId,
    /// Plan currently being executed.
    pub plan: FanOutPlan,
    /// Chunks already received successfully.
    pub completed_chunks: BTreeSet<ChunkHash>,
    /// Chunks currently in-flight, with the source we're waiting on.
    pub in_flight_chunks: BTreeMap<ChunkHash, [u8; DEVICE_ID_LEN]>,
    /// Sources that have failed (dropped, timed out, lost connection).
    pub failed_sources: BTreeSet<[u8; DEVICE_ID_LEN]>,
    /// Number of distinct shards needed to reconstruct
    /// (= `n_stripes` * policy.k from the manifest).
    pub completion_threshold: usize,
}

impl TransferProgress {
    /// Initialize a fresh tracker for a plan + manifest.
    #[must_use]
    pub fn new(plan: FanOutPlan, manifest: &FileManifest) -> Self {
        let stripe = manifest.policy.total_shards() as usize;
        let n_stripes = manifest.chunks.len() / stripe.max(1);
        let completion_threshold = n_stripes * (manifest.policy.k as usize);
        Self {
            file_id: plan.file_id,
            plan,
            completed_chunks: BTreeSet::new(),
            in_flight_chunks: BTreeMap::new(),
            failed_sources: BTreeSet::new(),
            completion_threshold,
        }
    }

    /// Begin tracking a chunk as in-flight from `source`.
    pub fn mark_in_flight(&mut self, chunk: ChunkHash, source: [u8; DEVICE_ID_LEN]) {
        if !self.completed_chunks.contains(&chunk) {
            self.in_flight_chunks.insert(chunk, source);
        }
    }

    /// Mark a chunk completed. Returns `true` iff this completion
    /// brought us to or past the threshold for the first time.
    pub fn complete_chunk(&mut self, chunk: ChunkHash) -> bool {
        let was_at_threshold = self.completed_chunks.len() >= self.completion_threshold;
        self.in_flight_chunks.remove(&chunk);
        self.completed_chunks.insert(chunk);
        let now_at_threshold = self.completed_chunks.len() >= self.completion_threshold;
        now_at_threshold && !was_at_threshold
    }

    /// Mark a source as failed. Returns the list of in-flight chunks
    /// previously assigned to it, which the higher layer should
    /// `replan_after_source_failure` against the surviving sources.
    pub fn mark_source_failed(&mut self, source: [u8; DEVICE_ID_LEN]) -> Vec<ChunkHash> {
        self.failed_sources.insert(source);
        let mut released = Vec::new();
        let still_in_flight: BTreeMap<ChunkHash, [u8; DEVICE_ID_LEN]> = self
            .in_flight_chunks
            .iter()
            .filter_map(|(chunk, src)| {
                if *src == source {
                    released.push(*chunk);
                    None
                } else {
                    Some((*chunk, *src))
                }
            })
            .collect();
        self.in_flight_chunks = still_in_flight;
        released
    }

    /// Have we collected enough distinct shards?
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.completed_chunks.len() >= self.completion_threshold
    }

    /// Chunks the plan assigned that haven't completed and aren't
    /// currently in-flight.
    #[must_use]
    pub fn pending(&self) -> Vec<ChunkHash> {
        let mut out = Vec::new();
        for a in &self.plan.assignments {
            if self.failed_sources.contains(&a.source_device_id) {
                continue;
            }
            for c in &a.chunk_hashes {
                if !self.completed_chunks.contains(c) && !self.in_flight_chunks.contains_key(c) {
                    out.push(*c);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distributed_fs::ErasurePolicy;
    use crate::fan_out::plan::FanOutAssignment;

    fn manifest() -> FileManifest {
        let chunks: Vec<ChunkHash> = (1u8..=6).map(|i| [i; 32]).collect();
        let policy = ErasurePolicy::new(2, 1, 1).unwrap();
        FileManifest {
            file_size: 6,
            chunk_size: 1,
            chunks,
            mime: b"x".to_vec(),
            created_unix: 0,
            policy,
        }
    }

    fn plan() -> FanOutPlan {
        FanOutPlan {
            file_id: [0xAA; 32],
            assignments: vec![
                FanOutAssignment {
                    source_device_id: [1; DEVICE_ID_LEN],
                    chunk_hashes: vec![[1; 32], [3; 32]],
                    estimated_bytes: 2,
                },
                FanOutAssignment {
                    source_device_id: [2; DEVICE_ID_LEN],
                    chunk_hashes: vec![[2; 32], [4; 32]],
                    estimated_bytes: 2,
                },
            ],
            total_chunks: 4,
        }
    }

    #[test]
    fn fresh_tracker_is_incomplete_with_threshold_4() {
        // manifest has 6 chunks at (k=2, m=1) ⇒ 2 stripes × 2 data
        // = 4 needed.
        let t = TransferProgress::new(plan(), &manifest());
        assert_eq!(t.completion_threshold, 4);
        assert!(!t.is_complete());
    }

    #[test]
    fn pending_and_in_flight_partition() {
        let mut t = TransferProgress::new(plan(), &manifest());
        assert_eq!(t.pending().len(), 4);
        t.mark_in_flight([1; 32], [1; 16]);
        assert_eq!(t.pending().len(), 3);
    }

    #[test]
    fn complete_chunk_threshold_signal() {
        let mut t = TransferProgress::new(plan(), &manifest());
        assert!(!t.complete_chunk([1; 32]));
        assert!(!t.complete_chunk([2; 32]));
        assert!(!t.complete_chunk([3; 32]));
        // Fourth completion brings us to threshold for the first time.
        assert!(t.complete_chunk([4; 32]));
        // Another completion doesn't re-fire the signal.
        assert!(!t.complete_chunk([5; 32]));
    }

    #[test]
    fn source_failure_releases_its_chunks() {
        let mut t = TransferProgress::new(plan(), &manifest());
        t.mark_in_flight([1; 32], [1; 16]);
        t.mark_in_flight([3; 32], [1; 16]);
        t.mark_in_flight([2; 32], [2; 16]);
        let released = t.mark_source_failed([1; 16]);
        let mut sorted = released.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec![[1; 32], [3; 32]]);
        assert!(!t.in_flight_chunks.contains_key(&[1; 32]));
        assert!(!t.in_flight_chunks.contains_key(&[3; 32]));
        assert!(t.in_flight_chunks.contains_key(&[2; 32]));
    }

    #[test]
    fn pending_excludes_failed_source_chunks() {
        let mut t = TransferProgress::new(plan(), &manifest());
        t.mark_source_failed([1; 16]);
        let pending = t.pending();
        // Source 2's chunks remain; source 1's chunks excluded.
        for c in &pending {
            assert!(c[0] == 2 || c[0] == 4);
        }
    }
}
