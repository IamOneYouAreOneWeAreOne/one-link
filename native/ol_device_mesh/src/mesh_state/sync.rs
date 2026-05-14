//! Pairwise sync session + anti-entropy.
//!
//! Each replica keeps a [`SyncState`]: the highest sequence number
//! it has observed per peer device, plus a chronological op log.
//! Two replicas converge by:
//!
//! 1. Exchanging [`SyncSummary`] records (a compact `device_id ->
//!    highest_seq` map).
//! 2. Each side replies with the ops the peer is missing, up to
//!    [`MAX_OPS_PER_SYNC`] per round.
//! 3. Each side ingests the peer's ops via [`SyncState::ingest`],
//!    which drops replays (seq ≤ `last_seen`) and signature failures.
//!
//! The protocol is monotonic: a peer that has fallen behind by N ops
//! catches up in `ceil(N / MAX_OPS_PER_SYNC)` rounds. There is no
//! "rejected-because-out-of-order" path; CRDTs converge under any
//! delivery order.

use std::collections::{BTreeMap, BTreeSet};

use ol_pqsig::HybridVerifyingKey;

use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::subkey::DEVICE_ID_LEN;

use super::ops::AuthenticatedOp;
use super::state::MeshState;

/// Maximum number of ops a replica returns in one sync reply.
pub const MAX_OPS_PER_SYNC: usize = 1024;

/// Sync state for one replica.
#[derive(Debug, Clone, Default)]
pub struct SyncState {
    /// Sparse set of `(device_id, seq)` pairs already observed.
    /// Used for ingest-time dedup; CRDT idempotence handles the
    /// actual state-merge correctness.
    seen: BTreeSet<([u8; DEVICE_ID_LEN], u64)>,
    /// Highest seq observed per device. Used by [`SyncSummary`]
    /// + by [`Self::record_local_emit`] for monotonicity.
    last_seen_seq: BTreeMap<[u8; DEVICE_ID_LEN], u64>,
    /// Chronological log of ops we hold, in ingest order. Used to
    /// reply to peer summaries.
    op_log: Vec<AuthenticatedOp>,
}

impl SyncState {
    /// Fresh sync state with no peers observed.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Borrow the op log in chronological-emit order.
    #[must_use] 
    pub fn op_log(&self) -> &[AuthenticatedOp] {
        &self.op_log
    }

    /// Highest seq seen from `device_id` (0 if never seen).
    #[must_use]
    pub fn last_seen(&self, device_id: &[u8; DEVICE_ID_LEN]) -> u64 {
        self.last_seen_seq.get(device_id).copied().unwrap_or(0)
    }

    /// Summary of what we've seen — what we send to a peer when
    /// initiating sync.
    #[must_use]
    pub fn summary(&self) -> SyncSummary {
        SyncSummary {
            last_seen_seq: self.last_seen_seq.clone(),
        }
    }

    /// Ingest an op from a peer. Returns `Ok(true)` if the op is
    /// newly applied; `Ok(false)` if it was a replay (already seen).
    /// Returns the underlying [`DeviceMeshError`] if signature verify
    /// fails, the subkey VK can't be resolved, the subtree is
    /// missing, or the delta kind mismatches the subtree.
    ///
    /// `vk_lookup` resolves a `(device_id, day_index)` pair to the
    /// emitter's hybrid verifying key. Callers typically wrap their
    /// Layer-1 `SubkeyAttestation` cache here.
    pub fn ingest<F>(
        &mut self,
        op: AuthenticatedOp,
        state: &mut MeshState,
        vk_lookup: F,
    ) -> DeviceMeshResult<bool>
    where
        F: Fn(&[u8; DEVICE_ID_LEN], u64) -> DeviceMeshResult<HybridVerifyingKey>,
    {
        // Replay check via the seen-set, NOT a max-seen comparator.
        // CRDTs are idempotent under replay, so applying twice is
        // safe; the seen-set just skips redundant verify + apply
        // work. Crucially this allows out-of-order delivery for the
        // same device (seq 3 arriving after seq 5 from the same
        // emitter), which the gossip / anti-entropy protocol relies
        // on for partial-network healing.
        if self.seen.contains(&(op.device_id, op.seq)) {
            return Ok(false);
        }
        // Resolve VK + verify signature.
        let vk = vk_lookup(&op.device_id, op.day_index)?;
        op.verify(&vk)?;
        // Apply to state. The subtree must already exist (created
        // by `MeshState::ensure_subtree` at higher-layer setup).
        state.apply_delta(&op.subtree, &op.delta, &op.device_id)?;
        // Record sequence + append to log.
        self.seen.insert((op.device_id, op.seq));
        let entry = self.last_seen_seq.entry(op.device_id).or_insert(0);
        if op.seq > *entry {
            *entry = op.seq;
        }
        self.op_log.push(op);
        Ok(true)
    }

    /// Return up to [`MAX_OPS_PER_SYNC`] ops the peer is missing.
    /// "Missing" = ops in our log whose `seq > peer.last_seen[device_id]`.
    #[must_use]
    pub fn diff_for_peer(&self, peer: &SyncSummary) -> Vec<AuthenticatedOp> {
        let mut out = Vec::new();
        for op in &self.op_log {
            let peer_seen = peer.last_seen_seq.get(&op.device_id).copied().unwrap_or(0);
            if op.seq > peer_seen {
                out.push(op.clone());
                if out.len() >= MAX_OPS_PER_SYNC {
                    break;
                }
            }
        }
        out
    }

    /// Emit (sign + record + append to log) the next op for this
    /// device. Caller supplies the next `seq`; bookkeeping enforces
    /// strict monotonicity per device.
    pub fn record_local_emit(
        &mut self,
        op: AuthenticatedOp,
    ) -> DeviceMeshResult<()> {
        let prior = self.last_seen(&op.device_id);
        if op.seq <= prior {
            return Err(DeviceMeshError::OpSeqNotMonotonic {
                device_id: op.device_id,
                got: op.seq,
                last_seen: prior,
            });
        }
        self.seen.insert((op.device_id, op.seq));
        self.last_seen_seq.insert(op.device_id, op.seq);
        self.op_log.push(op);
        Ok(())
    }
}

/// Compact summary of one replica's progress — exchanged at sync
/// start so each side can compute the diff.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncSummary {
    /// Highest sequence number seen from each peer device id.
    pub last_seen_seq: BTreeMap<[u8; DEVICE_ID_LEN], u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master::MasterIdentity;
    use crate::mesh_state::ops::Delta;
    use crate::mesh_state::policy::SubtreePolicyKind;
    use crate::subkey::{fresh_device_id, mint_subkey, SubkeyAttestation};
    use crate::DeviceClass;
    use ol_pqsig::HYBRID_VK_LEN;
    use rand::rngs::OsRng;

    fn vk_from_attestation(att: &SubkeyAttestation) -> HybridVerifyingKey {
        assert_eq!(att.subkey_vk_bytes.len(), HYBRID_VK_LEN);
        HybridVerifyingKey::from_bytes(&att.subkey_vk_bytes).unwrap()
    }

    #[test]
    fn ingest_round_trips_then_replays_no_op() {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = fresh_device_id(&mut OsRng);
        let (sk, att) =
            mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        let mut state = MeshState::empty();
        state
            .ensure_subtree(b"x".to_vec(), SubtreePolicyKind::LwwRegister)
            .unwrap();
        let mut sync = SyncState::empty();

        let op = AuthenticatedOp::sign(
            &sk,
            b"x".to_vec(),
            Delta::LwwSet { value: b"v".to_vec(), ts: 1 },
            1,
            1_700_000_000,
        )
        .unwrap();

        let vk = vk_from_attestation(&att);
        let applied = sync
            .ingest(op.clone(), &mut state, |_, _| Ok(vk.clone()))
            .unwrap();
        assert!(applied);
        // Replay is a no-op.
        let applied = sync.ingest(op, &mut state, |_, _| Ok(vk.clone())).unwrap();
        assert!(!applied);
    }

    #[test]
    fn diff_returns_ops_peer_is_missing() {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = fresh_device_id(&mut OsRng);
        let (sk, _att) =
            mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        let mut sync = SyncState::empty();
        for seq in 1..=5u64 {
            let op = AuthenticatedOp::sign(
                &sk,
                b"x".to_vec(),
                Delta::LwwSet { value: vec![seq as u8], ts: seq },
                seq,
                seq,
            )
            .unwrap();
            sync.record_local_emit(op).unwrap();
        }
        let mut peer = SyncSummary::default();
        peer.last_seen_seq.insert(id, 2);
        let diff = sync.diff_for_peer(&peer);
        assert_eq!(diff.len(), 3); // seqs 3, 4, 5
        for op in &diff {
            assert!(op.seq > 2);
        }
    }

    #[test]
    fn record_local_emit_rejects_regression() {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = fresh_device_id(&mut OsRng);
        let (sk, _) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        let mut sync = SyncState::empty();
        let op_a = AuthenticatedOp::sign(
            &sk,
            b"x".to_vec(),
            Delta::LwwSet { value: b"a".to_vec(), ts: 1 },
            5,
            1,
        )
        .unwrap();
        sync.record_local_emit(op_a).unwrap();
        let op_b = AuthenticatedOp::sign(
            &sk,
            b"x".to_vec(),
            Delta::LwwSet { value: b"b".to_vec(), ts: 2 },
            5, // same seq
            2,
        )
        .unwrap();
        let err = sync.record_local_emit(op_b).unwrap_err();
        assert!(matches!(err, DeviceMeshError::OpSeqNotMonotonic { .. }));
    }

    #[test]
    fn two_replicas_converge() {
        // Two devices, each emits an op; after a full pair-sync,
        // both have identical state.
        let master = MasterIdentity::generate(&mut OsRng);
        let id_a = fresh_device_id(&mut OsRng);
        let id_b = fresh_device_id(&mut OsRng);
        let (sk_a, att_a) =
            mint_subkey(&master, DeviceClass::Phone, id_a, 0, 365).unwrap();
        let (sk_b, att_b) =
            mint_subkey(&master, DeviceClass::Laptop, id_b, 0, 365).unwrap();
        let vk_a = vk_from_attestation(&att_a);
        let vk_b = vk_from_attestation(&att_b);
        let lookup = |id: &[u8; 16], _day: u64| -> DeviceMeshResult<HybridVerifyingKey> {
            if id == &id_a {
                Ok(vk_a.clone())
            } else if id == &id_b {
                Ok(vk_b.clone())
            } else {
                Err(DeviceMeshError::AttestationMissing {
                    device_id: *id,
                    day_index: 0,
                })
            }
        };

        let mut sa = SyncState::empty();
        let mut sb = SyncState::empty();
        let mut state_a = MeshState::empty();
        let mut state_b = MeshState::empty();
        state_a
            .ensure_subtree(b"x".to_vec(), SubtreePolicyKind::LwwMap)
            .unwrap();
        state_b
            .ensure_subtree(b"x".to_vec(), SubtreePolicyKind::LwwMap)
            .unwrap();

        let op_a = AuthenticatedOp::sign(
            &sk_a,
            b"x".to_vec(),
            Delta::MapPut { key: b"k1".to_vec(), value: b"a".to_vec(), ts: 1 },
            1,
            1,
        )
        .unwrap();
        sa.ingest(op_a, &mut state_a, &lookup).unwrap();
        let op_b = AuthenticatedOp::sign(
            &sk_b,
            b"x".to_vec(),
            Delta::MapPut { key: b"k2".to_vec(), value: b"b".to_vec(), ts: 2 },
            1,
            2,
        )
        .unwrap();
        sb.ingest(op_b, &mut state_b, &lookup).unwrap();

        // Each side computes its diff for the other; ingests.
        let diff_for_b = sa.diff_for_peer(&sb.summary());
        for op in diff_for_b {
            sb.ingest(op, &mut state_b, &lookup).unwrap();
        }
        let diff_for_a = sb.diff_for_peer(&sa.summary());
        for op in diff_for_a {
            sa.ingest(op, &mut state_a, &lookup).unwrap();
        }
        assert_eq!(state_a.root(), state_b.root());
    }
}
