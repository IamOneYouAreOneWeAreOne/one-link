//! Row 8 Layer 3 — full-state CRDT mirror across the device mesh.
//!
//! Every device replica holds the same logical app state: contacts,
//! capability ledger, clipboard, settings, file manifests, anything
//! the higher layers want to keep in sync across phone / laptop /
//! tablet / desktop.
//!
//! ## Composition with Layers 1 and 2
//!
//! - Every state change ([`AuthenticatedOp`]) is signed by the
//!   emitting device's Layer-1 subkey. Replicas verify the signature
//!   under the master-attested subkey VK before merging.
//! - High-stakes subtrees (capability ledger, master settings, the
//!   device roster itself) are flagged in the [`SubtreePolicy`] as
//!   requiring a Layer-2 [`crate::quorum::QuorumCertificate`].
//!   Replicas refuse to merge an op against a quorum-gated subtree
//!   unless a valid certificate is attached.
//! - The Layer-1 [`crate::LivenessProof`]'s `state_root` field IS
//!   the [`MeshState::root`] of this layer. A sibling failing to
//!   converge to the same root within the heartbeat window gets
//!   flagged for Layer-2 quorum revocation.
//!
//! ## Subtree taxonomy
//!
//! - [`Subtree::LwwRegister`] — single-value last-writer-wins.
//! - [`Subtree::OrSet`] — observed-remove set with tombstones.
//! - [`Subtree::PnCounter`] — per-device positive/negative counter.
//! - [`Subtree::LwwMap`] — Map<bytes, lww-bytes>; tombstones on
//!   delete.
//!
//! These four primitives compose into 95 % of real app state: chat
//! drafts are LWW-Register, contact lists are OR-Set, send-counts
//! are PN-Counter, settings are LWW-Map, etc.
//!
//! ## Sync protocol
//!
//! Each device keeps a [`SyncState`] tracking the highest sequence
//! number it has seen per peer device. To converge, two devices
//! exchange [`SyncSummary`] records and reply with the ops the peer
//! is missing. Anti-entropy is bounded by the gap between summaries;
//! a freshly-paired device gets a one-shot catch-up.
//!
//! ## Replay protection
//!
//! Every op carries a strictly-increasing per-device sequence
//! number. Replicas drop ops where `seq <= last_seen_seq[device]`,
//! so an attacker who captures a signed op cannot replay it after
//! the sender has issued a newer op for the same device. The
//! per-op wall-clock timestamp + LWW ordering preserve eventual
//! consistency even if replay is attempted concurrently with new
//! ops.
//!
//! ## What this layer doesn't ship
//!
//! - Sequence CRDTs (Yjs / RGA / Logoot). Out of scope for the
//!   first ship; LWW-Map covers the immediate need.
//! - Compaction / snapshot encoding for cold-start sync. The
//!   `SyncState` exposes an op-log iterator; persistence is a
//!   higher-layer concern.
//! - Sub-second pairwise sync. Anti-entropy is bandwidth-bounded
//!   and assumes minute-scale convergence.
//!
//! ## Example: two replicas converge
//!
//! ```no_run
//! // Doctest is `no_run` because ML-DSA key material is ~2 KB —
//! // signing operations push doctest stacks past their default
//! // size on Windows. Compile-time validation is preserved.
//! use ol_device_mesh::mesh_state::{
//!     AuthenticatedOp, Delta, MeshState, SubtreePolicyKind, SyncState,
//! };
//! use ol_device_mesh::{
//!     mint_subkey, DeviceClass, MasterIdentity, DeviceMeshResult,
//! };
//! use ol_pqsig::HybridVerifyingKey;
//! use rand::rngs::OsRng;
//!
//! let master = MasterIdentity::generate(&mut OsRng);
//! let (phone_sk, phone_att) =
//!     mint_subkey(&master, DeviceClass::Phone, [0xAA; 16], 0, 365).unwrap();
//! let phone_vk = HybridVerifyingKey::from_bytes(&phone_att.subkey_vk_bytes).unwrap();
//!
//! // Replica A: tracks one LWW-Map subtree.
//! let mut state_a = MeshState::empty();
//! state_a.ensure_subtree(b"contacts".to_vec(), SubtreePolicyKind::LwwMap).unwrap();
//! let mut sync_a = SyncState::empty();
//!
//! // Phone signs an op and ingests it locally.
//! let op = AuthenticatedOp::sign(
//!     &phone_sk,
//!     b"contacts".to_vec(),
//!     Delta::MapPut { key: b"alice".to_vec(), value: b"alice@example".to_vec(), ts: 1 },
//!     1,
//!     1_700_000_000,
//! ).unwrap();
//! let lookup: fn(&[u8;16], u64) -> DeviceMeshResult<HybridVerifyingKey> =
//!     |_, _| panic!("populated at call site");
//! sync_a.ingest(op.clone(), &mut state_a, |_, _| Ok(phone_vk.clone())).unwrap();
//!
//! // Replica B (laptop) starts empty, then ingests the same op.
//! let mut state_b = MeshState::empty();
//! state_b.ensure_subtree(b"contacts".to_vec(), SubtreePolicyKind::LwwMap).unwrap();
//! let mut sync_b = SyncState::empty();
//! sync_b.ingest(op, &mut state_b, |_, _| Ok(phone_vk.clone())).unwrap();
//!
//! assert_eq!(state_a.root(), state_b.root());
//! let _ = lookup;
//! ```

pub mod ops;
pub mod policy;
pub mod state;
pub mod sync;

pub use ops::{
    Delta, AuthenticatedOp, AUTH_OP_DOMAIN, MAX_DELTA_VALUE_LEN,
    MAX_SUBTREE_LABEL_LEN,
};
pub use policy::{SubtreePolicy, SubtreePolicyKind};
pub use state::{
    LwwRegister, LwwMap, MeshState, OrSet, OrSetTag, PnCounter,
    Subtree, SubtreeLabel, SubtreeRoot, StateRoot,
};
pub use sync::{SyncState, SyncSummary, MAX_OPS_PER_SYNC};
