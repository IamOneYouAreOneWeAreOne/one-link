//! Row 8 Layer 4 — content-addressed distributed filesystem.
//!
//! Files live across the device mesh as content-addressed chunks
//! (matching the Phase A1 `ol_chunk` chunk hash format), erasure-
//! coded for 1.5×+ redundancy, and indexed via a per-chunk
//! placement map that lives as a Layer-3 CRDT subtree.
//!
//! ## Composition with the lower layers
//!
//! - **Layer 1 (subkeys)**: every [`StorageAttestation`] (a device
//!   claiming "I hold chunks X at time T") is signed by the
//!   emitter's per-device subkey. Replicas verify under the
//!   master-attested subkey VK.
//! - **Layer 2 (quorum)**: catastrophic operations on the FS
//!   (e.g., revoke a device + redistribute all of its chunks, or
//!   change the global erasure policy) are tagged for K-of-N
//!   approval via [`crate::quorum::QuorumCertificate`].
//! - **Layer 3 (CRDT mirror)**: the file index (`FileId` → manifest
//!   bytes) and the placement map (chunk hash → device-id set)
//!   are CRDT subtrees on the mesh state. Every device sees the
//!   same logical index without a central coordinator.
//!
//! ## Wire shape
//!
//! - [`FileManifest`] — ordered chunk-hash list + size +
//!   mime + erasure policy. The [`FileId`] is BLAKE3 over the
//!   canonical manifest bytes, so identical content produces
//!   identical `FileIds` across all devices (cross-device dedup).
//! - [`ErasurePolicy`] — Reed-Solomon `(k, m)` shard count + the
//!   minimum number of distinct devices that must hold each shard
//!   for the file to count as "durable."
//! - [`ChunkPlacement`] — the per-chunk index entry: which devices
//!   currently claim to hold this chunk, and when each device last
//!   attested.
//! - [`StorageAttestation`] — signed by the holding device:
//!   "I am `device_id`; at time T I held these chunk hashes;
//!   here's my subkey signature." Recipients verify under the
//!   master-attested subkey VK and update the placement map.
//!
//! ## Repair flow
//!
//! 1. Each device periodically issues a [`StorageAttestation`] for
//!    the chunks it currently holds.
//! 2. Every replica ingests attestations and updates the placement
//!    CRDT.
//! 3. Periodically (or on a device leaving the mesh), the repair
//!    daemon computes [`under_replicated`] chunks and a
//!    [`repair_plan`] that assigns them to additional devices.
//! 4. Each receiving device fetches the chunk via Phase A1's
//!    `ol_chunk_store` (over the mesh transport, layered below)
//!    and starts attesting to it on the next heartbeat.
//!
//! ## What this layer doesn't ship
//!
//! - The actual chunking + encryption pipeline. That's Phase A1
//!   (`ol_chunk`) + the AEAD layer.
//! - The Reed-Solomon encode/decode primitives. That's Phase C
//!   (`ol_erasure`). This layer references the policy parameters
//!   `(k, m)` and trusts the underlying crate's correctness.
//! - The fetch transport — Phase A2 QUIC + Layer 6 self-mesh
//!   routing once shipped.
//! - The bandwidth scheduler for repair (Phase D bandit, shipped,
//!   wires later).
//!
//! ## Worked example
//!
//! ```no_run
//! // Doctest is `no_run` because ML-DSA key material is ~2 KB —
//! // signing operations push doctest stacks past their default
//! // size on Windows. Compile-time validation is preserved.
//! use std::collections::BTreeSet;
//! use ol_device_mesh::distributed_fs::{
//!     repair_plan, sign_storage_attestation, under_replicated,
//!     ChunkHash, ChunkPlacement, ErasurePolicy, FileManifest,
//! };
//! use ol_device_mesh::{
//!     mint_subkey, DeviceClass, MasterIdentity,
//! };
//! use rand::rngs::OsRng;
//!
//! // Mint a master + one phone subkey.
//! let master = MasterIdentity::generate(&mut OsRng);
//! let (phone_sk, _att) =
//!     mint_subkey(&master, DeviceClass::Phone, [0xAA; 16], 0, 365).unwrap();
//!
//! // Phone signs an attestation that it holds two chunks.
//! let att = sign_storage_attestation(
//!     &phone_sk,
//!     1_700_000_000,
//!     vec![[0x01; 32], [0x02; 32]],
//! ).unwrap();
//! att.verify(&phone_sk.verifying_key()).unwrap();
//!
//! // Replicas track per-chunk placement; the under-replication
//! // detector finds chunks below the durability rule.
//! let policy = ErasurePolicy::new(2, 1, 3).unwrap();
//! let mut p = ChunkPlacement::empty([0x01; 32]);
//! p.add_holder([0xAA; 16], 1_700_000_000);
//! let under = under_replicated([&p], &policy);
//! assert_eq!(under, vec![[0x01; 32]]);  // only 1 holder, need 3
//!
//! // Repair planner spreads under-replicated chunks across eligible
//! // mesh devices.
//! let mesh: BTreeSet<[u8; 16]> =
//!     [[0xAA; 16], [0xBB; 16], [0xCC; 16], [0xDD; 16]].into_iter().collect();
//! let plan = repair_plan([&p], &mesh, &policy);
//! assert_eq!(plan.len(), 2);
//! ```

pub mod attest;
pub mod manifest;
pub mod placement;
pub mod policy;
pub mod repair;

pub use attest::{
    sign_storage_attestation, StorageAttestation, ATTEST_DOMAIN,
    MAX_CHUNKS_PER_ATTESTATION,
};
pub use manifest::{
    file_id, FileId, FileManifest, ChunkHash, CHUNK_HASH_LEN,
    FILE_ID_LEN, MAX_CHUNKS_PER_FILE, MAX_MIME_LEN, MANIFEST_DOMAIN,
};
pub use placement::{ChunkPlacement, under_replicated};
pub use policy::{ErasurePolicy, MAX_K_PLUS_M};
pub use repair::{repair_plan, RepairAssignment};
