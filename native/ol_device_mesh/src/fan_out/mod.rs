//! Row 8 Layer 5 — multi-device fan-out for big transfers.
//!
//! When a receiver wants a large file, fan-out lets multiple source
//! devices in the same personal mesh stream chunks in parallel.
//! Phone in TX requests "the 50GB project folder" → laptop +
//! desktop + tablet each carry a fraction → phone reassembles via
//! Phase B fountain codes (any K of K+M shards suffice).
//!
//! ## Composition with the lower layers
//!
//! - **Layer 1 (subkeys)**: every [`FetchRequest`] is signed by the
//!   receiver's per-device subkey; every [`ChunkAck`] is signed by
//!   the source's subkey. The other party verifies under the
//!   master-attested subkey VK from Layer 1.
//! - **Layer 4 (placement)**: the planner reads the per-chunk
//!   placement map to know which sources hold which chunks.
//! - **Layer 6 (`τ_c` routing, future)**: per-source capacity scores
//!   are populated by the daemon's bandit + tau-field measurement;
//!   the planner is policy-agnostic about how they're computed.
//! - **Phase B fountain codes (shipped)**: the planner over-requests
//!   slightly so the receiver completes as soon as ANY `k` shards
//!   arrive, even if some sources are slow.
//!
//! ## What this layer does
//!
//! - [`fan_out_plan`] assigns each chunk in a fetch set to one
//!   source device, weighted by source capacity, while respecting
//!   "only holders can serve" and "spread load."
//! - [`replan_after_source_failure`] redistributes the chunks
//!   assigned to a dropped source across the remaining sources.
//! - [`TransferProgress`] tracks per-chunk arrival state and signals
//!   completion when `≥ k` shards have arrived.
//!
//! ## What this layer doesn't ship
//!
//! - The actual wire transport (Phase A2 QUIC + Layer 6 self-mesh
//!   routing once shipped).
//! - The fountain-code encode / decode (Phase B `ol_fountain`,
//!   shipped). The planner counts shards; the decoder runs upstream
//!   when chunks arrive.
//! - The capacity estimator (Phase D bandit, shipped).
//!
//! ## Example
//!
//! ```no_run
//! // Doctest is `no_run` because ML-DSA key material is ~2 KB —
//! // signing operations push doctest stacks past their default
//! // size on Windows. Compile-time validation is preserved.
//! use ol_device_mesh::distributed_fs::{ChunkHash, ChunkPlacement, ErasurePolicy, FileManifest};
//! use ol_device_mesh::fan_out::{fan_out_plan, SourceCapacity};
//! use ol_device_mesh::DEVICE_ID_LEN;
//!
//! // 3 chunks across 3 sources of varying capacity.
//! let chunks: Vec<ChunkHash> = vec![[0x11; 32], [0x22; 32], [0x33; 32]];
//! let policy = ErasurePolicy::new(2, 1, 1).unwrap();
//! let manifest = FileManifest {
//!     file_size: 1_000_000,
//!     chunk_size: 8192,
//!     chunks: chunks.clone(),
//!     mime: b"x".to_vec(),
//!     created_unix: 0,
//!     policy,
//! };
//! let placements: Vec<ChunkPlacement> = chunks
//!     .iter()
//!     .map(|c| {
//!         let mut p = ChunkPlacement::empty(*c);
//!         p.add_holder([1; DEVICE_ID_LEN], 1);
//!         p.add_holder([2; DEVICE_ID_LEN], 1);
//!         p.add_holder([3; DEVICE_ID_LEN], 1);
//!         p
//!     })
//!     .collect();
//! let sources = vec![
//!     SourceCapacity { device_id: [1; DEVICE_ID_LEN], estimated_bps: 100_000_000, current_load_bytes: 0 },
//!     SourceCapacity { device_id: [2; DEVICE_ID_LEN], estimated_bps:  50_000_000, current_load_bytes: 0 },
//!     SourceCapacity { device_id: [3; DEVICE_ID_LEN], estimated_bps:  10_000_000, current_load_bytes: 0 },
//! ];
//! let plan = fan_out_plan(&manifest, &placements, &sources, 1.0).unwrap();
//! // Every assigned chunk has exactly one source.
//! let total_chunks: usize = plan.assignments.iter().map(|a| a.chunk_hashes.len()).sum();
//! assert_eq!(total_chunks, 3);
//! ```

pub mod ack;
pub mod plan;
pub mod progress;
pub mod request;

pub use ack::{sign_chunk_ack, ChunkAck, ACK_DOMAIN};
pub use plan::{
    fan_out_plan, replan_after_source_failure, FanOutAssignment, FanOutPlan,
    SourceCapacity,
};
pub use progress::TransferProgress;
pub use request::{
    sign_fetch_request, FetchRequest, FetchNonce, FETCH_NONCE_LEN, FETCH_REQUEST_DOMAIN,
    MAX_CHUNKS_PER_FETCH,
};
