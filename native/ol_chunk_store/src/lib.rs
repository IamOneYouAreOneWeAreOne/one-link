//! `ol_chunk_store` — the integrating chunk store for One Link's file
//! engine v2.
//!
//! Combines:
//!
//! - [`ol_wal`] crash-only WAL (`chunk_log` + `manifest_log` files per
//!   [ADR-0003](../../../docs/decisions/0003-on-disk-format.md))
//! - [`ol_chunk`] BLAKE3 derivation (chunk addresses, `ratchet_key_id`,
//!   stripe seeds per [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md))
//! - [`ol_aead`] per-chunk AEAD encrypt/decrypt
//! - In-memory **memtable**: `chunk_id` → on-disk location
//! - **Bloom filter front**: sub-microsecond chunk-presence checks
//! - Manifest WAL coupling via `chunk_log_anchor` per
//!   [ADR-0005](../../../docs/decisions/0005-manifest-wal-coupling.md)
//! - **Stripe descriptor** support from day one per
//!   [ADR-0004](../../../docs/decisions/0004-stripe-layout.md), even though
//!   the encoder ships in Phase C
//! - **Both raw and convergent** chunk addressing in the `chunk_log` header
//!   so Phase B can flip the default without a format break
//!
//! ## Surface
//!
//! - [`ChunkStore::open`] — open/create a store rooted at a directory.
//! - [`ChunkStore::write_chunk`] — write a chunk record (writes `chunk_log`
//!   THEN matching `manifest_log` entry per ADR-0005 atomicity protocol).
//! - [`ChunkStore::has_chunk`] — bloom + memtable presence check.
//! - [`ChunkStore::read_chunk`] — read a chunk's on-wire ciphertext +
//!   `ratchet_key_id` + stripe descriptor.
//! - [`ChunkStore::write_manifest`] — append a manifest record (with
//!   `chunk_log_anchor` automatically set to the most-recent `chunk_log`
//!   offset).
//! - [`ChunkStore::flush`] — durability barrier on both logs.
//! - [`ChunkStore::stats`] — counters for diagnostics.

#![doc(html_root_url = "https://docs.rs/ol_chunk_store/0.21.0")]

pub mod chunk_record;
pub mod error;
pub mod location;
pub mod manifest_record;
pub mod memtable;
pub mod store;
pub mod stripe;

pub use chunk_record::{
    convergent_default_for_content_type, ChunkAddressKind, ChunkAeadKind, ChunkRecord,
    ChunkRecordKind, CHUNK_RECORD_HEADER_LEN, MAX_CHUNK_CIPHERTEXT_LEN,
};
pub use error::ChunkStoreError;
pub use location::{decode_chunk_log_anchor, encode_chunk_log_anchor, ChunkLocation};
pub use manifest_record::{
    ManifestRecord, ManifestRecordKind, MANIFEST_RECORD_HEADER_LEN, MAX_MANIFEST_BODY_LEN,
};
pub use memtable::{Memtable, MAX_MEMTABLE_CAPACITY_HINT};
pub use store::{ChunkStore, StoreStats};
pub use stripe::{StripeDescriptor, StripeRole, STRIPE_DESCRIPTOR_LEN};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
