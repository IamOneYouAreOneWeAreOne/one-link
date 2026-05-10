//! `ol_erasure` — chunk-level Reed-Solomon erasure coding for One Link's
//! durability layer per ADR-0018.
//!
//! Phase C item #2 (erasure-coded durability). Builds on [`ol_fec`]'s
//! shard-level codec and integrates with `ol_chunk_store`'s
//! `StripeDescriptor` for on-disk + on-wire identification of which
//! shard a chunk belongs to.
//!
//! ## Model
//!
//! A "stripe" is a single source plaintext (typically a CDC chunk)
//! split into `k` data shards plus `m` parity shards. Each shard:
//!
//! - Has its own content-addressed `chunk_id` (BLAKE3 of the shard bytes).
//! - Carries a `StripeDescriptor` that records the stripe identity,
//!   the shard's role (Data vs Parity), and its index within the stripe.
//!
//! Any `k` of the `k + m` shards reconstruct the original chunk. Dedup
//! happens at the data-shard level: if two senders have the same source
//! plaintext, their data shards are byte-equivalent (same BLAKE3
//! address), but the parity shards are NOT cross-storer-deduplicated
//! (different cohorts produce different parity bytes; this is by design
//! per the plan's stress-test #3).
//!
//! ## Surface
//!
//! - [`encode_stripe`] — split a plaintext into K+M shards.
//! - [`decode_stripe`] — recover the plaintext from any K of K+M shards.
//! - [`Shard`] — one piece of a stripe with its descriptor.
//! - [`StripeView`] — a typed view over the K+M shards for decode input.

#![doc(html_root_url = "https://docs.rs/ol_erasure/0.21.0")]

pub mod error;
pub mod stripe;

pub use error::ErasureError;
pub use stripe::{decode_stripe, encode_stripe, Shard, ShardRole, StripeId, StripeParams};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
