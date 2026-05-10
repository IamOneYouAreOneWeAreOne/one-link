//! `ol_fountain` — LT fountain codes for One Link's swarm transfer
//! layer per [ADR-0015](../../../docs/decisions/0015-fountain-codes.md).
//!
//! ## What this gives you
//!
//! - [`LtEncoder`] — encodes a chunk plaintext into a stream of LT
//!   symbols, deterministically seeded by `symbol_id`.
//! - [`LtDecoder`] — reconstructs the chunk plaintext from any
//!   sufficient subset of encoded symbols via belief propagation.
//! - [`FountainPacket`] — on-wire encode/decode of a single fountain
//!   packet (chunk_id + k + symbol_id + source_length + payload).
//! - [`Distribution`](distribution) — Robust Soliton degree distribution
//!   with Phase B-fixed (`c=0.03`, `δ=0.05`) parameters.
//!
//! ## What this crate does NOT do
//!
//! - It does not wire fountain packets through the QUIC frame layer;
//!   that's `ol_transfer`'s job (will land in Phase B-1.5 once a
//!   `FountainBurst` frame kind ships).
//! - It does not verify chunk integrity. The caller is expected to
//!   compute `BLAKE3(decoded_plaintext)` and compare to the chunk_id
//!   before storing.

#![doc(html_root_url = "https://docs.rs/ol_fountain/0.21.0")]

pub mod decoder;
pub mod distribution;
pub mod encoder;
pub mod error;
pub mod packet;
pub mod rng;

pub use decoder::{LtDecoder, MAX_ENCODED_PER_CHUNK};
pub use distribution::{robust_soliton_cdf, sample_degree, sample_neighbors, C, DELTA};
pub use encoder::LtEncoder;
pub use error::FountainError;
pub use packet::{FountainPacket, PACKET_HEADER_LEN};
pub use rng::{seed_for, SplitMix64};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
