//! `ol_transfer` — the integrating engine for One Link's file engine v2
//! per [ADR-0013](../../../docs/decisions/0013-transfer-engine.md).
//!
//! Wires together:
//!
//! - [`ol_chunk_store::ChunkStore`] (Phase A1 storage)
//! - [`ol_quic::Endpoint`] / [`ol_quic::Connection`] (Phase A2 transport)
//! - [`ol_bloom::Bloom`] (Phase B Bloom-init handshake per ADR-0011)
//!
//! ## Surface
//!
//! - [`TransferEngine::new`] — construct (returns `Arc<Self>`).
//! - [`TransferEngine::register_peer`] / [`TransferEngine::forget_peer`]
//!   — peer registry management.
//! - [`TransferEngine::fetch_chunk`] — single-chunk fetch (idempotent,
//!   skips transport if chunk is already local).
//! - [`TransferEngine::fetch_many`] — bounded-concurrency batch fetch.
//! - [`TransferEngine::bloom_handshake`] — ADR-0011 Bloom-init exchange.
//! - [`TransferEngine::ping`] — liveness probe.
//! - [`TransferEngine::run_server`] — long-running inbound dispatcher
//!   (spawn on a tokio task).
//!
//! ## Threading
//!
//! `TransferEngine` is `Send + Sync` and designed to be shared via
//! `Arc<Self>`. The chunk store is held under a `std::sync::Mutex` so
//! the engine can mutate it from any task; the lock is held only for
//! short critical sections and never across `.await`.

#![doc(html_root_url = "https://docs.rs/ol_transfer/0.21.0")]

pub mod config;
pub mod engine;
pub mod error;
pub mod outcome;
pub mod peer;
pub mod server;
pub mod wire;

pub use config::TransferConfig;
pub use engine::TransferEngine;
pub use error::TransferError;
pub use outcome::FetchOutcome;
pub use peer::PeerEntry;

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
