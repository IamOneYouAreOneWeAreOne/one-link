//! `ol_bloom` — content-addressed Bloom filter for One Link's
//! transfer-initiation handshake per [ADR-0011].
//!
//! The Bloom filter is sized for a target false-positive rate (default
//! 1%) and uses Kirsch + Mitzenmacher 2006 double-hashing to avoid
//! computing `k` independent BLAKE3 hashes per insert/query. Two
//! BLAKE3-derived hashes (one per registered domain context) are
//! computed once per `chunk_id`; the `k` bit-positions are linear
//! combinations.
//!
//! ## Wire format
//!
//! ```text
//! +--------+--------+----------+--- bit array ---+
//! | m_bits | k_funcs| reserved | filter bits     |
//! | u32 LE | u32 LE | u32 LE=0 | ceil(m/8) bytes |
//! +--------+--------+----------+-----------------+
//! ```
//!
//! 12-byte header + filter bits. Single QUIC frame for filters ≤ 1 MiB.
//!
//! [ADR-0011]: ../../../docs/decisions/0011-bloom-transfer-init.md

#![doc(html_root_url = "https://docs.rs/ol_bloom/0.21.0")]

pub mod error;
pub mod filter;
pub mod sizing;

pub use error::BloomError;
pub use filter::{Bloom, BLOOM_HEADER_LEN, MAX_FILTER_BITS, MAX_FILTER_BYTES};
pub use sizing::{optimal_k, optimal_m_bits, target_fp_rate, DEFAULT_TARGET_FP_RATE};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
