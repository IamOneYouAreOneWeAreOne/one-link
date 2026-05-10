//! `ol_fec` — Reed-Solomon FEC over GF(2^8) using a Cauchy systematic
//! matrix per [ADR-0016](../../../docs/decisions/0016-reed-solomon-fec.md).
//!
//! Phase C item #1 (erasure-recovery codec) and substrate for item #2
//! (erasure-coded durability via `ol_erasure`).
//!
//! ## Surface
//!
//! - [`Codec`] — pre-built `(k, m)` Reed-Solomon codec.
//! - [`gf256`] — GF(2^8) primitive operations + log/exp tables.
//! - [`cauchy::CauchyMatrix`] — the always-invertible generator matrix
//!   structure underlying the codec.
//!
//! ## Why custom, not `reed-solomon-erasure`?
//!
//! Per ADR-0016: sovereignty + always-invertible recovery (Cauchy
//! submatrices, unlike Vandermonde, are invertible for ANY erasure
//! pattern). Speed is ~500 MiB/s/core scalar; SIMD acceleration is a
//! Phase D upgrade.

#![doc(html_root_url = "https://docs.rs/ol_fec/0.21.0")]

pub mod cauchy;
pub mod codec;
pub mod error;
pub mod gf256;

pub use cauchy::CauchyMatrix;
pub use codec::Codec;
pub use error::FecError;

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
