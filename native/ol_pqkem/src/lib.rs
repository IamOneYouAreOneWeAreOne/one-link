//! `ol_pqkem` — Post-quantum hybrid KEM combining ML-KEM-768 + X25519
//! with a BLAKE3 combiner per [ADR-0017](../../../docs/decisions/0017-pq-hybrid-kem.md).
//!
//! Phase C item #7 (PQ-hybrid by default). Replaces the daemon's
//! placeholder `pq_hybrid.NullKEM`.
//!
//! ## Security
//!
//! A hybrid KEM is secure against an adversary who breaks **either**
//! the classical component (X25519) or the post-quantum component
//! (ML-KEM-768), as long as the combiner is correctly bound to both
//! KEMs' public state. Per the X-Wing construction proof, our combiner
//! input includes:
//!
//! - ML-KEM ciphertext
//! - ML-KEM shared secret
//! - X25519 ephemeral pubkey
//! - X25519 shared secret
//!
//! ## API
//!
//! - [`keypair`] — generate a fresh `(HybridPublicKey, HybridSecretKey)`.
//! - [`encapsulate`] — initiator side: produce `(ciphertext, shared_secret)`.
//! - [`decapsulate`] — responder side: recover `shared_secret`.
//!
//! All outputs are 32-byte AEAD keys, ready for direct use by `ol_aead`.

#![doc(html_root_url = "https://docs.rs/ol_pqkem/0.21.0")]

pub mod error;
pub mod hybrid;

pub use error::PqKemError;
pub use hybrid::{
    decapsulate, encapsulate, keypair, HybridCiphertext, HybridPublicKey, HybridSecretKey,
    SharedSecret, HYBRID_CIPHERTEXT_LEN, HYBRID_PUBLIC_KEY_LEN, HYBRID_SECRET_KEY_LEN,
    SHARED_SECRET_LEN,
};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
