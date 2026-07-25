//! `ol_pqkem` — Post-quantum hybrid KEM combining ML-KEM-768 + X25519
//! with a BLAKE3 combiner per [ADR-0017](../../../docs/decisions/0017-pq-hybrid-kem.md).
//!
//! Phase C item #7 primitive. Repository presence does not make every daemon,
//! browser, or WebRTC channel post-quantum; runtime negotiation and self-test
//! evidence must be checked by the calling product path.
//!
//! ## Security
//!
//! Design intent: retain shared-secret security while at least one component
//! remains secure, subject to the exact combiner construction, transcript
//! binding, implementation, and protocol context. The fact that this custom
//! BLAKE3 combiner includes the following values does not inherit the X-Wing
//! proof automatically and is not a proof of a complete daemon handshake:
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
//! The 32-byte output is shared-secret material. Callers must bind the full
//! handshake transcript, roles, suite, and application context before use.

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
