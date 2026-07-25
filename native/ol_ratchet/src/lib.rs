//! `ol_ratchet` — per-chunk one-way symmetric key chain for One
//! Link's chunk-AEAD pipeline per ADR-0020.
//!
//! Phase C item #6 (per-chunk forward-secret ratchet). The shipping
//! daemon's `double_ratchet.py` ratchets PER MESSAGE; this crate
//! ratchets PER CHUNK so the AEAD key for chunk N is unrelated to the
//! key for chunk N+1 except via a one-way KDF chain.
//!
//! ## Threat model
//!
//! - **Compromise of one derived chunk/message key** does not directly
//!   expose the chain key in this API. Confidentiality still depends on
//!   caller erasure, key separation, the KDF assumption, and correct AEAD
//!   integration; this crate does not prove that only one plaintext is
//!   exposed in a complete runtime.
//! - **Compromise of the current chain key** reveals all FUTURE chunks
//!   until an independent root-key ratchet step. Prior chain states are not
//!   derivable through this API under the KDF one-wayness and erasure
//!   assumptions.
//! - **Replay is out of scope**: replaying a previously valid AEAD frame can
//!   authenticate again under the same key/nonce. Callers must persist and
//!   enforce transfer/chunk sequence or receipt state.
//!
//! ## Algorithm — symmetric chain
//!
//! Given a 32-byte root chain key `CK_0`, the per-chunk keys + the
//! advanced chain key are derived deterministically:
//!
//! ```text
//! (CK_{i+1}, MK_{i+1}) = HKDF-Expand(CK_i, "ol-ratchet-chain-step-v1", 64 bytes)
//! ```
//!
//! where the first 32 bytes is the next chain key and the second 32
//! bytes is the AEAD message key for chunk `i+1`. Backward derivation
//! (`CK_i` from `CK_{i+1}`) requires inverting a BLAKE3 keyed hash —
//! infeasible.
//!
//! ## Surface
//!
//! - [`Chain`] — owns a chain-key + step counter; advances on demand.
//! - [`SkippedKeyStore`] — bounded buffer of out-of-order keys for
//!   senders/receivers that may see chunks reordered (per ADR-0015
//!   fountain delivery, this is the common case).
//! - [`derive_root_chain_key`] — bootstrap the chain from a shared
//!   secret (e.g. the `ol_pqkem` hybrid output).

#![doc(html_root_url = "https://docs.rs/ol_ratchet/0.21.0")]

pub mod chain;
pub mod error;
pub mod skipped;

pub use chain::{
    derive_root_chain_key, Chain, ChainKey, MessageKey, CHAIN_KEY_LEN, MAX_SKIP_STEPS,
    MESSAGE_KEY_LEN,
};
pub use error::RatchetError;
pub use skipped::{SkippedKeyStore, DEFAULT_SKIPPED_CAP};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
