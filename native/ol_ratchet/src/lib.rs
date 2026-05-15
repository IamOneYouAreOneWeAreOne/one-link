//! `ol_ratchet` — per-chunk forward-secret symmetric ratchet for One
//! Link's chunk-AEAD pipeline per ADR-0020.
//!
//! Phase C item #6 (per-chunk forward-secret ratchet). The shipping
//! daemon's `double_ratchet.py` ratchets PER MESSAGE; this crate
//! ratchets PER CHUNK so the AEAD key for chunk N is unrelated to the
//! key for chunk N+1 except via a one-way KDF chain.
//!
//! ## Threat model
//!
//! - **Compromise of one chunk's key** reveals exactly that chunk;
//!   subsequent chunks remain confidential (forward secrecy).
//! - **Compromise of the current chain key** reveals all FUTURE chunks
//!   until the next root-key ratchet step. Past chunks still safe.
//! - **Replay attacks**: each chunk gets a unique nonce derived from
//!   the chain key + chunk index; replays decrypt as garbage (AEAD
//!   tag fails).
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
