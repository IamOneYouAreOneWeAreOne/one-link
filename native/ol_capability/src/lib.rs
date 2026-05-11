//! `ol_capability` — macaroon-style capabilities per ADR-0021.
//!
//! Phase C item #3. Replaces the daemon's Phase A1 Ed25519-grant
//! scheme (`One_link/src/one_link/capabilities.py`) with first-party
//! HMAC-chained capabilities.
//!
//! ## Surface
//!
//! - [`Capability`] — the token: identifier + caveats + signature.
//! - [`Caveat`] — typed restrictions (time-bound, scope-bound, etc).
//! - [`Context`] — the runtime context against which a cap is verified.
//! - [`RootKey`] — 32-byte HMAC root key the issuer keeps secret.
//!
//! ## Threat model
//!
//! - Holder of a cap CAN attenuate (append more caveats); the new
//!   signature is derivable from the current one + the new caveat.
//! - Holder CANNOT remove caveats (HMAC chain would no longer verify).
//! - Holder CANNOT forge a fresh cap (would need the root HMAC key).
//! - Constant-time signature comparison prevents bit-by-bit forgery.

#![doc(html_root_url = "https://docs.rs/ol_capability/0.21.0")]
// The crate's public surface (`Capability`, `Caveat`, `Context`, `CapError`)
// is fully documented; internal helpers and module-private items are
// allowed to skip docs to keep the working surface focused.
#![allow(missing_docs)]

pub mod capability;
pub mod caveat;
pub mod context;
pub mod error;

pub use capability::{Capability, RootKey, SIGNATURE_LEN, ROOT_KEY_LEN, CAP_ID_LEN};
pub use caveat::Caveat;
pub use context::Context;
pub use error::CapError;

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
