//! `ol_duress` — duress-gate and signaling primitives.
//!
//! Per `FILE_ENGINE_V2_PLAN.md` Phase D item #6:
//!
//! > Plausibly deniable storage + duress codes — decoy volume +
//! > duress-key-unlocks-decoy + steganographic coercion signal in
//! > ratchet header. Coercion-resistant tier.
//!
//! ## Design target and current boundary
//!
//! The design target is a coercion-aware filesystem in which an operator can
//! open a decoy volume and notify trusted peers. This crate does not implement
//! storage layout, a filesystem driver, UI behavior, or network embedding, so
//! it does not provide plausible deniability or coercion resistance by itself.
//! It classifies a presented passphrase against caller-supplied checks and
//! returns either:
//!
//! - A derived **real-volume key**.
//! - A derived **decoy-volume key** plus deterministic signal bytes that a
//!   caller may embed in another authenticated protocol.
//!
//! The crate is **policy + primitives**, not a full filesystem
//! driver — that wiring lands in the daemon when Phase D production
//! integration begins.
//!
//! ## Approach
//!
//! - [`Volume`] represents a 32-byte volume secret. Real and decoy
//!   volumes are independent.
//! - [`DuressGate::open`] takes a presented passphrase plus expected check
//!   values and decides real | decoy | reject. It evaluates both derivations
//!   before selecting an outcome, but source structure and timing tests are
//!   not a universal side-channel proof.
//! - [`DuressGate::signal_in_ratchet_header`] emits a deterministic 32-byte
//!   keyed marker. This crate does not place it on a wire or establish that
//!   its surrounding traffic is covert or indistinguishable from non-duress
//!   traffic; that is a promotion gate for a complete protocol.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod gate;

pub use gate::{
    decode_covert_signal, DuressGate, DuressOutcome, GateError, Volume, SIGNAL_LEN,
    VOLUME_SECRET_LEN,
};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
