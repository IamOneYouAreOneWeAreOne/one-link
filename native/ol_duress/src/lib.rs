//! `ol_duress` — plausibly deniable storage + duress codes.
//!
//! Per `FILE_ENGINE_V2_PLAN.md` Phase D item #6:
//!
//! > Plausibly deniable storage + duress codes — decoy volume +
//! > duress-key-unlocks-decoy + steganographic coercion signal in
//! > ratchet header. Coercion-resistant tier.
//!
//! ## Threat model
//!
//! Operator is coerced (legal compulsion or physical threat) to
//! produce a decryption key. The "real" volume must look
//! indistinguishable from random data so its existence can be
//! plausibly denied; the "decoy" volume contains real-but-uninteresting
//! data that satisfies the coercer. The operator types either:
//!
//! - The **real key** — unlocks the protected volume; nothing
//!   observable changes for an external observer.
//! - The **duress key** — unlocks the decoy volume + emits a
//!   covert "I am under coercion" signal via the ratchet header
//!   that paired peers can decode but a network observer cannot.
//!
//! The crate is **policy + primitives**, not a full filesystem
//! driver — that wiring lands in the daemon when Phase D production
//! integration begins.
//!
//! ## Approach
//!
//! - [`Volume`] represents a 32-byte volume secret. Real and decoy
//!   volumes are independent.
//! - [`DuressGate::open`] takes a presented passphrase + the
//!   per-account `duress_marker` and decides: unlock real | unlock
//!   decoy | reject. The decision uses constant-time comparison so
//!   an attacker watching timing can't distinguish "wrong passphrase"
//!   from "duress passphrase."
//! - [`DuressGate::signal_in_ratchet_header`] emits a 32-byte
//!   covert marker that paired peers detect; the marker is
//!   indistinguishable from a random nonce to anyone without the
//!   pair-shared decoder.

#![forbid(unsafe_code)]
#![allow(missing_docs)]

mod gate;

pub use gate::{
    decode_covert_signal, DuressGate, DuressOutcome, GateError, Volume,
    SIGNAL_LEN, VOLUME_SECRET_LEN,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
