//! Hardware-bound key abstraction with a process-local TOFU prototype.
//!
//! See `docs/decisions/0023-hardware-bound-keys.md`.
//!
//! The plan's Phase C item #8 calls for "hardware-bound keys, TOFU-degrading."
//! The design is a `KeyStore` trait that platform-specific backends implement
//! (Apple Secure Enclave, Android `StrongBox`, Windows TPM via `NCrypt`). When no
//! hardware backend is available the crate currently exposes a software-only,
//! in-memory TOFU primitive. It is useful for exercising the trait and
//! rotation checks, but it is not a persistent production identity store.
//!
//! Vendor attestation chains are **optional**, not required — see ADR-0023.

#![forbid(unsafe_code)]
#![allow(missing_docs)]

mod error;
mod store;
mod tofu;

pub use error::{HwKeyError, Result};
pub use store::{Attestation, KeyHandle, KeyStore, PublicKey};
pub use tofu::{TofuStore, MAX_KEY_LABEL_BYTES, MAX_TOFU_ENTRIES};

/// The plan-mandated guarantee enum returned by `KeyStore::guarantee()`.
///
/// Callers can downgrade their threat model when the store can only offer
/// `TofuOnly` (no hardware backend present).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyGuarantee {
    /// Software-only TOFU primitive. The current implementation is
    /// process-local; callers must not infer disk persistence or hardware
    /// protection from this value.
    TofuOnly,
    /// Key is held by hardware (Secure Enclave / `StrongBox` / TPM). Use
    /// is gated by OS-level attestation of process identity. No vendor
    /// attestation chain.
    HardwareBound,
    /// Hardware-bound AND backed by a vendor attestation chain that the
    /// caller has chosen to verify (Apple App Attest / Android Play
    /// Integrity / Windows TPM EK).
    HardwareAttested,
}
