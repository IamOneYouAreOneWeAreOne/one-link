//! Row 10 — confidential-operation primitives.
//!
//! This crate defines sealed-blob and signed-attestation-envelope surfaces.
//! It does not place the One Link daemon inside a confidential-compute
//! boundary and does not close local root/kernel compromise of the long-term
//! identity key.
//!
//! ## The threat model this row closes
//!
//! - **T-LOCAL-MAL-USER**: user-mode malware on the device wants to
//!   read the master key from process memory. The software provider does
//!   **not** defeat malware that can inspect or inject into its process;
//!   both its sealing key and transient plaintext live in that process.
//!   It narrows accidental at-rest exposure outside the live provider.
//! - **T-LOCAL-MAL-ROOT**: root malware (Linux) / SYSTEM (Windows) /
//!   kexec / cold-boot. Software baseline DOES NOT defeat this — only
//!   a correctly integrated and remotely verified hardware boundary may
//!   reduce this risk. The provider tier
//!   ([`ConfidentialTier::HardwareBound`] / `HardwareAttested`) is
//!   the production answer; this crate provides the trait so per-
//!   platform back-ends slot in without breaking the API.
//! - **T-REMOTE-IMPERSONATE**: a peer wants proof that you're running
//!   in a genuine enclave before exchanging long-term secrets. An
//!   [`attestation::AttestationDoc`] proves a signed transcript and fresh
//!   challenge response. Genuine hardware claims additionally require a
//!   verified vendor/EK chain and platform measurements; a provider tag or
//!   self-contained ECDSA public key is insufficient.
//!
//! ## What ships in Phase 1 (this crate)
//!
//! - The [`ConfidentialProvider`] trait — the platform-agnostic
//!   sealed-op surface (sealed sign / sealed derive child / verifying
//!   key / attestation).
//! - [`software::SoftwareProvider`] — software reference
//!   baseline. ChaCha20-Poly1305 sealing under a per-process
//!   ephemeral key, [`Zeroize`] on drop, attestation signed by the
//!   master identity. Tier = [`ConfidentialTier::Software`].
//! - [`attestation::AttestationDoc`] — canonical signed envelope.
//!   PQ-hybrid + freshness window + replay nonce + optional field
//!   witness binding.
//! - [`tier::detect_runtime_tier`] — probe at startup to pick the
//!   best provider available. Today returns
//!   [`ConfidentialTier::Software`]; per-platform detection lands
//!   in Phase 2 commits.
//!
//! ## Composition with other rows
//!
//! - Row 1 (`ol_pqsig`): every sealed signature uses the hybrid
//!   `Ed25519 + ML-DSA-65` primitive. The provider IS the place
//!   where the secret half lives sealed; the public half is
//!   exposed for verification.
//! - Row 8 ([`ol_device_mesh::MasterIdentity`]): the master
//!   identity is the long-term key the provider seals. Sealed
//!   signing replaces direct calls to `master.signing_key().sign()`
//!   in any caller that opts into Row 10.
//! - Row 9 ([`ol_threshold_recovery`]): the same field-witness
//!   machinery binds attestation docs to a coherence-field state, so
//!   a signed commitment can require verifier-supplied bytes to match. It
//!   does not prove that those bytes came from a physical field/location or
//!   prevent copying the same bytes to another host.
//! - [`ol_hwkey::KeyGuarantee`]: [`ConfidentialTier`] generalises
//!   this. `Software` < `HardwareBound` < `HardwareAttested`.
//!
//! ## What is deliberately NOT in this crate yet
//!
//! - Per-platform hardware back-ends (SGX, SEV-SNP, Secure Enclave,
//!   TPM, `TrustZone`). Each is a separate Phase-2 ship because each
//!   needs platform-specific testing infrastructure.
//! - The Python daemon migration that wires sealed sign into the
//!   running daemon. That lands as a follow-up commit so this row
//!   ships atomically.

// `unsafe` is forbidden everywhere except the platform-specific
// hardware backends (e.g., `windows_tpm`) where FFI into the OS
// crypto APIs is unavoidable. Those modules document each unsafe
// block and justify why the invariant holds.
#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod attestation;
pub mod errors;
pub mod heartbeat;
pub mod platform_quote;
pub mod provider;
pub mod sealed_key;
pub mod software;
pub mod tier;

#[cfg(all(target_os = "windows", feature = "windows-tpm"))]
pub mod windows_hardened;
#[cfg(all(target_os = "windows", feature = "windows-tpm"))]
pub mod windows_tpm;
#[cfg(all(target_os = "windows", feature = "windows-tpm"))]
pub use windows_hardened::WindowsHardenedProvider;

pub use attestation::{
    fresh_attestation_nonce, sign_attestation, verify_attestation, AttestationDoc,
    AttestationNonce, IssuerSdpPubkey, ATTESTATION_DOMAIN, ATTESTATION_FRESHNESS_WINDOW_SECS,
    ATTESTATION_MAX_AGE_SECS, ATTESTATION_MAX_CLOCK_SKEW_SECS, ATTESTATION_NONCE_LEN,
    ISSUER_SDP_PUBKEY_LEN,
};
pub use errors::{ConfidentialError, ConfidentialResult};
pub use platform_quote::{
    canonical_platform_quote_subtranscript, parse_platform_quote, verify_platform_quote,
    PLATFORM_QUOTE_DOMAIN,
};
pub use provider::{ConfidentialProvider, ProviderTag};
pub use sealed_key::SealedKey;
pub use software::SoftwareProvider;
pub use tier::{detect_runtime_tier, ConfidentialTier};
