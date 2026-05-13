//! Coherence Mesh Row 8 — Personal Device Mesh identity layer (Layer 1).
//!
//! Builds the cryptographic foundation that lets one logical identity
//! own many devices without revealing the device count to friends and
//! without sacrificing per-device forward secrecy.
//!
//! ## What this crate provides
//!
//! - `MasterIdentity`: a [`ol_pqsig::HybridSigningKey`] anchored to a
//!   32-byte master seed. Generated once per human. Friends pin the
//!   master verifying key.
//! - `DeviceClass`: phone / laptop / tablet / desktop / server /
//!   wearable / appliance — drives device-policy decisions in higher
//!   layers (battery, network, allowed-caps) and is bound into the
//!   subkey-derivation transcript so two devices of the same class but
//!   different `device_id` never collide.
//! - `DeviceSubkey`: a per-device hybrid signing key deterministically
//!   derived from `(master_seed, device_class, device_id, day_index)`
//!   via BLAKE3-keyed HKDF.  Friends never see subkey verifying keys
//!   directly; everything is signed under the master pubkey via a
//!   cross-sign attestation (see `SubkeyAttestation`).
//! - **Daily ratchet**: each subkey has an underlying *chain root* and
//!   a current *day index*. `step_one_day()` advances the chain via
//!   `S_{n+1} = HKDF(S_n, "ratchet")` and zeroizes `S_n`.  A stolen
//!   device whose subkey is captured today cannot decrypt any prior
//!   day's traffic, even with the master pubkey, because the prior
//!   subkeys are not recoverable without the master *seed*.
//! - **Field-binding hook**: subkey derivation optionally consumes a
//!   [`ol_threshold_recovery::FieldWitness`] so a captured raw seed is
//!   useless without reproducing the coherence-field state at mint.
//! - **Cross-witness attestation**: each device periodically signs a
//!   `LivenessProof` over its own state + the wall-clock epoch.  A
//!   sibling device that fails to produce a fresh proof gets flagged
//!   for auto-revocation by quorum at Layer 2.
//! - **HardwareWrapper trait**: opaque interface for wrapping the raw
//!   subkey bytes under platform key storage (Secure Enclave / TPM /
//!   StrongBox / TrustZone).  A software-only reference impl is
//!   provided; production builds wire platform backends via the trait.
//!
//! ## Layer-1 acceptance gate
//!
//! - Subkey derivation is deterministic on `(master_seed, device_class,
//!   device_id, day_index)` and byte-stable across builds.
//! - Daily ratchet advances forward only; old seeds zeroize on step.
//! - Subkey attestations are cross-signed by the master and verify
//!   under the master's `HybridVerifyingKey`.
//! - LivenessProof timing variance under the ct-gate ≤ 15 %.
//! - 1M iters of property-testing on the subkey/ratchet/attestation
//!   surface pass with no panics.
//!
//! ## Layer status
//!
//! - **Layer 1** (this crate): identity stack — what's documented
//!   above.  Pure Rust; no daemon wiring yet.
//! - **Layer 2** (separate ship): threshold device quorum on top of
//!   row 9 Shamir.
//! - **Layer 3+** (separate ships): CRDT state mirror, distributed
//!   filesystem, multi-device fan-out, τ_c-routed self-mesh, etc.
//!
//! ## Worked example
//!
//! ```no_run
//! // Doctest is `no_run` because ML-DSA-65 key material is ~2 KB
//! // and signing operations push doctest stacks past their default
//! // size on Windows. Compile-time validation is preserved.
//! use ol_device_mesh::{
//!     mint_subkey, sibling_witness, state_root, verify_liveness,
//!     DeviceClass, LivenessProof, MasterIdentity,
//!     DEFAULT_LIVENESS_SKEW_SECS,
//! };
//! use rand::rngs::OsRng;
//!
//! // Generate the master identity once per human; friends pin its VK.
//! let master = MasterIdentity::generate(&mut OsRng);
//! let pinned_vk = master.verifying_key();
//!
//! // Mint a per-device subkey for the phone, valid for one year.
//! let phone_id = [0x42u8; 16];
//! let (phone_subkey, phone_attestation) =
//!     mint_subkey(&master, DeviceClass::Phone, phone_id, 0, 365).unwrap();
//!
//! // Friends only ever check attestations under the pinned master VK.
//! phone_attestation.verify(&pinned_vk).unwrap();
//!
//! // The phone issues a liveness proof every N minutes so siblings
//! // can confirm it's alive + not seized.
//! let now_unix = 1_700_000_000u64;
//! let proof = LivenessProof::issue(
//!     &phone_subkey,
//!     now_unix,
//!     state_root(b"current crdt state hash"),
//! ).unwrap();
//!
//! // A sibling device verifies the proof under the phone's subkey VK
//! // (obtained from the attestation it cached) and the wall clock.
//! let witness = sibling_witness(phone_subkey.verifying_key(), DEFAULT_LIVENESS_SKEW_SECS);
//! verify_liveness(&proof, &witness, now_unix).unwrap();
//! ```

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]

pub mod active_routing;
pub mod attestation;
pub mod compute;
pub mod derivation;
pub mod device_class;
pub mod distributed_fs;
pub mod duress;
pub mod errors;
pub mod fan_out;
pub mod hardware;
pub mod master;
pub mod mesh_state;
pub mod quorum;
pub mod ratchet;
pub mod self_onion;
pub mod self_routing;
pub mod subkey;

pub use attestation::{
    sibling_witness, state_root, verify_liveness, LivenessProof, SiblingWitness,
    DEFAULT_LIVENESS_SKEW_SECS, LIVENESS_DOMAIN,
};
pub use derivation::{
    derive_subkey_seed, HKDF_DOMAIN, SUBKEY_SEED_LEN,
};
pub use device_class::{DeviceClass, DEVICE_CLASS_TAG_LEN};
pub use errors::{DeviceMeshError, DeviceMeshResult};
pub use hardware::{HardwareWrapper, SoftwareWrapper, WRAPPED_KEY_OVERHEAD};
pub use master::{MasterIdentity, MASTER_SEED_LEN};
pub use ol_pqsig::{HybridSigningKey, HybridVerifyingKey};
pub use ratchet::{ratchet_one_day, RATCHET_DOMAIN};
pub use subkey::{
    fresh_device_id, master_pin_handle, mint_subkey, mint_subkey_field_bound,
    redrive_subkey_at_day, DeviceSubkey, SubkeyAttestation, DEVICE_ID_LEN,
    SUBKEY_ATTESTATION_DOMAIN,
};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
