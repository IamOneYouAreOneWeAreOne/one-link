//! Row 8 Layer 10 — adversary-grade privacy tier: duress mode +
//! plausibly-deniable second persona + steganographic pairing.
//!
//! Experimental primitives with three design goals. This module does not
//! by itself provide a complete decoy persona, sensor acquisition, silent
//! delivery, coercion resistance, or forensic deniability:
//!
//! 1. **Duress mode**: a device gets seized (border crossing,
//!    coercion, mugging). The user types a *duress code* instead
//!    of the real unlock. The device:
//!    - The target UI presents a complete, plausible decoy mesh state.
//!    - The target daemon delivers a signed [`DuressAlert`] to siblings.
//!    - This crate encrypts real and decoy payload slots, but the envelope
//!      format itself reveals that two slots exist; no claim is made that a
//!      forensic examiner cannot identify the duress feature.
//!
//! 2. **Plausibly deniable second persona**: every [`DuressEnvelope`]
//!    on disk has two ciphertexts (real + decoy) that are
//!    structurally matched. Without the *secret, high-entropy* witness,
//!    knowing the user's password recovers at most the decoy through this
//!    API. Public/low-entropy field output is not an independent key.
//!    The real ciphertext is XOR-bound to a coherence-field
//!    witness (the row-9 mechanism reused at Layer 1).
//!
//! 3. **Steganographic pairing**: pairing a new device commits over
//!    THREE channels (QR + sub-perceptible audio chirp +
//!    accelerometer-pattern). The pair completes only when all
//!    three commit to the same secret within a time window. A
//!    verifier checks commitments supplied by callers. This crate does not
//!    capture/authenticate real audio or motion sensors, so it does not prove
//!    proximity or defeat a remote attacker by itself.
//!
//! ## What this layer ships
//!
//! - [`DuressCode`] — Argon2id-derived 32-byte key from a short
//!   user-entered code.
//! - [`DuressEnvelope`] — two ChaCha20-Poly1305 AEAD ciphertexts
//!   (`real_ct` + `decoy_ct`) plus salts. Slot encodings are structurally
//!   matched, while the two-slot envelope type remains observable.
//! - [`UnlockOutcome`] — `Real(_)`, `Decoy(_)`, or `WrongCode`.
//!   The daemon flips the duress flag on `Decoy`.
//! - [`DuressAlert`] — signed broadcast "I'm under duress as of T."
//! - [`PairingCommitment`] + [`verify_pairing_cross_channel`] —
//!   the cross-channel pair verifier.
//! - [`DuressPolicy`] — daemon-side policy (whether to emit a
//!   silent alert immediately on decoy unlock; how long to keep
//!   the device in decoy-only mode after a duress unlock; etc.).
//!
//! ## Field-binding
//!
//! `DuressEnvelope::create` requires a 32-byte `field_witness` for
//! the REAL ciphertext. The witness derives from the Phase E
//! coherence-field state at mint time (or any 32-byte secret the
//! user holds out-of-band). It must be independently generated or
//! demonstrated to have adequate min-entropy and stored separately;
//! otherwise the field context adds no cryptographic boundary.
//!
//! ## Composition with the lower layers
//!
//! - **Layer 1**: every [`DuressAlert`] is signed by the seized
//!   device's subkey.
//! - **Layer 2**: receiving siblings escalate the alert into a
//!   K-of-N [`crate::quorum::QuorumCertificate`] to formally
//!   revoke the seized device's subkey.
//! - **Layer 9 field-witness machinery** (`ol_threshold_recovery`):
//!   reused as the witness binding mechanism for the real
//!   ciphertext.
//! - **F2 pair-by-QR**: the cross-channel commit extends the
//!   shipped QR-pair primitive with the audio + motion channels.

pub mod alert;
pub mod code;
pub mod envelope;
pub mod pair;
pub mod policy;

pub use alert::{sign_duress_alert, DuressAlert, DUR_ALERT_DOMAIN};
pub use code::{derive_duress_key, DuressCode, ARGON2_M_COST_KIB, ARGON2_T_COST};
pub use envelope::{
    create_duress_envelope, unlock_duress_envelope, DuressEnvelope, UnlockOutcome,
    DUR_ENVELOPE_DOMAIN, DUR_SALT_LEN,
};
pub use pair::{
    verify_pairing_cross_channel, PairingChannel, PairingCommitment, PAIR_COMMITMENT_DOMAIN,
    REQUIRED_PAIR_CHANNELS,
};
pub use policy::{DuressPolicy, DURESS_DEFAULT_QUARANTINE_SECS};
