//! Row 8 Layer 10 — adversary-grade privacy tier: duress mode +
//! plausibly-deniable second persona + steganographic pairing.
//!
//! The dramatic finisher. Three properties:
//!
//! 1. **Duress mode**: a device gets seized (border crossing,
//!    coercion, mugging). The user types a *duress code* instead
//!    of the real unlock. The device:
//!    - Presents a complete, plausible DECOY mesh state to the
//!      captor (decoy contacts, decoy files, decoy messages).
//!    - Silently emits a signed [`DuressAlert`] to siblings so
//!      Layer-2 quorum revocation kicks in.
//!    - The real state remains encrypted; the captor cannot tell
//!      from the disk image alone that it exists.
//!
//! 2. **Plausibly deniable second persona**: every [`DuressEnvelope`]
//!    on disk has two ciphertexts (real + decoy) that are
//!    structurally identical. Without the field witness, even
//!    knowing the user's password recovers AT MOST the decoy.
//!    The real ciphertext is XOR-bound to a coherence-field
//!    witness (the row-9 mechanism reused at Layer 1).
//!
//! 3. **Steganographic pairing**: pairing a new device commits over
//!    THREE channels (QR + sub-perceptible audio chirp +
//!    accelerometer-pattern). The pair completes only when all
//!    three commit to the same secret within a time window. A
//!    remote attacker who photographs the QR from across the room
//!    cannot reproduce the audio + motion, so the pairing fails.
//!
//! ## What this layer ships
//!
//! - [`DuressCode`] — Argon2id-derived 32-byte key from a short
//!   user-entered code.
//! - [`DuressEnvelope`] — two ChaCha20-Poly1305 AEAD ciphertexts
//!   (real_ct + decoy_ct) plus the salts. Structurally
//!   indistinguishable from the outside.
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
//! user holds out-of-band). Without it, no password recovers the
//! real ciphertext — the attacker can only see the decoy.
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

pub use alert::{
    sign_duress_alert, DuressAlert, DUR_ALERT_DOMAIN,
};
pub use code::{derive_duress_key, DuressCode, ARGON2_M_COST_KIB, ARGON2_T_COST};
pub use envelope::{
    create_duress_envelope, unlock_duress_envelope, DuressEnvelope, UnlockOutcome,
    DUR_ENVELOPE_DOMAIN, DUR_SALT_LEN,
};
pub use pair::{
    verify_pairing_cross_channel, PairingChannel, PairingCommitment,
    PAIR_COMMITMENT_DOMAIN, REQUIRED_PAIR_CHANNELS,
};
pub use policy::{DuressPolicy, DURESS_DEFAULT_QUARANTINE_SECS};
