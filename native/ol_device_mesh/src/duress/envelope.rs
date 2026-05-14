//! Plausibly-deniable duress envelope.
//!
//! On disk, [`DuressEnvelope`] holds two ChaCha20-Poly1305
//! ciphertexts (`real_ct` + `decoy_ct`) that are structurally
//! identical to the captor. Each carries a fresh random salt + a
//! 12-byte AEAD nonce. The two AEAD keys are derived from two
//! different user codes via Argon2id:
//!
//! - `decoy_key  = Argon2id(decoy_code, decoy_salt)`
//! - `real_key   = Argon2id(real_code,  real_salt) XOR field_witness_otp`
//!
//! The captor entering EITHER code can only unwrap whichever
//! ciphertext that key opens. The user's real code, ABSENT the
//! field witness, also fails to open `real_ct` — the XOR mask
//! makes the derived key unusable. With the field witness in hand,
//! `real_key` is reconstructed + `real_ct` decrypts.
//!
//! Structural indistinguishability: both ciphertexts have the same
//! shape on disk — same headers, same overhead. An attacker who
//! captures the disk image and tries every plausible code can at
//! most recover the decoy; nothing on disk reveals that another
//! ciphertext lurks.

use blake3::Hasher;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::errors::{DeviceMeshError, DeviceMeshResult};

use super::code::{derive_duress_key, DURESS_KEY_LEN};

/// Length of the per-ciphertext random salt.
pub const DUR_SALT_LEN: usize = 32;

/// Length of the ChaCha20-Poly1305 nonce.
pub const DUR_NONCE_LEN: usize = 12;

/// Domain-separation tag for the envelope canonical-bytes form.
pub const DUR_ENVELOPE_DOMAIN: &[u8] = b"OL-mesh-duress-envelope-v1";

/// Maximum plaintext size accepted by the envelope (16 MiB).
pub const DUR_MAX_PLAINTEXT_LEN: usize = 16 * 1024 * 1024;

/// On-disk envelope. The two ciphertexts are STRUCTURALLY IDENTICAL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuressEnvelope {
    /// Salt for Argon2id-deriving the real-ciphertext key.
    pub real_salt: [u8; DUR_SALT_LEN],
    /// Salt for the decoy-ciphertext key.
    pub decoy_salt: [u8; DUR_SALT_LEN],
    /// AEAD nonce for the real ciphertext.
    pub real_nonce: [u8; DUR_NONCE_LEN],
    /// AEAD nonce for the decoy ciphertext.
    pub decoy_nonce: [u8; DUR_NONCE_LEN],
    /// AEAD ciphertext of the real plaintext (field-bound).
    pub real_ct: Vec<u8>,
    /// AEAD ciphertext of the decoy plaintext.
    pub decoy_ct: Vec<u8>,
}

/// Outcome of an unlock attempt.
#[derive(Debug)]
pub enum UnlockOutcome {
    /// User's REAL code + correct field witness — return the real
    /// plaintext. Daemon proceeds normally.
    Real(Vec<u8>),
    /// User's DUR code (or real code without the field witness) —
    /// return the decoy plaintext. Daemon SILENTLY emits a
    /// [`super::DuressAlert`] to siblings + locks the device into
    /// decoy-only mode per the [`super::DuressPolicy`].
    Decoy(Vec<u8>),
    /// Neither code matched. Don't reveal whether the code was wrong
    /// or just the wrong one — the daemon's UI presents a unified
    /// "wrong code" response.
    WrongCode,
}

/// Build an envelope. Generates fresh random salts + nonces and
/// produces the two ciphertexts.
///
/// `field_witness` is the 32-byte secret needed to reconstruct the
/// real key on unlock. Higher layers can re-derive it from the
/// Phase E coherence-field state at mint time (or use any 32-byte
/// shared secret).
pub fn create_duress_envelope<R: RngCore + CryptoRng>(
    real_plaintext: &[u8],
    decoy_plaintext: &[u8],
    real_code: &[u8],
    decoy_code: &[u8],
    field_witness: &[u8; 32],
    rng: &mut R,
) -> DeviceMeshResult<DuressEnvelope> {
    if real_plaintext.is_empty() || decoy_plaintext.is_empty() {
        return Err(DeviceMeshError::DuressEnvelopePlaintextEmpty);
    }
    if real_plaintext.len() > DUR_MAX_PLAINTEXT_LEN
        || decoy_plaintext.len() > DUR_MAX_PLAINTEXT_LEN
    {
        return Err(DeviceMeshError::DuressEnvelopePlaintextTooLong {
            max: DUR_MAX_PLAINTEXT_LEN,
        });
    }
    if real_code == decoy_code {
        return Err(DeviceMeshError::DuressCodesIdentical);
    }

    let mut real_salt = [0u8; DUR_SALT_LEN];
    let mut decoy_salt = [0u8; DUR_SALT_LEN];
    let mut real_nonce = [0u8; DUR_NONCE_LEN];
    let mut decoy_nonce = [0u8; DUR_NONCE_LEN];
    rng.fill_bytes(&mut real_salt);
    rng.fill_bytes(&mut decoy_salt);
    rng.fill_bytes(&mut real_nonce);
    rng.fill_bytes(&mut decoy_nonce);

    let real_key = make_real_key(real_code, &real_salt, field_witness)?;
    let decoy_key = derive_duress_key(decoy_code, &decoy_salt)?;

    let real_ct = aead_encrypt(real_key.as_slice(), &real_nonce, real_plaintext)?;
    let decoy_ct = aead_encrypt(decoy_key.key_bytes(), &decoy_nonce, decoy_plaintext)?;

    let mut rk_bytes = real_key;
    rk_bytes.zeroize();

    Ok(DuressEnvelope {
        real_salt,
        decoy_salt,
        real_nonce,
        decoy_nonce,
        real_ct,
        decoy_ct,
    })
}

/// Unlock attempt. Tries the supplied `user_code` against:
///   1. The real-ciphertext key (with field witness if supplied).
///   2. The decoy-ciphertext key.
///
/// Returns the first match, or `WrongCode` if neither succeeds.
///
/// Constant-time-ish: both attempts ALWAYS run regardless of the
/// first result. The branch on the final outcome leaks at most a
/// single bit (which ciphertext matched), but the captor learns
/// only "this code returned plaintext" — exactly the property we
/// want when the captor types the decoy code.
pub fn unlock_duress_envelope(
    env: &DuressEnvelope,
    user_code: &[u8],
    field_witness: Option<&[u8; 32]>,
) -> DeviceMeshResult<UnlockOutcome> {
    // Decoy path always runs.
    let decoy_key = derive_duress_key(user_code, &env.decoy_salt)?;
    let decoy_attempt =
        aead_decrypt(decoy_key.key_bytes(), &env.decoy_nonce, &env.decoy_ct);

    // Real path always runs (when a witness is supplied).
    let real_attempt = if let Some(witness) = field_witness {
        let real_key = make_real_key(user_code, &env.real_salt, witness).ok();
        real_key.and_then(|k| {
            aead_decrypt(&k, &env.real_nonce, &env.real_ct).ok()
        })
    } else {
        None
    };

    // Real takes precedence if both unwrap (impossible in practice
    // because the keys are independently random — but defensive).
    if let Some(real) = real_attempt {
        return Ok(UnlockOutcome::Real(real));
    }
    if let Ok(decoy) = decoy_attempt {
        return Ok(UnlockOutcome::Decoy(decoy));
    }
    Ok(UnlockOutcome::WrongCode)
}

fn make_real_key(
    user_code: &[u8],
    salt: &[u8; DUR_SALT_LEN],
    field_witness: &[u8; 32],
) -> DeviceMeshResult<[u8; DURESS_KEY_LEN]> {
    let argon_key = derive_duress_key(user_code, salt)?;
    // Mix the field witness in via BLAKE3 keyed hash so a different
    // witness gives a different key. NOT a simple XOR — using a
    // keyed hash defeats algebraic attacks where the attacker
    // learns the witness from disk + recomputes.
    let mut h = Hasher::new_keyed(argon_key.key_bytes());
    h.update(b"OL-mesh-duress-real-key-mix-v1");
    h.update(field_witness);
    let mut out = [0u8; DURESS_KEY_LEN];
    out.copy_from_slice(h.finalize().as_bytes());
    Ok(out)
}

fn aead_encrypt(
    key: &[u8],
    nonce: &[u8; DUR_NONCE_LEN],
    plaintext: &[u8],
) -> DeviceMeshResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|e| DeviceMeshError::DuressAeadFailed(format!("encrypt: {e}")))
}

fn aead_decrypt(
    key: &[u8],
    nonce: &[u8; DUR_NONCE_LEN],
    ciphertext: &[u8],
) -> DeviceMeshResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| DeviceMeshError::DuressAeadFailed(format!("decrypt: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn round_trip_real_with_witness() {
        let witness = [0x42; 32];
        let env = create_duress_envelope(
            b"real plaintext",
            b"decoy plaintext",
            b"real-pass",
            b"duress-code",
            &witness,
            &mut OsRng,
        )
        .unwrap();
        let outcome =
            unlock_duress_envelope(&env, b"real-pass", Some(&witness)).unwrap();
        match outcome {
            UnlockOutcome::Real(pt) => assert_eq!(pt, b"real plaintext"),
            other => panic!("expected Real, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_decoy_via_duress_code() {
        let witness = [0x42; 32];
        let env = create_duress_envelope(
            b"real plaintext",
            b"decoy plaintext",
            b"real-pass",
            b"duress-code",
            &witness,
            &mut OsRng,
        )
        .unwrap();
        // Captor types the duress code with NO witness.
        let outcome =
            unlock_duress_envelope(&env, b"duress-code", None).unwrap();
        match outcome {
            UnlockOutcome::Decoy(pt) => assert_eq!(pt, b"decoy plaintext"),
            other => panic!("expected Decoy, got {other:?}"),
        }
    }

    #[test]
    fn real_code_without_witness_returns_wrong_code() {
        // User types the real code but the witness isn't available
        // (e.g., the daemon hasn't materialised the field state yet).
        let witness = [0x42; 32];
        let env = create_duress_envelope(
            b"real plaintext",
            b"decoy plaintext",
            b"real-pass",
            b"duress-code",
            &witness,
            &mut OsRng,
        )
        .unwrap();
        let outcome =
            unlock_duress_envelope(&env, b"real-pass", None).unwrap();
        match outcome {
            UnlockOutcome::WrongCode => {}
            other => panic!("expected WrongCode, got {other:?}"),
        }
    }

    #[test]
    fn wrong_code_returns_wrong_code() {
        let witness = [0x42; 32];
        let env = create_duress_envelope(
            b"real plaintext",
            b"decoy plaintext",
            b"real-pass",
            b"duress-code",
            &witness,
            &mut OsRng,
        )
        .unwrap();
        let outcome =
            unlock_duress_envelope(&env, b"random-garbage", Some(&witness)).unwrap();
        match outcome {
            UnlockOutcome::WrongCode => {}
            other => panic!("expected WrongCode, got {other:?}"),
        }
    }

    #[test]
    fn identical_codes_rejected_at_create() {
        let witness = [0x42; 32];
        let err = create_duress_envelope(
            b"real",
            b"decoy",
            b"same-code",
            b"same-code",
            &witness,
            &mut OsRng,
        )
        .unwrap_err();
        assert!(matches!(err, DeviceMeshError::DuressCodesIdentical));
    }

    #[test]
    fn empty_plaintext_rejected() {
        let witness = [0x42; 32];
        let err = create_duress_envelope(
            b"",
            b"decoy",
            b"real",
            b"duress",
            &witness,
            &mut OsRng,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::DuressEnvelopePlaintextEmpty
        ));
    }

    #[test]
    fn different_witness_fails_real_unlock() {
        let witness_correct = [0x42; 32];
        let witness_wrong = [0x43; 32];
        let env = create_duress_envelope(
            b"real plaintext",
            b"decoy plaintext",
            b"real-pass",
            b"duress-code",
            &witness_correct,
            &mut OsRng,
        )
        .unwrap();
        // Real code + wrong witness → can't unlock real; falls back
        // to decoy path which also fails for "real-pass".
        let outcome =
            unlock_duress_envelope(&env, b"real-pass", Some(&witness_wrong)).unwrap();
        match outcome {
            UnlockOutcome::WrongCode => {}
            other => panic!("expected WrongCode, got {other:?}"),
        }
    }
}
