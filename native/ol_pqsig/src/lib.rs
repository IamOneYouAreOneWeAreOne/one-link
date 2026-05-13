//! `ol_pqsig` — Ed25519 + ML-DSA-65 hybrid digital signatures.
//!
//! Per [`COHERENCE_MESH_PLAN.md`] row 1 — post-quantum identity.
//! The master identity key needs to survive a future cryptanalytic
//! break of Ed25519 (Shor's algorithm reduces ECDLP to polynomial
//! time on a sufficiently large quantum computer). ML-DSA-65
//! (NIST FIPS 204, formerly CRYSTALS-Dilithium-Level3) gives us
//! lattice-based PQ signatures with strong NIST analysis.
//!
//! ## Hybrid construction
//!
//! Both signatures cover the same canonical transcript (BLAKE3 of
//! `PROTOCOL_DOMAIN || message`). A hybrid signature is the
//! concatenation:
//!
//! ```text
//!   hybrid_sig = ed25519_sig (64 B) || ml_dsa_65_sig (3309 B)
//! ```
//!
//! Verification REQUIRES BOTH halves to pass. An attacker must break
//! BOTH the classical and PQ schemes to forge a hybrid signature.
//!
//! ## Key layout
//!
//! - **Signing key**: 32-byte Ed25519 seed + 32-byte ML-DSA seed
//!   = 64 bytes. The ML-DSA SigningKey is expanded from its seed
//!   at sign time (FIPS 204 §6).
//! - **Verifying key**: 32-byte Ed25519 pubkey + 1952-byte ML-DSA
//!   verifying key = 1984 bytes.
//! - **Signature**: 64 + 3309 = 3373 bytes.
//!
//! ## When to use this
//!
//! - **Master identity** (rare ops: device pair, social-recovery
//!   share commits, capability root) — yes, use hybrid.
//! - **Per-message signing** (chat messages, file chunks) — no, the
//!   3373-byte signature is too heavy + the ML-DSA seed expansion
//!   costs ~ms per sign. Use Ed25519 alone + Double Ratchet for
//!   forward secrecy.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use blake3::Hasher;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use ml_dsa::{
    signature::{Keypair as _, Signer as _},
    B32, EncodedSignature, EncodedVerifyingKey, MlDsa65,
    SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use thiserror::Error;

/// Length of an Ed25519 verifying key.
pub const ED25519_VK_LEN: usize = 32;
/// Length of an Ed25519 signing key seed.
pub const ED25519_SK_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const ED25519_SIG_LEN: usize = 64;

/// Length of an ML-DSA-65 verifying key (FIPS 204 §4 table 2).
pub const ML_DSA_65_VK_LEN: usize = 1952;
/// Length of an ML-DSA-65 signing seed (the 32-byte ξ from §5).
pub const ML_DSA_65_SEED_LEN: usize = 32;
/// Length of an ML-DSA-65 signature.
pub const ML_DSA_65_SIG_LEN: usize = 3309;

/// Length of a hybrid verifying key.
pub const HYBRID_VK_LEN: usize = ED25519_VK_LEN + ML_DSA_65_VK_LEN;
/// Length of a hybrid signing key (Ed25519 seed + ML-DSA seed).
pub const HYBRID_SK_LEN: usize = ED25519_SK_LEN + ML_DSA_65_SEED_LEN;
/// Length of a hybrid signature.
pub const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + ML_DSA_65_SIG_LEN;

/// Domain-separation tag prepended to every signed message.
pub const PROTOCOL_DOMAIN: &[u8] = b"OL-pqsig-v1";

// (The `signature::Signer` trait's `try_sign` uses default
// (empty) context internally — our BLAKE3-hashed transcript
// already bakes in domain separation.)

/// Typed error surface.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PqSigError {
    /// A serialized key/sig was the wrong byte length.
    #[error("wrong byte length: expected {expected}, got {got}")]
    BadLength {
        /// Required length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
    /// Ed25519 verification failed.
    #[error("Ed25519 signature did not verify")]
    Ed25519VerifyFail,
    /// ML-DSA-65 verification failed.
    #[error("ML-DSA-65 signature did not verify")]
    MlDsaVerifyFail,
    /// A pubkey decoded but was not a valid encoding.
    #[error("invalid public key encoding")]
    InvalidPubkey,
    /// ML-DSA `sign_deterministic` returned an error (should not
    /// happen with our fixed-context inputs).
    #[error("ML-DSA signing failed")]
    MlDsaSignFail,
}

/// Result alias.
pub type PqSigResult<T> = Result<T, PqSigError>;

/// Hybrid signing key — stores both Ed25519 seed bytes and the
/// ML-DSA-65 seed bytes. ML-DSA SigningKey is expanded from its
/// seed on each sign (the expansion is part of the per-sign cost).
pub struct HybridSigningKey {
    ed25519_seed: [u8; ED25519_SK_LEN],
    ml_dsa_seed: [u8; ML_DSA_65_SEED_LEN],
}

impl std::fmt::Debug for HybridSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridSigningKey").finish_non_exhaustive()
    }
}

impl Drop for HybridSigningKey {
    fn drop(&mut self) {
        // Best-effort zeroize.
        for b in self.ed25519_seed.iter_mut() {
            *b = 0;
        }
        for b in self.ml_dsa_seed.iter_mut() {
            *b = 0;
        }
    }
}

/// Hybrid verifying key — Ed25519 + ML-DSA-65 public halves.
#[derive(Clone)]
pub struct HybridVerifyingKey {
    ed25519: VerifyingKey,
    ml_dsa: MlDsaVerifyingKey<MlDsa65>,
}

impl std::fmt::Debug for HybridVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridVerifyingKey").finish_non_exhaustive()
    }
}

impl PartialEq for HybridVerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.to_bytes().ct_eq(&other.to_bytes()))
    }
}
impl Eq for HybridVerifyingKey {}

impl HybridVerifyingKey {
    /// Serialize to wire bytes: `ed25519_pk || ml_dsa_pk`.
    pub fn to_bytes(&self) -> [u8; HYBRID_VK_LEN] {
        let mut out = [0u8; HYBRID_VK_LEN];
        out[..ED25519_VK_LEN].copy_from_slice(self.ed25519.as_bytes());
        let ml_dsa_bytes: EncodedVerifyingKey<MlDsa65> = self.ml_dsa.encode();
        out[ED25519_VK_LEN..].copy_from_slice(&ml_dsa_bytes);
        out
    }

    /// Parse from wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> PqSigResult<Self> {
        if bytes.len() != HYBRID_VK_LEN {
            return Err(PqSigError::BadLength {
                expected: HYBRID_VK_LEN,
                got: bytes.len(),
            });
        }
        let mut ed_bytes = [0u8; ED25519_VK_LEN];
        ed_bytes.copy_from_slice(&bytes[..ED25519_VK_LEN]);
        let ed25519 = VerifyingKey::from_bytes(&ed_bytes)
            .map_err(|_| PqSigError::InvalidPubkey)?;
        let ml_dsa_slice: &[u8] = &bytes[ED25519_VK_LEN..];
        let ml_dsa_arr = EncodedVerifyingKey::<MlDsa65>::try_from(ml_dsa_slice)
            .map_err(|_| PqSigError::BadLength {
                expected: ML_DSA_65_VK_LEN,
                got: ml_dsa_slice.len(),
            })?;
        let ml_dsa = MlDsaVerifyingKey::<MlDsa65>::decode(&ml_dsa_arr);
        Ok(Self { ed25519, ml_dsa })
    }

    /// Verify a hybrid signature. BOTH halves must pass.
    pub fn verify(&self, message: &[u8], sig: &[u8]) -> PqSigResult<()> {
        if sig.len() != HYBRID_SIG_LEN {
            return Err(PqSigError::BadLength {
                expected: HYBRID_SIG_LEN,
                got: sig.len(),
            });
        }
        let transcript = transcript(message);
        // Ed25519 half.
        let mut ed_sig_bytes = [0u8; ED25519_SIG_LEN];
        ed_sig_bytes.copy_from_slice(&sig[..ED25519_SIG_LEN]);
        let ed_sig = ed25519_dalek::Signature::from_bytes(&ed_sig_bytes);
        self.ed25519
            .verify(&transcript, &ed_sig)
            .map_err(|_| PqSigError::Ed25519VerifyFail)?;
        // ML-DSA-65 half.
        let ml_sig_slice: &[u8] = &sig[ED25519_SIG_LEN..];
        let ml_sig_arr = EncodedSignature::<MlDsa65>::try_from(ml_sig_slice)
            .map_err(|_| PqSigError::BadLength {
                expected: ML_DSA_65_SIG_LEN,
                got: ml_sig_slice.len(),
            })?;
        let ml_sig = ml_dsa::Signature::<MlDsa65>::decode(&ml_sig_arr)
            .ok_or(PqSigError::MlDsaVerifyFail)?;
        use ml_dsa::signature::Verifier as _;
        self.ml_dsa
            .verify(&transcript, &ml_sig)
            .map_err(|_| PqSigError::MlDsaVerifyFail)?;
        Ok(())
    }
}

impl HybridSigningKey {
    /// Generate a fresh hybrid keypair from a cryptographically
    /// secure RNG.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> (Self, HybridVerifyingKey) {
        let mut ed25519_seed = [0u8; ED25519_SK_LEN];
        rng.fill_bytes(&mut ed25519_seed);
        let mut ml_dsa_seed = [0u8; ML_DSA_65_SEED_LEN];
        rng.fill_bytes(&mut ml_dsa_seed);
        let signing = Self {
            ed25519_seed,
            ml_dsa_seed,
        };
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    /// Derive the matching hybrid verifying key.
    pub fn verifying_key(&self) -> HybridVerifyingKey {
        let ed25519 = SigningKey::from_bytes(&self.ed25519_seed).verifying_key();
        let ml_dsa_seed_arr: B32 = self.ml_dsa_seed.into();
        let ml_dsa_sk = MlDsaSigningKey::<MlDsa65>::from_seed(&ml_dsa_seed_arr);
        let ml_dsa = ml_dsa_sk.verifying_key();
        HybridVerifyingKey { ed25519, ml_dsa }
    }

    /// Sign `message`. Both halves cover the same BLAKE3-hashed
    /// transcript (PROTOCOL_DOMAIN || message).
    pub fn sign(&self, message: &[u8]) -> PqSigResult<[u8; HYBRID_SIG_LEN]> {
        let transcript = transcript(message);
        let ed25519 = SigningKey::from_bytes(&self.ed25519_seed);
        let ed_sig = ed25519.sign(&transcript);
        let ml_dsa_seed_arr: B32 = self.ml_dsa_seed.into();
        let ml_dsa_sk = MlDsaSigningKey::<MlDsa65>::from_seed(&ml_dsa_seed_arr);
        // Use the `signature::Signer` trait — SigningKey impls it
        // by expanding the seed each call (we pay that cost here).
        let ml_sig = ml_dsa_sk
            .try_sign(&transcript)
            .map_err(|_| PqSigError::MlDsaSignFail)?;
        let mut out = [0u8; HYBRID_SIG_LEN];
        out[..ED25519_SIG_LEN].copy_from_slice(&ed_sig.to_bytes());
        let ml_sig_bytes: EncodedSignature<MlDsa65> = ml_sig.encode();
        out[ED25519_SIG_LEN..].copy_from_slice(&ml_sig_bytes);
        Ok(out)
    }

    /// Serialize to wire bytes: `ed25519_seed || ml_dsa_seed`.
    pub fn to_bytes(&self) -> [u8; HYBRID_SK_LEN] {
        let mut out = [0u8; HYBRID_SK_LEN];
        out[..ED25519_SK_LEN].copy_from_slice(&self.ed25519_seed);
        out[ED25519_SK_LEN..].copy_from_slice(&self.ml_dsa_seed);
        out
    }

    /// Parse from wire bytes.
    pub fn from_bytes(bytes: &[u8]) -> PqSigResult<Self> {
        if bytes.len() != HYBRID_SK_LEN {
            return Err(PqSigError::BadLength {
                expected: HYBRID_SK_LEN,
                got: bytes.len(),
            });
        }
        let mut ed25519_seed = [0u8; ED25519_SK_LEN];
        ed25519_seed.copy_from_slice(&bytes[..ED25519_SK_LEN]);
        let mut ml_dsa_seed = [0u8; ML_DSA_65_SEED_LEN];
        ml_dsa_seed.copy_from_slice(&bytes[ED25519_SK_LEN..]);
        Ok(Self {
            ed25519_seed,
            ml_dsa_seed,
        })
    }
}

/// Canonical message transcript = BLAKE3(PROTOCOL_DOMAIN || message).
/// Domain-separation prevents cross-protocol signature replay.
fn transcript(message: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(PROTOCOL_DOMAIN);
    h.update(message);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_bytes());
    out
}

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn round_trip_sign_verify() {
        let (sk, vk) = HybridSigningKey::generate(&mut OsRng);
        let msg = b"hello world";
        let sig = sk.sign(msg).unwrap();
        assert_eq!(sig.len(), HYBRID_SIG_LEN);
        vk.verify(msg, &sig).unwrap();
    }

    #[test]
    fn verifying_key_serialization_roundtrip() {
        let (_, vk) = HybridSigningKey::generate(&mut OsRng);
        let bytes = vk.to_bytes();
        assert_eq!(bytes.len(), HYBRID_VK_LEN);
        let vk2 = HybridVerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk, vk2);
    }

    #[test]
    fn signing_key_serialization_roundtrip() {
        let (sk, vk) = HybridSigningKey::generate(&mut OsRng);
        let bytes = sk.to_bytes();
        assert_eq!(bytes.len(), HYBRID_SK_LEN);
        let sk2 = HybridSigningKey::from_bytes(&bytes).unwrap();
        let sig = sk2.sign(b"test").unwrap();
        vk.verify(b"test", &sig).unwrap();
    }

    #[test]
    fn tampered_ed25519_half_fails() {
        let (sk, vk) = HybridSigningKey::generate(&mut OsRng);
        let mut sig = sk.sign(b"hello").unwrap();
        sig[0] ^= 0x01;
        let err = vk.verify(b"hello", &sig).unwrap_err();
        assert_eq!(err, PqSigError::Ed25519VerifyFail);
    }

    #[test]
    fn tampered_ml_dsa_half_fails() {
        let (sk, vk) = HybridSigningKey::generate(&mut OsRng);
        let mut sig = sk.sign(b"hello").unwrap();
        sig[ED25519_SIG_LEN + 100] ^= 0x01;
        let err = vk.verify(b"hello", &sig).unwrap_err();
        assert_eq!(err, PqSigError::MlDsaVerifyFail);
    }

    #[test]
    fn cross_message_replay_fails() {
        let (sk, vk) = HybridSigningKey::generate(&mut OsRng);
        let sig = sk.sign(b"message-a").unwrap();
        let err = vk.verify(b"message-b", &sig).unwrap_err();
        assert_eq!(err, PqSigError::Ed25519VerifyFail);
    }

    #[test]
    fn cross_key_replay_fails() {
        let (sk_a, _vk_a) = HybridSigningKey::generate(&mut OsRng);
        let (_sk_b, vk_b) = HybridSigningKey::generate(&mut OsRng);
        let sig = sk_a.sign(b"x").unwrap();
        let err = vk_b.verify(b"x", &sig).unwrap_err();
        assert_eq!(err, PqSigError::Ed25519VerifyFail);
    }

    #[test]
    fn wrong_signature_length_rejected() {
        let (_, vk) = HybridSigningKey::generate(&mut OsRng);
        let bad_sig = vec![0u8; 100];
        let err = vk.verify(b"x", &bad_sig).unwrap_err();
        assert!(matches!(err, PqSigError::BadLength { .. }));
    }

    #[test]
    fn wrong_vk_length_rejected() {
        let err = HybridVerifyingKey::from_bytes(&[0u8; 100]).unwrap_err();
        assert!(matches!(err, PqSigError::BadLength { .. }));
    }

    #[test]
    fn wrong_sk_length_rejected() {
        let err = HybridSigningKey::from_bytes(&[0u8; 100]).unwrap_err();
        assert!(matches!(err, PqSigError::BadLength { .. }));
    }

    #[test]
    fn empty_message_signs_and_verifies() {
        let (sk, vk) = HybridSigningKey::generate(&mut OsRng);
        let sig = sk.sign(b"").unwrap();
        vk.verify(b"", &sig).unwrap();
    }

    #[test]
    fn large_message_signs_and_verifies() {
        let (sk, vk) = HybridSigningKey::generate(&mut OsRng);
        let msg = vec![0xAAu8; 1_000_000];
        let sig = sk.sign(&msg).unwrap();
        vk.verify(&msg, &sig).unwrap();
    }

    #[test]
    fn deterministic_pubkey_from_sk() {
        let (sk, vk) = HybridSigningKey::generate(&mut OsRng);
        let vk_derived = sk.verifying_key();
        assert_eq!(vk, vk_derived);
    }

    #[test]
    fn deterministic_sign_matches_per_seed() {
        // sign_deterministic is deterministic for the same (sk, message).
        let (sk, _vk) = HybridSigningKey::generate(&mut OsRng);
        let sig1 = sk.sign(b"deterministic-test").unwrap();
        let sig2 = sk.sign(b"deterministic-test").unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn constants_match_fips_204() {
        assert_eq!(ML_DSA_65_VK_LEN, 1952);
        assert_eq!(ML_DSA_65_SEED_LEN, 32);
        assert_eq!(ML_DSA_65_SIG_LEN, 3309);
        assert_eq!(HYBRID_VK_LEN, 1984);
        assert_eq!(HYBRID_SK_LEN, 64);
        assert_eq!(HYBRID_SIG_LEN, 3373);
    }

    #[test]
    fn protocol_domain_separation_property() {
        let (sk, vk) = HybridSigningKey::generate(&mut OsRng);
        let mut prepended = PROTOCOL_DOMAIN.to_vec();
        prepended.extend_from_slice(b"x");
        let sig_prepended = sk.sign(&prepended).unwrap();
        // Signing PROTOCOL_DOMAIN||x produces a different transcript
        // than signing x, so the prepended signature should not
        // verify against the raw-x message.
        let err = vk.verify(b"x", &sig_prepended).unwrap_err();
        assert_eq!(err, PqSigError::Ed25519VerifyFail);
    }
}
