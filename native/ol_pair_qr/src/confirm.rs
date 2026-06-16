//! [`PairConfirm`] — the inviter's final commit to the transcript.
//!
//! Wire layout (after the 2-byte header):
//!
//! ```text
//!   u8   version    (= CONFIRM_VERSION)
//!   u8   type tag   (= TAG_CONFIRM)
//!   [32] id_pubkey  Ed25519 verifying key of the inviter's identity
//!   [32] transcript transcript hash bytes
//!   [64] signature  Ed25519(id_pubkey).sign("OL-pair-qr-v1-confirm" || transcript)
//! ```
//!
//! Receipt of a valid `PairConfirm` is what flips the scanner from
//! "pending" to "trusted." Both sides MUST also compare the
//! human-readable SAS out of band — the signature alone proves the
//! inviter possesses the master key, not that the user actually
//! intended to pair this particular scanner.

use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};

use crate::canon::{Reader, Writer};
use crate::errors::{PairError, PairResult};
use crate::transcript::{TranscriptHash, TRANSCRIPT_LEN};

/// Pair-by-QR confirm version on the wire.
pub const CONFIRM_VERSION: u8 = 1;

/// Type-tag byte distinguishing a `PairConfirm` frame.
pub const TAG_CONFIRM: u8 = 0x03;

/// Maximum encoded byte length for a `PairConfirm`.
pub const CONFIRM_MAX_BYTES: usize = 200;

/// Domain-separation tag for the confirm signature.
pub const CONFIRM_SIG_DOMAIN: &[u8] = b"OL-pair-qr-v1-confirm";

/// Pair-by-QR confirm frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairConfirm {
    /// Inviter's master identity verifying key.
    pub id_pubkey: [u8; PUBLIC_KEY_LENGTH],
    /// Transcript hash being committed to.
    pub transcript: TranscriptHash,
    /// Ed25519 signature over `CONFIRM_SIG_DOMAIN || transcript`.
    pub signature: [u8; SIGNATURE_LENGTH],
}

impl PairConfirm {
    /// Sign a confirm from the inviter side.
    pub fn sign(signer: &SigningKey, transcript: TranscriptHash) -> Self {
        let id_pubkey = signer.verifying_key().to_bytes();
        let sig = signer.sign(&signing_payload(&transcript));
        Self {
            id_pubkey,
            transcript,
            signature: sig.to_bytes(),
        }
    }

    /// Encode to canon bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(CONFIRM_MAX_BYTES);
        w.write_u8(CONFIRM_VERSION);
        w.write_u8(TAG_CONFIRM);
        w.write_fixed(&self.id_pubkey);
        w.write_fixed(self.transcript.as_bytes());
        w.write_fixed(&self.signature);
        w.into_bytes()
    }

    /// Decode and verify the confirm in one step.
    ///
    /// `expected_inviter_pubkey` is the inviter pubkey the scanner
    /// already pinned from the QR; this method refuses any confirm
    /// signed by a different key (defeats key-substitution).
    /// `expected_transcript` is the transcript the scanner computed
    /// locally; this method refuses any confirm committed to a
    /// different transcript (defeats MITM swap).
    ///
    /// Both checks use `subtle::ConstantTimeEq` so a timing oracle
    /// cannot leak which byte mismatched. Symmetry with the
    /// transcript check + protection-in-depth (pubkey is public, but
    /// keeping the verification surface uniformly constant-time is
    /// the auditable property).
    pub fn decode_and_verify(
        bytes: &[u8],
        expected_inviter_pubkey: &[u8; PUBLIC_KEY_LENGTH],
        expected_transcript: &TranscriptHash,
    ) -> PairResult<Self> {
        use subtle::ConstantTimeEq;
        let conf = Self::decode_raw(bytes)?;
        if !bool::from(conf.id_pubkey.ct_eq(expected_inviter_pubkey)) {
            return Err(PairError::BadSignature);
        }
        if !conf.transcript.ct_eq(expected_transcript) {
            return Err(PairError::TranscriptMismatch);
        }
        let vk = VerifyingKey::from_bytes(&conf.id_pubkey).map_err(|_| PairError::BadSignature)?;
        let sig = Signature::from_bytes(&conf.signature);
        vk.verify(&signing_payload(&conf.transcript), &sig)
            .map_err(|_| PairError::BadSignature)?;
        Ok(conf)
    }

    /// Raw decode without verification. Fuzz harnesses only.
    pub fn decode_raw(bytes: &[u8]) -> PairResult<Self> {
        if bytes.len() > CONFIRM_MAX_BYTES {
            return Err(PairError::Oversize {
                got: bytes.len(),
                cap: CONFIRM_MAX_BYTES,
            });
        }
        let mut r = Reader::new(bytes);
        let ver = r.read_u8()?;
        if ver != CONFIRM_VERSION {
            return Err(PairError::UnsupportedVersion {
                got: ver,
                supported: CONFIRM_VERSION,
            });
        }
        let tag = r.read_u8()?;
        if tag != TAG_CONFIRM {
            return Err(PairError::BadTag {
                expected: TAG_CONFIRM,
                got: tag,
            });
        }
        let id_slice = r.read_fixed(PUBLIC_KEY_LENGTH)?;
        let mut id_pubkey = [0u8; PUBLIC_KEY_LENGTH];
        id_pubkey.copy_from_slice(id_slice);

        let tslice = r.read_fixed(TRANSCRIPT_LEN)?;
        let mut tbytes = [0u8; TRANSCRIPT_LEN];
        tbytes.copy_from_slice(tslice);
        let transcript = TranscriptHash::from_bytes(tbytes);

        let sig_slice = r.read_fixed(SIGNATURE_LENGTH)?;
        let mut signature = [0u8; SIGNATURE_LENGTH];
        signature.copy_from_slice(sig_slice);

        if !r.is_empty() {
            return Err(PairError::Oversize {
                got: bytes.len(),
                cap: r.position(),
            });
        }
        Ok(Self {
            id_pubkey,
            transcript,
            signature,
        })
    }
}

fn signing_payload(transcript: &TranscriptHash) -> Vec<u8> {
    let mut w = Writer::with_capacity(CONFIRM_SIG_DOMAIN.len() + TRANSCRIPT_LEN);
    w.write_fixed(CONFIRM_SIG_DOMAIN);
    w.write_fixed(transcript.as_bytes());
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn fresh_keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn fresh_transcript() -> TranscriptHash {
        let mut b = [0u8; TRANSCRIPT_LEN];
        use rand::RngCore;
        OsRng.fill_bytes(&mut b);
        TranscriptHash::from_bytes(b)
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let sk = fresh_keypair();
        let t = fresh_transcript();
        let c = PairConfirm::sign(&sk, t);
        let encoded = c.encode();
        let pk = sk.verifying_key().to_bytes();
        let decoded = PairConfirm::decode_and_verify(&encoded, &pk, &t).unwrap();
        assert_eq!(decoded, c);
    }

    #[test]
    fn mismatched_transcript_rejected() {
        let sk = fresh_keypair();
        let t = fresh_transcript();
        let c = PairConfirm::sign(&sk, t);
        let encoded = c.encode();
        let pk = sk.verifying_key().to_bytes();
        let other_t = fresh_transcript();
        let err = PairConfirm::decode_and_verify(&encoded, &pk, &other_t).unwrap_err();
        assert_eq!(err, PairError::TranscriptMismatch);
    }

    #[test]
    fn key_substitution_rejected() {
        let sk = fresh_keypair();
        let t = fresh_transcript();
        let c = PairConfirm::sign(&sk, t);
        let encoded = c.encode();
        let other_sk = fresh_keypair();
        let other_pk = other_sk.verifying_key().to_bytes();
        // Inviter pubkey we pinned doesn't match what's on the wire.
        let err = PairConfirm::decode_and_verify(&encoded, &other_pk, &t).unwrap_err();
        assert_eq!(err, PairError::BadSignature);
    }

    #[test]
    fn tampered_signature_rejected() {
        let sk = fresh_keypair();
        let t = fresh_transcript();
        let c = PairConfirm::sign(&sk, t);
        let mut encoded = c.encode();
        let last = encoded.len() - 1;
        encoded[last] ^= 0x01;
        let pk = sk.verifying_key().to_bytes();
        let err = PairConfirm::decode_and_verify(&encoded, &pk, &t).unwrap_err();
        assert_eq!(err, PairError::BadSignature);
    }
}
