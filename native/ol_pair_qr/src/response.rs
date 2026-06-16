//! [`PairResponse`] — the scanner's reply to the inviter.
//!
//! Wire layout (after the 2-byte header):
//!
//! ```text
//!   u8   version         (= RESPONSE_VERSION)
//!   u8   type tag        (= TAG_RESPONSE)
//!   [32] id_pubkey       Ed25519 verifying key of the scanner's identity
//!   [32] ephem_x25519_pk scanner's one-time X25519 public
//!   [32] nonce           RESPONSE_NONCE_LEN bytes of cryptographic randomness
//!   [64] signature       Ed25519(id_pubkey).sign("OL-pair-qr-v1-response" || transcript_bind)
//! ```
//!
//! `transcript_bind` is the scanner's local view of the invite's
//! body bytes — see [`PairResponse::sign_for_transcript`]. The
//! signature binds the scanner's reply to the exact invite they
//! scanned, so a network attacker cannot pair the scanner's reply
//! with a different invite (cross-protocol replay).

use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use zeroize::Zeroize;

use crate::canon::{Reader, Writer};
use crate::errors::{PairError, PairResult};
use crate::invite::{INVITE_MAX_BYTES, X25519_PUBKEY_LEN};

/// Pair-by-QR response version on the wire.
pub const RESPONSE_VERSION: u8 = 1;

/// Type-tag byte distinguishing a `PairResponse` frame.
pub const TAG_RESPONSE: u8 = 0x02;

/// Length of the cryptographic nonce baked into the response.
pub const RESPONSE_NONCE_LEN: usize = 32;

/// Maximum encoded byte length for a `PairResponse`.
pub const RESPONSE_MAX_BYTES: usize = 256;

/// Domain-separation tag for the response signature. Prepended to
/// `transcript_bind` so a response signature can never be replayed
/// as some other Ed25519-signed message.
pub const RESPONSE_SIG_DOMAIN: &[u8] = b"OL-pair-qr-v1-response";

/// The pair-by-QR response — what the scanner sends back to the
/// inviter over the freshly-discovered network channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairResponse {
    /// Master identity public key of the scanner.
    pub id_pubkey: [u8; PUBLIC_KEY_LENGTH],
    /// Ephemeral X25519 public key bound to this single response.
    pub ephemeral_x25519_pk: [u8; X25519_PUBKEY_LEN],
    /// Cryptographic nonce baked into the response.
    pub nonce: [u8; RESPONSE_NONCE_LEN],
    /// Ed25519 signature over `RESPONSE_SIG_DOMAIN || transcript_bind`.
    pub signature: [u8; SIGNATURE_LENGTH],
}

impl PairResponse {
    /// Sign a response. `transcript_bind` MUST be the body bytes of
    /// the invite the scanner just scanned (i.e. `invite.body_bytes()`).
    /// This binding is what defeats invite-substitution attacks.
    pub fn sign_for_transcript(
        signer: &SigningKey,
        ephemeral_x25519_pk: [u8; X25519_PUBKEY_LEN],
        nonce: [u8; RESPONSE_NONCE_LEN],
        transcript_bind: &[u8],
    ) -> Self {
        let id_pubkey = signer.verifying_key().to_bytes();
        let sig = signer.sign(&signing_payload(
            transcript_bind,
            &nonce,
            &ephemeral_x25519_pk,
        ));
        Self {
            id_pubkey,
            ephemeral_x25519_pk,
            nonce,
            signature: sig.to_bytes(),
        }
    }

    /// Encode the signed response to its canon byte representation.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(RESPONSE_MAX_BYTES);
        w.write_u8(RESPONSE_VERSION);
        w.write_u8(TAG_RESPONSE);
        w.write_fixed(&self.id_pubkey);
        w.write_fixed(&self.ephemeral_x25519_pk);
        w.write_fixed(&self.nonce);
        w.write_fixed(&self.signature);
        w.into_bytes()
    }

    /// Decode the byte representation AND verify the Ed25519
    /// signature against the locally-computed `transcript_bind`.
    /// This is the only safe decode path for production code.
    pub fn decode_and_verify(bytes: &[u8], transcript_bind: &[u8]) -> PairResult<Self> {
        if transcript_bind.len() > INVITE_MAX_BYTES {
            // Defensive: a hostile inviter-side bug could pass an
            // unreasonable bind. Refuse before signature work.
            return Err(PairError::Oversize {
                got: transcript_bind.len(),
                cap: INVITE_MAX_BYTES,
            });
        }
        let resp = Self::decode_raw(bytes)?;
        let vk = VerifyingKey::from_bytes(&resp.id_pubkey).map_err(|_| PairError::BadSignature)?;
        let sig = Signature::from_bytes(&resp.signature);
        vk.verify(
            &signing_payload(transcript_bind, &resp.nonce, &resp.ephemeral_x25519_pk),
            &sig,
        )
        .map_err(|_| PairError::BadSignature)?;
        Ok(resp)
    }

    /// Raw decode WITHOUT signature verification. Fuzz harnesses
    /// only.
    pub fn decode_raw(bytes: &[u8]) -> PairResult<Self> {
        if bytes.len() > RESPONSE_MAX_BYTES {
            return Err(PairError::Oversize {
                got: bytes.len(),
                cap: RESPONSE_MAX_BYTES,
            });
        }
        let mut r = Reader::new(bytes);
        let ver = r.read_u8()?;
        if ver != RESPONSE_VERSION {
            return Err(PairError::UnsupportedVersion {
                got: ver,
                supported: RESPONSE_VERSION,
            });
        }
        let tag = r.read_u8()?;
        if tag != TAG_RESPONSE {
            return Err(PairError::BadTag {
                expected: TAG_RESPONSE,
                got: tag,
            });
        }
        let id_slice = r.read_fixed(PUBLIC_KEY_LENGTH)?;
        let mut id_pubkey = [0u8; PUBLIC_KEY_LENGTH];
        id_pubkey.copy_from_slice(id_slice);

        let ephem_slice = r.read_fixed(X25519_PUBKEY_LEN)?;
        let mut ephemeral_x25519_pk = [0u8; X25519_PUBKEY_LEN];
        ephemeral_x25519_pk.copy_from_slice(ephem_slice);

        let nonce_slice = r.read_fixed(RESPONSE_NONCE_LEN)?;
        let mut nonce = [0u8; RESPONSE_NONCE_LEN];
        nonce.copy_from_slice(nonce_slice);

        let sig_slice = r.read_fixed(SIGNATURE_LENGTH)?;
        let mut signature = [0u8; SIGNATURE_LENGTH];
        signature.copy_from_slice(sig_slice);

        if !r.is_empty() {
            return Err(PairError::Oversize {
                got: bytes.len(),
                cap: r.position(),
            });
        }
        Ok(PairResponse {
            id_pubkey,
            ephemeral_x25519_pk,
            nonce,
            signature,
        })
    }
}

fn signing_payload(
    transcript_bind: &[u8],
    nonce: &[u8; RESPONSE_NONCE_LEN],
    ephem_pk: &[u8; X25519_PUBKEY_LEN],
) -> Vec<u8> {
    // Domain-tag || u32 len-prefix(transcript_bind) || transcript_bind
    //            || nonce || ephem_pk
    let mut w = Writer::with_capacity(RESPONSE_SIG_DOMAIN.len() + transcript_bind.len() + 96);
    w.write_fixed(RESPONSE_SIG_DOMAIN);
    w.write_u32(transcript_bind.len() as u32);
    w.write_fixed(transcript_bind);
    w.write_fixed(nonce);
    w.write_fixed(ephem_pk);
    w.into_bytes()
}

impl Drop for PairResponse {
    fn drop(&mut self) {
        self.nonce.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn fresh_keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn fresh_ephem_pk() -> [u8; X25519_PUBKEY_LEN] {
        let s = StaticSecret::random_from_rng(OsRng);
        PublicKey::from(&s).to_bytes()
    }

    fn fresh_nonce() -> [u8; RESPONSE_NONCE_LEN] {
        let mut n = [0u8; RESPONSE_NONCE_LEN];
        OsRng.fill_bytes(&mut n);
        n
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let sk = fresh_keypair();
        let bind = b"any-transcript-bind-bytes";
        let resp = PairResponse::sign_for_transcript(&sk, fresh_ephem_pk(), fresh_nonce(), bind);
        let encoded = resp.encode();
        assert!(encoded.len() <= RESPONSE_MAX_BYTES);
        let decoded = PairResponse::decode_and_verify(&encoded, bind).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn mismatched_bind_fails_verify() {
        let sk = fresh_keypair();
        let resp =
            PairResponse::sign_for_transcript(&sk, fresh_ephem_pk(), fresh_nonce(), b"original");
        let encoded = resp.encode();
        let err = PairResponse::decode_and_verify(&encoded, b"different").unwrap_err();
        assert_eq!(err, PairError::BadSignature);
    }

    #[test]
    fn tampered_signature_fails_verify() {
        let sk = fresh_keypair();
        let resp = PairResponse::sign_for_transcript(&sk, fresh_ephem_pk(), fresh_nonce(), b"x");
        let mut encoded = resp.encode();
        let last = encoded.len() - 1;
        encoded[last] ^= 0x01;
        let err = PairResponse::decode_and_verify(&encoded, b"x").unwrap_err();
        assert_eq!(err, PairError::BadSignature);
    }

    #[test]
    fn tampered_nonce_fails_verify() {
        let sk = fresh_keypair();
        let resp = PairResponse::sign_for_transcript(&sk, fresh_ephem_pk(), fresh_nonce(), b"x");
        let mut encoded = resp.encode();
        // Header(2) + id_pk(32) + ephem(32) + nonce_start
        let nonce_offset = 2 + 32 + 32;
        encoded[nonce_offset] ^= 0x40;
        let err = PairResponse::decode_and_verify(&encoded, b"x").unwrap_err();
        assert_eq!(err, PairError::BadSignature);
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut bytes = vec![0xFFu8, TAG_RESPONSE];
        bytes.resize(200, 0);
        let err = PairResponse::decode_raw(&bytes).unwrap_err();
        assert!(matches!(err, PairError::UnsupportedVersion { .. }));
    }

    #[test]
    fn wrong_tag_rejected() {
        let mut bytes = vec![RESPONSE_VERSION, 0x99u8];
        bytes.resize(200, 0);
        let err = PairResponse::decode_raw(&bytes).unwrap_err();
        assert!(matches!(err, PairError::BadTag { .. }));
    }

    #[test]
    fn truncated_buffer_rejected() {
        let bytes = vec![RESPONSE_VERSION, TAG_RESPONSE, 0x00, 0x01];
        let err = PairResponse::decode_raw(&bytes).unwrap_err();
        assert!(matches!(err, PairError::Truncated { .. }));
    }

    #[test]
    fn oversize_buffer_rejected() {
        let huge = vec![0u8; RESPONSE_MAX_BYTES + 1];
        let err = PairResponse::decode_raw(&huge).unwrap_err();
        assert!(matches!(err, PairError::Oversize { .. }));
    }

    #[test]
    fn trailing_garbage_rejected() {
        let sk = fresh_keypair();
        let resp = PairResponse::sign_for_transcript(&sk, fresh_ephem_pk(), fresh_nonce(), b"x");
        let mut encoded = resp.encode();
        encoded.push(0xFF);
        let err = PairResponse::decode_raw(&encoded).unwrap_err();
        assert!(matches!(err, PairError::Oversize { .. }));
    }
}
