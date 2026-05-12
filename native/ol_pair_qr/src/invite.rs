//! [`Invite`] — the QR payload + Ed25519 signature.
//!
//! Wire layout (after the 2-byte header):
//!
//! ```text
//!   u8   version             (= INVITE_VERSION)
//!   u8   type tag            (= TAG_INVITE)
//!   [32] id_pubkey           Ed25519 verifying key of the inviter's master identity
//!   [32] ephemeral_x25519_pk inviter's one-time X25519 public
//!   [32] nonce               INVITE_NONCE_LEN bytes of cryptographic randomness
//!   u64  expiry_unix         wall-clock expiry, unix seconds
//!   u16  scope.len()
//!   [..] scope.bytes         caller-defined capability scope (see CapabilityScope)
//!   [64] signature           Ed25519(id_pubkey).sign(body)
//! ```
//!
//! `body` is every byte from `version` through `scope.bytes`
//! inclusive — i.e. everything EXCEPT the trailing signature. The
//! signature is verified before any field is trusted.

use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use zeroize::Zeroize;

use crate::canon::{Reader, Writer, MAX_FIELD_BYTES};
use crate::errors::{PairError, PairResult};

/// Pair-by-QR protocol version on the wire. Bump in lockstep with
/// any incompatible canon-encoding change.
pub const INVITE_VERSION: u8 = 1;

/// Type-tag byte distinguishing an `Invite` from other frames.
pub const TAG_INVITE: u8 = 0x01;

/// Length of the cryptographic nonce baked into the invite.
pub const INVITE_NONCE_LEN: usize = 32;

/// Length of an X25519 raw public key.
pub const X25519_PUBKEY_LEN: usize = 32;

/// Maximum encoded byte length for an `Invite` (well within QR-code
/// Version-15 alphanumeric capacity even at error-correction level
/// `H`, leaving generous headroom for base32 encoding overhead).
pub const INVITE_MAX_BYTES: usize = 512;

/// Capability scope the inviter is granting to the scanner. The
/// daemon layer encodes its own semantics here; this crate treats it
/// as an opaque byte string but transcript-binds it so neither side
/// can be tricked into agreeing on a different scope than the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityScope(pub Vec<u8>);

impl CapabilityScope {
    /// Construct from raw bytes. Returns [`PairError::Oversize`] if
    /// the caller passes more than [`MAX_FIELD_BYTES`].
    pub fn from_bytes(b: &[u8]) -> PairResult<Self> {
        if b.len() > MAX_FIELD_BYTES {
            return Err(PairError::Oversize {
                got: b.len(),
                cap: MAX_FIELD_BYTES,
            });
        }
        Ok(Self(b.to_vec()))
    }

    /// View as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convenience: an empty scope (most narrow contact-only invite).
    pub fn empty() -> Self {
        Self(Vec::new())
    }
}

/// The pair-by-QR invite — what the inviter encodes into the QR code.
///
/// Created via [`Invite::sign`]; verified + decoded via
/// [`Invite::decode_and_verify`]. The raw constructor (`new_unsigned`)
/// exists only to support test vectors and adversarial fuzzing.
///
/// ## Example
///
/// ```
/// use ed25519_dalek::SigningKey;
/// use rand_core::OsRng;
/// use ol_pair_qr::invite::{CapabilityScope, Invite, INVITE_NONCE_LEN};
/// use x25519_dalek::{PublicKey, StaticSecret};
///
/// let sk = SigningKey::generate(&mut OsRng);
/// let esk = StaticSecret::random_from_rng(OsRng);
/// let epk = PublicKey::from(&esk).to_bytes();
/// let mut nonce = [0u8; INVITE_NONCE_LEN];
/// rand_core::RngCore::fill_bytes(&mut OsRng, &mut nonce);
///
/// let invite = Invite::sign(
///     &sk, epk, nonce, 1_900_000_000,
///     CapabilityScope::from_bytes(b"contact").unwrap(),
/// );
/// let encoded = invite.encode();
/// let decoded = Invite::decode_and_verify(&encoded).unwrap();
/// assert_eq!(decoded, invite);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// Master identity public key of the inviter.
    pub id_pubkey: [u8; PUBLIC_KEY_LENGTH],
    /// Ephemeral X25519 public key bound to this single invite.
    pub ephemeral_x25519_pk: [u8; X25519_PUBKEY_LEN],
    /// Cryptographic nonce baked into the invite (never reused).
    pub nonce: [u8; INVITE_NONCE_LEN],
    /// Wall-clock expiry, unix seconds.
    pub expiry_unix: u64,
    /// Capability scope (opaque to this crate).
    pub scope: CapabilityScope,
    /// Ed25519 signature over the canon-encoded body.
    pub signature: [u8; SIGNATURE_LENGTH],
}

impl Invite {
    /// Sign an invite. The signing key MUST be the secret half of
    /// `id_pubkey`. Returns the fully-signed [`Invite`] ready to
    /// encode into a QR code.
    pub fn sign(
        signer: &SigningKey,
        ephemeral_x25519_pk: [u8; X25519_PUBKEY_LEN],
        nonce: [u8; INVITE_NONCE_LEN],
        expiry_unix: u64,
        scope: CapabilityScope,
    ) -> Self {
        let id_pubkey = signer.verifying_key().to_bytes();
        let body = encode_body(
            &id_pubkey,
            &ephemeral_x25519_pk,
            &nonce,
            expiry_unix,
            &scope,
        );
        let sig: Signature = signer.sign(&body);
        Self {
            id_pubkey,
            ephemeral_x25519_pk,
            nonce,
            expiry_unix,
            scope,
            signature: sig.to_bytes(),
        }
    }

    /// Encode the signed invite to its canon byte representation.
    ///
    /// Use this for QR-encoding. The returned `Vec<u8>` is the raw
    /// payload; the QR layer (base32 + level-M ECC) is upstream.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(INVITE_MAX_BYTES);
        w.write_u8(INVITE_VERSION);
        w.write_u8(TAG_INVITE);
        w.write_fixed(&self.id_pubkey);
        w.write_fixed(&self.ephemeral_x25519_pk);
        w.write_fixed(&self.nonce);
        w.write_u64(self.expiry_unix);
        w.write_var(self.scope.as_bytes());
        w.write_fixed(&self.signature);
        w.into_bytes()
    }

    /// Decode the byte representation **and** verify the Ed25519
    /// signature in one step. Returns [`PairError::BadSignature`]
    /// if the signature doesn't verify.
    ///
    /// This is the only safe decode path — `decode_raw` exists for
    /// fuzz harnesses and explicitly does NOT verify.
    pub fn decode_and_verify(bytes: &[u8]) -> PairResult<Self> {
        let inv = Self::decode_raw(bytes)?;
        let body = encode_body(
            &inv.id_pubkey,
            &inv.ephemeral_x25519_pk,
            &inv.nonce,
            inv.expiry_unix,
            &inv.scope,
        );
        let vk = VerifyingKey::from_bytes(&inv.id_pubkey)
            .map_err(|_| PairError::BadSignature)?;
        let sig = Signature::from_bytes(&inv.signature);
        vk.verify(&body, &sig).map_err(|_| PairError::BadSignature)?;
        Ok(inv)
    }

    /// Raw decode WITHOUT signature verification. Fuzz harnesses use
    /// this to exercise pure parsing paths. Daemon code must NEVER
    /// call this — use [`Invite::decode_and_verify`] instead.
    pub fn decode_raw(bytes: &[u8]) -> PairResult<Self> {
        if bytes.len() > INVITE_MAX_BYTES {
            return Err(PairError::Oversize {
                got: bytes.len(),
                cap: INVITE_MAX_BYTES,
            });
        }
        let mut r = Reader::new(bytes);
        let ver = r.read_u8()?;
        if ver != INVITE_VERSION {
            return Err(PairError::UnsupportedVersion {
                got: ver,
                supported: INVITE_VERSION,
            });
        }
        let tag = r.read_u8()?;
        if tag != TAG_INVITE {
            return Err(PairError::BadTag {
                expected: TAG_INVITE,
                got: tag,
            });
        }
        let id_pubkey_slice = r.read_fixed(PUBLIC_KEY_LENGTH)?;
        let mut id_pubkey = [0u8; PUBLIC_KEY_LENGTH];
        id_pubkey.copy_from_slice(id_pubkey_slice);

        let ephemeral_slice = r.read_fixed(X25519_PUBKEY_LEN)?;
        let mut ephemeral_x25519_pk = [0u8; X25519_PUBKEY_LEN];
        ephemeral_x25519_pk.copy_from_slice(ephemeral_slice);

        let nonce_slice = r.read_fixed(INVITE_NONCE_LEN)?;
        let mut nonce = [0u8; INVITE_NONCE_LEN];
        nonce.copy_from_slice(nonce_slice);

        let expiry_unix = r.read_u64()?;
        let scope_bytes = r.read_var()?;
        let scope = CapabilityScope(scope_bytes.to_vec());

        let sig_slice = r.read_fixed(SIGNATURE_LENGTH)?;
        let mut signature = [0u8; SIGNATURE_LENGTH];
        signature.copy_from_slice(sig_slice);

        // Refuse trailing garbage — strict frame.
        if !r.is_empty() {
            return Err(PairError::Oversize {
                got: bytes.len(),
                cap: r.position(),
            });
        }

        Ok(Invite {
            id_pubkey,
            ephemeral_x25519_pk,
            nonce,
            expiry_unix,
            scope,
            signature,
        })
    }

    /// Return the canon-encoded body (everything except the
    /// signature) — used by the transcript hash + by tests.
    pub fn body_bytes(&self) -> Vec<u8> {
        encode_body(
            &self.id_pubkey,
            &self.ephemeral_x25519_pk,
            &self.nonce,
            self.expiry_unix,
            &self.scope,
        )
    }

    /// BLAKE3 fingerprint of this invite. Used as a short identifier
    /// for log records; not a transcript anchor.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(b"OL-pair-qr-v1-invite-fp");
        h.update(&self.encode());
        *h.finalize().as_bytes()
    }

    /// Refuse if the invite's `expiry_unix` is at or before
    /// `now_unix`. Returns [`PairError::Expired`] on miss.
    pub fn check_not_expired(&self, now_unix: u64) -> PairResult<()> {
        if now_unix >= self.expiry_unix {
            return Err(PairError::Expired {
                now: now_unix,
                expiry: self.expiry_unix,
            });
        }
        Ok(())
    }
}

fn encode_body(
    id_pubkey: &[u8; PUBLIC_KEY_LENGTH],
    ephemeral_x25519_pk: &[u8; X25519_PUBKEY_LEN],
    nonce: &[u8; INVITE_NONCE_LEN],
    expiry_unix: u64,
    scope: &CapabilityScope,
) -> Vec<u8> {
    let mut w = Writer::with_capacity(INVITE_MAX_BYTES);
    w.write_u8(INVITE_VERSION);
    w.write_u8(TAG_INVITE);
    w.write_fixed(id_pubkey);
    w.write_fixed(ephemeral_x25519_pk);
    w.write_fixed(nonce);
    w.write_u64(expiry_unix);
    w.write_var(scope.as_bytes());
    w.into_bytes()
}

impl Drop for Invite {
    fn drop(&mut self) {
        // Nonce isn't sensitive after the protocol completes, but
        // zeroizing on drop is cheap and keeps the value out of
        // freed-allocation residue.
        self.nonce.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn fresh_keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn fresh_nonce() -> [u8; INVITE_NONCE_LEN] {
        let mut n = [0u8; INVITE_NONCE_LEN];
        OsRng.fill_bytes(&mut n);
        n
    }

    fn fresh_ephem_pk() -> [u8; X25519_PUBKEY_LEN] {
        // Use a real x25519 keypair so the bytes are well-formed.
        let s = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let pk = x25519_dalek::PublicKey::from(&s);
        pk.to_bytes()
    }

    #[test]
    fn sign_then_decode_and_verify_roundtrips() {
        let sk = fresh_keypair();
        let invite = Invite::sign(
            &sk,
            fresh_ephem_pk(),
            fresh_nonce(),
            1_900_000_000,
            CapabilityScope::from_bytes(b"contact:josh").unwrap(),
        );
        let encoded = invite.encode();
        assert!(encoded.len() <= INVITE_MAX_BYTES);
        let decoded = Invite::decode_and_verify(&encoded).unwrap();
        assert_eq!(decoded, invite);
    }

    #[test]
    fn tampered_signature_fails_verify() {
        let sk = fresh_keypair();
        let invite = Invite::sign(
            &sk,
            fresh_ephem_pk(),
            fresh_nonce(),
            1_900_000_000,
            CapabilityScope::empty(),
        );
        let mut encoded = invite.encode();
        // Flip the last byte (which is inside the signature).
        let last = encoded.len() - 1;
        encoded[last] ^= 0x01;
        let err = Invite::decode_and_verify(&encoded).unwrap_err();
        assert_eq!(err, PairError::BadSignature);
    }

    #[test]
    fn tampered_body_fails_verify() {
        let sk = fresh_keypair();
        let invite = Invite::sign(
            &sk,
            fresh_ephem_pk(),
            fresh_nonce(),
            1_900_000_000,
            CapabilityScope::from_bytes(b"contact:legit").unwrap(),
        );
        let mut encoded = invite.encode();
        // Flip a byte in the nonce region.
        encoded[2 + 32 + 32 + 1] ^= 0x80;
        let err = Invite::decode_and_verify(&encoded).unwrap_err();
        assert_eq!(err, PairError::BadSignature);
    }

    #[test]
    fn unsupported_version_rejected() {
        let mut encoded = vec![0xFFu8, TAG_INVITE];
        encoded.resize(200, 0);
        let err = Invite::decode_raw(&encoded).unwrap_err();
        assert!(matches!(
            err,
            PairError::UnsupportedVersion { got: 0xFF, supported: 1 }
        ));
    }

    #[test]
    fn wrong_tag_rejected() {
        let mut encoded = vec![INVITE_VERSION, 0x99u8];
        encoded.resize(200, 0);
        let err = Invite::decode_raw(&encoded).unwrap_err();
        assert!(matches!(
            err,
            PairError::BadTag { expected: 0x01, got: 0x99 }
        ));
    }

    #[test]
    fn truncated_buffer_rejected() {
        let encoded = vec![INVITE_VERSION, TAG_INVITE, 0x00, 0x01];
        let err = Invite::decode_raw(&encoded).unwrap_err();
        assert!(matches!(err, PairError::Truncated { .. }));
    }

    #[test]
    fn oversize_buffer_rejected_before_decode() {
        let huge = vec![0u8; INVITE_MAX_BYTES + 1];
        let err = Invite::decode_raw(&huge).unwrap_err();
        assert!(matches!(err, PairError::Oversize { .. }));
    }

    #[test]
    fn check_not_expired_works() {
        let sk = fresh_keypair();
        let invite = Invite::sign(
            &sk,
            fresh_ephem_pk(),
            fresh_nonce(),
            100,
            CapabilityScope::empty(),
        );
        invite.check_not_expired(99).unwrap();
        let err = invite.check_not_expired(100).unwrap_err();
        assert!(matches!(err, PairError::Expired { .. }));
        let err = invite.check_not_expired(200).unwrap_err();
        assert!(matches!(err, PairError::Expired { .. }));
    }

    #[test]
    fn body_bytes_excludes_signature() {
        let sk = fresh_keypair();
        let invite = Invite::sign(
            &sk,
            fresh_ephem_pk(),
            fresh_nonce(),
            1_900_000_000,
            CapabilityScope::empty(),
        );
        let body = invite.body_bytes();
        let full = invite.encode();
        assert_eq!(full.len(), body.len() + SIGNATURE_LENGTH);
        assert_eq!(&full[..body.len()], body.as_slice());
    }

    #[test]
    fn fingerprint_deterministic() {
        let sk = fresh_keypair();
        let invite = Invite::sign(
            &sk,
            fresh_ephem_pk(),
            fresh_nonce(),
            1_900_000_000,
            CapabilityScope::empty(),
        );
        let fp1 = invite.fingerprint();
        let fp2 = invite.fingerprint();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn trailing_garbage_rejected() {
        let sk = fresh_keypair();
        let invite = Invite::sign(
            &sk,
            fresh_ephem_pk(),
            fresh_nonce(),
            1_900_000_000,
            CapabilityScope::empty(),
        );
        let mut encoded = invite.encode();
        encoded.push(0xFF);
        let err = Invite::decode_raw(&encoded).unwrap_err();
        assert!(matches!(err, PairError::Oversize { .. }));
    }

    #[test]
    fn capability_scope_oversize_rejected() {
        let huge = vec![0u8; MAX_FIELD_BYTES + 1];
        let err = CapabilityScope::from_bytes(&huge).unwrap_err();
        assert!(matches!(err, PairError::Oversize { .. }));
    }
}
