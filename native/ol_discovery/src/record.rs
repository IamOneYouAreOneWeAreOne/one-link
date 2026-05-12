//! Signed peer-announcement records published into the DHT.
//!
//! Each record carries:
//!   - The publisher's Ed25519 master pubkey (32 bytes).
//!   - Reachability endpoints (transport addresses).
//!   - A freshness timestamp (publish_time, unix seconds).
//!   - A TTL (record expires at publish_time + ttl_secs).
//!   - An Ed25519 signature by the publisher over the canonical
//!     byte serialization of the above.
//!
//! Lookups verify the signature before trusting any returned record.
//! Forged records are rejected at lookup time, not stored.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;

use crate::node_id::NodeId;

/// Default record TTL: 24 hours. Publishers republish on a tick (~1h).
pub const RECORD_DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;

/// Maximum endpoint string length. Bounded to keep records small +
/// resistant to amplification attacks during DHT gossip.
const MAX_ENDPOINT_LEN: usize = 128;

/// Maximum number of endpoints per record. Keeps record size bounded.
const MAX_ENDPOINTS: usize = 8;

/// The unsigned record payload. This is what's signed; serialization
/// is canonical (length-prefixed; same encoding both sides) so a
/// signature commits to a unique byte string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerRecord {
    /// Ed25519 master pubkey of the publisher. The NodeId is
    /// `BLAKE3(pubkey)`; lookups verify signature against this key.
    pub publisher_pubkey: [u8; 32],
    /// Reachability endpoints. Each is a transport-specific
    /// address string ("udp://1.2.3.4:5678", "quic://host:port",
    /// "circuit-relay://peer-fp/path", etc.). Length-bounded.
    pub endpoints: Vec<String>,
    /// Unix seconds when the record was published.
    pub publish_time_unix: u64,
    /// Record-lifetime seconds; expires at `publish_time + ttl`.
    pub ttl_secs: u64,
}

impl PeerRecord {
    /// Compute the canonical byte serialization that gets signed.
    ///
    /// Format (length-prefixed, big-endian sizes):
    ///   - 4-byte magic "OLR1"
    ///   - 32-byte publisher_pubkey
    ///   - 8-byte publish_time_unix (BE)
    ///   - 8-byte ttl_secs (BE)
    ///   - 2-byte n_endpoints (BE)
    ///   - For each endpoint:
    ///       - 2-byte len (BE)
    ///       - `len` bytes UTF-8
    ///
    /// Pure; same input always produces same output. Used both for
    /// signing and verification.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.endpoints.len() * 64);
        out.extend_from_slice(b"OLR1");
        out.extend_from_slice(&self.publisher_pubkey);
        out.extend_from_slice(&self.publish_time_unix.to_be_bytes());
        out.extend_from_slice(&self.ttl_secs.to_be_bytes());
        let n = u16::try_from(self.endpoints.len().min(u16::MAX as usize))
            .unwrap_or(u16::MAX);
        out.extend_from_slice(&n.to_be_bytes());
        for ep in &self.endpoints {
            let bytes = ep.as_bytes();
            let len = u16::try_from(bytes.len().min(u16::MAX as usize))
                .unwrap_or(u16::MAX);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&bytes[..len as usize]);
        }
        out
    }

    /// The NodeId implied by this record's publisher pubkey.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        NodeId::from_pubkey(&self.publisher_pubkey)
    }

    /// Is the record currently fresh (not expired)?
    ///
    /// `now_unix` is the caller's current unix-seconds clock.
    #[must_use]
    pub fn is_fresh(&self, now_unix: u64) -> bool {
        now_unix < self.publish_time_unix.saturating_add(self.ttl_secs)
    }

    /// Validate basic record shape (size bounds, non-empty).
    fn shape_check(&self) -> Result<(), RecordError> {
        if self.endpoints.len() > MAX_ENDPOINTS {
            return Err(RecordError::TooManyEndpoints {
                got: self.endpoints.len(),
                max: MAX_ENDPOINTS,
            });
        }
        for ep in &self.endpoints {
            if ep.len() > MAX_ENDPOINT_LEN {
                return Err(RecordError::EndpointTooLong {
                    got: ep.len(),
                    max: MAX_ENDPOINT_LEN,
                });
            }
        }
        Ok(())
    }
}

/// Errors that can occur signing / verifying / parsing records.
#[derive(Debug, Error, PartialEq)]
pub enum RecordError {
    /// Signature verification failed.
    #[error("signature verification failed")]
    BadSignature,
    /// Publisher pubkey is malformed (not a valid Ed25519 point).
    #[error("malformed publisher pubkey")]
    MalformedPubkey,
    /// Record has more than [`MAX_ENDPOINTS`] endpoints.
    #[error("too many endpoints: {got} (max {max})")]
    TooManyEndpoints {
        /// Actual count.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// One endpoint exceeds [`MAX_ENDPOINT_LEN`] bytes.
    #[error("endpoint too long: {got} bytes (max {max})")]
    EndpointTooLong {
        /// Actual length.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Record's claimed publisher pubkey doesn't match the signing
    /// key (defensive check; the public API generally signs a record
    /// with its own publisher_pubkey).
    #[error("record's publisher_pubkey doesn't match the signing key")]
    PubkeyMismatch,
}

/// A signed record: the payload plus the 64-byte Ed25519 signature
/// over its canonical bytes. This is what gossips through the DHT.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRecord {
    /// The underlying payload.
    pub record: PeerRecord,
    /// Ed25519 signature over `record.canonical_bytes()`.
    pub signature: [u8; 64],
}

impl SignedRecord {
    /// Sign `record` with `signing_key`. The signing key's public
    /// component MUST equal `record.publisher_pubkey` (defensive
    /// check; prevents a caller from accidentally signing a record
    /// that claims a different publisher).
    ///
    /// # Errors
    /// - [`RecordError::PubkeyMismatch`] when the signing key's
    ///   public component doesn't match `record.publisher_pubkey`.
    /// - [`RecordError::TooManyEndpoints`] / [`RecordError::EndpointTooLong`]
    ///   on shape violations.
    pub fn sign(
        record: PeerRecord,
        signing_key: &SigningKey,
    ) -> Result<Self, RecordError> {
        record.shape_check()?;
        let derived_pub: VerifyingKey = signing_key.verifying_key();
        if derived_pub.to_bytes() != record.publisher_pubkey {
            return Err(RecordError::PubkeyMismatch);
        }
        let bytes = record.canonical_bytes();
        let sig: Signature = signing_key.sign(&bytes);
        Ok(Self {
            record,
            signature: sig.to_bytes(),
        })
    }

    /// Verify the signature against the record's canonical bytes.
    ///
    /// # Errors
    /// - [`RecordError::MalformedPubkey`] when the publisher pubkey
    ///   isn't a valid Ed25519 point.
    /// - [`RecordError::BadSignature`] on any verification failure.
    pub fn verify(&self) -> Result<(), RecordError> {
        self.record.shape_check()?;
        let verifying_key = VerifyingKey::from_bytes(&self.record.publisher_pubkey)
            .map_err(|_| RecordError::MalformedPubkey)?;
        let sig = Signature::from_bytes(&self.signature);
        let bytes = self.record.canonical_bytes();
        verifying_key
            .verify(&bytes, &sig)
            .map_err(|_| RecordError::BadSignature)
    }

    /// Convenience: verify + check freshness in one call.
    ///
    /// # Errors
    /// Same as [`Self::verify`], plus returns `Ok(false)` (not an
    /// error) when the record is expired but the signature is valid.
    pub fn verify_and_check_freshness(
        &self,
        now_unix: u64,
    ) -> Result<bool, RecordError> {
        self.verify()?;
        Ok(self.record.is_fresh(now_unix))
    }

    /// The NodeId the record refers to.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.record.node_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn make_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn make_record(sk: &SigningKey, eps: Vec<&str>) -> PeerRecord {
        PeerRecord {
            publisher_pubkey: sk.verifying_key().to_bytes(),
            endpoints: eps.into_iter().map(String::from).collect(),
            publish_time_unix: 1_700_000_000,
            ttl_secs: RECORD_DEFAULT_TTL_SECS,
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = make_key();
        let rec = make_record(&sk, vec!["udp://1.2.3.4:5678"]);
        let signed = SignedRecord::sign(rec, &sk).unwrap();
        signed.verify().unwrap();
    }

    #[test]
    fn tamper_endpoint_invalidates_sig() {
        let sk = make_key();
        let rec = make_record(&sk, vec!["udp://1.2.3.4:5678"]);
        let mut signed = SignedRecord::sign(rec, &sk).unwrap();
        signed.record.endpoints[0] = "udp://9.9.9.9:6666".into();
        assert_eq!(signed.verify().unwrap_err(), RecordError::BadSignature);
    }

    #[test]
    fn tamper_publish_time_invalidates_sig() {
        let sk = make_key();
        let rec = make_record(&sk, vec!["udp://1.2.3.4:5678"]);
        let mut signed = SignedRecord::sign(rec, &sk).unwrap();
        signed.record.publish_time_unix = signed.record.publish_time_unix.wrapping_add(1);
        assert_eq!(signed.verify().unwrap_err(), RecordError::BadSignature);
    }

    #[test]
    fn tamper_publisher_pubkey_fails() {
        let sk = make_key();
        let rec = make_record(&sk, vec!["udp://1.2.3.4:5678"]);
        let mut signed = SignedRecord::sign(rec, &sk).unwrap();
        signed.record.publisher_pubkey[0] ^= 1;
        // Tampered pubkey: signature won't match the (different) signed bytes.
        // Could also be MalformedPubkey if the byte flip yields a non-curve point.
        let err = signed.verify().unwrap_err();
        assert!(matches!(
            err,
            RecordError::BadSignature | RecordError::MalformedPubkey
        ));
    }

    #[test]
    fn pubkey_mismatch_at_sign_time() {
        let sk_a = make_key();
        let sk_b = make_key();
        let mut rec = make_record(&sk_a, vec!["udp://1.2.3.4:5678"]);
        rec.publisher_pubkey = sk_b.verifying_key().to_bytes();
        let err = SignedRecord::sign(rec, &sk_a).unwrap_err();
        assert_eq!(err, RecordError::PubkeyMismatch);
    }

    #[test]
    fn freshness_check() {
        let sk = make_key();
        let mut rec = make_record(&sk, vec!["udp://1.2.3.4:5678"]);
        rec.publish_time_unix = 1000;
        rec.ttl_secs = 100;
        let signed = SignedRecord::sign(rec, &sk).unwrap();
        // Within TTL.
        assert!(signed
            .verify_and_check_freshness(1050)
            .unwrap());
        // Expired.
        assert!(!signed
            .verify_and_check_freshness(1101)
            .unwrap());
    }

    #[test]
    fn too_many_endpoints_rejected() {
        let sk = make_key();
        let mut rec = make_record(&sk, vec![]);
        for i in 0..(MAX_ENDPOINTS + 1) {
            rec.endpoints.push(format!("udp://{i}.0.0.0:1"));
        }
        let err = SignedRecord::sign(rec, &sk).unwrap_err();
        assert!(matches!(err, RecordError::TooManyEndpoints { .. }));
    }

    #[test]
    fn endpoint_too_long_rejected() {
        let sk = make_key();
        let mut rec = make_record(&sk, vec![]);
        rec.endpoints.push("x".repeat(MAX_ENDPOINT_LEN + 1));
        let err = SignedRecord::sign(rec, &sk).unwrap_err();
        assert!(matches!(err, RecordError::EndpointTooLong { .. }));
    }

    #[test]
    fn node_id_matches_pubkey_hash() {
        let sk = make_key();
        let rec = make_record(&sk, vec!["x"]);
        let pk = sk.verifying_key().to_bytes();
        assert_eq!(rec.node_id(), NodeId::from_pubkey(&pk));
    }

    #[test]
    fn canonical_bytes_deterministic() {
        let sk = make_key();
        let rec1 = make_record(&sk, vec!["udp://1.1.1.1:1", "quic://2.2.2.2:2"]);
        let rec2 = rec1.clone();
        assert_eq!(rec1.canonical_bytes(), rec2.canonical_bytes());
    }

    #[test]
    fn different_endpoint_order_yields_different_canonical() {
        let sk = make_key();
        let rec1 = make_record(&sk, vec!["a", "b"]);
        let rec2 = make_record(&sk, vec!["b", "a"]);
        assert_ne!(rec1.canonical_bytes(), rec2.canonical_bytes());
    }
}
