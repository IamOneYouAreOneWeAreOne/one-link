//! Peer identity for QUIC transport per [ADR-0010].
//!
//! An [`Identity`] is an Ed25519 keypair plus its self-signed X.509
//! certificate. The cert's `SubjectPublicKeyInfo` carries the Ed25519
//! public key; verifiers reduce to "is `BLAKE3(SPKI raw pubkey bytes)`
//! equal to the expected fingerprint?" per ADR-0010.
//!
//! Identities are persistent: generated once at peer creation, written
//! to disk, loaded on every daemon start. This module exposes both the
//! ephemeral (in-memory only) and persistent (PKCS#8 PEM round-trip)
//! constructors.
//!
//! [ADR-0010]: ../../../docs/decisions/0010-identity-bound-tls.md

use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::SigningKey;
use rcgen::{
    CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
    SignatureAlgorithm,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::error::QuicError;

/// Length of a peer fingerprint in bytes (BLAKE3-256 of the raw Ed25519
/// public key, 32 bytes).
pub const FINGERPRINT_LEN: usize = 32;

/// Peer fingerprint = `BLAKE3(ed25519_pubkey_raw_32)`.
pub type PeerFingerprint = [u8; FINGERPRINT_LEN];

/// A peer identity: Ed25519 keypair + self-signed identity-bound cert.
///
/// Generated via [`Identity::generate`] for fresh peers, or
/// [`Identity::from_pkcs8_pem`] for restored peers. The fingerprint is
/// what other peers know us by — passed in QR pairing, capability
/// tickets, peer registry lookups.
pub struct Identity {
    signing_key: SigningKey,
    der_cert: Vec<u8>,
    fingerprint: PeerFingerprint,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't print the private key bytes.
        f.debug_struct("Identity")
            .field("fingerprint_hex", &hex_lower(&self.fingerprint))
            .field("cert_der_len", &self.der_cert.len())
            .finish()
    }
}

impl Identity {
    /// Generate a fresh identity from the OS RNG.
    ///
    /// # Errors
    ///
    /// Returns [`QuicError::Rcgen`] if cert generation fails (very
    /// unlikely; only happens on truly broken Ed25519 inputs).
    pub fn generate() -> Result<Self, QuicError> {
        let mut csprng = rand_core::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self::from_signing_key(signing_key)
    }

    /// Restore an identity from a PKCS#8 PEM-encoded Ed25519 private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM doesn't parse, isn't an Ed25519 key,
    /// or is structurally invalid.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, QuicError> {
        let signing_key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| QuicError::X509(format!("pkcs8 parse: {e}")))?;
        Self::from_signing_key(signing_key)
    }

    /// Construct an identity from an existing Ed25519 [`SigningKey`].
    ///
    /// Generates the matching self-signed cert per ADR-0010.
    pub fn from_signing_key(signing_key: SigningKey) -> Result<Self, QuicError> {
        let pubkey_bytes = signing_key.verifying_key().to_bytes();
        let fingerprint: PeerFingerprint = *blake3::hash(&pubkey_bytes).as_bytes();
        let der_cert = build_self_signed_cert(&signing_key)?;
        Ok(Self {
            signing_key,
            der_cert,
            fingerprint,
        })
    }

    /// Borrow the cert in DER format for [`rustls`] config.
    #[must_use]
    pub fn cert_der(&self) -> CertificateDer<'_> {
        CertificateDer::from(self.der_cert.as_slice())
    }

    /// Owned PKCS#8 DER copy of the private key for [`rustls`] config.
    #[must_use]
    pub fn private_key_der(&self) -> PrivatePkcs8KeyDer<'static> {
        let pkcs8 = self
            .signing_key
            .to_pkcs8_der()
            .expect("Ed25519 always serializes to PKCS#8 DER");
        PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec())
    }

    /// PKCS#8 PEM encoding for at-rest storage (e.g. `data_dir/identity.pem`).
    #[must_use]
    pub fn to_pkcs8_pem(&self) -> String {
        self.signing_key
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .expect("Ed25519 PKCS#8 PEM serialization is infallible")
            .to_string()
    }

    /// 32-byte BLAKE3 fingerprint that other peers know us by.
    #[inline]
    #[must_use]
    pub fn fingerprint(&self) -> PeerFingerprint {
        self.fingerprint
    }

    /// Lower-32-byte raw Ed25519 public key (the SubjectPublicKey bits
    /// our cert advertises).
    #[inline]
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

/// Build the self-signed X.509 cert per [ADR-0010](../../../docs/decisions/0010-identity-bound-tls.md).
fn build_self_signed_cert(signing_key: &SigningKey) -> Result<Vec<u8>, QuicError> {
    let pkcs8_der = signing_key
        .to_pkcs8_der()
        .map_err(|e| QuicError::X509(format!("pkcs8 encode: {e}")))?;
    // rcgen's `KeyPair::from_pkcs8_der_and_sign_algo` consumes a DER-
    // encoded private key as a typed `rustls_pki_types::PrivatePkcs8KeyDer`.
    // We pass our PKCS#8 DER and explicitly select the Ed25519 signature
    // algorithm so rcgen doesn't try to negotiate.
    let pkcs8_typed = rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8_der.as_bytes().to_vec());
    let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_typed, &rcgen::PKCS_ED25519)?;

    let mut params = CertificateParams::new(vec!["one-link".to_string()])?;
    // ADR-0010 §"Cert generation": Subject CN = "one-link".
    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "one-link");
    params.distinguished_name = dn;
    // ADR-0010: zero serial. Standard X.509 expects unique-per-issuer
    // serials; for self-signed certs this is irrelevant. Zero is canonical.
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&[0u8; 16]));
    // Effectively no expiry.
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    params.not_after = rcgen::date_time_ymd(9999, 12, 31);
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];

    let cert = params.self_signed(&key_pair)?;
    Ok(cert.der().to_vec())
}

/// rcgen's signature algorithm constant for Ed25519. Re-exported from
/// rcgen via a static reference; convenience for downstream callers.
#[allow(dead_code)]
pub(crate) static ED25519_SIG_ALGO: &SignatureAlgorithm = &rcgen::PKCS_ED25519;

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_yields_distinct_identities() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
        assert_ne!(a.public_key_bytes(), b.public_key_bytes());
    }

    #[test]
    fn fingerprint_equals_blake3_of_pubkey() {
        let id = Identity::generate().unwrap();
        let computed = *blake3::hash(&id.public_key_bytes()).as_bytes();
        assert_eq!(id.fingerprint(), computed);
    }

    #[test]
    fn pkcs8_pem_round_trip_preserves_identity() {
        let original = Identity::generate().unwrap();
        let pem = original.to_pkcs8_pem();
        let restored = Identity::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(original.fingerprint(), restored.fingerprint());
        assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn cert_der_starts_with_x509_sequence() {
        let id = Identity::generate().unwrap();
        let der = id.cert_der();
        // X.509 DER starts with 0x30 (SEQUENCE).
        assert_eq!(der.as_ref()[0], 0x30);
    }

    #[test]
    fn cert_subject_pubkey_matches_identity() {
        // The fingerprint MUST equal BLAKE3 of the SubjectPublicKey bytes
        // extracted from the cert. This is the property ADR-0010
        // verifiers rely on.
        let id = Identity::generate().unwrap();
        let der = id.cert_der();
        let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
        let spki_pubkey = cert.public_key().subject_public_key.data.as_ref();
        let fp_from_cert = *blake3::hash(spki_pubkey).as_bytes();
        assert_eq!(fp_from_cert, id.fingerprint());
    }

    #[test]
    fn cert_algorithm_is_ed25519() {
        let id = Identity::generate().unwrap();
        let der = id.cert_der();
        let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
        // Ed25519 OID = 1.3.101.112
        let oid = cert.public_key().algorithm.algorithm.to_string();
        assert_eq!(oid, "1.3.101.112", "expected Ed25519 OID");
    }

    #[test]
    fn debug_does_not_leak_private_key() {
        let id = Identity::generate().unwrap();
        let s = format!("{id:?}");
        assert!(s.contains("Identity"));
        assert!(s.contains("fingerprint_hex"));
        // Should NOT include any "signing_key" or PKCS-style content.
        assert!(!s.contains("signing_key"));
    }
}
