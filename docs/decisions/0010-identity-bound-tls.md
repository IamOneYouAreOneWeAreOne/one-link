# ADR-0010: Identity-Bound TLS — Self-Signed Cert Derived from Ed25519 Peer Identity

**Status:** ACCEPTED (Phase A2 acceptance number)
**Phase:** A2 (companion to ADR-0009)
**Depends on:** ADR-0009 (QUIC transport)

---

## Context

QUIC mandates TLS 1.3 (RFC 9001). The standard X.509 PKI model assumes a chain of trust rooted in a public CA — incompatible with One Link's sovereignty stance:

1. **No vendor in the chain**: every CA is a corporate entity that can issue or revoke certs against our will. The defang table forbids this.
2. **No global namespace**: peers are identified by their Ed25519 fingerprint, not by a DNS name registered with a CA.
3. **No expiry-driven re-issuance**: peer certs that need annual renewal are operational toxic for users who paired devices once and walked away.

The standard alternative — raw public keys (RFC 7250) — is supported by TLS 1.3 in spec but rustls 0.23 doesn't expose it as a stable API in the way QUIC needs. So we take a third path: **self-signed X.509 certs whose subject public key IS the peer's Ed25519 identity key, with a custom verifier that ignores the X.509 chain entirely and only accepts certs whose pubkey matches the expected peer fingerprint.**

This is the same pattern WireGuard / iroh / Veilid use for identity-bound transport. We're following well-trodden ground.

## Decision

**Each peer's QUIC TLS certificate is a self-signed X.509 cert whose `SubjectPublicKeyInfo` contains the peer's Ed25519 identity public key. The TLS handshake verifier accepts a cert iff `BLAKE3(cert.subject_public_key_info)` equals the expected `peer_fingerprint` known from out-of-band pairing.**

### Cert generation

Performed once at peer-identity creation, persisted alongside the identity key:

```rust
fn generate_identity_cert(identity_key: &Ed25519IdentityKey) -> Cert {
    let cert = rcgen::CertificateParams::new(vec!["one-link".into()])
        .serial_number(SerialNumber::from_slice(&[0; 16]))    // deterministic; not load-bearing
        .not_before(Time::unix(0))                             // 1970 — pre-dates "no expiry needed"
        .not_after(Time::unix(0xFFFF_FFFF_FFFF))               // year 9999 — eternal
        .key_usage(&[KeyUsage::DigitalSignature])
        .extended_key_usage(&[ExtendedKeyUsage::ServerAuth, ExtendedKeyUsage::ClientAuth])
        .key_pair(KeyPair::from_pkcs8_pem_and_sign_algo(
            identity_key.pkcs8_pem(),
            &PKCS_ED25519,
        )?)
        .self_signed()?;
    cert
}
```

Properties:

- Subject CN: `"one-link"` (irrelevant to us; populated to satisfy spec parsers).
- Serial: zero. Standard X.509 expects unique serials per issuer; for self-signed certs this is irrelevant. Zero is canonical.
- Validity: 1970-01-01 to year 9999. Effectively no expiry. Operationally important: peers paired once shouldn't have to re-pair because a cert expired.
- Key usage: DigitalSignature only. No CertSign — we never issue subordinate certs.
- Extended key usage: ServerAuth + ClientAuth. We are both ends of a QUIC connection.
- Signature algorithm: Ed25519 (PKCS#8 PEM). Same key as identity.

### Server-name (SNI)

The QUIC client must send an SNI value. We use the **expected peer fingerprint as a hex string**:
```
<hex>.peer.one-link.local
```

Example: `1a2b3c4d5e6f...32-bytes-hex.peer.one-link.local`.

This serves two purposes:
1. The connecting peer announces "I think I'm talking to peer X" up-front — useful for server-side routing if a future ship runs multiple peer identities on one process.
2. Provides the verifier with the expected fingerprint without out-of-band coordination at the TLS layer.

The SNI is informational. The verifier independently confirms the cert's subject pubkey matches the fingerprint we passed in via API.

### Custom certificate verifier

```rust
pub struct IdentityBoundVerifier {
    expected_fingerprint: [u8; 32], // BLAKE3 of peer's Ed25519 pubkey
}

impl rustls::client::ServerCertVerifier for IdentityBoundVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // 1. Parse the cert just enough to extract SubjectPublicKeyInfo.
        let cert = parse_x509(end_entity)?;
        let spki = cert.subject_public_key_info();

        // 2. Verify the algorithm is Ed25519 (curve25519, OID 1.3.101.112).
        if spki.algorithm() != ED25519_OID {
            return Err(rustls::Error::General("non-Ed25519 cert".into()));
        }

        // 3. Compute BLAKE3 of the raw subject_public_key bits.
        let pubkey_bytes = spki.subject_public_key_bytes();
        let computed_fp = blake3::hash(pubkey_bytes);

        // 4. Constant-time compare against the expected fingerprint.
        if !constant_time_eq(&computed_fp, &self.expected_fingerprint) {
            return Err(rustls::Error::General("peer fingerprint mismatch".into()));
        }

        // 5. Verify the cert's self-signature using the same pubkey
        //    (proves the cert wasn't manufactured by someone with a stolen
        //    identity key but no signing key — i.e., the holder of the key
        //    that signed the cert IS the holder of the key in the cert).
        cert.verify_self_signature()?;

        Ok(ServerCertVerified::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
```

The same verifier shape applies for `ClientCertVerifier` (mTLS). QUIC connections are mutually authenticated — both ends present a cert and both ends verify the other.

### Fingerprint derivation

```
peer_fingerprint = BLAKE3.hash(peer.identity_pubkey_raw_32_bytes)
```

This is the same fingerprint used everywhere else in One Link (peer pairing, capability tickets per ADR-0006). No new derivation function.

### Pairing flow

1. Two peers pair out-of-band (existing `pairing.py` flow over QR + SAS).
2. Each peer learns the other's fingerprint and stores it in the peer registry.
3. When opening a QUIC connection, the dialer constructs an `IdentityBoundVerifier` with the expected fingerprint and a `rustls::ClientConfig` that uses it.
4. Server side, the listener uses an `IdentityBoundClientCertVerifier` configured to accept any cert in the registry — i.e., it looks up the presented cert's fingerprint and accepts iff it matches a known paired peer.

## Consequences

**Positive:**
- Zero CA dependency. Every peer cert is self-issued.
- Zero expiry maintenance. Certs are valid forever.
- Defends against the "stolen pubkey but no signing key" attack: a cert presented by someone who has the public key but not the private signing key would fail self-signature verification.
- TLS 1.3 channel binding: rustls binds the symmetric session keys to the cert's pubkey, so a successful TLS handshake confirms the peer holds the corresponding private key.
- Constant-time fingerprint compare prevents the timing side-channel that would otherwise leak partial fingerprint matches.

**Negative:**
- Non-standard from a PKI-tools perspective: tools like `openssl s_client` will refuse to connect because they don't have the verifier. This is fine — only One Link daemons ever connect.
- Browser-as-peer (Phase A1's WebRTC path) cannot do this — browsers force WebPKI cert chains. That's why WebRTC stays for browser↔daemon. Daemon↔daemon uses QUIC + ADR-0010.
- If an attacker steals BOTH the identity key AND the cert, they impersonate the peer until the user revokes. Mitigation: capability-layer revocation (ADR-0008 / Phase C) puts identity keys behind the OS keystore and supports key rotation.

## Verification

1. **Fingerprint round-trip**: Generate cert from identity key K; extract subject pubkey from cert; assert `BLAKE3(extracted_pubkey) == BLAKE3(K.public_bytes())`.
2. **Self-signature verifies**: Generated cert passes its own self-signature check (sanity).
3. **Wrong-fingerprint rejection**: Verifier configured with fingerprint A receives cert generated for identity B. TLS handshake fails. `ChunkRequest` payload never reaches the server.
4. **Algorithm-spoof rejection**: A cert with valid pubkey-bits but RSA algorithm OID is rejected by the verifier (we only accept Ed25519).
5. **Constant-time compare**: Manual audit of the verifier's compare path; no early-return on byte mismatch.
6. **No CA dependency**: The build pipeline contains no CA roots. `cargo build` does not network. The runtime never reaches out for OCSP / CRL.

## References

- RFC 8446 (TLS 1.3): https://datatracker.ietf.org/doc/html/rfc8446
- rustls custom verifier API: https://docs.rs/rustls/latest/rustls/client/danger/trait.ServerCertVerifier.html
- rcgen self-signed cert generation: https://docs.rs/rcgen/
- WireGuard's static-pubkey-bound transport: https://www.wireguard.com/papers/wireguard.pdf §5
- Iroh's NodeId-bound TLS: https://github.com/n0-computer/iroh/blob/main/iroh-net/src/tls.rs
- BLAKE3 keyed-hash for fingerprints: ADR-0006.
