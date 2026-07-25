# `ol_confidential` — Row 10 confidential-operation primitives

> **Capability boundary:** this crate supplies sealed-blob, signed-envelope,
> and optional Windows PCP-key primitives. It does not place the daemon or
> master identity inside an enclave, does not make the software provider safe
> from same-user process inspection, and does not provide a vendor/EK
> attestation chain proving remote TPM residency. The live daemon must report
> its own wiring and tier; crate presence is not confidential-compute proof.

## Layered model

```
                        ┌────────────────────────────────────┐
                        │       AttestationDoc (PQ-hybrid)   │
                        │  master_sig over canonical bytes   │
                        └──────────┬─────────────────────────┘
                                   │ commits to →
                                   ▼
                        ┌────────────────────────────────────┐
                        │      platform_quote (per-tag)      │
                        ├────────────────────────────────────┤
                        │ Software baseline:  empty bytes    │
                        │ WindowsTpm:         ECDSA-P256 sig │
                        │                     by TPM-resident│
                        │                     attestation key│
                        │ AppleSecureEnclave: future ship    │
                        │ IntelSgx / SEV-SNP: future ship    │
                        └────────────────────────────────────┘
```

The master hybrid signature (Ed25519 + ML-DSA-65) covers the FULL
canonical transcript, which includes the `platform_quote` bytes.
So, within this envelope protocol:

- A peer that pins only the master VK still gets tamper detection
  on the platform_quote (master sig fails if quote is swapped).
- A peer that validates the platform signature proves possession of the
  included ECDSA private key. The current envelope contains no TPM EK/vendor
  certificate or standard TPM quote, so a remote peer cannot infer hardware
  residency merely from that self-contained key/signature. Pinning the public
  blob can establish continuity for later documents.

## Tiers

```rust
pub enum ConfidentialTier {
    Software,         // production baseline
    HardwareBound,    // key in TPM / Secure Enclave / StrongBox
    HardwareAttested, // + vendor-issued attestation chain
}
```

## Backends

| Tag | Backend | Status |
|---|---|---|
| `Software` | ChaCha20-Poly1305 sealing under a key in the same process | Implemented primitive; at-rest/process-lifetime boundary only |
| `WindowsTpm` | NCrypt Platform Crypto Provider ECDSA-P256 attestation-key path | Feature-gated primitive; no vendor/EK chain, master seal/sign remain software, physical/package qualification required |
| `AppleSecureEnclave` | `security-framework` crate | future ship |
| `AndroidStrongBox` | Android KeyStore + StrongBox attestation | future ship |
| `IntelSgx` | `fortanix-sgx` | future ship |
| `AmdSevSnp` | `sev-snp-tools` | future ship |
| `ArmTrustZone` | OP-TEE TA | future ship |

## Threat coverage

| Threat/property | Software | Windows PCP-key path |
|---|---|---|
| Plaintext at rest outside the live provider process | AEAD sealed blob, subject to caller/key-lifecycle correctness | Same software master-key boundary |
| Same-user malware able to inspect/inject into the daemon process | **Not defeated** | **Not defeated for the master key/sign path** |
| Replay of a document against a fresh independent challenge | Nonce/deadline checks reject a stale transcript when the challenge channel is authentic | Same, plus platform-key signature continuity |
| Proof that two parties supplied the same field bytes | Signed commitment equality only; not physical-host attestation | Same |
| Remote proof that the signing key is TPM-resident | None | **Not provided by the current self-contained public blob/signature; needs an authenticated EK/vendor attestation chain** |
| Root/kernel/cold-boot compromise of master material | **Not defeated** | **Not defeated; only the platform ECDSA attestation key is requested through PCP** |

## Quickstart

```rust
use ol_confidential::{SoftwareProvider, ConfidentialProvider, fresh_attestation_nonce, verify_attestation};
use rand::rngs::OsRng;

let provider = SoftwareProvider::generate(&mut OsRng);
let seed = [0x42u8; 32];  // your master seed
let sealed = provider.seal_master(&seed)?;
let nonce = fresh_attestation_nonce(&mut OsRng);
let doc = provider.attest(&sealed, nonce, now_unix, now_unix + 30, None)?;
// Send `doc` to peer; peer calls verify_attestation(&doc, &nonce, None, peer_now).
```

With Windows TPM:

```rust
#[cfg(all(target_os = "windows", feature = "windows-tpm"))]
use ol_confidential::windows_tpm::{
    attest_with_tpm, verify_attestation_with_tpm, TpmAttestationClaims,
    TpmAttestationKey,
};

let tpm = TpmAttestationKey::acquire_or_create("OL-confidential-attestation-v1")?;
let issuer_sdp_pubkey = [0u8; ISSUER_SDP_PUBKEY_LEN];
let doc = attest_with_tpm(
    &provider,
    &sealed,
    &tpm,
    TpmAttestationClaims {
        peer_nonce: nonce,
        issued_unix: now_unix,
        deadline_unix: now_unix + 30,
        field_witness: None,
        issuer_sdp_pubkey,
    },
)?;
let tpm_pub = verify_attestation_with_tpm(
    &doc,
    &nonce,
    None,
    peer_now,
    ConfidentialTier::HardwareBound,
    &issuer_sdp_pubkey,
)?; // returns TPM pub-blob for pinning
```

See `BENCH_RESULTS.md` for historical performance measurements and
`docs/formal/confidential_attestation.tla` for an abstract design-time model.
Neither is a runtime hardware-attestation or security certification.
