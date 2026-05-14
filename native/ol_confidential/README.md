# `ol_confidential` — Row 10 of the Coherence Mesh

**Confidential-compute daemon.** Where hardware supports it, the
daemon runs (or at minimum the key-handling subsystem runs) inside a
hardware-attested enclave. Even local malware can't extract identity
keys.

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
So:

- A peer that pins only the master VK still gets tamper detection
  on the platform_quote (master sig fails if quote is swapped).
- A peer that ALSO validates the platform_quote gets a
  hardware-bound chain (this doc was minted on the specific TPM).

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
| `Software` | ChaCha20-Poly1305 sealing under per-process ephemeral key, Zeroize on drop | ✓ shipped |
| `WindowsTpm` | NCrypt Platform Crypto Provider, ECDSA-P256 in the TPM, user-mode, no admin | ✓ shipped (this crate, `windows-tpm` feature) |
| `AppleSecureEnclave` | `security-framework` crate | future ship |
| `AndroidStrongBox` | Android KeyStore + StrongBox attestation | future ship |
| `IntelSgx` | `fortanix-sgx` | future ship |
| `AmdSevSnp` | `sev-snp-tools` | future ship |
| `ArmTrustZone` | OP-TEE TA | future ship |

## Threat coverage

| Threat | Software | WindowsTpm |
|---|:-:|:-:|
| T-LOCAL-MAL-USER (user-mode malware grabs key from process memory) | ✓ | ✓ |
| T-REMOTE-IMPERSONATE (replay attestation across challenges) | ✓ | ✓ |
| T-REMOTE-IMPERSONATE-PHYSICAL (replay attestation across hosts) | ✓ via field witness | ✓ via TPM identity binding |
| T-LOCAL-MAL-ROOT (root malware reads /proc/mem, kernel debugger) | ✗ | ✓ for platform_quote ECDSA key; ✗ for master PQ-hybrid (TPM can't sign PQ) |

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
use ol_confidential::windows_tpm::{TpmAttestationKey, attest_with_tpm, verify_attestation_with_tpm};

let tpm = TpmAttestationKey::acquire_or_create("OL-confidential-attestation-v1")?;
let doc = attest_with_tpm(&provider, &sealed, &tpm, nonce, now_unix, now_unix + 30, None)?;
let tpm_pub = verify_attestation_with_tpm(&doc, &nonce, None, peer_now)?;  // returns TPM pub-blob for pinning
```

See `BENCH_RESULTS.md` for performance numbers and `docs/formal/confidential_attestation.tla` for the design-time TLA+ spec.
