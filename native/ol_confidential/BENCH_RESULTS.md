# `ol_confidential` (Row 10 — confidential-compute daemon) microbenchmarks

Captured against `0.21.0-alpha.0` on Windows 11 Intel host, release
profile (`cargo bench -p ol_confidential --bench confidential_bench`).

## Software baseline

| Benchmark                            | Time     | Notes                                             |
|---                                   |---       |---                                                |
| `confidential::seal_master`          | 1.19 µs  | ChaCha20-Poly1305 encrypt of 32 B + 12 B nonce    |
| `confidential::derive_child`         | 2.53 µs  | unseal master + BLAKE3-keyed derive + reseal      |
| `confidential::sealed_sign`          | 362 µs   | unseal + Ed25519 sign + ML-DSA-65 sign + zeroize  |
| `confidential::attest_issue`         | 894 µs   | single-unseal pair-derive + sign over 2 KB doc transcript |
| `confidential::attest_verify`        | 60 µs    | hybrid sig verify + transcript rebuild            |

## Real-hardware Windows TPM (NCrypt PCP)

`cargo bench -p ol_confidential --features windows-tpm --bench windows_tpm_bench`.

Same Win11 host as above, talking to the local TPM 2.0 via the
Microsoft Platform Crypto Provider in user mode (no admin required).

| Benchmark                                       | Time     | Notes                                             |
|---                                              |---       |---                                                |
| `confidential::tpm_public_blob_export`          | 21 µs    | NCryptExportKey, cached metadata round trip       |
| `confidential::tpm_ecdsa_p256_sign`             | 35 ms    | TPM-internal ECDSA-P256 sign over a 32 B digest   |
| `confidential::tpm_platform_quote_produce`      | 34 ms    | public_blob + sign + wire-format envelope         |

The TPM sign is ~100× slower than software ECDSA on the same host —
that's the price of holding the key inside the chip with kernel-
gated access. The numbers are bounded by the TPM's TIS bus speed,
not the curve math.

## What this means for the daemon

- **Sealed master at rest is free**: 1.19 µs. Boot can seal at process
  start and the cost is invisible.
- **Child derivation under 3 µs**: per-day ratchet across 365 days
  totals < 1 ms even if recomputed on every cold boot.
- **Sealed sign matches Row 1 sign cost (~250 µs)** with the ~100 µs
  extra for unseal + keygen + zeroize.
- **Attestation verify cost = single hybrid verify (~50 µs) + 10 µs
  transcript rebuild**. A peer can re-verify on every reconnect
  without breaking a sweat.
- **TPM-rooted attestation costs ~35 ms** dominated by the TPM ECDSA
  sign. The TPM is on a slow bus; this is normal. Daemons should
  issue at most a few attestations per peer per session, not per
  message.

## Repro

```text
cargo bench -p ol_confidential --bench confidential_bench
```
