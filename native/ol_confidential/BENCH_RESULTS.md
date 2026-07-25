# `ol_confidential` primitive microbenchmarks (historical)

> These timings are one source-host snapshot. They do not prove daemon
> wiring, same-user-malware resistance, remote TPM residency, side-channel
> security, or current packaged-release behavior.

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

## Windows Microsoft Platform Crypto Provider path (measured host)

`cargo bench -p ol_confidential --features windows-tpm --bench windows_tpm_bench`.

Same Win11 host as above, talking to the local TPM 2.0 via the
Microsoft Platform Crypto Provider in user mode (no admin required).

| Benchmark                                       | Time     | Notes                                             |
|---                                              |---       |---                                                |
| `confidential::tpm_public_blob_export`          | 21 µs    | NCryptExportKey, cached metadata round trip       |
| `confidential::tpm_ecdsa_p256_sign`             | 35 ms    | TPM-internal ECDSA-P256 sign over a 32 B digest   |
| `confidential::tpm_platform_quote_produce`      | 34 ms    | public_blob + sign + wire-format envelope         |

The measured provider call was roughly 100× slower than software ECDSA on
that host. This timing and local provider selection are not remote hardware-
provenance evidence; the current wire envelope has no EK/vendor chain.

## What this measured for these primitives

- **Measured seal cost**: 1.19 µs for this input/host. Product boot and key-
  lifecycle cost require an end-to-end packaged measurement.
- **Child derivation under 3 µs**: per-day ratchet across 365 days
  totals < 1 ms even if recomputed on every cold boot.
- **Sealed sign matches Row 1 sign cost (~250 µs)** with the ~100 µs
  extra for unseal + keygen + zeroize.
- **Envelope signature verification measured ~60 µs**; this verifies the
  signed bytes, not a vendor hardware root by itself.
- **The PCP platform-key signature call measured ~35 ms** on this host.
  Daemons should
  issue at most a few attestations per peer per session, not per
  message.

## Repro

```text
cargo bench -p ol_confidential --bench confidential_bench
```
