# `ol_confidential` (Row 10 — confidential-compute daemon) microbenchmarks

Captured against `0.21.0-alpha.0` on Windows 11 Intel host, release
profile (`cargo bench -p ol_confidential --bench confidential_bench`).

## Numbers

| Benchmark                            | Time     | Notes                                             |
|---                                   |---       |---                                                |
| `confidential::seal_master`          | 1.21 µs  | ChaCha20-Poly1305 encrypt of 32 B + 12 B nonce    |
| `confidential::derive_child`         | 2.53 µs  | unseal master + BLAKE3-keyed derive + reseal      |
| `confidential::sealed_sign`          | 359 µs   | unseal + Ed25519 sign + ML-DSA-65 sign + zeroize  |
| `confidential::attest_issue`         | 859 µs   | sealed_sign cost on the attestation transcript    |
| `confidential::attest_verify`        | 60 µs    | hybrid sig verify + transcript rebuild            |

## What this means for the daemon

- **Sealed master at rest is free**: 1.21 µs. Boot can seal at process
  start and the cost is invisible.
- **Child derivation under 3 µs**: per-day ratchet across 365 days
  totals < 1 ms even if recomputed on every cold boot.
- **Sealed sign matches Row 1 sign cost (~260 µs)** with the ~100 µs
  extra for unseal + zeroize.
- **Attestation verify cost = single hybrid verify (~50 µs) + 10 µs
  transcript rebuild**. A peer can re-verify on every reconnect
  without breaking a sweat.
- **Attestation issue ≈ 2× sealed_sign** (unseal hits twice — once for
  the `verifying_key()` lookup, once for the actual sign). A future
  micro-optimisation caches the unsealed key for the duration of the
  attest call.

## Repro

```text
cargo bench -p ol_confidential --bench confidential_bench
```
