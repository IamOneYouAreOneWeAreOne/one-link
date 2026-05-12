# ol_pair_qr microbenchmark results

Captured against `0.21.0-alpha.0` on Windows 11, Intel host, release
profile (`cargo bench -p ol_pair_qr`). Numbers are median of 100
samples after 3s warm-up via Criterion default config.

Reproduce: `cargo bench -p ol_pair_qr`. CI gate considers a >15%
regression vs. these numbers a failure (manually tracked; not yet
automated).

| Benchmark                  | Time         | Throughput           |
|---                         |---           |---                   |
| `pair_full_roundtrip`      | 222.03 µs    | ~4,500 pairs / sec   |
| `invite_decode_and_verify` |  25.46 µs    | ~39,000 decodes/sec  |
| `sas_derive`               |  62.30 ns    | ~16,000,000 SAS/sec  |

## Breakdown — `pair_full_roundtrip` (222 µs total)

The full roundtrip performs, per pair:

- 3 × `ed25519::Signer::sign`              (~3 × 15 µs ≈ 45 µs)
- 3 × `ed25519::Verifier::verify`          (~3 × 25 µs ≈ 75 µs)
- 2 × X25519 ECDH `diffie_hellman`         (~2 × 30 µs ≈ 60 µs)
- 2 × `BLAKE3` hash (transcript + chain key) (~5 µs)
- Canon encode / decode of 3 frames        (~1 µs)
- SAS derive                                 (~0.06 µs)
- Total accounted for                        ≈ 186 µs
- Residual (allocator, rand, drop)           ≈ 36 µs

Ed25519 verify dominates. Acceptable for the pair-by-QR use case
(cold path, called once per new contact). No batch-verification
optimisation has been applied; the cold-path nature means it
wouldn't help in practice.

## Anchor budget

The pair-by-QR flow has a human-in-the-loop SAS-compare step that
takes 3–5 seconds. The Rust crypto path adds ~222 µs to that — five
orders of magnitude below the wall-clock budget. Optimization is
NOT a priority for this layer.
