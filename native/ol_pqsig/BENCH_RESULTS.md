# ol_pqsig microbenchmark results

Captured against `0.21.0-alpha.0` on Windows 11 Intel host, release
profile (`cargo bench -p ol_pqsig`). Median of 100 Criterion samples
after 3 s warm-up.

## Final numbers

| Benchmark                | Time       | Throughput              |
|---                       |---         |---                      |
| `pqsig::generate_keypair`| 177 µs     | ~5,650 keys / sec       |
| `pqsig::sign`            | 594 µs     | ~1,680 sigs / sec       |
| `pqsig::verify`          | 53 µs      | ~18,800 verifies / sec  |

## Why verify is the fastest path

`verify` does Ed25519 verify (~25 µs) + ML-DSA verify (~25-30 µs).
Both ALWAYS run — no short-circuit on Ed25519-fail — to keep the
verify path constant-time-uniform across tamper position (see
`tests/constant_time_gate.rs`).

## Why sign is the slowest path

`sign` reconstructs the ML-DSA `ExpandedSigningKey` from the 32-byte
seed on every call (~150 µs NTT + matrix expansion), then signs
(~400 µs). For master-identity workloads (rare ops), this is fine.

If we ever need high-rate signing, the API could cache the expanded
key — but the master identity should sign at most a few times per
session.

## Anchor budget

Master identity signing in One Link covers:
- Pair-by-QR capability commits (~per new contact, rare).
- Social-recovery share commits (~once at setup).
- Capability-root delegations (~per app-grant, rare).

All sub-second wall-clock. The ~0.6 ms per sign / ~50 µs per verify
budget is far below any user-visible threshold.
