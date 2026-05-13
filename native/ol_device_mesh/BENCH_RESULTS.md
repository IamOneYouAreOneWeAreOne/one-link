# ol_device_mesh (Row 8 Layer 1) microbenchmark results

Captured against `0.21.0-alpha.0` on Windows 11 Intel host, release
profile (`cargo bench -p ol_device_mesh --bench device_mesh_bench`).

## Final numbers

| Benchmark                                       | Time     | Notes                            |
|---                                              |---       |---                               |
| `device_mesh::derive_subkey_seed`               | 221 ns   | BLAKE3-keyed HKDF, 64-byte out   |
| `device_mesh::derive_field_bound_subkey_seed`   | 352 ns   | + field-witness XOR mask         |
| `device_mesh::ratchet_one_day`                  | 238 ns   | one-way step + zeroize prev      |
| `device_mesh::master_pin_handle`                | 1.6 µs   | BLAKE3 over master VK            |
| `device_mesh::software_wrapper_wrap_64`         | 326 ns   | BLAKE3 keystream + MAC           |
| `device_mesh::software_wrapper_unwrap_64`       | 330 ns   | MAC verify + keystream           |
| `device_mesh::liveness_proof_verify`            | 53.2 µs  | hybrid signature verify          |
| `device_mesh::mint_subkey`                      | 433 µs   | derive seed + master signs vk    |
| `device_mesh::liveness_proof_issue`             | 688 µs   | subkey signs transcript          |

## What this means for the daemon

- **Subkey derivation is free**: 221 ns. Re-deriving any historical
  day on the master takes microseconds for a 365-day chain.
- **Field binding costs ~130 ns extra**: the OTP mask is one BLAKE3
  XOF expansion, then byte-XOR. Negligible.
- **Ratchet step is free**: 238 ns. The daemon advances at midnight
  local time; runtime cost is well under any scheduling jitter.
- **Master pin handle is fast enough for UI**: 1.6 µs. The friend's
  app can re-derive the pin handle on every render without it being
  measurable.
- **Hardware-wrap round-trip is ~330 ns per direction**: cold-storage
  + load happens once per device boot. Even a daemon that boots 100
  times a day pays only microseconds total.
- **Mint + attestation is ~430 µs**: this is the master signing a
  fresh subkey. Once per device pair, period.
- **Liveness verify is ~53 µs**: same cost as a single PQ-hybrid
  signature verify (row 1). At a 60-second heartbeat across 10
  siblings, total verify cost is ~530 µs per minute.
- **Liveness issue is ~688 µs**: dominated by the ML-DSA sign cost,
  same as row 1's `pqsig::sign`. Each device pays this once per
  heartbeat interval.

## Repro

```text
cargo bench -p ol_device_mesh --bench device_mesh_bench
```
