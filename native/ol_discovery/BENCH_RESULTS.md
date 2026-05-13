# ol_discovery microbenchmark results

Captured against `0.21.0-alpha.0` on Windows 11 Intel host, release
profile (`cargo bench -p ol_discovery`). Median of Criterion samples
after warm-up.

## Final numbers

| Benchmark                              | Time      | Notes                          |
|---                                     |---        |---                             |
| `node_id::distance`                    | ~ns       | 32-byte XOR + copy             |
| `record::canonical_bytes` (2 endpoints)| 32.9 ns   | length-prefixed encoder        |
| `routing::insert_into_empty`           | 39.1 ns   | first peer in a bucket         |
| `routing::insert_into_populated_100`   | 28.3 ns   | replace-or-bump hot path       |
| `routing::synthetic_id_for_bucket(128)`|  7.0 ns   | bucket-refresh hot path        |
| `routing::stale_buckets_n_512`         |  140 ns   | maintenance scan, 512 entries  |
| `routing::closest_to_n_16`             |  344 ns   | sort over 16-peer table        |
| `routing::closest_to_n_64`             | 1.54 µs   | 64-peer table                  |
| `routing::closest_to_n_256`            | 2.64 µs   | 256-peer table                 |
| `routing::closest_to_n_1024`           | 3.80 µs   | 1024-peer table                |
| `record::sign`                         | 11.7 µs   | Ed25519 sign                   |
| `record::verify`                       | 26.1 µs   | Ed25519 verify                 |

## What this lets the daemon do

The hot maintenance path (`tick_maintenance` on a 1-minute timer):
- `stale_buckets(now, max_age)` scans the table in ~140 ns per 512-bucket
  pass; for 256 fully-populated buckets the scan is microseconds, not
  milliseconds.
- Each issued refresh lookup picks a `synthetic_id_for_bucket(i)` in
  7 ns. Even refreshing all 256 buckets in one tick is < 2 µs of
  CPU before any network I/O.
- Republishing one record costs one Ed25519 sign (~12 µs) plus the
  STORE network send. Republishing the full TTL window of records is
  CPU-bound on the network, not on the crypto.

## Why `synthetic_id_for_bucket` exists at all

After the May-2026 `synthetic_id_for_bucket` correctness fix (it was
flipping the LSB-numbered bit instead of the MSB-numbered bit), the
function now actually lands the synthetic ID in the requested bucket.
Caught by the `synthetic_id_round_trip` proptest. Without the fix,
`refresh_stale_buckets` was issuing FIND_NODE refresh lookups against
the wrong bucket — silently degrading the maintenance loop's value.

## Repro

```text
cargo bench -p ol_discovery --bench discovery_bench
```
