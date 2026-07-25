# Coherence Mesh Native Bench Results — archived aggregate

> Historical source-tree snapshot from one Windows host. These numbers are
> not current packaged-platform, release, security, or production evidence;
> rerun the pinned benchmark and release gates on the artifact being judged.

One-pager covering every native crate that's been brought to the
F1.x audit-closeout polish bar. Numbers captured on Windows 11
Intel host (Alex's box), `cargo bench --release` against
`0.21.0-alpha.0`.

## Row 1 — `ol_pqsig` (PQ-hybrid signatures)

See [`ol_pqsig/BENCH_RESULTS.md`](ol_pqsig/BENCH_RESULTS.md).

| Benchmark                  | Time    | Throughput              |
|---                         |---      |---                      |
| `pqsig::generate_keypair`  | 177 µs  | ~5,650 keys/sec         |
| `pqsig::sign`              | 594 µs  | ~1,680 sigs/sec         |
| `pqsig::verify`            | 53 µs   | ~18,800 verifies/sec    |

Verify path is constant-time uniform across tamper position (always
runs both Ed25519 + ML-DSA halves). 30% relative-stddev ct gate.

## Row 3 — `ol_discovery` (sovereign Kademlia DHT)

See [`ol_discovery/BENCH_RESULTS.md`](ol_discovery/BENCH_RESULTS.md).

| Benchmark                                | Time      | Notes                          |
|---                                       |---        |---                             |
| `routing::synthetic_id_for_bucket_mid`   |  7.0 ns   | bucket-refresh hot path        |
| `routing::stale_buckets_n_512`           |  140 ns   | maintenance scan, 512 entries  |
| `routing::closest_to_n_64`               | 1.54 µs   | 64-peer table sort             |
| `record::canonical_bytes`                | 32.9 ns   | length-prefixed encoder        |
| `record::sign`                           | 11.7 µs   | Ed25519 sign                   |
| `record::verify`                         | 26.1 µs   | Ed25519 verify                 |

Maintenance-loop bug fix shipped alongside the polish:
`synthetic_id_for_bucket(k)` was flipping bit (255-k) instead of bit
k — caught by the new `synthetic_id_round_trip` proptest. Without
the fix, `refresh_stale_buckets` was issuing FIND_NODE refreshes
against the wrong bucket. Pinned via proptest-regressions seed.

## Row 6 — `ol_onion::sphinx::cover` (cover traffic)

See [`ol_onion/COVER_BENCH_RESULTS.md`](ol_onion/COVER_BENCH_RESULTS.md).

| Benchmark                                  | Time      | Notes                          |
|---                                         |---        |---                             |
| `cover::is_cover_payload_true/false`       | ~400 ps   | sentinel-check (per call)      |
| `cover::scheduler_next_wait_ms`            | 73.3 ns   | BLAKE3 keystream + Exp(λ)      |
| `cover::rate_equalizer_observe_emit`       | 3.6 ns    | EWMA update                    |
| `cover::rate_equalizer_current_cover_rate` | 195 ps    | trivial subtract               |
| `cover::build_cover_packet_3_hop`          | 159 µs    | 3-hop Sphinx + sentinel        |

The cover primitive uses the same Sphinx encoded length and packet machinery
as an equally shaped real packet. The benchmark does not test timing, volume,
route, real-traffic shaping, mixing, or observer classification and therefore
does not establish wire-traffic indistinguishability or anonymity.

## Row 7 — `ol_onion::transport_obfs` (pluggable transport)

See [`ol_onion/TRANSPORT_OBFS_BENCH_RESULTS.md`](ol_onion/TRANSPORT_OBFS_BENCH_RESULTS.md).

| Benchmark                               | Time      | Throughput            |
|---                                      |---        |---                    |
| `obfs::derive_nonce`                    | 1.3 ns    | ~770M nonces/sec      |
| `obfs::obfuscate_1500` (MTU)            | 635 ns    | ~2.4 GB/s             |
| `obfs::obfuscate_65536`                 | 19.1 µs   | ~3.4 GB/s             |
| `obfs::session_seal_outbound_1500`      | 635 ns    | ~2.4 GB/s             |
| `obfs::handshake_full_round_trip`       | 92.2 µs   | ~11 K conns/sec       |

obfs4-style handshake with bridge-ID HMAC + 1-epoch skew tolerance;
ct-gate at 15% relative stddev on MAC verify path. TLA+ spec at
`docs/formal/ObfsHandshake.tla` proves NoCrossBridgeReplay /
NoOutOfEpochAccept / NoUnauthBypass / SessionAgreementOnHonestRun.

## Row 9 — `ol_threshold_recovery` (wired path)

See [`ol_threshold_recovery/WIRED_BENCH_RESULTS.md`](ol_threshold_recovery/WIRED_BENCH_RESULTS.md).

For a 32-byte master seed at (k=3, n=5), 100 iterations:

| Operation        | Native    | Pure-Python | Speedup        |
|---               |---        |---          |---             |
| `split_compat`   | 0.37 ms   | 4.33 ms     | **11.8 ×**     |
| `combine_compat` | 0.19 ms   | 4.88 ms     | **25.5 ×**     |

CI gate: `tests/unit/test_threshold_recovery_native_vs_python.py`
fails if the speedup ratio drops below 2× on either operation, so
silent regressions to the pure-Python fallback would be caught at
test time.

## Reproduction

```text
# Row 1
cargo bench -p ol_pqsig

# Row 3
cargo bench -p ol_discovery --bench discovery_bench

# Row 6
cargo bench -p ol_onion --bench cover_bench

# Row 7
cargo bench -p ol_onion --bench transport_obfs_bench

# Row 9 (Python-level)
python -m pytest tests/unit/test_threshold_recovery_native_vs_python.py -s
```

## Test surface added in this polish pass

| Row | Crate                  | New tests added | Files added                      |
|---  |---                     |---:             |---                               |
| 1   | ol_pqsig               | 10 + 5 + 1      | property + KAT + ct-gate         |
| 3   | ol_discovery           | 7 + 5           | property_maintenance + KAT       |
| 6   | ol_onion::cover        | 11 + 5          | property_cover + KAT             |
| 7   | ol_onion::transport_obfs | 12+2 + 5 + 12 + 1 | property + KAT + adversarial + ct |
| 9   | ol_threshold_recovery (wired) | 23            | native-vs-python                 |

Fuzz targets added: 4 (pqsig_verify, cover_sentinel,
obfs_handshake_accept, obfs_primitive). Picked up by the nightly
cargo-fuzz CI.

TLA+ specs added: 1 (`ObfsHandshake.tla` + `.cfg`).
