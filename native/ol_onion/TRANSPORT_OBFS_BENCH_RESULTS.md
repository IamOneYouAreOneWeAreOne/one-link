# ol_onion::transport_obfs (Row 7) microbenchmark results

Captured against `0.21.0-alpha.0` on Windows 11 Intel host, release
profile (`cargo bench -p ol_onion --bench transport_obfs_bench`).

## Final numbers

| Benchmark                              | Time      | Throughput            |
|---                                     |---        |---                    |
| `obfs::derive_nonce`                   | 1.3 ns    | ~770 M nonces / sec   |
| `obfs::obfuscate_64`                   | 105 ns    | ~600 MB/s             |
| `obfs::obfuscate_512`                  | 184 ns    | ~2.8 GB/s             |
| `obfs::obfuscate_1500`                 | 635 ns    | ~2.4 GB/s             |
| `obfs::obfuscate_65536`                | 19.1 µs   | ~3.4 GB/s             |
| `obfs::deobfuscate_1500`               | 635 ns    | ~2.4 GB/s             |
| `obfs::session_seal_outbound_1500`     | 635 ns    | ~2.4 GB/s             |
| `obfs::handshake_client_start`         | 10.8 µs   | ~92 K starts / sec    |
| `obfs::handshake_server_accept`        | 45.0 µs   | ~22 K accepts / sec   |
| `obfs::handshake_full_round_trip`      | 92.2 µs   | ~11 K conns / sec     |

## What this means for the daemon

- **Bulk-cipher throughput**: 2.4 GB/s on 1500-byte MTU packets, rising
  to 3.4 GB/s on 64K writes. Saturates any practical network link.
- **Per-packet cost is bounded**: 635 ns for a 1500-byte packet means
  ~1.5M packets/sec/core before the obfs layer becomes a bottleneck.
- **Handshake is the slow part** (as expected — X25519 + BLAKE3 + KDF):
  ~92 µs for a full client-start → server-accept → client-finish.
  ~11K connections/sec/core; a daemon doing 1 handshake/sec/peer can
  support thousands of concurrent bridge peers.
- **Nonce derivation is free**: 1.3 ns — fits in the L1 hot loop.

## Why the handshake costs ~90 µs

Both `start` and `finish` do one X25519 scalarmul (~20-30 µs each).
Accept does two X25519 scalarmuls (one ephemeral generation, one
DH). The remainder is BLAKE3 keyed hashes for the MAC and KDF (each
~hundreds of ns).

## Repro

```text
cargo bench -p ol_onion --bench transport_obfs_bench
```
