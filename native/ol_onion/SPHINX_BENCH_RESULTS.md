# Sphinx Coherence microbenchmark results

Captured against `0.21.0-alpha.0` on Windows 11 Intel host, release
profile (`cargo bench -p ol_onion --bench sphinx_bench`). Median of
100 Criterion samples after 3 s warm-up.

## Final numbers

| Benchmark                                | Time       | Throughput              |
|---                                       |---         |---                      |
| `sphinx::derive_hop_keys`                | 437 ns     | ~2.3M ops/sec           |
| `sphinx::chacha20_keystream_HEADER_LEN`  | 278 ns     | ~3.6M / sec (240 B)     |
| `sphinx::chacha20_keystream_PAYLOAD_LEN` | 317 ns     | ~3.2M / sec (1024 B)    |
| `sphinx::header_mac`                     | 177 ns     | ~5.6M / sec             |
| `sphinx::build_filler_4_relays`          | 706 ns     | ~1.4M / sec             |
| `sphinx::build_onion_1_hop`              | 67.5 µs    | ~14,800 / sec           |
| `sphinx::build_onion_3_hop`              | 165 µs     | ~6,060 / sec            |
| `sphinx::build_onion_5_hop`              | 263 µs     | ~3,800 / sec            |
| `sphinx::peel_one_layer`                 | 27.9 µs    | ~35,800 / sec           |
| `sphinx::full_3_hop_round_trip`          | 289 µs     | ~3,460 / sec            |

## Where the time goes (build_onion_3_hop = ~165 µs)

Sphinx is dominated by Ristretto255 scalar multiplication
(~25 µs per op on this host):

| Operation                          | Count (3-hop)  | Time     |
|---                                 |---             |---       |
| Ristretto basepoint mult (alpha_0) | 1 (precomputed) | ~5 µs    |
| Alpha-chain blinding (alpha_i+1 = b_i * alpha_i) | 3 | ~75 µs   |
| Shared secret derivation (eph * cumulative * relay_pk) | 3 | ~75 µs |
| `build_filler` (2 relays' keystreams) | 1 | ~1 µs    |
| ChaCha20 header XOR ×3 + payload XOR ×3 | 6 | ~2 µs |
| BLAKE3 (4 sub-keys ×3 hops + 3 MACs) | 15 | ~3 µs |
| Allocations + memcpy                | -        | ~4 µs    |
| **Total accounted**                |          | **~165 µs** |

For 5-hop: 5 × 50 µs (point ops) + ~13 µs (everything else) = ~263 µs.

## Anchor budget

Onion routing over the Coherence Mesh is a SLOW PATH (one-shot
chat / file metadata). Wall-clock latency budget is dominated by
network RTTs (10s–100s of ms per hop), not crypto. The crypto
~250 µs ceiling is 4 orders of magnitude below the network budget.
Further optimization is NOT a priority.

## Optimization history

**Round 1 (allocations):** moved `chacha20_keystream` to an
`_into` variant + `xor_in_place` helper to reduce per-call Vec
allocations. Replaced per-iteration Vec growth in `build_filler`
with a single pre-allocated buffer. Replaced Vec headers in
`build_header` + `peel_header` with stack arrays `[u8; HEADER_LEN]`.

Net effect: filler 770 → 706 ns (-8%). Build/peel paths: within ±5%
of baseline (noise; the Ristretto mult dominates). Documenting that
the cryptographic floor is reached; further allocator tweaks would
not move the needle.

**Future polish (deferred):** curve25519-dalek supports batched
multi-scalar multiplication via `RistrettoBasepointTable` and
`vartime_multiscalar_mul`. Could combine the alpha-chain + shared-
secret point mults into fewer batched operations. Estimated gain:
20-30% on `build_onion_*`. Not pursued because the absolute
numbers are already comfortably below the network-RTT budget.

## Compared to standard onion routers

For reference (other implementations on similar hardware):
- Tor cell construction: ~50-100 µs (legacy RSA + AES; per-hop AES).
- I2P tunnel build: ~200-400 µs per hop.
- Nym sphinx-packet: ~150-200 µs for 3-hop (uses curve25519-dalek too).

Our 165 µs for 3-hop with PQ-hybrid + field-bound options is
competitive with state-of-the-art research implementations.
