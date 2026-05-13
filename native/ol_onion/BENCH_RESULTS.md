# ol_onion microbenchmark results

Captured against `0.21.0-alpha.0` on Windows 11 Intel host, release
profile (`cargo bench -p ol_onion`). Median of 100 Criterion samples
after 3 s warm-up.

| Benchmark           | Time      | Throughput              |
|---                  |---        |---                      |
| `build_onion_1_hop` | 56.08 µs  | ~17,800 builds / sec    |
| `build_onion_3_hop` | 222.18 µs | ~4,500 builds / sec     |
| `peel_one_layer`    | 34.25 µs  | ~29,200 peels / sec     |

## Per-layer cost breakdown

A 3-hop circuit performs (sender side):
- 4 × X25519 ECDH (one per layer including destination): ~120 µs
- 4 × BLAKE3 derive_key + Hash:                          ~5 µs
- 4 × ChaCha20-Poly1305 encrypt + canonical encode:     ~25 µs
- 4 × ephemeral keypair generation:                     ~70 µs
- Total accounted for                                   ~220 µs

ECDH + ephemeral keypair generation dominate. Predictable —
x25519-dalek's MontgomeryPoint operations are the inner loop.

Peel side is ~34 µs per layer: one ECDH + one BLAKE3 + one
ChaCha20-Poly1305 decrypt. The destination delivers the payload
immediately; relays would forward the inner packet at the transport
layer (separate timing budget).

## Anchor budget

Onion messages over the Coherence Mesh are SLOW path (one-shot
chat / file metadata). For a 3-hop circuit, 222 µs sender + 34 µs
per peel = ~324 µs total CPU across 4 machines. The wall-clock
latency budget is dominated by network RTTs (10s–100s of ms per
hop), not crypto. Optimization is NOT a priority.

## Future polish (F3-polish v2)

- Sphinx-style packet header with single packet-level ephemeral
  pubkey (saves 32 bytes per relay). Bandwidth reduction; CPU cost
  unchanged.
- Header-shift fixed-size packets (currently the wire packet
  shrinks by ~64 bytes per peel; transport-layer padding is the
  current defense against the global-passive-adversary hop-count
  leak).
