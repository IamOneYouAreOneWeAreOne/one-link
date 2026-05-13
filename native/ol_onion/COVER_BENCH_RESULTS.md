# ol_onion::sphinx::cover (Row 6) microbenchmark results

Captured against `0.21.0-alpha.0` on Windows 11 Intel host, release
profile (`cargo bench -p ol_onion --bench cover_bench`).

## Final numbers

| Benchmark                                  | Time      | Notes                              |
|---                                         |---        |---                                 |
| `cover::is_cover_payload_true`             | 401 ps    | length-check + 8-byte slice compare|
| `cover::is_cover_payload_false`            | 406 ps    | same path, branch differs          |
| `cover::scheduler_next_wait_ms`            | 73.3 ns   | BLAKE3 keystream + Exp(λ) sample   |
| `cover::rate_equalizer_observe_emit`       | 3.6 ns    | EWMA update on real-emit           |
| `cover::rate_equalizer_current_cover_rate` | 195 ps    | trivial subtract + max(0)          |
| `cover::build_cover_packet_1_hop`          | 66.5 µs   | 1-hop Sphinx onion + sentinel      |
| `cover::build_cover_packet_3_hop`          | 159 µs    | 3-hop Sphinx onion + sentinel      |

## What this means for the daemon

- **Sentinel check is free**: 400 ps per call. The daemon can run
  `is_cover_payload` on every delivered payload without measurable
  overhead.
- **Scheduler is fast**: 73 ns per Exp(λ) sample. At λ=5 Hz (200 ms
  mean wait) the scheduler costs ~5 ns/sec — negligible.
- **Rate equalizer is fast enough**: 3.6 ns per `observe_real_emission`,
  195 ps per `current_cover_rate()`. The daemon can update + query
  hundreds of thousands of times per second.
- **Build cost matches real Sphinx packets**: 66 µs / 1-hop and
  159 µs / 3-hop. Cover packets cost the same as real packets to
  build — by design, since they ARE real Sphinx packets with a
  sentinel payload.

## Repro

```text
cargo bench -p ol_onion --bench cover_bench
```
