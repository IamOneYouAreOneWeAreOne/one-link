# ol_threshold_recovery wired-path bench results

Captured against `0.21.0-alpha.0` on Windows 11 Intel host, Python 3.14.

`tests/unit/test_threshold_recovery_native_vs_python.py` enforces:
1. Round-trip correctness against parameter sweep (11 (secret_len, k, n)
   triples × 20 random secrets each).
2. Cross-implementation interop (native split ↔ Python combine, and
   vice versa).
3. Speedup gate: native path is ≥2× faster than pure-Python on a
   32-byte secret at (k=3, n=5). Test fails CI if regression drops
   the ratio below 2×.

## Captured numbers

For a 32-byte master seed at (k=3, n=5), 100 iterations:

| Operation        | Native      | Pure-Python | Speedup        |
|---               |---          |---          |---             |
| `split_compat`   | 0.37 ms     | 4.33 ms     | **11.8 ×**     |
| `combine_compat` | 0.19 ms     | 4.88 ms     | **25.5 ×**     |

## What this means for the daemon

Social-recovery wrap-shares for the master seed costs ~4 µs per share
in the native path vs ~43 µs per share in pure-Python. For a 3-of-5
recovery (the default), that's:

- Native: ~2 µs split + ~2 µs combine = under 5 µs of crypto.
- Pure-Python fallback: ~22 µs split + ~50 µs combine = ~70 µs.

Both are sub-millisecond — the wiring isn't load-bearing for latency.
The speedup matters when many seeds get split (e.g., capability
escrow at high fanout) and as a CI canary: if a future change drops
the native path below 2×, something has regressed.

## Repro

```text
python -m pytest tests/unit/test_threshold_recovery_native_vs_python.py -s
```
