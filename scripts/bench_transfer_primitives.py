"""Micro-benchmarks for One Link transfer primitives.

This is intentionally dependency-free and deterministic. It is not a lab-grade
network benchmark; it catches obvious regressions in CDC indexing, Merkle drift
walking, and compression decisions before they land in the daemon path.
"""

from __future__ import annotations

import random
import tempfile
import time
import zlib
from pathlib import Path

from one_link.cdc import build_dedup_plan, index_path
from one_link.merkle import build_tree, divergent_leaf_indexes, hash_leaf


def _mb_per_s(nbytes: int, seconds: float) -> float:
    return (nbytes / (1024 * 1024)) / max(seconds, 1e-9)


def main() -> int:
    rng = random.Random(20260505)
    with tempfile.TemporaryDirectory(prefix="ol_bench_") as td:
        root = Path(td)
        base = root / "base.bin"
        changed = root / "changed.bin"
        payload = rng.randbytes(8 * 1024 * 1024)
        base.write_bytes(payload)
        changed.write_bytes(b"prefix" + payload + b"tail")
        base_size = base.stat().st_size
        changed_size = changed.stat().st_size

        t0 = time.perf_counter()
        base_index = index_path(base)
        t1 = time.perf_counter()
        changed_index = index_path(changed)
        t2 = time.perf_counter()
        plan = build_dedup_plan(changed_index.chunks, {c.hash for c in base_index.chunks})
        t3 = time.perf_counter()

        leaves = [hash_leaf(f"row-{i}") for i in range(8192)]
        other = list(leaves)
        other[4097] = hash_leaf("changed")
        mt0 = time.perf_counter()
        diff = divergent_leaf_indexes(build_tree(leaves), build_tree(other))
        mt1 = time.perf_counter()

        easy = b"compress-me\n" * 200_000
        z0 = time.perf_counter()
        packed = zlib.compress(easy, level=1)
        z1 = time.perf_counter()

    print("One Link transfer primitive benchmark")
    print(f"  CDC base index:    {_mb_per_s(base_size, t1 - t0):8.1f} MiB/s")
    print(f"  CDC changed index: {_mb_per_s(changed_size, t2 - t1):8.1f} MiB/s")
    print(f"  CDC dedup hit:     {plan.hit_rate * 100:8.1f}%")
    print(f"  CDC bytes skipped: {plan.byte_savings:8d}")
    print(f"  Merkle diff leaves:{diff}")
    print(f"  Merkle diff time:  {(mt1 - mt0) * 1000:8.2f} ms")
    print(f"  zlib level1 ratio: {len(packed) / len(easy):8.3f}")
    print(f"  zlib throughput:   {_mb_per_s(len(easy), z1 - z0):8.1f} MiB/s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
