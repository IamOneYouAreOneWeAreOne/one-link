#!/usr/bin/env python3
"""Phase A1 ingest-throughput measurement harness.

Per ``docs/FILE_ENGINE_V2_PLAN.md``:

    End-to-end ingest throughput: >= 1 GiB/s on Linux NVMe

The plan gate is on Linux NVMe; this script runs on any platform but
the gate-passing threshold is **only meaningful on Linux NVMe**. On
Windows/NTFS the achievable throughput caps at ~400-500 MiB/s (which
this script will report honestly).

Drives the chunk-store ingest pipeline through synthetic data and
reports GiB/s through the CDC + BLAKE3 + WAL + index path.

Usage:
    python scripts/ingest_throughput_harness.py [--bytes 1G] [--out report.json]

Exit code 0 if achieved throughput >= plan threshold, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
import time
from pathlib import Path
from typing import Any


PLAN_THRESHOLD_BYTES_PER_SEC = 1.0 * (1 << 30)  # 1 GiB/s


def _require_native():
    try:
        from one_link_native import chunk, store

        return chunk, store
    except ImportError as e:
        raise RuntimeError(
            "one_link_native.chunk + .store not installed; build via "
            "`cd native && maturin develop --release --locked`"
        ) from e


def parse_size(s: str) -> int:
    """Accept '1G' / '512M' / '100K' or plain bytes."""
    s = s.strip().upper()
    mults = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}
    if s and s[-1] in mults:
        return int(float(s[:-1]) * mults[s[-1]])
    return int(s)


def gen_data(n_bytes: int, *, seed: int = 0) -> bytes:
    """Generate deterministic, incompressible bytes outside the timed path.

    BLAKE3's XOF is implemented in native code and avoids a Python loop that
    used to make a 1 GiB benchmark spend minutes preparing its input. The
    XOF output is suitable benchmark material; it is not used as a secret.
    """
    from blake3 import blake3

    seed_bytes = int(seed or 0xCAFEBABE).to_bytes(16, "little", signed=False)
    return blake3(seed_bytes).digest(length=n_bytes)


def run_ingest(target_bytes: int, store_dir: Path, quiet: bool = False) -> dict[str, Any]:
    chunk_mod, store_mod = _require_native()
    # Generate the data outside the timing window.
    data = gen_data(target_bytes)
    actual_bytes = len(data)

    # Create a fresh chunk store and exercise CDC + BLAKE3 addressing + WAL
    # append + in-memory index + a durable flush. Older versions stopped the
    # timer immediately after CDC yet labeled that number "end-to-end ingest";
    # that was a misleading performance gate and missed storage regressions.
    store_dir.mkdir(parents=True, exist_ok=True)
    store = store_mod.open_store(str(store_dir))
    ingest_t0 = time.perf_counter_ns()
    cdc_t0 = time.perf_counter_ns()
    boundaries = list(chunk_mod.cdc_iter(data))
    cdc_ns = time.perf_counter_ns() - cdc_t0

    ratchet_key_id = b"\x00" * 16
    try:
        for boundary in boundaries:
            plaintext = data[boundary.start : boundary.end]
            # Model the frame-tag overhead written by the transfer AEAD. The
            # cryptographic primitive has its own benchmark; this harness is
            # specifically the durable ingest/storage gate.
            tag_bytes = chunk_mod.frame_count(len(plaintext)) * 16
            ciphertext = plaintext + (b"\x00" * tag_bytes)
            store.append_chunk(
                "blob",
                "raw",
                "aes",
                boundary.raw_address,
                ratchet_key_id,
                len(plaintext),
                ciphertext,
            )
        store.flush()
        store_stats = dict(store.stats())
    finally:
        store.close()
    total_ns = time.perf_counter_ns() - ingest_t0

    cdc_throughput = actual_bytes / (cdc_ns / 1e9) if cdc_ns > 0 else float("inf")

    total_throughput = actual_bytes / (total_ns / 1e9) if total_ns > 0 else float("inf")
    report = {
        "platform": platform.platform(),
        "actual_bytes": actual_bytes,
        "chunk_count": len(boundaries),
        "cdc_ns": cdc_ns,
        "cdc_throughput_bytes_per_sec": cdc_throughput,
        "cdc_throughput_gib_per_sec": cdc_throughput / (1 << 30),
        "total_ns": total_ns,
        "store_stats": store_stats,
        "total_throughput_bytes_per_sec": total_throughput,
        "total_throughput_gib_per_sec": total_throughput / (1 << 30),
        "plan_threshold_gib_per_sec": PLAN_THRESHOLD_BYTES_PER_SEC / (1 << 30),
        "gate_passed": total_throughput >= PLAN_THRESHOLD_BYTES_PER_SEC,
        "gate_meaningful": "linux" in platform.system().lower(),
    }
    if not quiet:
        print("=== Phase A1 ingest harness ===")
        print(f"Platform: {report['platform']}")
        print(f"Bytes ingested: {actual_bytes:,}")
        print(f"Chunks produced: {report['chunk_count']:,}")
        print()
        print(
            f"CDC throughput: {cdc_throughput / 1e9:.2f} GB/s "
            f"= {report['cdc_throughput_gib_per_sec']:.2f} GiB/s"
        )
        print(
            f"Durable ingest: {total_throughput / 1e9:.2f} GB/s "
            f"= {report['total_throughput_gib_per_sec']:.2f} GiB/s"
        )
        if not report["gate_meaningful"]:
            print(
                f"NOTE: Plan gate (>= 1 GiB/s) is calibrated for Linux NVMe. "
                f"On {platform.system()}, achievable ceiling is much lower; "
                "the gate-passed bit is informational only off-Linux."
            )
        print(f"Gate (>= 1 GiB/s): {'PASS' if report['gate_passed'] else 'FAIL'}")
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bytes", default="256M",
                   help="Bytes to ingest (e.g. '1G', '256M'). Default: 256M.")
    p.add_argument("--store-dir", type=Path, default=None,
                   help="Working directory for the chunk store (default: tmp).")
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    n_bytes = parse_size(args.bytes)
    cleanup_store = args.store_dir is None
    if cleanup_store:
        import tempfile

        args.store_dir = Path(tempfile.mkdtemp(prefix="ol_ingest_"))

    try:
        report = run_ingest(n_bytes, args.store_dir, quiet=args.quiet)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    finally:
        if cleanup_store:
            shutil.rmtree(args.store_dir, ignore_errors=True)
    if args.out is not None:
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    # On Linux, exit non-zero if gate fails. Off-Linux, exit 0
    # regardless (the gate isn't calibrated for this platform).
    if report["gate_meaningful"]:
        return 0 if report["gate_passed"] else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
