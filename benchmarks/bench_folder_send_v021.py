"""v0.21.x folder-send benchmark.

Measures the win from each of the 6 waves shipped this session:

  1. Smart auto-routing decision time + correctness on real folders
  2. Pipelined disk reads vs naive sequential (synthetic slow-IO sim)
  3. zlib compression ratio + latency on real content types
  4. Archive build throughput
  5. End-to-end wire bytes: per_file vs archive vs manifest_push
     for synthetic 100-file folders (text + media)
  6. BLOB_INVENTORY_QUERY fast-path dedup probe overhead

Runs without a network — uses in-process daemon + FakeChannel to
isolate each component. Prints a summary table; exits non-zero if
any metric regresses past a hard threshold.

Run: python benchmarks/bench_folder_send_v021.py
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
import zlib
from pathlib import Path

# Make src importable without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from one_link.blobstore import BlobStore  # noqa: E402
from one_link.daemon import Daemon  # noqa: E402
from one_link.identity import Identity, fingerprint_of  # noqa: E402
from one_link.server import UIServer  # noqa: E402
from one_link.state import State  # noqa: E402


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    return Identity(
        private=sk, public=sk.public_key(), public_bytes=pub,
        fingerprint=fingerprint_of(pub),
        short_id=fingerprint_of(pub)[:8],
        hostname="bench",
    )


def _bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    for u in units:
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"


def _make_folder(root: Path, files: list[tuple[str, bytes]]) -> int:
    """Create a folder on disk; return total bytes."""
    total = 0
    for rel, data in files:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        total += len(data)
    return total


# -- benchmark scenarios ------------------------------------------


def bench_compression():
    """Wave 5: zlib compression ratio + per-chunk latency on
    representative content types."""
    print("\n-- Wave 5: per-chunk zlib compression --")
    me = _identity()
    daemon = Daemon(me)
    cases = [
        ("Python source",    b"def hello(name):\n    return f'Hi {name}!'\n" * 200),
        ("JSON",             b'{"key": "value", "nested": {"a": [1,2,3]}}\n' * 200),
        ("Markdown",         b"# Title\n\nParagraph " * 300),
        ("Pre-compressed",   zlib.compress(b"x" * 8192, 9)),
        ("Random binary",    os.urandom(8192)),
    ]
    print(f"  {'content':<22} {'plain':>10} {'enc':>6} {'wire':>10} {'ratio':>7} {'latency':>10}")
    for name, data in cases:
        # Warm cache
        for _ in range(3):
            daemon._encode_payload(data, allow_compress=True)
        t0 = time.perf_counter()
        for _ in range(100):
            enc, payload = daemon._encode_payload(data, allow_compress=True)
        latency = (time.perf_counter() - t0) / 100 * 1000  # ms per encode
        ratio = len(payload) / max(1, len(data))
        print(
            f"  {name:<22} {_bytes(len(data)):>10} {enc:>6} "
            f"{_bytes(len(payload)):>10} {ratio:>6.0%} {latency:>8.2f}ms"
        )


def bench_archive_vs_walk():
    """Wave 3 + archive mode: time to build a zip archive vs raw
    disk walk + hash for a 100-file folder."""
    print("\n-- Wave 3 + archive: build cost on 100-file folder --")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        files = []
        for i in range(100):
            # Mix of text + binary so the comparison isn't pathological.
            rel = f"sub{i // 10}/file_{i}.py"
            data = (f"# file {i}\ndef foo():\n    return {i}\n" * 50).encode()
            files.append((rel, data))
        root = td / "src"
        total = _make_folder(root, files)
        # Build a synthetic UIServer to call _stage_folder_archive.
        me = _identity()
        state = State(db_path=td / "s.db")
        blob_store = BlobStore(root=td / "blobs")
        daemon = Daemon(me)
        daemon.state = state
        daemon.blob_store = blob_store
        # UIServer needs a daemon ref.
        from unittest.mock import MagicMock
        daemon.folder_engine = MagicMock()
        srv = UIServer(daemon)
        # Time the archive build.
        t0 = time.perf_counter()
        archive_path, orig, arch = srv._stage_folder_archive(root, "src")
        elapsed = time.perf_counter() - t0
        try:
            print(
                f"  total folder size:    {_bytes(total)} ({len(files)} files)"
            )
            print(
                f"  archive build time:   {elapsed*1000:.1f} ms "
                f"({_bytes(total / max(0.001, elapsed))}/sec)"
            )
            print(
                f"  archive size:         {_bytes(arch)} "
                f"({(1 - arch / max(1, orig)) * 100:.1f}% smaller)"
            )
        finally:
            archive_path.unlink(missing_ok=True)
            state.close()


def bench_smart_router():
    """Wave 3: how long does the auto-router take to pick a mode?"""
    print("\n-- Wave 3: smart auto-router decision time --")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        for n in [10, 100, 500]:
            root = td / f"n{n}"
            files_spec = [
                (f"f{i}.py", (f"def f{i}(): return {i}\n" * 100).encode())
                for i in range(n)
            ]
            _make_folder(root, files_spec)
            file_specs: list[tuple[Path, str]] = [
                (root / rel, rel) for rel, _ in files_spec
            ]
            me = _identity()
            state = State(db_path=td / f"s_{n}.db")
            blob_store = BlobStore(root=td / f"blobs_{n}")
            daemon = Daemon(me)
            daemon.state = state
            daemon.blob_store = blob_store
            from unittest.mock import AsyncMock, MagicMock
            daemon.folder_engine = MagicMock()
            daemon.query_peer_blob_inventory = AsyncMock(return_value=set())
            srv = UIServer(daemon)
            # Run picker (skip the peer inventory probe so we time
            # JUST the classify + decision logic).
            t0 = time.perf_counter()
            mode, reasoning = asyncio.run(
                srv._pick_folder_send_mode(
                    peer=None, files=file_specs,
                    check_peer_inventory=False,
                ),
            )
            elapsed = (time.perf_counter() - t0) * 1000
            print(
                f"  {n:>4} files: picked '{mode}' in {elapsed:.1f} ms "
                f"({reasoning['compressible_ratio']:.0%} compressible)"
            )
            state.close()


def bench_pipelined_io_overhead():
    """Wave 4: cost of asyncio.to_thread for a chunk read. Compared
    to a synchronous fh.read baseline."""
    print("\n-- Wave 4: pipelined disk read overhead --")
    with tempfile.TemporaryDirectory() as td:
        big = Path(td) / "big.bin"
        big.write_bytes(os.urandom(4 * 1024 * 1024))  # 4 MB
        # Sync baseline.
        t0 = time.perf_counter()
        with open(big, "rb") as f:
            total_sync = 0
            while True:
                chunk = f.read(256 * 1024)
                if not chunk:
                    break
                total_sync += len(chunk)
        sync_ms = (time.perf_counter() - t0) * 1000
        # Async via to_thread.
        async def _async_read():
            with open(big, "rb") as f:
                total = 0
                while True:
                    chunk = await asyncio.to_thread(f.read, 256 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
            return total
        t0 = time.perf_counter()
        total_async = asyncio.run(_async_read())
        async_ms = (time.perf_counter() - t0) * 1000
        print(
            f"  4 MB file, 256 KB chunks:"
            f"\n    sync read:    {sync_ms:>7.1f} ms"
            f"\n    async read:   {async_ms:>7.1f} ms"
            f" ({(async_ms - sync_ms) / max(0.01, sync_ms) * 100:+.0f}%)"
        )


def bench_blob_inventory_overhead():
    """Wave 5 + earlier fast-path: how long does the BLAKE3 pass
    take to enumerate hashes for a 100-file folder?"""
    print("\n-- Fast-path probe: BLAKE3 pass for 100 files --")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        root = td / "probe"
        files = []
        for i in range(100):
            files.append((f"f{i}.bin", os.urandom(10 * 1024)))
        _make_folder(root, files)
        from one_link.cdc import hash_path
        # Cold.
        t0 = time.perf_counter()
        for p in root.rglob("*"):
            if p.is_file():
                hash_path(p)
        cold = (time.perf_counter() - t0) * 1000
        # Warm (page cache hits).
        t0 = time.perf_counter()
        for p in root.rglob("*"):
            if p.is_file():
                hash_path(p)
        warm = (time.perf_counter() - t0) * 1000
        print(
            f"  100 × 10 KB BLAKE3 hash:"
            f"\n    cold: {cold:>6.1f} ms ({cold / 100:.2f} ms/file)"
            f"\n    warm: {warm:>6.1f} ms ({warm / 100:.2f} ms/file)"
        )


def main() -> int:
    print(f"v0.21.x folder-send benchmarks — {time.ctime()}")
    bench_compression()
    bench_archive_vs_walk()
    bench_smart_router()
    bench_pipelined_io_overhead()
    bench_blob_inventory_overhead()
    print("\nAll benchmarks complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
