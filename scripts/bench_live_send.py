"""Benchmark a real One Link daemon send against a paired device.

This measures the production control path, not a synthetic loop. It is meant
for two-machine tuning:

    python scripts/bench_live_send.py Computer2 --size-mib 512 --repeat 2

The second repeat is the important one for One Link's "prior knowledge" path:
if the receiver already has chunks, effective throughput should rise while
wire bytes fall.
"""

from __future__ import annotations

import argparse
import json
import random
import socket
import tempfile
import time
from pathlib import Path

from one_link import daemon as daemon_mod


def _request(cmd: str, *, timeout: float = 3600.0, **kwargs) -> dict:
    port = daemon_mod.read_control_port()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(("127.0.0.1", port))
        sock.sendall((json.dumps({"cmd": cmd, **kwargs}) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.decode("utf-8").strip() or "{}")
    finally:
        sock.close()


def _mbps(nbytes: int, seconds: float) -> float:
    return (float(nbytes) * 8.0) / max(0.001, seconds) / 1_000_000.0


def _make_file(path: Path, size: int, *, seed: int) -> None:
    rng = random.Random(seed)
    block = bytearray(1024 * 1024)
    remaining = int(size)
    with path.open("wb") as f:
        while remaining > 0:
            n = min(len(block), remaining)
            block[:n] = rng.randbytes(n)
            f.write(block[:n])
            remaining -= n


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("peer", help="Paired peer short id, hostname, or display name")
    parser.add_argument("--path", type=Path, help="Existing file to send")
    parser.add_argument("--size-mib", type=int, default=128, help="Generated file size")
    parser.add_argument("--repeat", type=int, default=2, help="Send count")
    parser.add_argument("--seed", type=int, default=20260508)
    args = parser.parse_args()

    temp_dir: tempfile.TemporaryDirectory[str] | None = None
    if args.path:
        path = args.path.resolve()
        if not path.is_file():
            raise SystemExit(f"no file: {path}")
    else:
        temp_dir = tempfile.TemporaryDirectory(prefix="ol_live_bench_")
        path = Path(temp_dir.name) / f"bench-{args.size_mib}MiB.bin"
        print(f"Generating {args.size_mib} MiB at {path} ...")
        _make_file(path, args.size_mib * 1024 * 1024, seed=args.seed)

    try:
        size = path.stat().st_size
        print(f"One Link live send benchmark: peer={args.peer} file={path.name} size={size}")
        for i in range(max(1, int(args.repeat))):
            t0 = time.perf_counter()
            res = _request(
                "send_file",
                timeout=max(300.0, min(7200.0, size / (256 * 1024))),
                peer=args.peer,
                path=str(path),
            )
            elapsed = time.perf_counter() - t0
            if not res.get("ok"):
                print(f"run {i + 1}: failed after {elapsed:.2f}s: {res.get('error')}")
                return 2
            result = res.get("result") or {}
            raw_value = result.get("raw_bytes_sent")
            wire_value = result.get("wire_bytes_sent")
            raw = int(raw_value if raw_value is not None else size)
            wire = int(wire_value if wire_value is not None else raw)
            skipped = int(result.get("cdc_skipped") or 0)
            effective = size
            print(
                "run {run}: {seconds:.2f}s effective={effective:.1f} Mbps "
                "raw={raw:.1f} Mbps wire={wire:.1f} Mbps cdc={cdc} "
                "chunks={chunks}/{total_chunks} skipped_chunks={skipped}".format(
                    run=i + 1,
                    seconds=elapsed,
                    effective=_mbps(effective, elapsed),
                    raw=_mbps(raw, elapsed),
                    wire=_mbps(wire, elapsed),
                    cdc=bool(result.get("cdc")),
                    chunks=int(result.get("chunks") or 0),
                    total_chunks=int(result.get("total_chunks") or 0),
                    skipped=skipped,
                )
            )
        return 0
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
