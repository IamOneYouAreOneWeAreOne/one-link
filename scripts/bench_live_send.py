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
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args()

    temp_dir: tempfile.TemporaryDirectory[str] | None = None
    if args.path:
        path = args.path.resolve()
        if not path.is_file():
            raise SystemExit(f"no file: {path}")
    else:
        temp_dir = tempfile.TemporaryDirectory(prefix="ol_live_bench_")
        path = Path(temp_dir.name) / f"bench-{args.size_mib}MiB.bin"
        if not args.json:
            print(f"Generating {args.size_mib} MiB at {path} ...")
        _make_file(path, args.size_mib * 1024 * 1024, seed=args.seed)

    try:
        size = path.stat().st_size
        rows: list[dict[str, object]] = []
        if not args.json:
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
                failure = {
                    "run": i + 1,
                    "ok": False,
                    "elapsed_s": round(elapsed, 6),
                    "error": res.get("error"),
                }
                rows.append(failure)
                if args.json:
                    print(json.dumps({"ok": False, "runs": rows}, indent=2))
                else:
                    print(f"run {i + 1}: failed after {elapsed:.2f}s: {res.get('error')}")
                return 2
            result = res.get("result") or {}
            raw_value = result.get("raw_bytes_sent")
            wire_value = result.get("wire_bytes_sent")
            raw = int(raw_value if raw_value is not None else size)
            wire = int(wire_value if wire_value is not None else raw)
            skipped = int(result.get("cdc_skipped") or 0)
            effective = size
            report = result.get("transfer_report") or {}
            row = {
                "run": i + 1,
                "ok": True,
                "elapsed_s": round(elapsed, 6),
                "effective_mbps": round(_mbps(effective, elapsed), 3),
                "raw_mbps": round(_mbps(raw, elapsed), 3),
                "wire_mbps": round(_mbps(wire, elapsed), 3),
                "cdc": bool(result.get("cdc")),
                "chunks": int(result.get("chunks") or 0),
                "total_chunks": int(result.get("total_chunks") or 0),
                "skipped_chunks": skipped,
                "saved_bytes": int(report.get("saved_bytes") or max(0, effective - wire)),
                "bandwidth_savings_ratio": float(report.get("bandwidth_savings_ratio") or 0.0),
                "engine_oracle": result.get("transfer_engine_oracle") or {},
            }
            rows.append(row)
            if not args.json:
                print(
                    "run {run}: {seconds:.2f}s effective={effective:.1f} Mbps "
                    "raw={raw:.1f} Mbps wire={wire:.1f} Mbps cdc={cdc} "
                    "chunks={chunks}/{total_chunks} skipped_chunks={skipped} "
                    "saved={saved:.1f} MiB".format(
                        run=i + 1,
                        seconds=elapsed,
                        effective=row["effective_mbps"],
                        raw=row["raw_mbps"],
                        wire=row["wire_mbps"],
                        cdc=row["cdc"],
                        chunks=row["chunks"],
                        total_chunks=row["total_chunks"],
                        skipped=row["skipped_chunks"],
                        saved=row["saved_bytes"] / (1024 * 1024),
                    )
                )
        ok_rows = [r for r in rows if r.get("ok")]
        summary = {
            "ok": True,
            "peer": args.peer,
            "file": str(path),
            "size_bytes": size,
            "runs": rows,
            "best_effective_mbps": max((float(r["effective_mbps"]) for r in ok_rows), default=0.0),
            "best_wire_mbps": max((float(r["wire_mbps"]) for r in ok_rows), default=0.0),
            "total_saved_bytes": sum(int(r.get("saved_bytes") or 0) for r in ok_rows),
        }
        if args.json:
            print(json.dumps(summary, indent=2, sort_keys=True))
        elif len(ok_rows) > 1:
            print(
                "summary: best effective={:.1f} Mbps, total saved={:.1f} MiB".format(
                    summary["best_effective_mbps"],
                    summary["total_saved_bytes"] / (1024 * 1024),
                )
            )
        return 0
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
