"""Live two-device production gate for One Link.

This script intentionally talks to the real local daemon over the control
socket. It is not a synthetic benchmark: the peer must be up, paired, and
reachable on the LAN/rendezvous route.

Example:
    python scripts/live_soak_gate.py fc9f0a5f --sizes-mib 1,16,64 --repeat 2
"""

from __future__ import annotations

import argparse
import json
import random
import socket
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from one_link import daemon as daemon_mod


RESULTS_DIR = Path("benchmarks") / "results"


@dataclass(frozen=True)
class Thresholds:
    min_fresh_mbps: float
    min_repeat_effective_mbps: float
    min_repeat_savings_ratio: float


def _request(cmd: str, *, timeout: float = 3600.0, **kwargs: Any) -> dict[str, Any]:
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


def _parse_sizes(value: str) -> list[int]:
    sizes: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        n = int(part)
        if n <= 0:
            raise argparse.ArgumentTypeError("sizes must be positive MiB values")
        sizes.append(n)
    if not sizes:
        raise argparse.ArgumentTypeError("at least one size is required")
    return sizes


def _find_peer(peer: str, peers_payload: dict[str, Any]) -> dict[str, Any] | None:
    needle = peer.lower()
    for p in peers_payload.get("peers") or []:
        values = [
            str(p.get("short_id") or ""),
            str(p.get("hostname") or ""),
            str(p.get("display_name") or ""),
            str(p.get("alias") or ""),
            str(p.get("fingerprint") or ""),
        ]
        if any(v.lower() == needle or needle in v.lower() for v in values if v):
            return dict(p)
    return None


def _send_file(peer: str, path: Path, *, timeout: float) -> tuple[dict[str, Any], float]:
    t0 = time.perf_counter()
    res = _request("send_file", timeout=timeout, peer=peer, path=str(path))
    return res, time.perf_counter() - t0


def _row_from_send(
    *,
    size_bytes: int,
    size_mib: int,
    run: int,
    response: dict[str, Any],
    elapsed_s: float,
) -> dict[str, Any]:
    if not response.get("ok"):
        return {
            "ok": False,
            "size_mib": size_mib,
            "run": run,
            "elapsed_s": round(elapsed_s, 6),
            "error": response.get("error") or response.get("detail") or "send failed",
        }
    result = response.get("result") or {}
    report = result.get("transfer_report") or {}
    raw = int(result.get("raw_bytes_sent") or 0)
    wire = int(result.get("wire_bytes_sent") or raw)
    saved = int(report.get("saved_bytes") or max(0, size_bytes - wire))
    savings = float(report.get("bandwidth_savings_ratio") or (saved / max(1, size_bytes)))
    return {
        "ok": True,
        "size_mib": size_mib,
        "run": run,
        "elapsed_s": round(elapsed_s, 6),
        "effective_mbps": round(_mbps(size_bytes, elapsed_s), 3),
        "raw_mbps": round(_mbps(raw, elapsed_s), 3),
        "wire_mbps": round(_mbps(wire, elapsed_s), 3),
        "raw_bytes_sent": raw,
        "wire_bytes_sent": wire,
        "saved_bytes": saved,
        "bandwidth_savings_ratio": round(savings, 6),
        "cdc": bool(result.get("cdc")),
        "chunks": int(result.get("chunks") or 0),
        "total_chunks": int(result.get("total_chunks") or 0),
        "skipped_chunks": int(result.get("cdc_skipped") or 0),
        "transfer_id": result.get("transfer_id"),
        "performance_summary": result.get("performance_summary") or {},
    }


def _evaluate(rows: list[dict[str, Any]], thresholds: Thresholds) -> list[str]:
    failures: list[str] = []
    for row in rows:
        label = f"{row.get('size_mib')}MiB run {row.get('run')}"
        if not row.get("ok"):
            failures.append(f"{label}: {row.get('error')}")
            continue
        run = int(row.get("run") or 0)
        size_mib = int(row.get("size_mib") or 0)
        throughput_gate_applies = size_mib >= 4
        if (
            run == 1
            and throughput_gate_applies
            and float(row.get("effective_mbps") or 0.0) < thresholds.min_fresh_mbps
        ):
            failures.append(
                f"{label}: fresh send below {thresholds.min_fresh_mbps} Mbps "
                f"({row.get('effective_mbps')} Mbps)"
            )
        if run >= 2:
            if (
                throughput_gate_applies
                and float(row.get("effective_mbps") or 0.0)
                < thresholds.min_repeat_effective_mbps
            ):
                failures.append(
                    f"{label}: repeat effective below "
                    f"{thresholds.min_repeat_effective_mbps} Mbps "
                    f"({row.get('effective_mbps')} Mbps)"
                )
            if float(row.get("bandwidth_savings_ratio") or 0.0) < thresholds.min_repeat_savings_ratio:
                failures.append(
                    f"{label}: repeat savings below "
                    f"{thresholds.min_repeat_savings_ratio:.0%} "
                    f"({row.get('bandwidth_savings_ratio')})"
                )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("peer", help="Peer short id, hostname, display name, or fingerprint")
    parser.add_argument("--sizes-mib", type=_parse_sizes, default=[1, 16, 64])
    parser.add_argument("--repeat", type=int, default=2)
    parser.add_argument("--seed", type=int, default=20260512)
    parser.add_argument("--wait-peer-s", type=float, default=20.0)
    parser.add_argument("--min-fresh-mbps", type=float, default=25.0)
    parser.add_argument("--min-repeat-effective-mbps", type=float, default=250.0)
    parser.add_argument("--min-repeat-savings-ratio", type=float, default=0.90)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    thresholds = Thresholds(
        min_fresh_mbps=float(args.min_fresh_mbps),
        min_repeat_effective_mbps=float(args.min_repeat_effective_mbps),
        min_repeat_savings_ratio=float(args.min_repeat_savings_ratio),
    )
    started = time.time()
    peer_snapshot: dict[str, Any] | None = None
    peer_payload: dict[str, Any] = {}
    while time.time() - started <= float(args.wait_peer_s):
        peer_payload = _request("peers", timeout=10.0)
        peer_snapshot = _find_peer(args.peer, peer_payload)
        if peer_snapshot is not None:
            break
        time.sleep(1.0)
    if peer_snapshot is None:
        print(f"FAIL: peer {args.peer!r} not visible after {args.wait_peer_s:.1f}s")
        return 2

    chat_text = f"One Link live soak probe {int(time.time())}"
    chat = _request("send", timeout=30.0, peer=args.peer, body=chat_text)
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="ol_live_soak_") as td:
        root = Path(td)
        for idx, size_mib in enumerate(args.sizes_mib):
            size = int(size_mib) * 1024 * 1024
            path = root / f"soak-{size_mib}MiB-{args.seed + idx}.bin"
            _make_file(path, size, seed=int(args.seed) + idx)
            if not args.json:
                print(f"file {path.name}: {size_mib} MiB")
            for run in range(1, max(1, int(args.repeat)) + 1):
                response, elapsed = _send_file(
                    args.peer,
                    path,
                    timeout=max(300.0, min(7200.0, size / (128 * 1024))),
                )
                row = _row_from_send(
                    size_bytes=size,
                    size_mib=int(size_mib),
                    run=run,
                    response=response,
                    elapsed_s=elapsed,
                )
                rows.append(row)
                if not args.json:
                    if row["ok"]:
                        print(
                            "  run {run}: {elapsed_s:.2f}s effective={effective_mbps:.1f} Mbps "
                            "wire={wire_mbps:.1f} Mbps saved={saved:.1f} MiB "
                            "savings={savings:.1%}".format(
                                run=row["run"],
                                elapsed_s=row["elapsed_s"],
                                effective_mbps=row["effective_mbps"],
                                wire_mbps=row["wire_mbps"],
                                saved=row["saved_bytes"] / (1024 * 1024),
                                savings=row["bandwidth_savings_ratio"],
                            )
                        )
                    else:
                        print(f"  run {run}: FAIL {row['error']}")
                        break

    failures = _evaluate(rows, thresholds)
    ok = not failures and bool(chat.get("ok"))
    report = {
        "ok": ok,
        "peer": args.peer,
        "peer_snapshot": peer_snapshot,
        "chat_ok": bool(chat.get("ok")),
        "chat_ack": chat.get("ack"),
        "thresholds": thresholds.__dict__,
        "rows": rows,
        "failures": failures,
        "created_at": int(time.time()),
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = args.out or RESULTS_DIR / f"live-soak-{time.strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"report: {out}")
        if ok:
            print("PASS: live soak gate green")
        else:
            print("FAIL: live soak gate failed")
            for f in failures:
                print(f"  - {f}")
            if not chat.get("ok"):
                print(f"  - chat probe failed: {chat}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
