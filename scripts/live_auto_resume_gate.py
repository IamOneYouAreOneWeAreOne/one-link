"""Live gate for durable queued-send auto-resume.

This proves the production promise that a file send can become a durable
intent first, then drain itself without the user pressing Retry. The peer must
already be paired and reachable; the gate uses the local daemon control socket.

Example:
    python scripts/live_auto_resume_gate.py fc9f0a5f --size-mib 16
"""

from __future__ import annotations

import argparse
import json
import random
import tempfile
import time
from pathlib import Path
from typing import Any

from one_link import control_ipc
from one_link import daemon as daemon_mod


RESULTS_DIR = Path("benchmarks") / "results"


def _request(cmd: str, *, timeout: float = 60.0, **kwargs: Any) -> dict[str, Any]:
    port = daemon_mod.read_control_port()
    return control_ipc.request_control(
        port,
        {"cmd": cmd, **kwargs},
        timeout=timeout,
    )


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


def _transfer_by_id(transfer_id: str) -> dict[str, Any] | None:
    res = _request("transfers", timeout=10.0, transfer_id=transfer_id)
    if not res.get("ok"):
        return None
    rows = res.get("transfers") or []
    return dict(rows[0]) if rows else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("peer", help="Peer short id, hostname, display name, or fingerprint")
    parser.add_argument("--size-mib", type=int, default=16)
    parser.add_argument("--seed", type=int, default=20260512)
    parser.add_argument("--wait-peer-s", type=float, default=20.0)
    parser.add_argument("--timeout-s", type=float, default=180.0)
    parser.add_argument("--min-effective-mbps", type=float, default=25.0)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    started = time.time()
    peer_snapshot: dict[str, Any] | None = None
    while time.time() - started <= float(args.wait_peer_s):
        peers_payload = _request("peers", timeout=10.0)
        peer_snapshot = _find_peer(args.peer, peers_payload)
        if peer_snapshot is not None:
            break
        time.sleep(1.0)
    if peer_snapshot is None:
        print(f"FAIL: peer {args.peer!r} not visible after {args.wait_peer_s:.1f}s")
        return 2

    size = int(args.size_mib) * 1024 * 1024
    with tempfile.TemporaryDirectory(prefix="ol_auto_resume_") as td:
        src = Path(td) / f"auto-resume-{args.size_mib}MiB.bin"
        _make_file(src, size, seed=int(args.seed))
        queued_at = time.perf_counter()
        queued = _request(
            "queue_file_transfer",
            timeout=30.0,
            peer=args.peer,
            path=str(src),
            reason="live auto-resume gate",
        )
        if not queued.get("ok"):
            print(f"FAIL: queue_file_transfer: {queued}")
            return 3
        transfer = queued.get("transfer") or {}
        transfer_id = str(transfer.get("id") or "")
        if not transfer_id:
            print(f"FAIL: queue_file_transfer returned no transfer id: {queued}")
            return 3

        states: list[dict[str, Any]] = []
        deadline = time.perf_counter() + float(args.timeout_s)
        last: dict[str, Any] | None = None
        while time.perf_counter() <= deadline:
            row = _transfer_by_id(transfer_id)
            if row is not None:
                last = row
                states.append({
                    "t_s": round(time.perf_counter() - queued_at, 3),
                    "status": row.get("status"),
                    "delivery_state": (row.get("metadata") or {}).get("delivery_state"),
                    "progress_pct": row.get("progress_pct"),
                    "progress_bytes": row.get("progress_bytes"),
                    "wire_bytes": row.get("wire_bytes"),
                    "raw_bytes": row.get("raw_bytes"),
                })
                if row.get("status") == "complete":
                    break
                if row.get("status") == "failed":
                    break
            time.sleep(0.5)

    elapsed = time.perf_counter() - queued_at
    ok = bool(last and last.get("status") == "complete")
    effective_mbps = (float(size) * 8.0) / max(0.001, elapsed) / 1_000_000.0
    if ok and effective_mbps < float(args.min_effective_mbps):
        ok = False
    report = {
        "ok": ok,
        "peer": args.peer,
        "peer_snapshot": peer_snapshot,
        "transfer_id": transfer_id,
        "size_mib": int(args.size_mib),
        "elapsed_s": round(elapsed, 6),
        "effective_mbps": round(effective_mbps, 3),
        "min_effective_mbps": float(args.min_effective_mbps),
        "final": last,
        "states": states[-40:],
        "created_at": int(time.time()),
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = args.out or RESULTS_DIR / f"live-auto-resume-{time.strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"report: {out}")
        if ok:
            print(
                "PASS: queued send auto-resumed and completed "
                f"at {effective_mbps:.1f} Mbps effective"
            )
        else:
            print("FAIL: queued send did not auto-resume cleanly")
            if last:
                print(f"  final status: {last.get('status')} / {(last.get('metadata') or {}).get('delivery_state')}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
