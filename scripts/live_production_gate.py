"""Production live gate for One Link file-transfer behavior.

This intentionally exercises the real local daemon and a real paired peer.
It checks:

  * big-file cold/warm send performance
  * prior-knowledge savings on repeat sends
  * browser/API upload path creates a durable transfer and completes
  * queued durable sends survive a local daemon restart and drain on boot
  * the post-restart route can still send

Example:
    python scripts/live_production_gate.py fc9f0a5f --sizes-mib 64,256
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import aiohttp

from one_link import app as app_mod
from one_link import control_ipc
from one_link import daemon as daemon_mod
from one_link.fault_observability import report_best_effort_failure


RESULTS_DIR = Path("benchmarks") / "results"
log = logging.getLogger(__name__)


def _request(cmd: str, *, timeout: float = 3600.0, **kwargs: Any) -> dict[str, Any]:
    port = daemon_mod.read_control_port()
    return control_ipc.request_control(
        port,
        {"cmd": cmd, **kwargs},
        timeout=timeout,
    )


def _wait_status(timeout_s: float = 45.0) -> dict[str, Any]:
    deadline = time.time() + timeout_s
    last: BaseException | None = None
    while time.time() <= deadline:
        try:
            return _request("status", timeout=5.0)
        except Exception as exc:
            last = exc
            time.sleep(1.0)
    raise RuntimeError(f"daemon did not become ready: {last}")


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
    out: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if part:
            out.append(int(part))
    if not out or any(n <= 0 for n in out):
        raise argparse.ArgumentTypeError("sizes must be positive MiB values")
    return out


def _find_peer(peer: str) -> dict[str, Any] | None:
    needle = peer.lower()
    payload = _request("peers", timeout=10.0)
    for p in payload.get("peers") or []:
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


def _wait_peer(peer: str, timeout_s: float) -> dict[str, Any]:
    deadline = time.time() + timeout_s
    while time.time() <= deadline:
        found = _find_peer(peer)
        if found is not None:
            return found
        time.sleep(1.0)
    raise RuntimeError(f"peer {peer!r} not visible after {timeout_s:.1f}s")


def _send_file(peer: str, path: Path, *, timeout: float) -> tuple[dict[str, Any], float]:
    t0 = time.perf_counter()
    res = _request("send_file", timeout=timeout, peer=peer, path=str(path))
    return res, time.perf_counter() - t0


def _transfer_by_id(transfer_id: str) -> dict[str, Any] | None:
    res = _request("transfers", timeout=10.0, transfer_id=transfer_id)
    if not res.get("ok"):
        return None
    rows = res.get("transfers") or []
    return dict(rows[0]) if rows else None


def _process_memory_bytes(pid: int) -> int | None:
    try:
        import psutil  # type: ignore
        return int(psutil.Process(pid).memory_info().rss)
    except Exception as exc:
        report_best_effort_failure(log, "live_gate_psutil_memory_probe", exc)
    if os.name == "nt":
        try:
            out = subprocess.check_output(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    f"(Get-Process -Id {int(pid)}).WorkingSet64",
                ],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            ).strip()
            return int(out) if out else None
        except Exception:
            return None
    return None


def _send_row(
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
            "error": response.get("error") or "send failed",
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
        "wire_mbps": round(_mbps(wire, elapsed_s), 3),
        "raw_bytes_sent": raw,
        "wire_bytes_sent": wire,
        "saved_bytes": saved,
        "bandwidth_savings_ratio": round(savings, 6),
        "transfer_id": result.get("transfer_id"),
        "cdc": bool(result.get("cdc")),
        "chunks": int(result.get("chunks") or 0),
        "total_chunks": int(result.get("total_chunks") or 0),
        "skipped_chunks": int(result.get("cdc_skipped") or 0),
        "performance_summary": result.get("performance_summary") or {},
    }


async def _http_upload(peer: str, size_mib: int, *, seed: int) -> dict[str, Any]:
    daemon = app_mod._resolve_running_daemon(timeout=10.0)
    if daemon is None:
        raise RuntimeError("authenticated One Link daemon/UI is not available")
    port = daemon.server_port
    token = daemon.token
    rng = random.Random(seed)
    payload = rng.randbytes(int(size_mib) * 1024 * 1024)
    filename = f"http-live-{size_mib}MiB-{int(time.time())}.bin"
    form = aiohttp.FormData()
    form.add_field("peer", peer)
    form.add_field(
        "file",
        payload,
        filename=filename,
        content_type="application/octet-stream",
    )
    t0 = time.perf_counter()
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"http://127.0.0.1:{port}/api/send-file",
            data=form,
            headers={"Authorization": f"Bearer {token}"},
            timeout=aiohttp.ClientTimeout(total=max(120, size_mib * 10)),
        ) as resp:
            text = await resp.text()
            body = json.loads(text or "{}")
    elapsed = time.perf_counter() - t0
    transfer_id = body.get("transfer_id") or (body.get("result") or {}).get("transfer_id")
    row = _transfer_by_id(str(transfer_id)) if transfer_id else None
    return {
        "ok": resp.status in (200, 202) and bool(body.get("ok")),
        "status": resp.status,
        "elapsed_s": round(elapsed, 6),
        "effective_mbps": round(_mbps(len(payload), elapsed), 3),
        "transfer_id": transfer_id,
        "transfer_status": row.get("status") if row else None,
        "autopilot_truth": (row or {}).get("autopilot_truth"),
    }


def _shutdown_daemon() -> None:
    try:
        _request("shutdown", timeout=5.0)
    except Exception as exc:
        report_best_effort_failure(log, "live_gate_daemon_shutdown", exc)
    time.sleep(2.0)


def _daemon_creation_flags() -> int:
    if os.name != "nt":
        return 0
    flags = 0
    for name in ("CREATE_NO_WINDOW", "CREATE_NEW_PROCESS_GROUP", "DETACHED_PROCESS"):
        flags |= int(getattr(subprocess, name, 0))
    return flags


def _start_daemon() -> dict[str, Any]:
    subprocess.Popen(
        [sys.executable, "-m", "one_link.cli", "daemon", "-v"],
        cwd=str(Path.cwd()),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        creationflags=_daemon_creation_flags(),
    )
    return _wait_status(timeout_s=60.0)


def _restart_daemon() -> dict[str, Any]:
    _shutdown_daemon()
    return _start_daemon()


def _queued_restart_resume(peer: str, path: Path, timeout_s: float) -> dict[str, Any]:
    queued = _request(
        "queue_file_transfer",
        timeout=60.0,
        peer=peer,
        path=str(path),
        reason="live restart-resume gate",
        schedule_resume=False,
    )
    if not queued.get("ok"):
        return {"ok": False, "stage": "queue", "response": queued}
    transfer_id = str((queued.get("transfer") or {}).get("id") or "")
    before = _request("status", timeout=10.0)
    after = _restart_daemon()
    deadline = time.time() + timeout_s
    states: list[dict[str, Any]] = []
    final: dict[str, Any] | None = None
    while time.time() <= deadline:
        row = _transfer_by_id(transfer_id)
        if row is not None:
            states.append({
                "status": row.get("status"),
                "delivery_state": (row.get("metadata") or {}).get("delivery_state"),
                "progress_pct": row.get("progress_pct"),
                "updated_ms": row.get("updated_ms"),
            })
            if row.get("status") in ("complete", "failed"):
                final = row
                break
        time.sleep(1.0)
    return {
        "ok": bool(final and final.get("status") == "complete"),
        "transfer_id": transfer_id,
        "before_pid": (before.get("pid") if before else None),
        "after_pid": (after.get("pid") if after else None),
        "states": states[-60:],
        "final_status": final.get("status") if final else None,
        "autopilot_truth": (final or {}).get("autopilot_truth"),
    }


def _evaluate(
    rows: list[dict[str, Any]],
    *,
    min_fresh_mbps: float,
    min_repeat_mbps: float,
    min_repeat_savings: float,
) -> list[str]:
    failures: list[str] = []
    for row in rows:
        label = f"{row.get('size_mib')}MiB run {row.get('run')}"
        if not row.get("ok"):
            failures.append(f"{label}: {row.get('error')}")
            continue
        if int(row.get("run") or 0) == 1 and float(row.get("effective_mbps") or 0) < min_fresh_mbps:
            failures.append(f"{label}: cold below {min_fresh_mbps} Mbps")
        if int(row.get("run") or 0) >= 2:
            if float(row.get("effective_mbps") or 0) < min_repeat_mbps:
                failures.append(f"{label}: warm below {min_repeat_mbps} Mbps")
            if float(row.get("bandwidth_savings_ratio") or 0) < min_repeat_savings:
                failures.append(f"{label}: warm savings below {min_repeat_savings:.0%}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("peer", help="Peer short id, hostname, display name, or fingerprint")
    parser.add_argument("--sizes-mib", type=_parse_sizes, default=[64, 256])
    parser.add_argument("--repeat", type=int, default=2)
    parser.add_argument("--seed", type=int, default=20260512)
    parser.add_argument("--wait-peer-s", type=float, default=30.0)
    parser.add_argument("--http-mib", type=int, default=4)
    parser.add_argument("--restart-mib", type=int, default=16)
    parser.add_argument("--min-fresh-mbps", type=float, default=40.0)
    parser.add_argument("--min-repeat-mbps", type=float, default=250.0)
    parser.add_argument("--min-repeat-savings", type=float, default=0.90)
    parser.add_argument("--skip-restart", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    status = _wait_status(timeout_s=20.0)
    peer_snapshot = _wait_peer(args.peer, args.wait_peer_s)
    pid = int(status.get("pid") or 0)
    memory_start = _process_memory_bytes(pid) if pid else None
    rows: list[dict[str, Any]] = []
    http_upload: dict[str, Any] = {}
    restart_resume: dict[str, Any] = {"ok": True, "skipped": True}
    post_restart_chat: dict[str, Any] | None = None

    with tempfile.TemporaryDirectory(prefix="ol_prod_gate_") as td:
        root = Path(td)
        for idx, size_mib in enumerate(args.sizes_mib):
            size = int(size_mib) * 1024 * 1024
            path = root / f"prod-{size_mib}MiB-{args.seed + idx}.bin"
            _make_file(path, size, seed=int(args.seed) + idx)
            if not args.json:
                print(f"file {path.name}: {size_mib} MiB")
            for run in range(1, max(1, int(args.repeat)) + 1):
                response, elapsed = _send_file(
                    args.peer,
                    path,
                    timeout=max(300.0, min(7200.0, size / (96 * 1024))),
                )
                row = _send_row(
                    size_bytes=size,
                    size_mib=int(size_mib),
                    run=run,
                    response=response,
                    elapsed_s=elapsed,
                )
                rows.append(row)
                if not args.json:
                    if row.get("ok"):
                        print(
                            f"  run {run}: {row['elapsed_s']:.2f}s "
                            f"effective={row['effective_mbps']:.1f} Mbps "
                            f"wire={row['wire_mbps']:.1f} Mbps "
                            f"savings={row['bandwidth_savings_ratio']:.1%}"
                        )
                    else:
                        print(f"  run {run}: FAIL {row.get('error')}")
                        break

        http_upload = asyncio.run(_http_upload(args.peer, int(args.http_mib), seed=int(args.seed) + 99))
        if not args.json:
            print(
                "http upload: "
                f"status={http_upload.get('status')} "
                f"effective={http_upload.get('effective_mbps')} Mbps "
                f"transfer={http_upload.get('transfer_status')}"
            )

        if not args.skip_restart:
            restart_path = root / f"restart-{args.restart_mib}MiB-{args.seed}.bin"
            _make_file(
                restart_path,
                int(args.restart_mib) * 1024 * 1024,
                seed=int(args.seed) + 199,
            )
            restart_resume = _queued_restart_resume(
                args.peer,
                restart_path,
                timeout_s=max(420.0, int(args.restart_mib) * 30.0),
            )
            post_restart_chat = _request(
                "send",
                timeout=30.0,
                peer=args.peer,
                body=f"One Link production gate post-restart {int(time.time())}",
            )
            if not args.json:
                print(
                    "restart resume: "
                    f"ok={restart_resume.get('ok')} "
                    f"final={restart_resume.get('final_status')} "
                    f"pid={restart_resume.get('before_pid')}->{restart_resume.get('after_pid')}"
                )

    status_end = _wait_status(timeout_s=20.0)
    end_pid = int(status_end.get("pid") or 0)
    memory_end = _process_memory_bytes(end_pid) if end_pid else None
    failures = _evaluate(
        rows,
        min_fresh_mbps=float(args.min_fresh_mbps),
        min_repeat_mbps=float(args.min_repeat_mbps),
        min_repeat_savings=float(args.min_repeat_savings),
    )
    if not http_upload.get("ok") or http_upload.get("transfer_status") != "complete":
        failures.append("HTTP upload did not complete cleanly")
    if not restart_resume.get("ok"):
        failures.append("queued transfer did not resume after daemon restart")
    if post_restart_chat is not None and not post_restart_chat.get("ok"):
        failures.append("post-restart route sanity chat failed")

    report = {
        "ok": not failures,
        "peer": args.peer,
        "peer_snapshot": peer_snapshot,
        "thresholds": {
            "min_fresh_mbps": float(args.min_fresh_mbps),
            "min_repeat_mbps": float(args.min_repeat_mbps),
            "min_repeat_savings": float(args.min_repeat_savings),
        },
        "memory": {
            "start_rss_bytes": memory_start,
            "end_rss_bytes": memory_end,
            "delta_bytes": (
                memory_end - memory_start
                if memory_start is not None and memory_end is not None
                else None
            ),
        },
        "rows": rows,
        "http_upload": http_upload,
        "restart_resume": restart_resume,
        "post_restart_chat": post_restart_chat,
        "failures": failures,
        "created_at": int(time.time()),
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = args.out or RESULTS_DIR / f"live-production-{time.strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"report: {out}")
        print("PASS: production live gate green" if report["ok"] else "FAIL: production live gate failed")
        for failure in failures:
            print(f"  - {failure}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
