"""End-to-end file engine benchmark.

Spawns a daemon pair, runs a series of representative scenarios, and
reports throughput / memory / chunk-count / cache-hit metrics so we
can answer the question "is it actually fast and lean?" with
numbers instead of vibes.

Scenarios:

  1. Cold transfer at 5 sizes (1 KiB → 256 MiB). Wall-clock + MB/s.
  2. Receiver RSS peak during the 256 MiB transfer. psutil sample
     loop while the transfer runs.
  3. Warm transfer (same file again). Should be near-instant because
     every chunk is cache-hit; verifies the dedup path.
  4. Resume effectiveness: 32 MiB transfer, kill receiver at the
     first cached chunk, restart, verify completion + measure how
     many chunks needed re-fetch.
  5. Chunk cache GC: fill cache to 100 MiB, evict to 50 MiB, time.
  6. Resume sidecar lifecycle: persist + load 1000 sidecars, time.

Run::

    python scripts/bench_file_engine.py

Pass --json to emit machine-readable results::

    python scripts/bench_file_engine.py --json bench_results.json
"""

from __future__ import annotations

import argparse
import http.client
import json
import logging
import os
import statistics
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

# Make the project's tests/ harness importable.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import psutil  # noqa: E402  (must come after sys.path mutation)

from one_link import app as app_mod  # noqa: E402
from one_link import control_ipc  # noqa: E402
from one_link.fault_observability import report_best_effort_failure  # noqa: E402
from tests.harness import (  # noqa: E402
    LIVE_INTEGRATION_ENV,
    _bring_up,
    daemon_pair as _daemon_pair,
    inbox_files,
    request,
)

log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────
# helpers
# ──────────────────────────────────────────────────────────────────

def _human_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KiB"
    if n < 1024 ** 3:
        return f"{n / 1024 ** 2:.1f} MiB"
    return f"{n / 1024 ** 3:.2f} GiB"


def _api(home: Path, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Call one benchmark daemon's authenticated loopback API."""

    data_dir = home / "data"
    control_port = int(
        control_ipc.read_private_bytes_strict(
            data_dir / "control.port",
            max_bytes=64,
            label="control port",
        )
        .decode("ascii")
        .strip()
    )
    secret = control_ipc.read_control_secret(data_dir)
    daemon = app_mod.resolve_authenticated_daemon(
        control_port,
        secret,
        timeout=10.0,
    )
    if daemon is None:
        raise RuntimeError("benchmark daemon/UI authentication failed")
    port = daemon.server_port
    token = daemon.token
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Authorization": f"Bearer {token}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    try:
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        raw = response.read()
    finally:
        connection.close()
    if not 200 <= response.status < 300:
        detail = raw.decode("utf-8", errors="replace")[:1024]
        raise RuntimeError(
            f"benchmark API {method} {path} failed ({response.status}): {detail}"
        )
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"benchmark API {method} {path} returned a non-object")
    return payload


def _wait_api_peer(home: Path, short_id: str, *, timeout_s: float = 20.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        payload = _api(home, "GET", "/api/peers?include_unpaired=1")
        last = [item for item in payload.get("peers", []) if isinstance(item, dict)]
        for peer in last:
            if peer.get("short_id") == short_id:
                return peer
        time.sleep(0.05)
    raise RuntimeError(f"benchmark peer {short_id} did not appear; peers={last!r}")


@contextmanager
def daemon_pair() -> Iterator[Any]:
    """Yield an isolated pair with explicit file capability policy."""

    with _daemon_pair() as pair:
        peer_a = _wait_api_peer(pair.b.home, pair.a.short_id)
        peer_b = _wait_api_peer(pair.a.home, pair.b.short_id)
        for home, peer in ((pair.a.home, peer_b), (pair.b.home, peer_a)):
            fingerprint = str(peer.get("fingerprint") or "")
            if not fingerprint:
                raise RuntimeError("benchmark peer did not expose a fingerprint")
            trust_result = _api(
                home,
                "POST",
                f"/api/peers/{fingerprint}/trust",
                {"trust": "pinned"},
            )
            if trust_result.get("ok") is not True:
                raise RuntimeError(f"benchmark trust setup failed: {trust_result!r}")
            result = _api(
                home,
                "POST",
                f"/api/peers/{fingerprint}/capabilities",
                {"allowed": ["chat", "files"], "note": "isolated benchmark lane"},
            )
            if result.get("ok") is not True:
                raise RuntimeError(f"benchmark capability setup failed: {result!r}")
        yield pair


def _human_throughput(bytes_: int, seconds: float) -> str:
    if seconds <= 0:
        return "∞"
    bps = bytes_ / seconds
    if bps < 1024 ** 2:
        return f"{bps / 1024:.1f} KiB/s"
    if bps < 1024 ** 3:
        return f"{bps / 1024 ** 2:.1f} MiB/s"
    return f"{bps / 1024 ** 3:.2f} GiB/s"


def _wait_for_payload(home: Path, payload: bytes, timeout: float) -> tuple[Path | None, float]:
    end = time.time() + timeout
    while time.time() < end:
        for f in inbox_files(home):
            try:
                if f.stat().st_size == len(payload):
                    if f.read_bytes() == payload:
                        return f, time.time()
            except OSError:
                pass
        time.sleep(0.05)
    return None, time.time()


class _RssTracker:
    """Sample RSS of a target process every ``interval`` seconds in
    a background thread. Returns peak RSS in bytes when stopped."""

    def __init__(self, pid: int, interval: float = 0.05) -> None:
        self.pid = pid
        self.interval = interval
        self._stop = threading.Event()
        self._peak: int = 0
        self._samples: list[int] = []
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            proc = psutil.Process(self.pid)
        except psutil.NoSuchProcess:
            return
        while not self._stop.is_set():
            try:
                rss = proc.memory_info().rss
                self._peak = max(self._peak, rss)
                self._samples.append(rss)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            time.sleep(self.interval)

    def stop(self) -> dict:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        return {
            "peak_bytes": self._peak,
            "mean_bytes": int(statistics.mean(self._samples)) if self._samples else 0,
            "samples": len(self._samples),
        }


def _build_payload(size: int, seed: int = 0) -> bytes:
    """Build a deterministic, CDC-friendly payload of ``size`` bytes.

    We use a repeating 4 KiB block of pseudo-random data so the
    benchmark is reproducible across runs but the payload is
    realistic enough that the compressor doesn't collapse it to
    near-zero (which would distort wire-time measurements)."""
    import random
    rng = random.Random(seed)
    block = bytes(rng.randint(0, 255) for _ in range(4096))
    if size <= len(block):
        return block[:size]
    repeat = size // len(block)
    tail = size % len(block)
    return block * repeat + block[:tail]


# ──────────────────────────────────────────────────────────────────
# Scenarios
# ──────────────────────────────────────────────────────────────────

SIZES_DEFAULT = [
    ("1 KiB",   1024),
    ("1 MiB",   1024 * 1024),
    ("16 MiB",  16 * 1024 * 1024),
    ("64 MiB",  64 * 1024 * 1024),
    ("256 MiB", 256 * 1024 * 1024),
]

# How many times to repeat each ``--scenario cold`` size; we
# report the median so a single hiccup doesn't skew the headline
# numbers. Override via ``--repeat`` on the command line.
REPEAT_DEFAULT = 1


def bench_cold_transfer(sizes: list[tuple[str, int]], *, repeat: int = REPEAT_DEFAULT) -> list[dict]:
    """Time + throughput at each size, fresh daemons each run so
    the chunk cache is empty (cold path). When ``repeat`` > 1 we
    report the median; wall-clock variance on loopback can be
    ±10 %, so a single sample can mislead."""
    results = []
    for label, size in sizes:
        payload = _build_payload(size)
        elapsed_samples: list[float] = []
        for _ in range(max(1, repeat)):
            with tempfile.TemporaryDirectory() as td:
                src = Path(td) / f"cold_{label.replace(' ', '_')}.bin"
                src.write_bytes(payload)
                with daemon_pair() as p:
                    t0 = time.time()
                    res = request(
                        p.a.control_port, cmd="send_file",
                        peer=p.b.short_id, path=str(src), timeout=300,
                    )
                    if not res.get("ok"):
                        results.append({
                            "scenario": "cold_transfer", "size_label": label,
                            "size_bytes": size, "error": res,
                        })
                        break
                    landed, _ = _wait_for_payload(p.b.home, payload, timeout=300.0)
                    elapsed = time.time() - t0
                    if landed:
                        elapsed_samples.append(elapsed)
        if not elapsed_samples:
            continue
        elapsed_median = statistics.median(elapsed_samples)
        elapsed_min = min(elapsed_samples)
        results.append({
            "scenario": "cold_transfer",
            "size_label": label,
            "size_bytes": size,
            "elapsed_median_sec": round(elapsed_median, 4),
            "elapsed_min_sec": round(elapsed_min, 4),
            "throughput_median_bps": round(size / elapsed_median, 2) if elapsed_median > 0 else 0,
            "throughput_best_bps": round(size / elapsed_min, 2) if elapsed_min > 0 else 0,
            "samples": len(elapsed_samples),
        })
        print(f"  cold {label:>9}: {_human_bytes(size)} "
              f"median {elapsed_median:6.3f}s "
              f"-> {_human_throughput(size, elapsed_median)} "
              f"(best {_human_throughput(size, elapsed_min)}, n={len(elapsed_samples)})")
    return results


def bench_sender_memory(size: int) -> dict:
    """RSS peak on the SENDER during a single transfer. Symmetric
    counterpart to bench_receiver_memory — proves the sender's
    streaming-encode path doesn't read the whole file into heap.

    The sender's send_file uses ``with open(path, 'rb') as f`` +
    seek/read per chunk, so the only file-data in heap at any
    moment is the current chunk's plaintext + the encoded
    wire-frame. RSS should stay bounded regardless of file size.
    """
    payload = _build_payload(size, seed=11)
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "sender_mem.bin"
        src.write_bytes(payload)
        with daemon_pair() as p:
            tracker = _RssTracker(p.a.proc.pid)
            tracker.start()
            t0 = time.time()
            request(p.a.control_port, cmd="send_file",
                    peer=p.b.short_id, path=str(src), timeout=300)
            landed, _ = _wait_for_payload(p.b.home, payload, timeout=300.0)
            elapsed = time.time() - t0
            mem = tracker.stop()
    out = {
        "scenario": "sender_memory",
        "size_bytes": size,
        "elapsed_sec": round(elapsed, 4),
        "rss_peak_bytes": mem["peak_bytes"],
        "rss_mean_bytes": mem["mean_bytes"],
        "rss_samples": mem["samples"],
        "rss_overhead_ratio": (
            round(mem["peak_bytes"] / size, 3) if size > 0 else None
        ),
        "landed": landed is not None,
    }
    print(f"  sender RSS during {_human_bytes(size)}: "
          f"peak {_human_bytes(mem['peak_bytes'])} "
          f"(mean {_human_bytes(mem['mean_bytes'])}, "
          f"overhead ratio {out['rss_overhead_ratio']}×)")
    return out


def bench_receiver_memory(size: int) -> dict:
    """RSS peak on the receiver during a single transfer of
    ``size`` bytes. Validates Wave 1d's stream-to-disk: receiver
    memory must stay bounded regardless of file size."""
    payload = _build_payload(size, seed=1)
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "mem.bin"
        src.write_bytes(payload)
        with daemon_pair() as p:
            tracker = _RssTracker(p.b.proc.pid)
            tracker.start()
            t0 = time.time()
            request(p.a.control_port, cmd="send_file",
                    peer=p.b.short_id, path=str(src), timeout=300)
            landed, _ = _wait_for_payload(p.b.home, payload, timeout=300.0)
            elapsed = time.time() - t0
            mem = tracker.stop()
    out = {
        "scenario": "receiver_memory",
        "size_bytes": size,
        "elapsed_sec": round(elapsed, 4),
        "rss_peak_bytes": mem["peak_bytes"],
        "rss_mean_bytes": mem["mean_bytes"],
        "rss_samples": mem["samples"],
        "rss_overhead_ratio": (
            round(mem["peak_bytes"] / size, 3) if size > 0 else None
        ),
        "landed": landed is not None,
    }
    print(f"  receiver RSS during {_human_bytes(size)}: "
          f"peak {_human_bytes(mem['peak_bytes'])} "
          f"(mean {_human_bytes(mem['mean_bytes'])}, "
          f"overhead ratio {out['rss_overhead_ratio']}×)")
    return out


def bench_many_small_files(n: int = 20, per_size: int = 4096) -> dict:
    """A/B compare sending N small files via the existing
    per-file send_file (each pays its own FILE_OFFER round-trip)
    vs the future FILE_OFFER_BATCH path. Wave 2b's receiver
    handler exists; the sender-side batcher is still a follow-up,
    so this bench currently establishes only the BASELINE — the
    cost-of-many-small-files that batching would optimize.
    """
    payloads = [_build_payload(per_size, seed=200 + i) for i in range(n)]
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        srcs = []
        for i, payload in enumerate(payloads):
            sp = td_path / f"small_{i}.bin"
            sp.write_bytes(payload)
            srcs.append(sp)
        with daemon_pair() as p:
            request(p.a.control_port, cmd="send",
                    peer=p.b.short_id, body="warm")
            time.sleep(0.2)
            t0 = time.time()
            for src in srcs:
                request(p.a.control_port, cmd="send_file",
                        peer=p.b.short_id, path=str(src), timeout=60)
            # Wait for all payloads to land.
            end = time.time() + 60.0
            seen = set()
            while time.time() < end:
                for f in inbox_files(p.b.home):
                    try:
                        data = f.read_bytes()
                        for i, payload in enumerate(payloads):
                            if i not in seen and data == payload:
                                seen.add(i)
                    except OSError:
                        pass
                if len(seen) >= n:
                    break
                time.sleep(0.1)
            elapsed = time.time() - t0
    total_bytes = n * per_size
    per_file_sec = elapsed / n if n > 0 else 0.0
    out = {
        "scenario": "many_small_files",
        "n": n,
        "per_size_bytes": per_size,
        "total_bytes": total_bytes,
        "elapsed_sec": round(elapsed, 4),
        "per_file_sec": round(per_file_sec, 4) if n > 0 else None,
        "aggregate_throughput_bps": round(total_bytes / elapsed, 2) if elapsed > 0 else 0,
        "completed": len(seen),
    }
    print(f"  many-small: {n}×{_human_bytes(per_size)} ({total_bytes} bytes) "
          f"sequentially -> {elapsed:.3f}s "
          f"({per_file_sec * 1000:.1f} ms/file avg)")
    return out


def bench_share_link_round_trip(size: int = 1 * 1024 * 1024) -> dict:
    """Wave 2g+ share-link end-to-end latency: mint on A, claim on
    B, file lands. Captures the wall-time cost of the new
    out-of-band-token flow vs paired-peer send_file (proxy via
    cold_transfer at same size). Useful to know: is share-link
    delivery materially slower than direct send, or is the
    overhead just the mint round-trip?"""
    payload = _build_payload(size, seed=303)
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "sharelink.bin"
        src.write_bytes(payload)
        with daemon_pair() as p:
            # Warm channel both directions.
            request(p.a.control_port, cmd="send",
                    peer=p.b.short_id, body="warm")
            time.sleep(0.5)
            t0 = time.time()
            mint = request(p.a.control_port, cmd="create_share_link",
                           path=str(src))
            if not mint.get("ok"):
                return {"scenario": "share_link_round_trip",
                        "size_bytes": size, "error": mint}
            mint_elapsed = time.time() - t0
            claim = request(p.b.control_port,
                            cmd="claim_share_link_from_peer",
                            peer=p.a.short_id,
                            token_hex=mint["token_hex"])
            if not claim.get("ok"):
                return {"scenario": "share_link_round_trip",
                        "size_bytes": size, "error": claim}
            # Wait for file to arrive.
            end = time.time() + 30.0
            landed = False
            while time.time() < end:
                for f in inbox_files(p.b.home):
                    try:
                        if f.stat().st_size == size and f.read_bytes() == payload:
                            landed = True
                            break
                    except OSError:
                        pass
                if landed:
                    break
                time.sleep(0.05)
            total_elapsed = time.time() - t0
    out = {
        "scenario": "share_link_round_trip",
        "size_bytes": size,
        "mint_elapsed_sec": round(mint_elapsed, 4),
        "total_elapsed_sec": round(total_elapsed, 4),
        "delivery_elapsed_sec": round(total_elapsed - mint_elapsed, 4),
        "throughput_bps": round(size / total_elapsed, 2) if total_elapsed > 0 else 0,
        "completed": landed,
    }
    print(f"  share-link round-trip {_human_bytes(size)}: "
          f"mint {mint_elapsed * 1000:.1f}ms + delivery "
          f"{(total_elapsed - mint_elapsed) * 1000:.1f}ms = "
          f"{total_elapsed:.3f}s ({_human_throughput(size, total_elapsed)})")
    return out


def bench_quic_vs_webrtc(size: int = 16 * 1024 * 1024) -> dict:
    """A/B compare a paired-pinned transfer (rides Wave 2e+2f
    QUIC batch path) vs the same transfer between unpinned peers
    (existing WebRTC pipeline). Both peers in each phase are
    fresh daemon pairs so the chunk cache is empty.

    The QUIC phase pins the peers + polls quic_status until both
    sides have learned the other's QUIC port + then runs send_file.
    The WebRTC baseline skips pinning entirely.
    """
    payload = _build_payload(size, seed=42)

    def _phase_pinned() -> float:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "quic.bin"
            src.write_bytes(payload)
            with daemon_pair() as p:
                a_pin = request(p.a.control_port, cmd="pin_peer",
                                peer=p.b.short_id)
                b_pin = request(p.b.control_port, cmd="pin_peer",
                                peer=p.a.short_id)
                if not (a_pin.get("ok") and b_pin.get("ok")):
                    return float("nan")
                request(p.a.control_port, cmd="send",
                        peer=p.b.short_id, body="warm")
                # Wait for both sides to learn each other's QUIC port.
                b_fp_prefix = a_pin["peer_fp"][:16]
                a_fp_prefix = b_pin["peer_fp"][:16]
                ready_end = time.time() + 30.0
                a_ready = b_ready = False
                while time.time() < ready_end:
                    if not a_ready:
                        st = request(p.a.control_port, cmd="quic_status")
                        if any(k.startswith(b_fp_prefix)
                               for k in (st.get("advertised_ports") or {})):
                            a_ready = True
                    if not b_ready:
                        st = request(p.b.control_port, cmd="quic_status")
                        if any(k.startswith(a_fp_prefix)
                               for k in (st.get("advertised_ports") or {})):
                            b_ready = True
                    if a_ready and b_ready:
                        break
                    time.sleep(0.1)
                if not (a_ready and b_ready):
                    return float("nan")
                # Time the actual transfer.
                t0 = time.time()
                request(p.a.control_port, cmd="send_file",
                        peer=p.b.short_id, path=str(src), timeout=300)
                _wait_for_payload(p.b.home, payload, timeout=300.0)
                return time.time() - t0

    def _phase_unpinned() -> float:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "wrtc.bin"
            src.write_bytes(payload)
            with daemon_pair() as p:
                request(p.a.control_port, cmd="send",
                        peer=p.b.short_id, body="warm")
                time.sleep(0.5)
                t0 = time.time()
                request(p.a.control_port, cmd="send_file",
                        peer=p.b.short_id, path=str(src), timeout=300)
                _wait_for_payload(p.b.home, payload, timeout=300.0)
                return time.time() - t0

    pinned_runs = []
    for _ in range(2):
        elapsed = _phase_pinned()
        if elapsed == elapsed:  # not NaN
            pinned_runs.append(elapsed)
    unpinned_runs = []
    for _ in range(2):
        elapsed = _phase_unpinned()
        if elapsed == elapsed:
            unpinned_runs.append(elapsed)
    pinned_med = statistics.median(pinned_runs) if pinned_runs else float("nan")
    unpinned_med = statistics.median(unpinned_runs) if unpinned_runs else float("nan")
    speedup = (
        unpinned_med / pinned_med
        if pinned_med == pinned_med and unpinned_med == unpinned_med and pinned_med > 0
        else float("nan")
    )
    out = {
        "scenario": "quic_vs_webrtc",
        "size_bytes": size,
        "pinned_quic_median_sec": round(pinned_med, 4) if pinned_med == pinned_med else None,
        "pinned_quic_throughput_bps": round(size / pinned_med, 2) if pinned_med == pinned_med and pinned_med > 0 else None,
        "unpinned_webrtc_median_sec": round(unpinned_med, 4) if unpinned_med == unpinned_med else None,
        "unpinned_webrtc_throughput_bps": round(size / unpinned_med, 2) if unpinned_med == unpinned_med and unpinned_med > 0 else None,
        "quic_speedup_x": round(speedup, 3) if speedup == speedup else None,
        "samples_pinned": len(pinned_runs),
        "samples_unpinned": len(unpinned_runs),
    }
    print(
        f"  QUIC vs WebRTC at {_human_bytes(size)}: "
        f"pinned/QUIC {pinned_med:.3f}s ({_human_throughput(size, pinned_med)}) "
        f"vs unpinned/WebRTC {unpinned_med:.3f}s ({_human_throughput(size, unpinned_med)}) "
        f"= {speedup:.2f}× speedup"
    )
    return out


def bench_concurrent_transfers(n: int = 4, size: int = 32 * 1024 * 1024) -> dict:
    """Send ``n`` distinct files in parallel from A to B. Measures
    aggregate throughput vs. the per-file baseline; if the engine
    serializes badly somewhere (e.g., a single per-channel send
    lock for files), aggregate stays near per-file. If it scales
    well, aggregate approaches n × per-file."""
    payloads = [_build_payload(size, seed=100 + i) for i in range(n)]
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        srcs = []
        for i, payload in enumerate(payloads):
            p = td_path / f"concurrent_{i}.bin"
            p.write_bytes(payload)
            srcs.append(p)
        with daemon_pair() as p:
            t0 = time.time()
            threads = []
            results: list[bool] = [False] * n

            def _send_one(idx: int) -> None:
                try:
                    res = request(
                        p.a.control_port, cmd="send_file",
                        peer=p.b.short_id, path=str(srcs[idx]),
                        timeout=300,
                    )
                    results[idx] = bool(res.get("ok"))
                except Exception:
                    results[idx] = False

            for i in range(n):
                t = threading.Thread(target=_send_one, args=(i,), daemon=True)
                threads.append(t)
                t.start()
            for t in threads:
                t.join(timeout=300.0)
            # Wait for all payloads to land.
            end = time.time() + 120.0
            seen = set()
            while time.time() < end:
                for f in inbox_files(p.b.home):
                    try:
                        if f.stat().st_size == size:
                            data = f.read_bytes()
                            for i, expected in enumerate(payloads):
                                if i in seen:
                                    continue
                                if data == expected:
                                    seen.add(i)
                                    break
                    except OSError:
                        pass
                if len(seen) >= n:
                    break
                time.sleep(0.2)
            elapsed = time.time() - t0
    total_bytes = n * size
    out = {
        "scenario": "concurrent_transfers",
        "n": n,
        "size_bytes": size,
        "total_bytes": total_bytes,
        "elapsed_sec": round(elapsed, 4),
        "aggregate_throughput_bps": round(total_bytes / elapsed, 2) if elapsed > 0 else 0,
        "per_transfer_throughput_bps": round(size / elapsed, 2) if elapsed > 0 else 0,
        "completed": len(seen),
    }
    print(f"  concurrent {n}×{_human_bytes(size)}: "
          f"{out['completed']}/{n} landed in {elapsed:.3f}s "
          f"-> aggregate {_human_throughput(total_bytes, elapsed)}")
    return out


def bench_warm_dedup(size: int = 64 * 1024 * 1024) -> dict:
    """Send the same file twice on the same daemon pair. Second
    send should be near-instant: every chunk hash hits the
    receiver's cache, FILE_WANTS comes back empty."""
    payload = _build_payload(size, seed=2)
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "warm.bin"
        src.write_bytes(payload)
        with daemon_pair() as p:
            # Cold pass
            t0 = time.time()
            request(p.a.control_port, cmd="send_file",
                    peer=p.b.short_id, path=str(src), timeout=300)
            _wait_for_payload(p.b.home, payload, timeout=300.0)
            cold_elapsed = time.time() - t0
            # Warm pass — same blob.
            t0 = time.time()
            request(p.a.control_port, cmd="send_file",
                    peer=p.b.short_id, path=str(src), timeout=300)
            # The receiver writes to a NEW unique path because
            # _unique_inbox_path adds " (1)" on collision; wait
            # for two payload-matching inbox files. Sub-10 ms poll
            # so wall-clock granularity doesn't drown the
            # hardlink-fast-path measurement (Wave 2a).
            end = time.time() + 60.0
            count = 0
            while time.time() < end:
                count = sum(
                    1 for f in inbox_files(p.b.home)
                    if f.stat().st_size == size and f.read_bytes() == payload
                )
                if count >= 2:
                    break
                time.sleep(0.005)
            warm_elapsed = time.time() - t0
    out = {
        "scenario": "warm_dedup",
        "size_bytes": size,
        "cold_elapsed_sec": round(cold_elapsed, 4),
        "warm_elapsed_sec": round(warm_elapsed, 4),
        "speedup_x": (
            round(cold_elapsed / warm_elapsed, 2) if warm_elapsed > 0 else None
        ),
    }
    print(f"  warm dedup at {_human_bytes(size)}: "
          f"cold {cold_elapsed:.3f}s -> warm {warm_elapsed:.3f}s "
          f"= {out['speedup_x']}× speedup")
    return out


def bench_resume_effectiveness(size: int = 32 * 1024 * 1024) -> dict:
    """Send a moderate file, kill receiver after ~50 % of chunks
    have landed in its cache, restart receiver, observe how many
    chunks the resumed transfer needs from the wire (vs already
    cached). Wave 1a + 1d + 1g all flow through this."""
    payload = _build_payload(size, seed=3)
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "resume.bin"
        src.write_bytes(payload)
        with daemon_pair() as p:
            def _do_send():
                try:
                    request(p.a.control_port, cmd="send_file",
                            peer=p.b.short_id, path=str(src), timeout=120)
                except Exception as exc:
                    report_best_effort_failure(log, "benchmark_resume_sender", exc)
            sender = threading.Thread(target=_do_send, daemon=True)
            sender.start()
            # Wait for at least 5 chunks to land in B's cache —
            # killing after just one chunk under-measures the
            # resume win because the receiver would barely have
            # cached anything to start with.
            chunk_cache = p.b.home / "data" / "file_chunks"
            ready = time.time() + 30.0
            chunks_before_kill = 0
            while time.time() < ready:
                if chunk_cache.is_dir():
                    chunks_before_kill = sum(
                        1 for e in chunk_cache.rglob("*") if e.is_file()
                    )
                    if chunks_before_kill >= 5:
                        break
                time.sleep(0.05)
            # Hard kill receiver mid-transfer.
            p.b.proc.kill()
            try:
                p.b.proc.wait(timeout=5.0)
            except Exception as exc:
                report_best_effort_failure(log, "benchmark_resume_receiver_wait", exc)
            try:
                if p.b.log_fh is not None:
                    p.b.log_fh.close()
            except Exception as exc:
                report_best_effort_failure(log, "benchmark_resume_log_close", exc)
            sender.join(timeout=30.0)
            # Restart B on the same home dir.  Delete the stale
            # port files first so the harness's _read_port waits
            # for the NEW daemon's bind instead of reading the
            # dead daemon's port and connecting nowhere.
            for stale in ("control.port", "peer.port", "instance.lock"):
                p_stale = p.b.home / "data" / stale
                try:
                    p_stale.unlink()
                except OSError:
                    pass
            t_resume = time.time()
            new_b = _bring_up(p.b.home, p.b.log, "B-resume")
            p.b = new_b
            # Wait for cross-discovery.
            deadline = time.time() + 30.0
            while time.time() < deadline:
                ra = request(p.a.control_port, cmd="peers")
                rb = request(p.b.control_port, cmd="peers")
                a_sees_b = any(pp["short_id"] == p.b.short_id for pp in ra.get("peers", []))
                b_sees_a = any(pp["short_id"] == p.a.short_id for pp in rb.get("peers", []))
                if a_sees_b and b_sees_a:
                    break
                time.sleep(0.2)
            # Wait up to 120 s for sender's auto-retry to complete.
            end = time.time() + 120.0
            landed = None
            while time.time() < end:
                for f in inbox_files(p.b.home):
                    if f.stat().st_size == size and f.read_bytes() == payload:
                        landed = f
                        break
                if landed:
                    break
                time.sleep(0.3)
            elapsed_after_resume = time.time() - t_resume
    out = {
        "scenario": "resume_effectiveness",
        "size_bytes": size,
        "chunks_cached_at_kill": chunks_before_kill,
        "completed_after_resume": landed is not None,
        "elapsed_after_restart_sec": round(elapsed_after_resume, 4),
    }
    print(f"  resume {_human_bytes(size)}: "
          f"{chunks_before_kill} chunk(s) cached at kill, "
          f"completion={'OK' if landed else 'FAIL'} "
          f"in {elapsed_after_resume:.1f}s")
    return out


# ──────────────────────────────────────────────────────────────────
# microbenchmarks
# ──────────────────────────────────────────────────────────────────

def bench_resume_sidecar(n: int = 1000) -> dict:
    """Time ``n`` persist + ``n`` load operations against a fresh
    inbox. Resume sidecar reads happen at startup; writes happen
    once per chunk-touch debounce window (Wave 1d's every-64-chunks
    cadence)."""
    from one_link.resume import (
        ResumeSidecar, persist_sidecar, load_sidecar,
    )
    with tempfile.TemporaryDirectory() as td:
        inbox = Path(td) / "inbox"
        inbox.mkdir()
        partial = inbox / "x.bin"
        partial.write_bytes(b"x" * 64)
        # Build n distinct sidecars.
        sidecars = []
        for i in range(n):
            blob = f"{i:064x}"
            sidecars.append(ResumeSidecar(
                blob_hex=blob,
                peer_fp="P" * 64,
                name=f"file_{i}.bin",
                size=4096,
                out_path=str(partial),
                cdc_chunks=[{"index": 0, "hash": "a" * 64, "size": 4096, "start": 0, "end": 4096}],
            ))
        t0 = time.perf_counter()
        for sc in sidecars:
            persist_sidecar(inbox, sc)
        write_elapsed = time.perf_counter() - t0
        t0 = time.perf_counter()
        for sc in sidecars:
            load_sidecar(inbox, sc.blob_hex)
        read_elapsed = time.perf_counter() - t0
    out = {
        "scenario": "resume_sidecar_microbench",
        "n": n,
        "write_total_sec": round(write_elapsed, 4),
        "write_per_op_us": round(write_elapsed * 1e6 / n, 2),
        "read_total_sec": round(read_elapsed, 4),
        "read_per_op_us": round(read_elapsed * 1e6 / n, 2),
    }
    print(f"  sidecar ops × {n}: "
          f"write {out['write_per_op_us']:.1f} µs/op, "
          f"read {out['read_per_op_us']:.1f} µs/op")
    return out


def bench_chunk_cache_gc(n_chunks: int = 1000, chunk_size: int = 65536) -> dict:
    """Time an eviction pass over ``n_chunks`` entries totalling
    ~``n_chunks * chunk_size`` bytes. Backstops the assertion that
    cache GC is fast enough to run synchronously at startup even
    on a cache that's grown to thousands of entries."""
    from one_link.chunk_cache_gc import evict_to_target
    with tempfile.TemporaryDirectory() as td:
        cache = Path(td) / "file_chunks"
        cache.mkdir()
        now = time.time()
        for i in range(n_chunks):
            h = f"{i:064x}"
            prefix = cache / h[:2]
            prefix.mkdir(parents=True, exist_ok=True)
            p = prefix / h[2:]
            p.write_bytes(b"\0" * chunk_size)
            # Spread mtimes so LRU has a real ordering to sort.
            os.utime(p, (now - i * 60, now - i * 60))

        class _FakeState:
            def __init__(self): self.forgotten = []
            def forget_chunk_available(self, h): self.forgotten.append(h)

        state = _FakeState()
        # Evict to 50 % of total bytes.
        target = (n_chunks * chunk_size) // 2
        t0 = time.perf_counter()
        report = evict_to_target(
            cache,
            max_bytes=target - 1,  # any value < total triggers
            target_bytes=target,
            state=state,
            min_age_seconds=0,
            now=now + 86400,  # all entries past min_age
        )
        elapsed = time.perf_counter() - t0
    out = {
        "scenario": "chunk_cache_gc_microbench",
        "n_chunks": n_chunks,
        "chunk_size_bytes": chunk_size,
        "evicted_files": report.evicted_files,
        "evicted_bytes": report.evicted_bytes,
        "elapsed_sec": round(elapsed, 4),
        "evict_rate_files_per_sec": round(
            report.evicted_files / elapsed, 1
        ) if elapsed > 0 else 0,
    }
    print(f"  cache GC: evicted {report.evicted_files}/{n_chunks} entries "
          f"({_human_bytes(report.evicted_bytes)}) in {elapsed * 1000:.1f} ms "
          f"= {out['evict_rate_files_per_sec']:.0f} files/s")
    return out


# ──────────────────────────────────────────────────────────────────
# main
# ──────────────────────────────────────────────────────────────────

def _enable_live_benchmark_lane() -> None:
    """Explicitly opt this live benchmark into the daemon-spawn lane."""

    # The shared test harness is fail-closed by default so a normal pytest run
    # cannot accidentally spawn dozens of real daemons. Invoking this script
    # is itself the operator's explicit request for a live benchmark.
    os.environ[LIVE_INTEGRATION_ENV] = "1"


def main() -> int:
    _enable_live_benchmark_lane()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--json", type=Path, default=None,
        help="Write machine-readable results JSON to this path",
    )
    parser.add_argument(
        "--quick", action="store_true",
        help="Skip the slowest scenarios (>= 64 MiB sizes)",
    )
    parser.add_argument(
        "--scenario",
        choices=[
            "cold", "memory", "sender_memory", "warm", "resume",
            "sidecar", "cache", "concurrent", "quic_vs_webrtc",
            "many_small", "share_link", "all",
        ],
        default="all",
        help="Run only the named scenario family",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=REPEAT_DEFAULT,
        help=("How many times to repeat each cold-transfer size. "
              "Reports median + best — useful for separating real "
              "regressions from wall-clock noise."),
    )
    args = parser.parse_args()

    sizes = SIZES_DEFAULT
    if args.quick:
        sizes = [(l, s) for (l, s) in sizes if s <= 16 * 1024 * 1024]

    results: dict[str, Any] = {"started_at": time.strftime("%Y-%m-%dT%H:%M:%S")}

    def run_section(name: str, fn) -> None:
        if args.scenario not in (name, "all"):
            return
        print(f"\n--- {name} ---")
        results[name] = fn()

    run_section("cold", lambda: bench_cold_transfer(sizes, repeat=args.repeat))
    run_section("memory", lambda: bench_receiver_memory(
        64 * 1024 * 1024 if args.quick else 256 * 1024 * 1024
    ))
    run_section("sender_memory", lambda: bench_sender_memory(
        64 * 1024 * 1024 if args.quick else 256 * 1024 * 1024
    ))
    run_section("concurrent", lambda: bench_concurrent_transfers(
        n=4,
        size=8 * 1024 * 1024 if args.quick else 32 * 1024 * 1024,
    ))
    run_section("quic_vs_webrtc", lambda: bench_quic_vs_webrtc(
        size=8 * 1024 * 1024 if args.quick else 16 * 1024 * 1024,
    ))
    run_section("many_small", lambda: bench_many_small_files(
        n=10 if args.quick else 20,
        per_size=4096,
    ))
    run_section("share_link", lambda: bench_share_link_round_trip(
        size=256 * 1024 if args.quick else 1 * 1024 * 1024,
    ))
    run_section("warm", lambda: bench_warm_dedup(
        16 * 1024 * 1024 if args.quick else 64 * 1024 * 1024
    ))
    run_section("resume", lambda: bench_resume_effectiveness(
        16 * 1024 * 1024 if args.quick else 32 * 1024 * 1024
    ))
    run_section("sidecar", lambda: bench_resume_sidecar(1000))
    run_section("cache", lambda: bench_chunk_cache_gc(1000, 65536))

    results["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    if args.json:
        args.json.write_text(json.dumps(results, indent=2))
        print(f"\nResults written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
