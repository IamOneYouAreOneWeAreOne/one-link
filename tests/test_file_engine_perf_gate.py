"""Perf regression gates for the CDC file engine.

These tests don't measure absolute performance — wall-clock numbers
vary too much across CI runners + developer laptops. They assert
*ranges* that catch regressions of the kind Wave 1d / 1f / 1g / 1i
introduced: a future change that puts the whole file back in heap,
or eats 10× as many wall-clock seconds, will fail one of these.

Each gate has a generous floor so green CI runs aren't flaky. The
goal is "alarm if something obvious broke," not "fail any
slowdown."

Tagged ``@pytest.mark.soak`` so they ride the same opt-in track as
``test_two_device_soak.py`` — pytest -m soak picks them up; a plain
``pytest`` skips them.
"""

from __future__ import annotations

import os
import statistics
import threading
import time
from pathlib import Path

import pytest

psutil = pytest.importorskip("psutil")

from tests.harness import (
    daemon_pair,
    inbox_files,
    request,
)


pytestmark = [pytest.mark.timeout(180), pytest.mark.soak]


def _build_payload(size: int, seed: int = 0) -> bytes:
    import random
    rng = random.Random(seed)
    block = bytes(rng.randint(0, 255) for _ in range(4096))
    if size <= len(block):
        return block[:size]
    repeat = size // len(block)
    tail = size % len(block)
    return block * repeat + block[:tail]


def _wait_for_payload(home: Path, payload: bytes, timeout: float) -> Path | None:
    end = time.time() + timeout
    while time.time() < end:
        for f in inbox_files(home):
            try:
                if f.stat().st_size == len(payload) and f.read_bytes() == payload:
                    return f
            except OSError:
                pass
        time.sleep(0.05)
    return None


# ──────────────────────────────────────────────────────────────────
# Memory regression gate (stream-to-disk must not regress)
# ──────────────────────────────────────────────────────────────────

def test_perf_gate_receiver_rss_under_cap(tmp_path: Path) -> None:
    """The receiver's RSS during a 64 MiB transfer must stay under
    a generous cap. Pre-Wave-1d the receiver would have held all
    64 MiB in heap, pushing RSS well past 150 MiB; with stream-to-
    disk it sits around 86 MiB. Cap at 200 MiB — plenty of slack
    for noisy CI without missing real regressions."""
    size = 64 * 1024 * 1024  # 64 MiB
    payload = _build_payload(size)
    src = tmp_path / "perf_memory.bin"
    src.write_bytes(payload)

    samples: list[int] = []
    peak = [0]
    stop = threading.Event()

    def sample(pid: int) -> None:
        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return
        while not stop.is_set():
            try:
                rss = proc.memory_info().rss
                samples.append(rss)
                peak[0] = max(peak[0], rss)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            time.sleep(0.05)

    with daemon_pair(pin_trust=True) as p:
        t = threading.Thread(target=sample, args=(p.b.proc.pid,), daemon=True)
        t.start()
        res = request(p.a.control_port, cmd="send_file",
                      peer=p.b.short_id, path=str(src), timeout=120)
        assert res["ok"], res
        landed = _wait_for_payload(p.b.home, payload, timeout=120.0)
        assert landed is not None, "64 MiB transfer never arrived"
        stop.set()
        t.join(timeout=2.0)

    # 200 MiB cap. Pre-Wave-1d: ~150 MiB minimum (base + file in
    # heap). Post-Wave-1d: ~86 MiB. The 200 MiB cap gives us
    # ~115 MiB of margin over the current real value AND ~50 MiB
    # under the pre-Wave-1d floor, so a regression that puts file
    # bytes back in heap fails cleanly.
    cap_bytes = 200 * 1024 * 1024
    assert peak[0] < cap_bytes, (
        f"receiver RSS peak {peak[0] / 1024 / 1024:.1f} MiB during a "
        f"64 MiB transfer exceeds the {cap_bytes / 1024 / 1024:.0f} MiB "
        f"regression cap — Wave 1d stream-to-disk may have regressed "
        f"and chunks are being buffered in heap again."
    )


# ──────────────────────────────────────────────────────────────────
# Throughput regression gate
# ──────────────────────────────────────────────────────────────────

def test_perf_gate_throughput_16mib_floor(tmp_path: Path) -> None:
    """A 16 MiB transfer on loopback must complete in under 2
    seconds. The current run lands in ~150 ms; the 2-second floor
    gives 10× headroom for slow CI runners while still flagging
    a 10× regression."""
    size = 16 * 1024 * 1024
    payload = _build_payload(size, seed=1)
    src = tmp_path / "perf_throughput.bin"
    src.write_bytes(payload)

    with daemon_pair(pin_trust=True) as p:
        t0 = time.time()
        res = request(p.a.control_port, cmd="send_file",
                      peer=p.b.short_id, path=str(src), timeout=60)
        assert res["ok"], res
        landed = _wait_for_payload(p.b.home, payload, timeout=60.0)
        elapsed = time.time() - t0
        assert landed is not None

    assert elapsed < 2.0, (
        f"16 MiB transfer took {elapsed:.2f}s — 10× regression "
        f"against the ~150 ms baseline. Investigate before merging."
    )


# ──────────────────────────────────────────────────────────────────
# Cache GC regression gate
# ──────────────────────────────────────────────────────────────────

def test_perf_gate_cache_gc_eviction_throughput(tmp_path: Path) -> None:
    """Eviction over a synthetic 1000-entry cache must finish in
    under 2 seconds. Current run: ~64 ms. Cap at 2 s gives 30×
    margin while catching catastrophic regressions in the
    file-walking or state-DB hookup."""
    from one_link.chunk_cache_gc import evict_to_target

    cache = tmp_path / "file_chunks"
    cache.mkdir()
    now = time.time()
    n = 1000
    chunk_size = 65536
    for i in range(n):
        h = f"{i:064x}"
        prefix = cache / h[:2]
        prefix.mkdir(parents=True, exist_ok=True)
        (prefix / h[2:]).write_bytes(b"\0" * chunk_size)
        # Backdate everything past the min_age floor.
        os.utime(prefix / h[2:], (now - 86400 * 30, now - 86400 * 30))

    class _NoopState:
        def forget_chunk_available(self, _h: str) -> None: pass

    t0 = time.perf_counter()
    report = evict_to_target(
        cache,
        max_bytes=(n * chunk_size) // 4,  # force aggressive eviction
        target_bytes=(n * chunk_size) // 8,
        state=_NoopState(),
        min_age_seconds=0,
        now=now,
    )
    elapsed = time.perf_counter() - t0
    assert report.evicted_files > 0, "eviction did not run"
    assert elapsed < 2.0, (
        f"cache GC took {elapsed:.2f}s for {n} entries — investigate."
    )


# ──────────────────────────────────────────────────────────────────
# Sidecar IO regression gate
# ──────────────────────────────────────────────────────────────────

def test_perf_gate_sidecar_write_under_5ms(tmp_path: Path) -> None:
    """Resume sidecar persist must stay under 5 ms per op. The
    daemon writes one per 64 chunks at the debounce cadence; a
    multi-ms regression here would dominate wall-time on big
    transfers. Current: ~740 µs. Cap at 5 ms gives ~7× margin."""
    from one_link.resume import ResumeSidecar, persist_sidecar

    inbox = tmp_path / "inbox"
    inbox.mkdir()
    partial = inbox / "x.bin"
    partial.write_bytes(b"x" * 64)
    sc = ResumeSidecar(
        blob_hex="a" * 64,
        peer_fp="P" * 64,
        name="perf.bin",
        size=4096,
        out_path=str(partial),
        cdc_chunks=[
            {"index": 0, "hash": "a" * 64, "size": 4096, "start": 0, "end": 4096},
        ],
    )

    # 100 round-trips, take the median so a single GC pause
    # doesn't blow up the average.
    durations: list[float] = []
    for _ in range(100):
        t0 = time.perf_counter()
        persist_sidecar(inbox, sc)
        durations.append(time.perf_counter() - t0)
    median_us = statistics.median(durations) * 1e6
    assert median_us < 5000.0, (
        f"sidecar persist median {median_us:.0f} µs exceeds the "
        f"5 ms regression cap. Disk slow? Schema bloated?"
    )
