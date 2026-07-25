"""Daemon-pair reliability harness: drive many pairs through the
real pair → send-message → send-file flow, count failures per step.

Replaces the ROADMAP's ⚠️ "untested" / "should work" entries with
measured truth. If the project's promise is 'unbelievably reliable',
the metric is: out of N pair attempts under realistic conditions,
how many complete cleanly? This script reports that number.

Each iteration:
  1. Spawn daemon A in a fresh ONE_LINK_HOME, wait for ready.
  2. Spawn daemon B in a fresh ONE_LINK_HOME, wait for ready.
  3. A reads its /api/me + B reads its /api/me (sanity).
  4. (Cleanup pass): tear down both daemons, wait for ports to free.
  5. Record per-step outcome + duration.

A full pair flow (QR mint + scan + confirm + send-msg + send-file)
needs network discovery + the WebRTC bridge, which doesn't work
fully over loopback without UI. For now the harness covers the
spawn / boot / port-bind / API-reachable steps - the same gates
the synthetic monitor checks, but at scale + with summary stats
that can feed back into the ROADMAP capability table.

Output: single JSON object on stdout. Per-step pass/fail rate +
latency percentiles + the full list of failures (with daemon log
tails attached for debugging).

Usage:

    python scripts/reliability_harness.py --pairs 10
    python scripts/reliability_harness.py --pairs 50 --out r.json
    python scripts/reliability_harness.py --pairs 5 --parallel 3
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from one_link import app as app_mod
from one_link import control_ipc

# ── per-pair execution ─────────────────────────────────────────────


@dataclass
class StepTrace:
    name: str
    ok: bool
    duration_ms: int
    error: str = ""


@dataclass
class PairResult:
    pair_id: int
    ok: bool
    duration_ms: int
    steps: list[StepTrace] = field(default_factory=list)
    log_tail_on_failure: str = ""


def _spawn(home: Path, log: Path) -> subprocess.Popen:
    env = os.environ.copy()
    env["ONE_LINK_HOME"] = str(home)
    env["ONE_LINK_BIND_HOST"] = "127.0.0.1"
    env["ONE_LINK_DISABLE_NATIVE_PICKER"] = "1"
    log_fh = log.open("ab", buffering=0)
    return subprocess.Popen(
        [sys.executable, "-m", "one_link.cli", "daemon"],
        env=env, stdout=log_fh, stderr=subprocess.STDOUT,
        cwd=str(Path(__file__).resolve().parent.parent),
    )


def _stop(proc: subprocess.Popen) -> None:
    with contextlib.suppress(Exception):
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def _wait_ready(home: Path, timeout: float) -> tuple[int, str] | None:
    """Return (port, token) only after control and UI mutual authentication."""
    deadline = time.time() + timeout
    data = home / "data"
    while time.time() < deadline:
        try:
            control_port = int(
                control_ipc.read_private_bytes_strict(
                    data / "control.port",
                    max_bytes=64,
                    label="control port",
                )
                .decode("ascii")
                .strip()
            )
            secret = control_ipc.read_control_secret(data)
            daemon = app_mod.resolve_authenticated_daemon(
                control_port,
                secret,
                timeout=2.0,
            )
            if daemon is not None:
                return daemon.server_port, daemon.token
        except (ValueError, OSError, RuntimeError):
            pass
        time.sleep(0.05)
    return None


def _api_me(port: int, token: str, timeout: float = 5.0) -> dict | None:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        # The URL is constructed locally from an integer daemon port; no
        # caller-controlled scheme can reach urlopen.
        with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310
            return json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None


def _api_peers(port: int, token: str, timeout: float = 5.0) -> list | None:
    """List peers visible to this daemon via mDNS discovery."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/peers?include_unpaired=1",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        # Fixed loopback HTTP request; see _api_me above.
        with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310
            data = json.loads(r.read().decode("utf-8"))
            return data.get("peers", [])
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None


def _wait_for_peer_via_discovery(
    port: int, token: str, target_fp: str, timeout: float,
) -> bool:
    """Poll /api/peers until the target fingerprint appears.
    Returns True if seen within timeout, False otherwise."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        peers = _api_peers(port, token, timeout=2.0)
        if peers is not None:
            for p in peers:
                if p.get("fingerprint") == target_fp:
                    return True
        time.sleep(0.5)
    return False


def _now_ms() -> int:
    return int(time.monotonic() * 1000)


def run_one_pair(pair_id: int, tmpdir: Path) -> PairResult:
    """Drive one pair through the spawn-and-handshake flow."""
    a_home = tmpdir / f"pair_{pair_id}_a"
    b_home = tmpdir / f"pair_{pair_id}_b"
    a_home.mkdir(parents=True, exist_ok=True)
    b_home.mkdir(parents=True, exist_ok=True)
    a_log = tmpdir / f"pair_{pair_id}_a.log"
    b_log = tmpdir / f"pair_{pair_id}_b.log"

    result = PairResult(pair_id=pair_id, ok=False, duration_ms=0)
    overall_t0 = _now_ms()
    a_proc: subprocess.Popen | None = None
    b_proc: subprocess.Popen | None = None
    try:
        # Step 1: spawn A
        t0 = _now_ms()
        try:
            a_proc = _spawn(a_home, a_log)
            a_ready = _wait_ready(a_home, timeout=30.0)
            if a_ready is None:
                raise RuntimeError("A never wrote ready files")
            a_port, a_tok = a_ready
            result.steps.append(StepTrace("spawn_a", True, _now_ms() - t0))
        except Exception as e:
            result.steps.append(StepTrace("spawn_a", False, _now_ms() - t0, str(e)))
            return result

        # Step 2: spawn B
        t0 = _now_ms()
        try:
            b_proc = _spawn(b_home, b_log)
            b_ready = _wait_ready(b_home, timeout=30.0)
            if b_ready is None:
                raise RuntimeError("B never wrote ready files")
            b_port, b_tok = b_ready
            result.steps.append(StepTrace("spawn_b", True, _now_ms() - t0))
        except Exception as e:
            result.steps.append(StepTrace("spawn_b", False, _now_ms() - t0, str(e)))
            return result

        # Step 3: A.api_me
        t0 = _now_ms()
        a_me = _api_me(a_port, a_tok)
        if a_me and a_me.get("fingerprint"):
            result.steps.append(StepTrace("api_me_a", True, _now_ms() - t0))
        else:
            result.steps.append(StepTrace(
                "api_me_a", False, _now_ms() - t0,
                f"api_me returned no fingerprint: {a_me}"
            ))
            return result

        # Step 4: B.api_me
        t0 = _now_ms()
        b_me = _api_me(b_port, b_tok)
        if b_me and b_me.get("fingerprint"):
            result.steps.append(StepTrace("api_me_b", True, _now_ms() - t0))
        else:
            result.steps.append(StepTrace(
                "api_me_b", False, _now_ms() - t0,
                f"api_me returned no fingerprint: {b_me}"
            ))
            return result

        # Step 5: distinct identities (catches a startup-reset bug
        # where both daemons accidentally derive the same identity)
        t0 = _now_ms()
        if a_me["fingerprint"] != b_me["fingerprint"]:
            result.steps.append(StepTrace("distinct_identity", True, _now_ms() - t0))
        else:
            result.steps.append(StepTrace(
                "distinct_identity", False, _now_ms() - t0,
                f"A and B derived the same fingerprint: {a_me['fingerprint']}"
            ))
            return result

        # Step 6: each daemon can read its own peer list cleanly.
        # /api/peers exercises a different code path than /api/me
        # (state.list_peers + JSON serialization + auth on a
        # query-param-bearing route). A regression in any of those
        # would surface here. Note: this does NOT exercise mDNS
        # cross-discovery - both daemons are bound to 127.0.0.1
        # by design (we don't want CI runners broadcasting on
        # the host's LAN), and mDNS doesn't traverse loopback.
        # Real cross-daemon discovery is exercised by
        # tests/test_integration.py + tests/test_pairing.py which
        # use a different binding strategy.
        t0 = _now_ms()
        a_peers = _api_peers(a_port, a_tok)
        if a_peers is None:
            result.steps.append(StepTrace(
                "api_peers_a", False, _now_ms() - t0,
                "/api/peers returned no parseable response",
            ))
            return result
        result.steps.append(StepTrace("api_peers_a", True, _now_ms() - t0))

        t0 = _now_ms()
        b_peers = _api_peers(b_port, b_tok)
        if b_peers is None:
            result.steps.append(StepTrace(
                "api_peers_b", False, _now_ms() - t0,
                "/api/peers returned no parseable response",
            ))
            return result
        result.steps.append(StepTrace("api_peers_b", True, _now_ms() - t0))

        result.ok = all(s.ok for s in result.steps)
    finally:
        if a_proc is not None:
            _stop(a_proc)
        if b_proc is not None:
            _stop(b_proc)
        # Capture log tails on failure only.
        if not result.ok:
            tails = []
            if a_log.is_file():
                tails.append("--- A log tail ---\n"
                             + a_log.read_text(encoding="utf-8", errors="replace")[-1500:])
            if b_log.is_file():
                tails.append("--- B log tail ---\n"
                             + b_log.read_text(encoding="utf-8", errors="replace")[-1500:])
            result.log_tail_on_failure = "\n".join(tails)
        result.duration_ms = _now_ms() - overall_t0
    return result


# ── aggregate ─────────────────────────────────────────────────────


def _summarize(pair_results: list[PairResult]) -> dict[str, Any]:
    """Per-step pass rate + latency percentiles + failure list."""
    step_names: list[str] = []
    for r in pair_results:
        for s in r.steps:
            if s.name not in step_names:
                step_names.append(s.name)

    step_summary: dict[str, dict[str, Any]] = {}
    for name in step_names:
        runs = [
            s for r in pair_results for s in r.steps if s.name == name
        ]
        durations = [s.duration_ms for s in runs if s.ok]
        passes = sum(1 for s in runs if s.ok)
        fails = sum(1 for s in runs if not s.ok)
        step_summary[name] = {
            "pass_count": passes,
            "fail_count": fails,
            "pass_rate": passes / (passes + fails) if (passes + fails) else 0.0,
            "p50_ms": int(statistics.median(durations)) if durations else None,
            "p95_ms": (
                int(sorted(durations)[max(0, int(len(durations) * 0.95) - 1)])
                if durations else None
            ),
            "max_ms": max(durations) if durations else None,
        }

    overall_pass = sum(1 for r in pair_results if r.ok)
    overall_fail = len(pair_results) - overall_pass
    failures = [
        {
            "pair_id": r.pair_id,
            "failed_step": next((s.name for s in r.steps if not s.ok), "unknown"),
            "error": next((s.error for s in r.steps if not s.ok), ""),
            "log_tail": r.log_tail_on_failure,
        }
        for r in pair_results if not r.ok
    ]
    return {
        "ts_ms": int(time.time() * 1000),
        "pair_count": len(pair_results),
        "overall_pass": overall_pass,
        "overall_fail": overall_fail,
        "overall_pass_rate": overall_pass / len(pair_results) if pair_results else 0.0,
        "step_summary": step_summary,
        "failures": failures,
    }


def main() -> int:
    p = argparse.ArgumentParser(description="One Link daemon-pair reliability harness")
    p.add_argument("--pairs", type=int, default=10, help="Number of pair attempts (default 10)")
    p.add_argument("--parallel", type=int, default=1,
                   help="Concurrent pair workers (default 1). >1 stresses port-binding.")
    p.add_argument("--out", type=Path, help="Write JSON summary to this path too")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args()

    def log(msg: str) -> None:
        if not args.quiet:
            print(msg, file=sys.stderr, flush=True)

    tmp = Path(tempfile.mkdtemp(prefix="ol_reliability_"))
    try:
        log(f"running {args.pairs} pair attempt(s), parallel={args.parallel}")
        results: list[PairResult] = []
        if args.parallel <= 1:
            for i in range(args.pairs):
                log(f"  pair {i+1}/{args.pairs}")
                r = run_one_pair(i, tmp)
                results.append(r)
                status = "PASS" if r.ok else f"FAIL ({next((s.name for s in r.steps if not s.ok), 'unknown')})"
                log(f"    -> {status} in {r.duration_ms} ms")
        else:
            with ThreadPoolExecutor(max_workers=args.parallel) as ex:
                futures = {
                    ex.submit(run_one_pair, i, tmp): i for i in range(args.pairs)
                }
                for fut in as_completed(futures):
                    r = fut.result()
                    results.append(r)
                    status = "PASS" if r.ok else "FAIL"
                    log(f"  pair {r.pair_id}: {status} in {r.duration_ms} ms")
            results.sort(key=lambda r: r.pair_id)

        summary = _summarize(results)
        text = json.dumps(summary, indent=2, sort_keys=True)
        print(text)
        if args.out:
            args.out.write_text(text + "\n", encoding="utf-8")
        # Exit non-zero if ANY pair failed.
        return 0 if summary["overall_fail"] == 0 else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
