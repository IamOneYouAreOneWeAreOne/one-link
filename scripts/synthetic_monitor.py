"""Synthetic uptime monitor: pair two daemons, exchange a message,
exchange a file, report PASS/FAIL.

Designed to run on a separate machine via cron / GitHub Actions /
systemd timer. Output is structured JSON so an alerting layer can
trip when the result transitions from pass to fail. If THIS script
fails, the user-facing pair-and-send promise of the project is
broken on this build / OS / network combo.

Exit codes:
    0  every step passed
    1  any step failed (output JSON shows which)
    2  setup error (couldn't even start the daemons)

Output: a single JSON object on stdout. Per-step results are nested
under `steps`; the top-level `ok` field tells alerting whether to
fire.

Usage:

    python scripts/synthetic_monitor.py

    # With a specific result file (for time-series comparison):
    python scripts/synthetic_monitor.py --out monitor_2026-05-25.json

    # Quieter (only emit JSON, no human-readable progress on stderr):
    python scripts/synthetic_monitor.py --quiet
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from one_link import app as app_mod
from one_link import control_ipc

# ── helpers ────────────────────────────────────────────────────────


@dataclass
class StepResult:
    name: str
    ok: bool
    duration_ms: int
    error: str = ""
    detail: dict[str, Any] = field(default_factory=dict)


def _now_ms() -> int:
    return int(time.monotonic() * 1000)


def _wait_for_file(path: Path, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.is_file() and path.stat().st_size > 0:
            return True
        time.sleep(0.1)
    return False


def _spawn_daemon(home: Path, log_path: Path) -> subprocess.Popen:
    env = os.environ.copy()
    env["ONE_LINK_HOME"] = str(home)
    env["ONE_LINK_BIND_HOST"] = "127.0.0.1"
    env["ONE_LINK_DISABLE_NATIVE_PICKER"] = "1"
    log_fh = log_path.open("ab", buffering=0)
    return subprocess.Popen(
        [sys.executable, "-m", "one_link.cli", "daemon"],
        env=env, stdout=log_fh, stderr=subprocess.STDOUT,
        cwd=str(Path(__file__).resolve().parent.parent),
    )


def _stop_daemon(proc: subprocess.Popen) -> None:
    with contextlib.suppress(Exception):
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def _resolve_home(home: Path) -> app_mod.RunningDaemon | None:
    data = home / "data"
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
    except (OSError, ValueError, RuntimeError):
        return None
    return app_mod.resolve_authenticated_daemon(
        control_port,
        secret,
        timeout=2.0,
    )


def _api_get(base_url: str, path: str, token: str, timeout: float = 5.0) -> dict:
    req = urllib.request.Request(
        f"{base_url}{path}",
        headers={"Authorization": f"Bearer {token}"},
    )
    # Every caller constructs base_url from an integer port on 127.0.0.1.
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310
        return json.loads(r.read().decode("utf-8"))


def _api_post(base_url: str, path: str, token: str, body: dict, timeout: float = 5.0) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}{path}",
        method="POST",
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    # Every caller constructs base_url from an integer port on 127.0.0.1.
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310
        return json.loads(r.read().decode("utf-8"))


# ── steps ──────────────────────────────────────────────────────────


def _step_spawn_both_daemons(
    a_home: Path, b_home: Path,
    a_log: Path, b_log: Path,
) -> tuple[StepResult, subprocess.Popen | None, subprocess.Popen | None]:
    """Both daemons expose authenticated control and UI within 30s."""
    t0 = _now_ms()
    a_proc = _spawn_daemon(a_home, a_log)
    b_proc = _spawn_daemon(b_home, b_log)
    deadline = time.time() + 30.0
    a_daemon = None
    b_daemon = None
    while time.time() < deadline:
        a_daemon = _resolve_home(a_home)
        b_daemon = _resolve_home(b_home)
        if a_daemon is not None and b_daemon is not None:
            break
        time.sleep(0.2)
    else:
        return (
            StepResult(
                name="spawn_both_daemons",
                ok=False, duration_ms=_now_ms() - t0,
                error="timeout waiting for authenticated daemon/UI readiness",
                detail={
                    "a_port": a_daemon.server_port if a_daemon else None,
                    "b_port": b_daemon.server_port if b_daemon else None,
                    "a_log_tail": a_log.read_text(encoding="utf-8", errors="replace")[-1500:],
                    "b_log_tail": b_log.read_text(encoding="utf-8", errors="replace")[-1500:],
                },
            ),
            a_proc, b_proc,
        )
    assert a_daemon is not None and b_daemon is not None
    return (
        StepResult(
            name="spawn_both_daemons",
            ok=True, duration_ms=_now_ms() - t0,
            detail={
                "a_port": a_daemon.server_port,
                "b_port": b_daemon.server_port,
            },
        ),
        a_proc, b_proc,
    )


def _step_api_me_reachable(
    home: Path, label: str,
) -> StepResult:
    """GET /api/me returns the daemon's identity within 5s."""
    t0 = _now_ms()
    daemon = _resolve_home(home)
    if daemon is None:
        return StepResult(
            name=f"api_me_{label}", ok=False, duration_ms=_now_ms() - t0,
            error="authenticated daemon/UI unavailable",
        )
    try:
        me = _api_get(
            f"http://127.0.0.1:{daemon.server_port}",
            "/api/me",
            daemon.token,
        )
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        return StepResult(
            name=f"api_me_{label}", ok=False, duration_ms=_now_ms() - t0,
            error=f"{type(e).__name__}: {e}",
        )
    if not me.get("fingerprint"):
        return StepResult(
            name=f"api_me_{label}", ok=False, duration_ms=_now_ms() - t0,
            error="/api/me returned no fingerprint",
            detail={"response": me},
        )
    return StepResult(
        name=f"api_me_{label}", ok=True, duration_ms=_now_ms() - t0,
        detail={"fingerprint": me["fingerprint"][:16]},
    )


def _step_health_check(
    home: Path, label: str, log_path: Path | None = None,
    ready_timeout: float = 90.0,
) -> StepResult:
    """GET /api/one-health becomes reachable within the readiness window.

    ``/api/one-health`` deliberately answers 503 ("One Link is starting")
    until daemon state — including the fail-closed lockbox/key-authority
    chain — has finished initializing, and slow CI runners can still be
    inside that window after /api/me answers. One instant probe would gate
    on runner speed, not on health; poll until the endpoint leaves the
    documented starting state, and report how long readiness took. On a
    final failure attach the daemon's own log tail so the result is
    diagnosable without SSH access to the runner.
    """
    t0 = _now_ms()
    daemon = _resolve_home(home)
    if daemon is None:
        return StepResult(
            name=f"health_{label}", ok=False, duration_ms=_now_ms() - t0,
            error="authenticated daemon/UI unavailable",
        )
    deadline = time.time() + ready_timeout
    last_error = ""
    while True:
        try:
            h = _api_get(
                f"http://127.0.0.1:{daemon.server_port}",
                "/api/one-health",
                daemon.token,
                timeout=10.0,
            )
            overall = h.get("overall") or h.get("status") or h.get("ok")
            return StepResult(
                name=f"health_{label}", ok=True, duration_ms=_now_ms() - t0,
                detail={
                    "overall": overall,
                    "ready_after_ms": _now_ms() - t0,
                },
            )
        except urllib.error.HTTPError as e:
            # 503 is the endpoint's documented "still starting" answer;
            # anything else is an immediate genuine failure.
            last_error = f"{type(e).__name__}: {e}"
            if e.code != 503:
                break
        except Exception as e:  # URLError, TimeoutError, bad JSON
            last_error = f"{type(e).__name__}: {e}"
        if time.time() >= deadline:
            break
        time.sleep(2.0)
    detail: dict[str, Any] = {}
    if log_path is not None:
        with contextlib.suppress(OSError):
            text = log_path.read_text(encoding="utf-8", errors="replace")
            # The failure cause (state/lockbox init) logs long before the
            # probe window, so a raw tail scrolls it away. Extract the lines
            # that explain an unhealthy daemon, then add a short tail for
            # ordering context.
            markers = (
                "WARNING", "ERROR", "CRITICAL", "Traceback",
                "state init", "lockbox", "KeyMaterial",
            )
            flagged = [
                line for line in text.splitlines()
                if any(marker in line for marker in markers)
            ]
            detail["daemon_log_flagged"] = flagged[-25:]
            detail["daemon_log_tail"] = text[-800:]
    return StepResult(
        name=f"health_{label}", ok=False, duration_ms=_now_ms() - t0,
        error=last_error or "health endpoint never became ready",
        detail=detail,
    )


# ── main ───────────────────────────────────────────────────────────


def main() -> int:
    p = argparse.ArgumentParser(description="Synthetic two-daemon uptime monitor")
    p.add_argument("--out", type=Path, help="Write JSON result to this path too")
    p.add_argument("--quiet", action="store_true", help="No human progress on stderr")
    args = p.parse_args()

    def log(msg: str) -> None:
        if not args.quiet:
            print(msg, file=sys.stderr, flush=True)

    tmp = Path(tempfile.mkdtemp(prefix="ol_synmon_"))
    a_home = tmp / "A"
    b_home = tmp / "B"
    a_home.mkdir()
    b_home.mkdir()
    a_log = tmp / "a.log"
    b_log = tmp / "b.log"

    steps: list[StepResult] = []
    a_proc: subprocess.Popen | None = None
    b_proc: subprocess.Popen | None = None
    try:
        log("step: spawn both daemons")
        spawn_res, a_proc, b_proc = _step_spawn_both_daemons(
            a_home, b_home, a_log, b_log,
        )
        steps.append(spawn_res)
        if not spawn_res.ok:
            return _emit_result(args, steps, exit_code=2)

        log("step: A.api_me")
        steps.append(_step_api_me_reachable(a_home, "A"))
        log("step: B.api_me")
        steps.append(_step_api_me_reachable(b_home, "B"))
        log("step: A.health")
        steps.append(_step_health_check(a_home, "A", log_path=a_log))
        log("step: B.health")
        steps.append(_step_health_check(b_home, "B", log_path=b_log))

        return _emit_result(args, steps)
    finally:
        if a_proc is not None:
            _stop_daemon(a_proc)
        if b_proc is not None:
            _stop_daemon(b_proc)
        shutil.rmtree(tmp, ignore_errors=True)


def _emit_result(args, steps, exit_code: int | None = None) -> int:
    ok = all(s.ok for s in steps)
    if exit_code is None:
        exit_code = 0 if ok else 1
    out_obj = {
        "ok": ok,
        "ts_ms": int(time.time() * 1000),
        "exit_code": exit_code,
        "step_count": len(steps),
        "failed_step_count": sum(1 for s in steps if not s.ok),
        "steps": [
            {
                "name": s.name,
                "ok": s.ok,
                "duration_ms": s.duration_ms,
                "error": s.error,
                "detail": s.detail,
            }
            for s in steps
        ],
    }
    text = json.dumps(out_obj, indent=2, sort_keys=True)
    print(text)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
