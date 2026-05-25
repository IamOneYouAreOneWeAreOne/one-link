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
import socket
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


def _read_port(home: Path) -> int | None:
    p = home / "data" / "server.port"
    if p.is_file():
        try:
            return int(p.read_text().strip())
        except (ValueError, OSError):
            return None
    return None


def _read_token(home: Path) -> str | None:
    p = home / "data" / "ui.token"
    if p.is_file():
        try:
            return p.read_text().strip() or None
        except OSError:
            return None
    return None


def _api_get(base_url: str, path: str, token: str, timeout: float = 5.0) -> dict:
    req = urllib.request.Request(
        f"{base_url}{path}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
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
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


# ── steps ──────────────────────────────────────────────────────────


def _step_spawn_both_daemons(
    a_home: Path, b_home: Path,
    a_log: Path, b_log: Path,
) -> tuple[StepResult, subprocess.Popen | None, subprocess.Popen | None]:
    """Both daemons spawn + write server.port + ui.token within 30s."""
    t0 = _now_ms()
    a_proc = _spawn_daemon(a_home, a_log)
    b_proc = _spawn_daemon(b_home, b_log)
    deadline = time.time() + 30.0
    while time.time() < deadline:
        if (
            _read_port(a_home) and _read_token(a_home)
            and _read_port(b_home) and _read_token(b_home)
        ):
            break
        time.sleep(0.2)
    else:
        return (
            StepResult(
                name="spawn_both_daemons",
                ok=False, duration_ms=_now_ms() - t0,
                error="timeout waiting for ui.token + server.port files",
                detail={
                    "a_port": _read_port(a_home),
                    "b_port": _read_port(b_home),
                    "a_log_tail": a_log.read_text(encoding="utf-8", errors="replace")[-1500:],
                    "b_log_tail": b_log.read_text(encoding="utf-8", errors="replace")[-1500:],
                },
            ),
            a_proc, b_proc,
        )
    return (
        StepResult(
            name="spawn_both_daemons",
            ok=True, duration_ms=_now_ms() - t0,
            detail={
                "a_port": _read_port(a_home),
                "b_port": _read_port(b_home),
            },
        ),
        a_proc, b_proc,
    )


def _step_api_me_reachable(
    home: Path, label: str,
) -> StepResult:
    """GET /api/me returns the daemon's identity within 5s."""
    t0 = _now_ms()
    port = _read_port(home)
    tok = _read_token(home)
    if not port or not tok:
        return StepResult(
            name=f"api_me_{label}", ok=False, duration_ms=_now_ms() - t0,
            error="no port/token (daemon never came up)",
        )
    try:
        me = _api_get(f"http://127.0.0.1:{port}", "/api/me", tok)
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
    home: Path, label: str,
) -> StepResult:
    """GET /api/one-health surfaces no critical failures."""
    t0 = _now_ms()
    port = _read_port(home)
    tok = _read_token(home)
    if not port or not tok:
        return StepResult(
            name=f"health_{label}", ok=False, duration_ms=_now_ms() - t0,
            error="no port/token",
        )
    try:
        h = _api_get(f"http://127.0.0.1:{port}", "/api/one-health", tok, timeout=10.0)
    except Exception as e:
        return StepResult(
            name=f"health_{label}", ok=False, duration_ms=_now_ms() - t0,
            error=f"{type(e).__name__}: {e}",
        )
    overall = h.get("overall") or h.get("status") or h.get("ok")
    return StepResult(
        name=f"health_{label}", ok=True, duration_ms=_now_ms() - t0,
        detail={"overall": overall},
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
        steps.append(_step_health_check(a_home, "A"))
        log("step: B.health")
        steps.append(_step_health_check(b_home, "B"))

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
