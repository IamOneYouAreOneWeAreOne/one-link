"""Test harness for spawning real daemons in subprocesses.

Each `daemon_pair()` invocation spins up two independent daemons in temp
ONE_LINK_HOME directories, waits for mDNS discovery to converge, and yields
control ports + identities for the test body. Cleans up on exit.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass
class DaemonHandle:
    home: Path
    log: Path
    proc: subprocess.Popen
    control_port: int
    peer_port: int
    short_id: str
    hostname: str
    # Audit fix: keep the log file handle on the handle so it can be
    # closed deterministically on _stop. Without this Python's GC
    # closes the BufferedWriter at finalization time, emitting a
    # ResourceWarning that shows up under pytest -W error::ResourceWarning.
    log_fh: object | None = None


@dataclass
class DaemonPair:
    a: DaemonHandle
    b: DaemonHandle
    tmp: Path


def _read_port(home: Path, name: str, timeout: float = 15.0) -> int:
    p = home / "data" / name
    end = time.time() + timeout
    while time.time() < end:
        if p.exists():
            try:
                return int(p.read_text().strip())
            except (ValueError, OSError):
                pass
        time.sleep(0.05)
    raise RuntimeError(f"port file did not appear: {p}")


def _wait_port(port: int, timeout: float = 5.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            s.connect(("127.0.0.1", port))
            return True
        except OSError:
            time.sleep(0.05)
        finally:
            s.close()
    return False


def request(control_port: int, *, timeout: float = 30.0, **req) -> dict:
    """Send a single control request and read one JSON response line.

    Under Windows TCP control-socket churn (documented in
    test_two_device_soak.py:85), a freshly-accepted connection can
    drop EOF before the daemon's reader serves the request, OR a
    fresh connect() can hit ConnectionRefusedError when the
    accept queue is briefly drained under suite-level resource
    pressure. Both surface as either an empty response or a
    refused connect.

    Retry up to 3 times with exponential backoff (0.1, 0.4, 1.6s)
    so an 11-minute suite under heavy subprocess churn doesn't
    spuriously fail on transient TCP-stack hiccups. A real daemon
    crash (proc.poll() != None) is undetectable from this side,
    but the timeout still caps the total wait at ~timeout seconds.
    """
    import time as _time
    last_buf = b""
    last_exc: Exception | None = None
    backoff_s = (0.1, 0.4, 1.6)
    max_attempts = len(backoff_s) + 1
    for attempt in range(max_attempts):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            try:
                s.connect(("127.0.0.1", control_port))
                s.sendall((json.dumps(req) + "\n").encode("utf-8"))
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
            except (ConnectionAbortedError, ConnectionResetError, OSError) as e:
                last_exc = e
                buf = b""
        finally:
            s.close()
        last_buf = buf
        if buf and buf.endswith(b"\n"):
            return json.loads(buf.decode("utf-8").strip() or "{}")
        if attempt < len(backoff_s):
            _time.sleep(backoff_s[attempt])
    if last_exc is not None and not last_buf:
        raise last_exc
    return json.loads(last_buf.decode("utf-8").strip() or "{}")


def _spawn(home: Path, log: Path) -> tuple[subprocess.Popen, object]:
    """Returns (proc, log_fh). Caller stores the log_fh on the handle
    and closes it after the proc exits — keeps Python's GC from
    emitting ResourceWarning at random later moments."""
    env = dict(os.environ)
    env["ONE_LINK_HOME"] = str(env.get("ONE_LINK_HOME") or "") or str(home)
    env["ONE_LINK_HOME"] = str(home)  # always per-test
    env["ONE_LINK_ALLOW_SAME_HOST_PEERS"] = "1"
    # 2026-05-22 UX: the production default changed to LAN-bind
    # (0.0.0.0) so phones can complete the pair flow without an env
    # var. Tests stay loopback-only — they don't need LAN exposure
    # and binding 0.0.0.0 conflicts with any other daemon (test or
    # real) holding the well-known port on a different interface.
    env.setdefault("ONE_LINK_BIND_HOST", "127.0.0.1")
    # v0.7.x: defence-in-depth. conftest.py already sets this at
    # module-import time, but if a future test path starts a daemon
    # before conftest runs (or via a different code path), keep
    # tests from popping real Explorer windows on the developer.
    env.setdefault("ONE_LINK_DISABLE_REVEAL", "1")
    # Wave 2g+ test hook ``_send_raw_message`` is hardened behind
    # this env in production so it doesn't ship a control-plane
    # bypass. Test daemons explicitly opt in.
    env.setdefault("ONE_LINK_DEV_HOOKS", "1")
    # v0.21.x: rotation integration test uses /api/peers/{fp}/_test_force_dial
    # to skip mDNS rediscovery after a daemon restart. The endpoint is
    # 404 unless this env is set — keeps the surface inert in
    # production builds.
    env.setdefault("ONE_LINK_ENABLE_TEST_API", "1")
    log.parent.mkdir(parents=True, exist_ok=True)
    f = open(log, "wb")
    proc = subprocess.Popen(
        [sys.executable, "-m", "one_link.cli", "daemon", "-v"],
        env=env,
        stdout=f,
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )
    return proc, f


def _stop(proc: subprocess.Popen) -> None:
    """Stop a test daemon GRACEFULLY so it has a chance to send mDNS goodbye
    packets — this is what stops cross-test pollution where a dead daemon's
    record lingers in another daemon's discovery registry.

    On Windows we send Ctrl+Break (the daemon is in its own process group).
    The daemon's outer try/except turns it into KeyboardInterrupt, which
    triggers Daemon.stop() → Discovery.stop() → async_unregister_service.

    On POSIX, SIGTERM does the same job via Python's default signal handling.
    SIGKILL (terminate's behaviour on Windows, .kill() everywhere) is the
    last-resort fallback.
    """
    if proc.poll() is not None:
        return

    import signal

    sent_graceful = False
    try:
        if os.name == "nt":
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proc.send_signal(signal.SIGTERM)
        sent_graceful = True
    except Exception:
        pass

    if sent_graceful:
        try:
            proc.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            pass

    # Fall through: hard terminate / kill
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        proc.wait(timeout=5)


def _read_log(p: Path, n: int = 4000) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")[-n:]
    except OSError:
        return "<no log>"


def _bring_up(home: Path, log: Path, label: str) -> DaemonHandle:
    proc, log_fh = _spawn(home, log)
    try:
        ctrl = _read_port(home, "control.port")
        peer = _read_port(home, "peer.port")
        if not _wait_port(ctrl, timeout=8.0):
            raise RuntimeError(
                f"daemon {label} control socket not responsive\n--- log ---\n"
                f"{_read_log(log)}"
            )
        info = request(ctrl, cmd="peers")
        if not info.get("ok"):
            raise RuntimeError(f"daemon {label} 'peers' failed: {info}")
        # The control socket coming up does NOT imply the HTTP server
        # has finished initializing - control + HTTP run as separate
        # tasks. ui.token + server.port get written by the HTTP server's
        # startup hook, and tests that read those files via
        # ``home/"data"/"ui.token"`` can race the writes under load.
        # Wait up to 6s for both files to appear before returning so
        # the test never sees a missing-file FileNotFoundError.
        http_deadline = time.time() + 6.0
        ui_token_path = home / "data" / "ui.token"
        server_port_path = home / "data" / "server.port"
        while time.time() < http_deadline:
            if ui_token_path.is_file() and server_port_path.is_file():
                # Files exist; one more guard against partial writes.
                # Both files are tiny so any non-empty read is the
                # finished write (atomic rename or single-write).
                try:
                    if (
                        ui_token_path.stat().st_size > 0
                        and server_port_path.stat().st_size > 0
                    ):
                        break
                except OSError:
                    pass
            time.sleep(0.05)
        else:
            raise RuntimeError(
                f"daemon {label} HTTP server did not write ui.token + "
                f"server.port within 6s\n--- log ---\n{_read_log(log)}"
            )
        return DaemonHandle(
            home=home,
            log=log,
            proc=proc,
            control_port=ctrl,
            peer_port=peer,
            short_id=info["me"]["short_id"],
            hostname=info["me"]["hostname"],
            log_fh=log_fh,
        )
    except Exception:
        _stop(proc)
        try:
            log_fh.close()
        except Exception:
            pass
        raise


@contextmanager
def daemon_pair() -> Iterator[DaemonPair]:
    """Spin up two daemons, wait for mDNS convergence, yield, then tear down."""
    tmp = Path(tempfile.mkdtemp(prefix="one_link_it_"))
    a_home = tmp / "A"
    b_home = tmp / "B"
    a_home.mkdir()
    b_home.mkdir()
    a_log = tmp / "a.log"
    b_log = tmp / "b.log"
    a: DaemonHandle | None = None
    b: DaemonHandle | None = None
    try:
        a = _bring_up(a_home, a_log, "A")
        b = _bring_up(b_home, b_log, "B")
        # Wait for cross-discovery
        deadline = time.time() + 20.0
        while time.time() < deadline:
            ra = request(a.control_port, cmd="peers")
            rb = request(b.control_port, cmd="peers")
            a_sees_b = any(p["short_id"] == b.short_id for p in ra.get("peers", []))
            b_sees_a = any(p["short_id"] == a.short_id for p in rb.get("peers", []))
            if a_sees_b and b_sees_a:
                break
            time.sleep(0.25)
        else:
            raise RuntimeError(
                "mDNS discovery did not converge in 20s\n"
                f"A.peers = {ra.get('peers')}\nB.peers = {rb.get('peers')}\n"
                f"--- A log ---\n{_read_log(a_log)}\n"
                f"--- B log ---\n{_read_log(b_log)}"
            )
        yield DaemonPair(a=a, b=b, tmp=tmp)
    finally:
        if a is not None:
            _stop(a.proc)
            try:
                if a.log_fh is not None:
                    a.log_fh.close()
            except Exception:
                pass
        if b is not None:
            _stop(b.proc)
            try:
                if b.log_fh is not None:
                    b.log_fh.close()
            except Exception:
                pass
        # Best-effort cleanup. Keep on failure so logs survive — pytest
        # passes/fails are signalled separately.
        try:
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            pass


async def await_peer_in_api(
    session,
    base: str,
    token: str,
    short_id: str,
    *,
    timeout: float = 8.0,
) -> dict:
    """Poll GET /api/peers until a peer with `short_id` appears, or fail.

    Eliminates an entire class of cross-test flakes: under heavy CI load the
    HTTP /api/peers endpoint can momentarily return an empty list even after
    mDNS has converged at the daemon's discovery registry, because the daemon
    coalesces some state via async tasks. Bare `next(p for p in peers if ...)`
    against the snapshot then raises StopIteration which Python turns into
    `RuntimeError: coroutine raised StopIteration`. Use this helper instead.
    """
    import time as _time
    deadline = _time.time() + timeout
    last: list[dict] = []
    while _time.time() < deadline:
        async with session.get(
            base + "/api/peers",
            headers={"X-One-Link-Token": token},
        ) as r:
            j = await r.json()
        last = j.get("peers", [])
        for pp in last:
            if pp.get("short_id") == short_id:
                return pp
        await _async_sleep_short()
    raise AssertionError(
        f"peer {short_id} did not appear in /api/peers within {timeout}s; "
        f"last snapshot: {last!r}"
    )


async def _async_sleep_short() -> None:
    import asyncio as _asyncio
    await _asyncio.sleep(0.05)


def message_log(home: Path) -> list[dict]:
    """Read message history from the daemon's sqlite state, returning dicts
    in the same wire-shape the JSONL log used. Tests written before the
    sqlite migration still work."""
    db = home / "data" / "state.db"
    if not db.exists():
        return []
    import sqlite3
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, ts_ms, direction, peer_fp, msg_type, body, room_id, "
            "metadata_json FROM messages ORDER BY ts_ms"
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []
    finally:
        conn.close()
    out: list[dict] = []
    for r in rows:
        try:
            md = json.loads(r["metadata_json"]) if r["metadata_json"] else {}
        except Exception:
            md = {}
        d = {
            "t": r["msg_type"],
            "id": r["id"],
            "ts": r["ts_ms"],
            "dir": r["direction"],
            "peer_fp": r["peer_fp"],
            "peer": md.get("short_id") or (r["peer_fp"][:8] if r["peer_fp"] else "?"),
            "room_id": r["room_id"],
        }
        if r["body"] is not None:
            d["body"] = r["body"]
        for k, v in md.items():
            if k != "short_id" and k not in d:
                d[k] = v
        out.append(d)
    return out


def inbox_files(home: Path) -> list[Path]:
    p = home / "data" / "inbox"
    if not p.exists():
        return []
    # Filter to actual files. The daemon stashes a ``.resume``
    # sidecar subdirectory next to the user-visible payloads; if we
    # returned that, callers iterating with .read_bytes() would
    # PermissionError on the directory entry.
    return sorted(e for e in p.iterdir() if e.is_file())


def wait_for_inbox_file(
    home: Path,
    name_suffix: str,
    *,
    expected_size: int | None = None,
    timeout: float = 15.0,
    poll_interval: float = 0.05,
    stable_for: float = 0.2,
) -> Path:
    """Wait until a file whose name ends with ``name_suffix`` appears in
    the daemon's inbox AND the size has stabilised. Returns the
    matching Path. Raises ``AssertionError`` if the file does not
    appear within ``timeout``, or never settles.

    ``expected_size`` — if set, wait until the file is at least that
    large. The receiver creates the inbox file when streaming starts,
    not when the transfer completes; without a size gate the caller
    races a partially-written file.

    ``stable_for`` — additional seconds the size must remain unchanged
    before the file is considered settled. Cheap insurance against the
    last-chunk-still-flushing race.

    Replaces brittle ``time.sleep(N)`` patterns in integration tests
    with an event-driven check that keeps the suite fast on a hot box
    and reliable on a slow one (CI, AV scan, hot native rebuild)."""
    deadline = time.monotonic() + timeout
    last_files: list[Path] = []
    target: Path | None = None
    while time.monotonic() < deadline:
        last_files = inbox_files(home)
        for f in last_files:
            if f.name.endswith(name_suffix):
                target = f
                break
        if target is not None:
            try:
                size = target.stat().st_size
            except FileNotFoundError:
                target = None
                time.sleep(poll_interval)
                continue
            if expected_size is None or size >= expected_size:
                stable_until = time.monotonic() + stable_for
                last_size = size
                ok = True
                while time.monotonic() < stable_until:
                    time.sleep(poll_interval)
                    try:
                        cur = target.stat().st_size
                    except FileNotFoundError:
                        ok = False
                        break
                    if cur != last_size:
                        last_size = cur
                        stable_until = time.monotonic() + stable_for
                if ok:
                    return target
        time.sleep(poll_interval)
    raise AssertionError(
        f"timed out after {timeout}s waiting for stable inbox file "
        f"ending with {name_suffix!r} "
        f"(expected_size={expected_size}); saw {[f.name for f in last_files]}"
    )
