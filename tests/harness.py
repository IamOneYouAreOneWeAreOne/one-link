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
    """Send a single control request and read one JSON response line."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(("127.0.0.1", control_port))
    try:
        s.sendall((json.dumps(req) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.decode("utf-8").strip() or "{}")
    finally:
        s.close()


def _spawn(home: Path, log: Path) -> subprocess.Popen:
    env = dict(os.environ)
    env["ONE_LINK_HOME"] = str(home)
    log.parent.mkdir(parents=True, exist_ok=True)
    f = open(log, "wb")
    return subprocess.Popen(
        [sys.executable, "-m", "one_link.cli", "daemon", "-v"],
        env=env,
        stdout=f,
        stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def _read_log(p: Path, n: int = 4000) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")[-n:]
    except OSError:
        return "<no log>"


def _bring_up(home: Path, log: Path, label: str) -> DaemonHandle:
    proc = _spawn(home, log)
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
        return DaemonHandle(
            home=home,
            log=log,
            proc=proc,
            control_port=ctrl,
            peer_port=peer,
            short_id=info["me"]["short_id"],
            hostname=info["me"]["hostname"],
        )
    except Exception:
        _stop(proc)
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
        if b is not None:
            _stop(b.proc)
        # Best-effort cleanup. Keep on failure so logs survive — pytest
        # passes/fails are signalled separately.
        try:
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:
            pass


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
    return sorted(p.iterdir())
