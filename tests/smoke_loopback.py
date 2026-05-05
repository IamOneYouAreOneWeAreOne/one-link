"""Loopback smoke test: spin up two daemons on this PC, run a full round-trip.

Run:
    python tests/smoke_loopback.py

Exits 0 on success, non-zero on any failure. Cleans up daemons on exit.
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
from pathlib import Path


def _wait_port(port: int, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            s.connect(("127.0.0.1", port))
            return True
        except OSError:
            time.sleep(0.1)
        finally:
            s.close()
    return False


def _read_port(home: Path, name: str, timeout: float = 10.0) -> int:
    p = home / "data" / name
    end = time.time() + timeout
    while time.time() < end:
        if p.exists():
            try:
                return int(p.read_text().strip())
            except (ValueError, OSError):
                pass
        time.sleep(0.1)
    raise RuntimeError(f"port file did not appear: {p}")


def _request(control_port: int, **req) -> dict:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(15.0)
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


def _spawn_daemon(home: Path, log_path: Path) -> subprocess.Popen:
    env = dict(os.environ)
    env["ONE_LINK_HOME"] = str(home)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = open(log_path, "wb")
    proc = subprocess.Popen(
        [sys.executable, "-m", "one_link.cli", "daemon", "-v"],
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    return proc


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="one_link_smoke_"))
    home_a = tmp / "A"
    home_b = tmp / "B"
    home_a.mkdir()
    home_b.mkdir()

    log_a = tmp / "a.log"
    log_b = tmp / "b.log"

    print(f"[smoke] tmpdir = {tmp}")
    print("[smoke] starting daemons …")
    proc_a = _spawn_daemon(home_a, log_a)
    proc_b = _spawn_daemon(home_b, log_b)

    failed = True  # default to failed; flip to False only on explicit pass
    try:
        ctrl_a = _read_port(home_a, "control.port")
        ctrl_b = _read_port(home_b, "control.port")
        print(f"[smoke] control ports: A={ctrl_a} B={ctrl_b}")

        if not _wait_port(ctrl_a) or not _wait_port(ctrl_b):
            print("[smoke] FAIL — daemon control sockets not responsive")
            return 1

        # Wait for mDNS to find both peers (zeroconf round-trip can take a few sec)
        print("[smoke] waiting for mDNS discovery …")
        deadline = time.time() + 15.0
        while time.time() < deadline:
            res_a = _request(ctrl_a, cmd="peers")
            res_b = _request(ctrl_b, cmd="peers")
            if (
                res_a.get("ok")
                and res_b.get("ok")
                and len(res_a["peers"]) >= 1
                and len(res_b["peers"]) >= 1
            ):
                break
            time.sleep(0.5)
        else:
            print(f"[smoke] FAIL — mDNS discovery never converged")
            print(f"   A.peers = {res_a.get('peers')}")
            print(f"   B.peers = {res_b.get('peers')}")
            failed = True
            return 1

        a_id = res_a["me"]["short_id"]
        b_id = res_b["me"]["short_id"]
        print(f"[smoke] A={a_id}  B={b_id}")
        print(f"[smoke] A sees: {[p['short_id'] for p in res_a['peers']]}")
        print(f"[smoke] B sees: {[p['short_id'] for p in res_b['peers']]}")

        # Send text A -> B
        print("[smoke] A -> B  TEXT")
        send_res = _request(ctrl_a, cmd="send", peer=b_id, body="hello from A")
        if not send_res.get("ok"):
            print(f"[smoke] FAIL — send: {send_res}")
            failed = True
            return 1
        print(f"   ack = {send_res['result']['ack']['t']}")

        # Verify B logged it
        time.sleep(0.5)
        log_b_path = home_b / "data" / "messages.jsonl"
        if not log_b_path.exists():
            print("[smoke] FAIL — B has no message log")
            failed = True
            return 1
        log_lines = log_b_path.read_text(encoding="utf-8").strip().splitlines()
        text_in = [
            json.loads(L)
            for L in log_lines
            if json.loads(L).get("t") == "TEXT" and json.loads(L).get("dir") == "in"
        ]
        if not text_in or text_in[-1]["body"] != "hello from A":
            print(f"[smoke] FAIL — B did not receive text. log={log_lines}")
            failed = True
            return 1
        print("   B received: " + text_in[-1]["body"])

        # Send a file A -> B
        sample = tmp / "sample.bin"
        sample.write_bytes(os.urandom(750_000))  # 750 KB, spans multiple chunks at 256KB
        print(f"[smoke] A -> B  FILE  ({sample.stat().st_size} bytes)")
        sf = _request(ctrl_a, cmd="send_file", peer=b_id, path=str(sample))
        if not sf.get("ok"):
            print(f"[smoke] FAIL — send_file: {sf}")
            failed = True
            return 1
        blob = sf["result"]["blob"]
        print(f"   blob={blob[:12]}  chunks={sf['result']['chunks']}")

        # Verify on B side
        time.sleep(1.0)
        inbox = home_b / "data" / "inbox"
        matches = list(inbox.glob(f"{blob[:8]}_*"))
        if not matches:
            print(f"[smoke] FAIL — file not in B inbox. ls={list(inbox.iterdir())}")
            failed = True
            return 1
        got = matches[0]
        if got.stat().st_size != sample.stat().st_size:
            print(
                f"[smoke] FAIL — size mismatch: "
                f"sent {sample.stat().st_size}, got {got.stat().st_size}"
            )
            failed = True
            return 1
        if got.read_bytes() != sample.read_bytes():
            print("[smoke] FAIL — bytes mismatch")
            failed = True
            return 1
        print(f"   B received -> {got}  (bytes match)")

        print("[smoke] PASS")
        failed = False
        return 0

    except Exception as e:
        print(f"[smoke] EXCEPTION: {type(e).__name__}: {e}")
        return 1

    finally:
        for p in (proc_a, proc_b):
            try:
                p.terminate()
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        if failed:
            print(f"[smoke] preserving logs at {tmp}")
            print("\n--- A daemon log (tail) ---")
            print(log_a.read_text(encoding="utf-8", errors="replace")[-2000:])
            print("\n--- B daemon log (tail) ---")
            print(log_b.read_text(encoding="utf-8", errors="replace")[-2000:])
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
