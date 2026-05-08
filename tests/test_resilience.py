"""Daemon resilience: stale state, dropped peers, malformed runtime traffic.

These exercise behaviors that often hide bugs in long-running services:
the daemon must keep serving good clients even after a bad one misbehaves.
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from tests.harness import daemon_pair, request


pytestmark = pytest.mark.timeout(120)


def test_cli_import_has_no_windows_wmi_startup_hang():
    """CLI import must be boring-fast. It used to import aiohttp/zeroconf
    transitively and could hang inside Windows WMI before One Link even wrote
    control.port."""
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import one_link.cli; print('ok')",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ok" in proc.stdout


def test_stale_port_files_dont_break_daemon():
    """Drop a port file from a 'previous' daemon run, then start a new daemon
    in the same home. The new daemon must overwrite cleanly."""
    tmp = Path(tempfile.mkdtemp(prefix="one_link_stale_"))
    try:
        home = tmp / "H"
        home.mkdir()
        # Pre-seed stale files
        (home / "data").mkdir()
        (home / "data" / "control.port").write_text("99999")
        (home / "data" / "peer.port").write_text("99998")

        env = dict(os.environ)
        env["ONE_LINK_HOME"] = str(home)
        log = tmp / "out.log"
        with open(log, "wb") as f:
            proc = subprocess.Popen(
                [sys.executable, "-m", "one_link.cli", "daemon", "-v"],
                env=env,
                stdout=f,
                stderr=subprocess.STDOUT,
            )
        try:
            # Wait up to 5s for new ports to be written
            deadline = time.time() + 8.0
            ctrl = None
            while time.time() < deadline:
                try:
                    ctrl_text = (home / "data" / "control.port").read_text().strip()
                    if ctrl_text and ctrl_text != "99999":
                        ctrl = int(ctrl_text)
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(0.1)
            assert ctrl is not None, log.read_text(encoding="utf-8", errors="replace")[-2000:]

            # Verify the new daemon is alive on the new port
            res = request(ctrl, cmd="peers")
            assert res["ok"]
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_read_control_port_auto_cleans_dead_runtime_files(monkeypatch):
    """If a daemon died hard, users should not inherit dead control/UI
    pointers. The next launcher/CLI probe must clean them and force a fresh
    daemon start path automatically."""
    from one_link import daemon as daemon_mod

    tmp = Path(tempfile.mkdtemp(prefix="one_link_dead_runtime_"))
    try:
        home = tmp / "H"
        data = home / "data"
        data.mkdir(parents=True)
        monkeypatch.setenv("ONE_LINK_HOME", str(home))

        (data / "control.port").write_text("65530")
        (data / "peer.port").write_text("65529")
        (data / "server.port").write_text("65528")
        (data / "daemon.lock").write_text("999999")

        with pytest.raises(RuntimeError, match="stale control.port"):
            daemon_mod.read_control_port()

        assert not (data / "control.port").exists()
        assert not (data / "peer.port").exists()
        assert not (data / "server.port").exists()
        assert not (data / "daemon.lock").exists()
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_control_liveness_requires_status_protocol():
    """A random process accepting TCP on localhost is not a One Link daemon."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    async def _close_after_accept():
        loop = asyncio.get_running_loop()
        conn, _ = await loop.run_in_executor(None, listener.accept)
        conn.close()
        listener.close()

    from one_link import daemon as daemon_mod

    async def _run():
        closer = asyncio.create_task(_close_after_accept())
        try:
            assert daemon_mod.is_daemon_alive(port, timeout=0.2) is False
        finally:
            await closer

    asyncio.run(_run())


def test_daemon_survives_garbage_on_peer_port():
    """Hammer the peer port with garbage from many clients; daemon stays up."""
    with daemon_pair() as p:
        for _ in range(20):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect(("127.0.0.1", p.b.peer_port))
                s.sendall(os.urandom(64))
                s.close()
            except OSError:
                pass

        # B should still be responsive
        res = request(p.b.control_port, cmd="peers")
        assert res["ok"]


def test_daemon_survives_burst_of_disconnects():
    """Open then immediately close the peer port many times. Daemon must
    not leak descriptors or hang."""
    with daemon_pair() as p:
        for _ in range(50):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect(("127.0.0.1", p.b.peer_port))
                s.close()
            except OSError:
                pass

        res = request(p.b.control_port, cmd="peers")
        assert res["ok"]

        # And legit traffic still works
        ok = request(
            p.a.control_port, cmd="send", peer=p.b.short_id, body="still alive"
        )
        assert ok["ok"], ok


def test_two_daemons_in_same_home_second_fails_gracefully():
    """Spinning a second daemon at the same ONE_LINK_HOME — what happens?

    The second process must not stay alive and advertise the same local
    device again; that duplicate advertising is what fills the sidebar
    with repeated entries."""
    tmp = Path(tempfile.mkdtemp(prefix="one_link_dup_"))
    try:
        home = tmp / "H"
        home.mkdir()
        env = dict(os.environ)
        env["ONE_LINK_HOME"] = str(home)
        log1 = tmp / "1.log"
        log2 = tmp / "2.log"
        with open(log1, "wb") as f1, open(log2, "wb") as f2:
            p1 = subprocess.Popen(
                [sys.executable, "-m", "one_link.cli", "daemon", "-v"],
                env=env, stdout=f1, stderr=subprocess.STDOUT,
            )
            time.sleep(2.0)  # let p1 fully start
            p2 = subprocess.Popen(
                [sys.executable, "-m", "one_link.cli", "daemon", "-v"],
                env=env, stdout=f2, stderr=subprocess.STDOUT,
            )
            time.sleep(2.0)
            try:
                assert p1.poll() is None, "p1 unexpectedly exited"
                assert p2.poll() is not None, "p2 should exit under instance lock"
                log_text = log2.read_text(encoding="utf-8", errors="replace")
                assert "already running" in log_text
            finally:
                for p in (p1, p2):
                    p.terminate()
                    try:
                        p.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        p.kill()
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_peer_disconnects_during_chunk_does_not_break_daemon():
    """Initiator opens a connection, sends a partial offer, drops mid-stream.
    Receiver daemon should clean up and continue serving good peers."""
    with daemon_pair() as p:
        # Open raw connection, send half of a HELLO frame, close.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(("127.0.0.1", p.b.peer_port))
        try:
            # Frame header says 200 bytes, send only 50.
            s.sendall((200).to_bytes(4, "big") + b"\x00" * 50)
            time.sleep(0.5)
        finally:
            s.close()

        # Legit message should still work
        time.sleep(0.5)
        res = request(p.a.control_port, cmd="send", peer=p.b.short_id, body="post")
        assert res["ok"], res
