"""Daemon lifecycle: persistent UI token, fixed port, single-instance.

These tests target the "browser tab should survive a daemon restart"
property — the user-visible reason these matter.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest


def _control_request(port: int, cmd: str, timeout: float = 5.0) -> dict:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall((json.dumps({"cmd": cmd}) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.decode("utf-8").strip() or "{}")
    finally:
        s.close()


def _read_port(home: Path, name: str, timeout: float = 12.0) -> int:
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


def _read_text(home: Path, name: str, timeout: float = 12.0) -> str:
    p = home / "data" / name
    end = time.time() + timeout
    while time.time() < end:
        if p.exists():
            try:
                t = p.read_text(encoding="utf-8").strip()
                if t:
                    return t
            except OSError:
                pass
        time.sleep(0.1)
    raise RuntimeError(f"file did not appear: {p}")


def _spawn_daemon(home: Path, log: Path) -> subprocess.Popen:
    env = dict(os.environ)
    env["ONE_LINK_HOME"] = str(home)
    log.parent.mkdir(parents=True, exist_ok=True)
    return subprocess.Popen(
        [sys.executable, "-m", "one_link.cli", "daemon"],
        env=env,
        stdout=open(log, "wb"),
        stderr=subprocess.STDOUT,
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


@pytest.mark.timeout(60)
def test_token_persists_across_daemon_restart():
    """Restart the daemon — the same UI token should still be in place."""
    tmp = Path(tempfile.mkdtemp(prefix="ol_lifecycle_"))
    try:
        home = tmp / "H"
        home.mkdir()
        log1 = tmp / "1.log"
        log2 = tmp / "2.log"

        proc = _spawn_daemon(home, log1)
        try:
            token1 = _read_text(home, "ui.token")
            port1 = _read_port(home, "server.port")
            assert len(token1) >= 32
            assert 7117 <= port1 <= 7117 + 16  # well-known range
        finally:
            _stop(proc)

        # Restart cleanly
        time.sleep(0.4)
        proc2 = _spawn_daemon(home, log2)
        try:
            token2 = _read_text(home, "ui.token")
            assert token2 == token1, (
                f"token rotated across restart: {token1!r} -> {token2!r}"
            )
        finally:
            _stop(proc2)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.timeout(60)
def test_ui_port_is_in_well_known_range():
    """First-port attempt must succeed when 7117 is free."""
    tmp = Path(tempfile.mkdtemp(prefix="ol_port_"))
    try:
        home = tmp / "H"
        home.mkdir()
        log = tmp / "out.log"

        proc = _spawn_daemon(home, log)
        try:
            port = _read_port(home, "server.port")
            assert 7117 <= port <= 7117 + 16
        finally:
            _stop(proc)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.timeout(60)
def test_control_status_and_shutdown_contract():
    """The launcher depends on status/shutdown to self-heal stale daemons."""
    from one_link import __version__

    tmp = Path(tempfile.mkdtemp(prefix="ol_lifecycle_status_"))
    try:
        home = tmp / "H"
        home.mkdir()
        proc = _spawn_daemon(home, tmp / "out.log")
        try:
            ctrl = _read_port(home, "control.port")
            ui_port = _read_port(home, "server.port")
            status = _control_request(ctrl, "status")
            assert status["ok"] is True
            assert status["app_version"] == __version__
            assert status["pid"] == proc.pid
            assert status["schema_version"] >= 1
            assert status["protocol_version"]
            assert isinstance(status["ui_server_port"], int)
            assert status["ui_server_port"] == ui_port

            shutdown = _control_request(ctrl, "shutdown")
            assert shutdown == {"ok": True, "stopping": True}
            proc.wait(timeout=10)
            assert proc.poll() is not None
        finally:
            _stop(proc)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_launcher_rejects_unknown_or_mismatched_daemon():
    from one_link import __version__
    from one_link.app import RunningDaemon
    from one_link.build_identity import runtime_build_identity

    _bid = runtime_build_identity()
    good = RunningDaemon(
        control_port=1,
        server_port=2,
        token="t",
        status={
            "ok": True,
            "app_version": __version__,
            "source_fingerprint": _bid["source_fingerprint"],
            "protocol_version": "OL1.2",
            "schema_version": 5,
        },
    )
    old = RunningDaemon(
        control_port=1,
        server_port=2,
        token="t",
        status={
            "ok": True,
            "app_version": "0.1.0",
            "protocol_version": "OL1.2",
            "schema_version": 5,
        },
    )
    unknown = RunningDaemon(
        control_port=1,
        server_port=2,
        token="t",
        status={"ok": False, "error": "unknown cmd"},
    )
    assert good.compatible is True
    assert old.compatible is False
    assert unknown.compatible is False


def test_launcher_rejects_ui_that_does_not_match_control_identity():
    from one_link import __version__
    from one_link.app import _runtime_matches_control
    from one_link.build_identity import runtime_build_identity

    _sf = runtime_build_identity()["source_fingerprint"]
    control = {
        "ok": True,
        "app_version": __version__,
        "source_fingerprint": _sf,
        "me": {"fingerprint": "aa" * 32},
    }
    matching_ui = {
        "ok": True,
        "app_version": __version__,
        "source_fingerprint": _sf,
        "me": {"fingerprint": "aa" * 32},
    }
    wrong_identity = {
        "ok": True,
        "app_version": __version__,
        "source_fingerprint": _sf,
        "me": {"fingerprint": "bb" * 32},
    }
    wrong_version = {
        "ok": True,
        "app_version": "0.0.1",
        "source_fingerprint": _sf,
        "me": {"fingerprint": "aa" * 32},
    }

    assert _runtime_matches_control(control, matching_ui) is True
    assert _runtime_matches_control(control, wrong_identity) is False
    assert _runtime_matches_control(control, wrong_version) is False
    assert _runtime_matches_control(control, {"ok": False}) is False


def test_launcher_uses_native_windows_url_open(monkeypatch):
    """Fallback path: when no Chromium browser is available AND/OR the
    caller opts out of standalone mode, the launcher uses
    os.startfile on Windows (the native shell-open) rather than
    webbrowser.open."""
    from one_link import app as app_mod

    opened = []

    monkeypatch.setattr(app_mod.os, "name", "nt")
    monkeypatch.setattr(app_mod.os, "startfile", lambda url: opened.append(url), raising=False)
    monkeypatch.setattr(app_mod.webbrowser, "open", lambda *_args, **_kw: (_ for _ in ()).throw(AssertionError("webbrowser fallback used")))
    # Force the Chromium-detector to return None so the launcher
    # takes the os.startfile fallback (the legacy path this test was
    # written for). The standalone-window path is exercised separately
    # in tests/unit/test_standalone_window.py.
    monkeypatch.setattr(app_mod, "_find_chromium_browser_exe", lambda: None)

    app_mod._open_browser_url("http://127.0.0.1:7117/?t=test")

    assert opened == ["http://127.0.0.1:7117/?t=test"]


def test_launcher_prefers_control_reported_ui_port(monkeypatch):
    from one_link import __version__
    from one_link import app as app_mod
    from one_link.build_identity import runtime_build_identity

    _sf = runtime_build_identity()["source_fingerprint"]
    monkeypatch.setattr(app_mod.daemon_mod, "read_control_port", lambda: 43210)
    monkeypatch.setattr(app_mod, "_alive", lambda port: port == 43210)
    monkeypatch.setattr(app_mod.server_mod, "read_ui_token", lambda: "token")
    monkeypatch.setattr(
        app_mod.server_mod,
        "read_server_port",
        lambda: (_ for _ in ()).throw(AssertionError("stale file read")),
    )
    monkeypatch.setattr(
        app_mod,
        "_control_request",
        lambda _port, _cmd: {
            "ok": True,
            "app_version": __version__,
            "source_fingerprint": _sf,
            "protocol_version": "OL1.2",
            "schema_version": 16,
            "ui_server_port": 7999,
            "me": {"fingerprint": "cc" * 32},
        },
    )
    monkeypatch.setattr(
        app_mod,
        "_ui_status",
        lambda port, token: {
            "ok": port == 7999 and token == "token",
            "app_version": __version__,
            "source_fingerprint": _sf,
            "me": {"fingerprint": "cc" * 32},
        },
    )

    info = app_mod._resolve_running_daemon()

    assert info is not None
    assert info.server_port == 7999


@pytest.mark.timeout(60)
def test_corrupt_token_file_is_replaced_safely():
    """If the persisted token file is garbage, daemon generates a fresh one
    rather than using the unsafe short value."""
    tmp = Path(tempfile.mkdtemp(prefix="ol_corrupt_"))
    try:
        home = tmp / "H"
        (home / "data").mkdir(parents=True)
        # Pre-seed a too-short / unsafe token
        (home / "data" / "ui.token").write_text("xx")
        log = tmp / "out.log"
        proc = _spawn_daemon(home, log)
        try:
            # Wait for full startup — server.port is written at end of UIServer.start().
            _read_port(home, "server.port")
            # Daemon writes server.port and ui.token in quick succession; small
            # margin ensures the new token has fully landed on disk.
            time.sleep(0.2)
            token = (home / "data" / "ui.token").read_text(encoding="utf-8").strip()
            assert len(token) >= 32, f"daemon kept unsafe short token: {token!r}"
        finally:
            _stop(proc)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_load_or_create_token_unit(monkeypatch, tmp_path):
    """Unit test the token logic directly.

    2026-05-22 audit Batch X: use ``monkeypatch.setenv`` instead of
    mutating ``os.environ`` directly + try/finally pop. Under
    pytest-xdist the bare mutation surfaces as flakiness on
    unrelated tests if a process is interrupted between set and pop.
    """
    from one_link.server import UIServer

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    # Force a re-import via direct module access; UIServer._load_or_create_token
    # uses one_link.server._token_path() which honours ONE_LINK_HOME via paths.py.
    # First call: no file → generates fresh
    from one_link.paths import data_dir
    token_path = data_dir() / "ui.token"
    if token_path.exists():
        token_path.unlink()

    t1 = UIServer._load_or_create_token()
    assert len(t1) >= 32
    # Second call: still no file written (token is only persisted on
    # daemon start). Each call returns a fresh one.
    t2 = UIServer._load_or_create_token()
    assert len(t2) >= 32

    # Now WRITE a valid token; load_or_create_token should return it.
    token_path.write_text("a" * 50)
    t3 = UIServer._load_or_create_token()
    assert t3 == "a" * 50

    # Corrupt token: too short → fresh one generated
    token_path.write_text("nope")
    t4 = UIServer._load_or_create_token()
    assert t4 != "nope"
    assert len(t4) >= 32

    # Corrupt token: invalid chars → fresh one generated
    token_path.write_text("a" * 40 + "\n!@#$")
    t5 = UIServer._load_or_create_token()
    assert "!" not in t5
    assert len(t5) >= 32
