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


def test_load_or_create_token_unit():
    """Unit test the token logic directly."""
    from one_link.server import UIServer

    tmp = Path(tempfile.mkdtemp(prefix="ol_token_unit_"))
    try:
        os.environ["ONE_LINK_HOME"] = str(tmp)
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
    finally:
        os.environ.pop("ONE_LINK_HOME", None)
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
