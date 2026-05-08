"""CLI surface tests: invoke `one-link <cmd>` as a real subprocess."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from tests.harness import daemon_pair


def _cli(*args, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "one_link.cli", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


def test_version_works():
    r = _cli("--version")
    assert r.returncode == 0
    assert "one-link" in r.stdout
    # match a semver-shaped token; specific value isn't the point
    import re
    assert re.search(r"\d+\.\d+\.\d+", r.stdout), r.stdout


def test_help_works():
    r = _cli("--help")
    assert r.returncode == 0
    assert "daemon" in r.stdout
    assert "send" in r.stdout
    assert "send-file" in r.stdout
    assert "peers" in r.stdout
    assert "native-status" in r.stdout


def test_native_status_works():
    r = _cli("native-status")
    assert r.returncode == 0
    assert "native_cdc:" in r.stdout
    assert "engine:" in r.stdout


def test_whoami_creates_identity(tmp_path: Path):
    env = dict(os.environ)
    env["ONE_LINK_HOME"] = str(tmp_path)
    r = _cli("whoami", env=env)
    assert r.returncode == 0
    assert "short_id" in r.stdout
    assert "fingerprint" in r.stdout
    # key file should now exist
    assert (tmp_path / "config" / "identity.key").is_file()


def test_whoami_persistent(tmp_path: Path):
    """Running whoami twice yields the same identity."""
    env = dict(os.environ)
    env["ONE_LINK_HOME"] = str(tmp_path)
    r1 = _cli("whoami", env=env)
    r2 = _cli("whoami", env=env)
    assert r1.stdout == r2.stdout


def test_peers_clean_error_when_daemon_not_running(tmp_path: Path):
    env = dict(os.environ)
    env["ONE_LINK_HOME"] = str(tmp_path)
    r = _cli("peers", env=env)
    assert r.returncode != 0
    # Should be a friendly click error, not a stack trace.
    combined = (r.stdout + r.stderr).lower()
    assert "daemon not running" in combined or "no control.port" in combined or "could not reach daemon" in combined
    assert "traceback" not in combined


def test_send_clean_error_when_daemon_not_running(tmp_path: Path):
    env = dict(os.environ)
    env["ONE_LINK_HOME"] = str(tmp_path)
    r = _cli("send", "abcdef12", "hi", env=env)
    assert r.returncode != 0


@pytest.mark.timeout(120)
def test_full_cli_round_trip():
    """Two daemons via the harness; drive A's CLI as a subprocess."""
    with daemon_pair() as p:
        env = dict(os.environ)
        env["ONE_LINK_HOME"] = str(p.a.home)

        # `one-link peers` should now list B
        r = _cli("peers", env=env)
        assert r.returncode == 0, r.stderr
        assert p.b.short_id[:8] in r.stdout

        # `one-link send <peer> "hi"`
        r = _cli("send", p.b.short_id, "hi from CLI", env=env)
        assert r.returncode == 0, r.stderr
        assert "ack" in r.stdout.lower()

        time.sleep(0.5)
        from tests.harness import message_log
        bodies = [
            m.get("body")
            for m in message_log(p.b.home)
            if m.get("t") == "TEXT" and m.get("dir") == "in"
        ]
        assert "hi from CLI" in bodies, bodies


@pytest.mark.timeout(120)
def test_cli_send_file_round_trip():
    with daemon_pair() as p:
        env = dict(os.environ)
        env["ONE_LINK_HOME"] = str(p.a.home)

        src = p.tmp / "cli_payload.bin"
        src.write_bytes(b"x" * 12345)

        r = _cli("send-file", p.b.short_id, str(src), env=env)
        assert r.returncode == 0, r.stderr
        assert "blob=" in r.stdout

        time.sleep(0.5)
        inbox = list((p.b.home / "data" / "inbox").iterdir())
        match = [f for f in inbox if "cli_payload.bin" in f.name]
        assert match
        assert match[0].read_bytes() == src.read_bytes()
