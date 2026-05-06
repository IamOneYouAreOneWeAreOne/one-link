"""Tests for the OS file-manager reveal endpoints.

Covers:
    POST /api/files/{name}/reveal  -> opens explorer/finder/xdg with file selected
    POST /api/inbox/reveal         -> opens the inbox folder itself

These endpoints shell out to the platform file manager via subprocess.Popen.
We monkeypatch Popen so the tests work on any host without actually opening
a window, and verify the right command is built per platform.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import aiohttp
import pytest

from tests.harness import daemon_pair


pytestmark = pytest.mark.timeout(120)


def _read(home: Path, name: str, timeout: float = 15.0) -> str:
    p = home / "data" / name
    import time as _time
    end = _time.time() + timeout
    last_err: Exception | None = None
    while _time.time() < end:
        try:
            txt = p.read_text(encoding="utf-8").strip()
            if txt:
                return txt
        except (FileNotFoundError, OSError) as e:
            last_err = e
        _time.sleep(0.05)
    if last_err is not None:
        raise last_err
    raise FileNotFoundError(p)


def _server_addr(home: Path) -> tuple[str, str]:
    port = _read(home, "server.port")
    token = _read(home, "ui.token")
    return f"http://127.0.0.1:{port}", token


# ─── Unit tests against handler functions directly ──────────────────────
# These don't need a real daemon — they exercise the file-name validation
# and platform dispatch with full control over subprocess.

@pytest.mark.asyncio
async def test_file_reveal_blocks_path_traversal(tmp_path: Path, monkeypatch):
    """Path-traversal defense: the handler must refuse anything whose
    basename doesn't equal the supplied name. Mirrors the equivalent
    test for /api/files/{name} download."""
    from one_link.server import UIServer
    from one_link import paths as paths_mod

    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setattr(paths_mod, "inbox_dir", lambda: inbox)
    # Re-import the handler module symbol so it picks up the patched inbox.
    import one_link.server as server_mod
    monkeypatch.setattr(server_mod, "inbox_dir", lambda: inbox)

    daemon = SimpleNamespace(
        state=None,
        discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
    )
    server = UIServer(daemon)

    popen_calls = []
    monkeypatch.setattr("subprocess.Popen", lambda *a, **kw: popen_calls.append(a) or MagicMock())

    for evil in ["../../etc/passwd", "..\\..\\foo", "../bar", "./x", ""]:
        req = SimpleNamespace(match_info={"name": evil})
        resp = await server.api_file_reveal(req)
        assert resp.status in (400, 404), f"reveal accepted {evil!r} (status={resp.status})"
    # No matter what evil names came in, we should never have invoked the OS.
    assert popen_calls == [], f"Popen invoked for traversal attempt: {popen_calls}"


@pytest.mark.asyncio
async def test_file_reveal_404_for_missing(tmp_path: Path, monkeypatch):
    """A clean filename that just isn't in the inbox returns 404, not 500."""
    from one_link.server import UIServer
    import one_link.server as server_mod

    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setattr(server_mod, "inbox_dir", lambda: inbox)

    daemon = SimpleNamespace(
        state=None, discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
    )
    server = UIServer(daemon)

    popen = MagicMock()
    monkeypatch.setattr("subprocess.Popen", popen)

    req = SimpleNamespace(match_info={"name": "definitely_not_there.txt"})
    resp = await server.api_file_reveal(req)
    assert resp.status == 404
    popen.assert_not_called()


@pytest.mark.asyncio
async def test_file_reveal_invokes_correct_platform_command(tmp_path: Path, monkeypatch):
    """When the file exists, the handler runs the right platform-specific
    command. We verify the args without actually launching a window."""
    from one_link.server import UIServer
    import one_link.server as server_mod

    inbox = tmp_path / "inbox"
    inbox.mkdir()
    target = inbox / "received.png"
    target.write_bytes(b"PNG-ish")
    monkeypatch.setattr(server_mod, "inbox_dir", lambda: inbox)

    daemon = SimpleNamespace(
        state=None, discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
    )
    server = UIServer(daemon)

    popen = MagicMock()
    monkeypatch.setattr("subprocess.Popen", popen)

    req = SimpleNamespace(match_info={"name": "received.png"})
    resp = await server.api_file_reveal(req)
    assert resp.status == 200, resp.text

    popen.assert_called_once()
    args = popen.call_args.args[0]
    if sys.platform == "win32":
        assert args[0] == "explorer.exe"
        # /select,<path>  (note: /select must be in the same arg as the path)
        assert args[1].startswith("/select,")
        assert "received.png" in args[1]
    elif sys.platform == "darwin":
        assert args == ["open", "-R", str(target)]
    else:
        # Linux fallback: open the parent dir.
        assert args == ["xdg-open", str(target.parent)]


@pytest.mark.asyncio
async def test_file_reveal_translates_oserror_to_500(tmp_path: Path, monkeypatch):
    """If the platform command can't be launched at all (e.g. missing
    binary), the user gets a 500 with a meaningful error string — not a
    crash."""
    from one_link.server import UIServer
    import one_link.server as server_mod

    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "x.txt").write_text("x")
    monkeypatch.setattr(server_mod, "inbox_dir", lambda: inbox)

    daemon = SimpleNamespace(
        state=None, discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
    )
    server = UIServer(daemon)

    def boom(*a, **kw):
        raise OSError("explorer.exe missing in this universe")
    monkeypatch.setattr("subprocess.Popen", boom)

    req = SimpleNamespace(match_info={"name": "x.txt"})
    resp = await server.api_file_reveal(req)
    assert resp.status == 500
    assert b"reveal failed" in resp.body


@pytest.mark.asyncio
async def test_inbox_reveal_invokes_correct_platform_command(tmp_path: Path, monkeypatch):
    """Inbox reveal opens the inbox folder itself — no /select."""
    from one_link.server import UIServer
    import one_link.server as server_mod

    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setattr(server_mod, "inbox_dir", lambda: inbox)

    daemon = SimpleNamespace(
        state=None, discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
    )
    server = UIServer(daemon)

    popen = MagicMock()
    monkeypatch.setattr("subprocess.Popen", popen)

    resp = await server.api_inbox_reveal(SimpleNamespace())
    assert resp.status == 200, resp.text

    popen.assert_called_once()
    args = popen.call_args.args[0]
    if sys.platform == "win32":
        assert args == ["explorer.exe", str(inbox)]
    elif sys.platform == "darwin":
        assert args == ["open", str(inbox)]
    else:
        assert args == ["xdg-open", str(inbox)]


# ─── End-to-end auth tests against a real daemon ───────────────────────

@pytest.mark.asyncio
async def test_file_reveal_requires_auth():
    """Reveal endpoints must be token-gated like the rest of the UI API."""
    with daemon_pair() as p:
        base, _ = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            # No token → 401, regardless of whether the file exists.
            async with s.post(f"{base}/api/files/anything.txt/reveal") as r:
                assert r.status == 401
            async with s.post(f"{base}/api/inbox/reveal") as r:
                assert r.status == 401


@pytest.mark.asyncio
async def test_inbox_reveal_authorized_returns_ok(monkeypatch):
    """With a valid token, /api/inbox/reveal returns ok+path. We can't
    easily monkeypatch into the live subprocess used by the spawned
    daemon, so we just confirm the auth + return shape — and on systems
    where the subprocess fails (e.g. no GUI in CI), it returns 500 with
    a clean error rather than crashing the daemon."""
    with daemon_pair() as p:
        base, token = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            async with s.post(
                f"{base}/api/inbox/reveal",
                headers={"Authorization": f"Bearer {token}"},
            ) as r:
                # 200 (subprocess launched) or 500 (no GUI / no xdg-open)
                # — both are acceptable, since the contract is "auth
                # passes and the daemon doesn't crash". We never want
                # 401 here; that would be an auth regression.
                assert r.status in (200, 500), await r.text()
                body = await r.json()
                if r.status == 200:
                    assert body.get("ok") is True
                else:
                    assert "error" in body
