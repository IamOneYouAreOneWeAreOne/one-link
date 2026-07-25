"""Adversarial regressions for public/UI trust boundaries."""

from __future__ import annotations

import sys
import time
import types
from pathlib import Path
from types import SimpleNamespace

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
import pytest


class _Part:
    def __init__(self, name: str, data: bytes):
        self.name = name
        self._data = data
        self._offset = 0

    async def read_chunk(self, size: int = 8192) -> bytes:
        chunk = self._data[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk


class _Multipart:
    def __init__(self, parts: list[_Part]):
        self._parts = iter(parts)

    async def next(self):
        return next(self._parts, None)


class _MultipartRequest:
    content_type = "multipart/form-data"

    def __init__(self, parts: list[_Part]):
        self._parts = parts

    async def multipart(self):
        return _Multipart(self._parts)


@pytest.mark.asyncio
async def test_recovery_bundle_multipart_avoids_base64_amplification() -> None:
    from one_link.server import UIServer

    server = object.__new__(UIServer)
    request = _MultipartRequest(
        [
            _Part("phrase", b"word " * 23 + b"word"),
            _Part("force", b"false"),
            _Part("confirmed_replace", b"1"),
            _Part("bundle", b"OLBAK\x01\x00\x00raw-ciphertext"),
        ]
    )

    fields, bundle = await server._read_recovery_bundle_request(request)

    assert fields["force"] is False
    assert fields["confirmed_replace"] is True
    assert isinstance(bundle, bytearray)
    assert bundle == b"OLBAK\x01\x00\x00raw-ciphertext"


@pytest.mark.asyncio
async def test_recovery_bundle_multipart_is_decoded_size_bounded(monkeypatch) -> None:
    from one_link import server as server_mod

    monkeypatch.setattr(server_mod, "RECOVERY_BUNDLE_MAX_BYTES", 8)
    server = object.__new__(server_mod.UIServer)
    request = _MultipartRequest([_Part("phrase", b"words"), _Part("bundle", b"123456789")])

    with pytest.raises(server_mod._RecoveryBundleTooLarge):
        await server._read_recovery_bundle_request(request)


@pytest.mark.asyncio
async def test_chunked_json_cannot_bypass_control_body_limit(monkeypatch) -> None:
    from one_link import server as server_mod

    monkeypatch.setattr(server_mod, "MAX_JSON_REQUEST_BYTES", 16)
    ui = object.__new__(server_mod.UIServer)
    ui.bind_host = "127.0.0.1"
    handled = False

    async def handler(_request: web.Request) -> web.Response:
        nonlocal handled
        handled = True
        return web.json_response({"ok": True})

    app = web.Application(middlewares=[ui._security_middleware])
    app.router.add_post("/json", handler)
    client = TestClient(TestServer(app))
    await client.start_server()

    async def chunks():
        yield b'{"payload":"'
        yield b"x" * 32
        yield b'"}'

    try:
        response = await client.post(
            "/json",
            data=chunks(),
            headers={"Content-Type": "application/json"},
        )
        assert response.status == 413
        assert handled is False
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_http_error_boundary_redacts_exceptions_and_hardens_response() -> None:
    from one_link.server import UIServer

    ui = object.__new__(UIServer)
    ui.bind_host = "127.0.0.1"

    async def handler(_request: web.Request) -> web.Response:
        raise RuntimeError("secret filesystem path C:/private/key.bin")

    app = web.Application(middlewares=[ui._security_middleware])
    app.router.add_get("/api/boom", handler)
    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        response = await client.get("/api/boom")
        body = await response.json()
        assert response.status == 500
        assert body["error"] == "internal server error"
        assert len(body["incident"]) == 12
        assert "secret" not in str(body).lower()
        assert response.headers["Server"] == "one-link"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["Cache-Control"] == "no-store"
        assert "geolocation=()" in response.headers["Permissions-Policy"]
        assert "on-device-speech-recognition=(self)" in response.headers["Permissions-Policy"]
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_public_connect_rejects_reflected_attribute_payload() -> None:
    from one_link.server import UIServer

    ui = object.__new__(UIServer)
    ui.bind_host = "127.0.0.1"
    ui.port = 7117
    ui.https_port = 7118
    request = SimpleNamespace(
        query={"token": '"><script>alert(1)</script>'},
        headers={"User-Agent": "iPhone Safari"},
        scheme="http",
        host="127.0.0.1:7117",
    )

    response = await ui._connect_landing(request)

    assert response.status == 400
    assert "script" not in (response.text or "").lower()


@pytest.mark.asyncio
async def test_public_invite_preview_is_bounded_and_does_not_leak_parser_errors() -> None:
    from one_link.server import UIServer

    ui = object.__new__(UIServer)
    ui._rate_buckets = {}
    request = SimpleNamespace(
        query={"token": "not!canonical"},
        transport=None,
        remote="192.0.2.4",
    )

    response = await ui.api_public_self_mesh_enrollment_invite_preview(request)
    body = __import__("json").loads(response.text)

    assert response.status == 400
    assert body == {"error": "self_mesh_invite_preview_rejected"}
    assert response.headers["Cache-Control"] == "no-store"


def test_invalid_session_cookie_is_read_only_before_rate_limiting() -> None:
    from one_link.server import SESSION_COOKIE_NAME, UIServer

    class FakeState:
        @staticmethod
        def ui_session_token_id(_token):
            return "record-key"

        @staticmethod
        def lookup_ui_session(_token):
            return None

        @staticmethod
        def touch_ui_session(_token):  # pragma: no cover - must not run
            raise AssertionError("invalid session attempted a SQLite touch")

    ui = object.__new__(UIServer)
    ui.daemon = SimpleNamespace(state=FakeState())
    request = SimpleNamespace(cookies={SESSION_COOKIE_NAME: "a" * 64})

    assert ui._check_session_cookie(request) is False


def test_session_touch_is_throttled_and_absolute_lifetime_enforced() -> None:
    from one_link.server import SESSION_COOKIE_NAME, UIServer

    now_ms = int(time.time() * 1000)

    class FakeState:
        def __init__(self):
            self.row = {
                "created_ms": now_ms - 1_000,
                "last_seen_ms": now_ms - 1_000,
            }
            self.touches = 0
            self.revokes = 0

        @staticmethod
        def ui_session_token_id(_token):
            return "record-key"

        def lookup_ui_session(self, _token):
            return dict(self.row)

        def touch_ui_session(self, _token):
            self.touches += 1
            return True

        def revoke_ui_session(self, _token):
            self.revokes += 1
            return True

    state = FakeState()
    ui = object.__new__(UIServer)
    ui.daemon = SimpleNamespace(state=state)
    request = SimpleNamespace(cookies={SESSION_COOKIE_NAME: "a" * 64})

    assert ui._check_session_cookie(request) is True
    assert state.touches == 0

    state.row["created_ms"] = now_ms - 31 * 24 * 60 * 60 * 1000
    assert ui._check_session_cookie(request) is False
    assert state.revokes == 1


def _make_symlink(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")


def test_ad_hoc_folder_walk_excludes_file_and_directory_symlinks(tmp_path: Path) -> None:
    from one_link.server import UIServer

    root = tmp_path / "share"
    outside = tmp_path / "private"
    root.mkdir()
    outside.mkdir()
    (root / "safe.txt").write_text("safe", encoding="utf-8")
    secret = outside / "secret.txt"
    secret.write_text("secret", encoding="utf-8")
    _make_symlink(root / "secret-link.txt", secret)
    _make_symlink(root / "private-link", outside, directory=True)

    ui = object.__new__(UIServer)
    files, total, skipped = ui._walk_folder_files(root, "share")
    relative = {rel for _path, rel in files}

    assert relative == {"share/safe.txt"}
    assert total == 4
    assert skipped >= 2


def test_backup_walk_excludes_filesystem_aliases(tmp_path: Path) -> None:
    from one_link.backup_bundle import _walk_data_dir

    data = tmp_path / "data"
    inbox = data / "inbox"
    outside = tmp_path / "private"
    inbox.mkdir(parents=True)
    outside.mkdir()
    (data / "state.db").write_bytes(b"db")
    (inbox / "safe.txt").write_text("safe", encoding="utf-8")
    secret = outside / "secret.txt"
    secret.write_text("secret", encoding="utf-8")
    _make_symlink(data / "master.seed", secret)
    _make_symlink(inbox / "secret-link.txt", secret)
    _make_symlink(inbox / "private-link", outside, directory=True)

    names = {name for _path, name in _walk_data_dir(data, include_files=True)}

    assert names == {"state.db", "inbox/safe.txt"}


@pytest.mark.asyncio
async def test_public_signaling_caps_pending_client_and_times_out(
    monkeypatch,
) -> None:
    from one_link import server as server_mod

    fake_aiortc = types.ModuleType("aiortc")
    fake_aiortc.RTCConfiguration = lambda **kwargs: kwargs
    fake_aiortc.RTCIceServer = lambda **kwargs: kwargs
    fake_aiortc.RTCPeerConnection = object
    fake_aiortc.RTCSessionDescription = object
    monkeypatch.setitem(sys.modules, "aiortc", fake_aiortc)
    monkeypatch.setattr(server_mod, "MAX_PENDING_SIGNALING_PER_CLIENT", 1)
    monkeypatch.setattr(server_mod, "SIGNALING_AUTH_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(server_mod, "SIGNALING_SESSION_TIMEOUT_SECONDS", 1.0)

    ui = object.__new__(server_mod.UIServer)
    ui.bind_host = "127.0.0.1"
    ui.daemon = SimpleNamespace(state=None)
    ui._rate_buckets = {}
    ui._pending_signaling_total = 0
    ui._pending_signaling_by_client = {}
    app = web.Application(middlewares=[ui._security_middleware])
    app.router.add_get("/signal", ui._peer_rtc_signaling)
    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        first = await client.ws_connect("/signal")
        with pytest.raises(aiohttp.WSServerHandshakeError) as rejected:
            await client.ws_connect("/signal")
        assert rejected.value.status == 429

        # A silent pre-auth socket is closed on the signed-offer deadline and
        # releases its reservation for the next legitimate device.
        await first.receive(timeout=2.0)
        await first.close()
        for _ in range(20):
            if ui._pending_signaling_total == 0:
                break
            await __import__("asyncio").sleep(0.01)
        assert ui._pending_signaling_total == 0
        assert ui._pending_signaling_by_client == {}
    finally:
        await client.close()
