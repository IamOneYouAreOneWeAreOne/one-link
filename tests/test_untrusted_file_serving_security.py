"""Security boundary for files received from another device.

Transferred active documents must not become executable content under the
authenticated One Link UI origin.  Safe media remains inline-previewable;
active formats are attachment-only and have an inert source-code preview.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from one_link.server import UIServer, _untrusted_file_headers
from one_link.state import State


def _server(tmp_path: Path, monkeypatch, *, state=None, blob_store=None) -> UIServer:
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    daemon = SimpleNamespace(
        state=state,
        blob_store=blob_store,
        discovery=None,
        me=SimpleNamespace(
            fingerprint="aa" * 32,
            short_id="aaaaaaaa",
            hostname="security-test",
        ),
    )
    return UIServer(daemon)


def _request(name: str, **query: str) -> SimpleNamespace:
    return SimpleNamespace(match_info={"name": name}, query=query)


def _assert_active_attachment(resp: web.FileResponse) -> None:
    assert resp.headers["Content-Type"] == "application/octet-stream"
    assert resp.headers["Content-Disposition"].startswith("attachment;")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    csp = resp.headers["Content-Security-Policy"]
    assert "sandbox" in csp
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name",
    [
        "attack.html",
        "attack.svg",
        "attack.xml",
        "attack.xhtml",
        "attack.mht",
        "attack.mhtml",
        "attack.webarchive",
        "attack.eml",
        "attack.js",
        "attack.css",
        "attack.svg.txt",
    ],
)
async def test_inbox_active_content_is_always_attachment(
    tmp_path: Path,
    monkeypatch,
    name: str,
) -> None:
    server = _server(tmp_path, monkeypatch)
    from one_link.paths import inbox_dir

    inbox_dir().mkdir(parents=True, exist_ok=True)
    (inbox_dir() / name).write_text(
        '<script>fetch("/api/me")</script>',
        encoding="utf-8",
    )

    response = await server.api_file_download(_request(name))

    assert isinstance(response, web.FileResponse)
    _assert_active_attachment(response)


@pytest.mark.asyncio
async def test_active_attachment_headers_survive_real_aiohttp_prepare(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """FileResponse.prepare and the security middleware must not replace
    the handler's fail-closed MIME, disposition, or CSP headers."""
    server = _server(tmp_path, monkeypatch)
    from one_link.paths import inbox_dir

    inbox_dir().mkdir(parents=True, exist_ok=True)
    (inbox_dir() / "attack.html").write_text(
        "<script>top.location='/api/me'</script>",
        encoding="utf-8",
    )
    client = TestClient(TestServer(server.app))
    await client.start_server()
    try:
        response = await client.get(
            "/api/files/attack.html",
            headers={"Authorization": f"Bearer {server.token}"},
        )
        assert response.status == 200
        assert response.headers["Content-Type"] == "application/octet-stream"
        assert response.headers["Content-Disposition"].startswith("attachment;")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "sandbox" in response.headers["Content-Security-Policy"]
        assert await response.read() == b"<script>top.location='/api/me'</script>"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_safe_raster_preview_remains_inline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    server = _server(tmp_path, monkeypatch)
    from one_link.paths import inbox_dir

    inbox_dir().mkdir(parents=True, exist_ok=True)
    (inbox_dir() / "photo.png").write_bytes(b"not-a-real-png")

    response = await server.api_file_download(_request("photo.png"))

    assert isinstance(response, web.FileResponse)
    assert response.headers["Content-Type"] == "image/png"
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert response.headers["Content-Security-Policy"] == "frame-ancestors 'self'"
    assert "Content-Disposition" not in response.headers


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["page.html", "vector.svg", "feed.xml"])
async def test_active_preview_is_inert_json_source(
    tmp_path: Path,
    monkeypatch,
    name: str,
) -> None:
    server = _server(tmp_path, monkeypatch)
    from one_link.paths import inbox_dir

    payload = '<script>globalThis.pwned = true</script>'
    inbox_dir().mkdir(parents=True, exist_ok=True)
    (inbox_dir() / name).write_text(payload, encoding="utf-8")

    response = await server.api_file_preview(_request(name))
    body = json.loads(response.text)

    assert response.content_type == "application/json"
    assert body["kind"] == "code"
    assert body["content"] == payload
    assert "stream_url" not in body


@pytest.mark.asyncio
async def test_blob_ledger_active_content_uses_same_boundary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    stored = tmp_path / "stored.bin"
    stored.write_text("<svg onload='alert(1)'></svg>", encoding="utf-8")
    state = State(db_path=tmp_path / "state.db")
    state.upsert_transfer(
        id="in:active",
        direction="in",
        peer_fp="bb" * 32,
        kind="file",
        name="shared.svg",
        size=stored.stat().st_size,
        blob_hash="ab" * 32,
        status="complete",
        progress_bytes=stored.stat().st_size,
        total_bytes=stored.stat().st_size,
        chunks_done=1,
        chunks_total=1,
        metadata={"path": str(stored)},
    )
    try:
        server = _server(tmp_path, monkeypatch, state=state)
        request = SimpleNamespace(match_info={"blob": "ab" * 32}, query={})
        response = await server.api_file_by_blob(request)
        assert isinstance(response, web.FileResponse)
        _assert_active_attachment(response)
    finally:
        state.close()


def test_active_mime_is_blocked_even_without_active_extension() -> None:
    headers = _untrusted_file_headers(
        name="opaque.bin",
        mime_type="text/html; charset=utf-8",
    )
    assert headers["Content-Type"] == "application/octet-stream"
    assert headers["Content-Disposition"].startswith("attachment;")
    assert "sandbox" in headers["Content-Security-Policy"]


def test_download_filename_cannot_inject_response_headers() -> None:
    headers = _untrusted_file_headers(
        name="page.html",
        mime_type="text/html",
        download_name='bad"\r\nX-Evil: yes.html',
    )
    disposition = headers["Content-Disposition"]
    assert "\r" not in disposition and "\n" not in disposition
    assert "X-Evil: yes" not in disposition
    assert "%0D%0A" in disposition
