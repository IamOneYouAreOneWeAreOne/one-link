"""v0.21.x Ship 1 behavioral tests — file browser endpoints.

Goes beyond the source-level pins: spins up a real UIServer with a
real folder + real files on disk, exercises every endpoint with
live HTTP requests, and verifies actual behavior (content returned,
status codes, path-traversal blocked, headers correct).

Endpoints covered:
  GET  /api/folders/{name}/tree
  GET  /api/folders/{name}/file/{path}/preview
  GET  /api/folders/{name}/file/{path}/raw
  POST /api/folders/{name}/file/{path}/reveal
"""
from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    return Identity(
        private=sk, public=sk.public_key(), public_bytes=pub,
        fingerprint=fingerprint_of(pub), short_id=fingerprint_of(pub)[:8],
        hostname="ship1-host",
    )


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def browser_ctx(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    monkeypatch.setenv("ONE_LINK_DISABLE_NATIVE_PICKER", "1")
    monkeypatch.setenv("ONE_LINK_DISABLE_REVEAL", "1")

    # Real on-disk folder with several files of different kinds.
    folder_dir = tmp_path / "synced_folder"
    folder_dir.mkdir()
    (folder_dir / "intro.md").write_text(
        "# Intro\n\nThis is markdown.\n", encoding="utf-8"
    )
    (folder_dir / "data.txt").write_text("plain text body", encoding="utf-8")
    (folder_dir / "image.png").write_bytes(
        b"\x89PNG\r\n\x1a\n" + b"fake-png-bytes" * 50
    )
    (folder_dir / "binary.bin").write_bytes(bytes(range(256)) * 4)
    subdir = folder_dir / "sub"
    subdir.mkdir()
    (subdir / "nested.txt").write_text("nested content", encoding="utf-8")

    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None

    # Register the folder + add manifest entries directly so the
    # tree endpoint has data to return.
    state.add_folder(
        name="synced", local_path=str(folder_dir.resolve()),
        shared_with=[], max_file_bytes=None, ignored_patterns=[],
        conflict_policy="latest-wins",
    )
    import hashlib
    for rel in ("intro.md", "data.txt", "image.png", "binary.bin", "sub/nested.txt"):
        path = folder_dir / rel
        size = path.stat().st_size
        # Synthetic but stable hash so tree endpoint returns
        # blob_hash. local will be False (blob_store not populated),
        # which is fine for browser-level tests.
        h = hashlib.sha256(path.read_bytes()).hexdigest()
        state.upsert_manifest_entry(
            folder_name="synced",
            file_path=rel.replace("\\", "/"),
            blob_hash=h,
            size=size,
            mtime_ms=int(path.stat().st_mtime * 1000),
            vclock={me.fingerprint: 1},
        )

    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield {
            "client": client, "daemon": daemon, "state": state,
            "server": server, "token": server.token,
            "folder_dir": folder_dir,
        }
    finally:
        await client.close()
        state.close()


# ── tree endpoint ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tree_returns_all_registered_entries(browser_ctx):
    """The tree endpoint must return every manifest entry under the
    folder, with sizes + mtimes + blob hashes."""
    client = browser_ctx["client"]
    token = browser_ctx["token"]
    r = await client.get("/api/folders/synced/tree", headers=_h(token))
    assert r.status == 200
    body = await r.json()
    assert body["folder"] == "synced"
    paths = {e["path"] for e in body["entries"]}
    assert paths == {"intro.md", "data.txt", "image.png", "binary.bin", "sub/nested.txt"}
    assert body["total_entries"] == 5
    # All entries have non-None blob hashes since we seeded them.
    for e in body["entries"]:
        assert e["blob_hash"]
        assert e["size"] > 0


@pytest.mark.asyncio
async def test_tree_404_for_unknown_folder(browser_ctx):
    client = browser_ctx["client"]
    token = browser_ctx["token"]
    r = await client.get("/api/folders/does-not-exist/tree", headers=_h(token))
    assert r.status == 404


# ── preview endpoint ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_preview_inlines_text_content(browser_ctx):
    """Text files must come back with their actual content inlined
    in the JSON, not just a stream URL."""
    client = browser_ctx["client"]
    token = browser_ctx["token"]
    r = await client.get(
        "/api/folders/synced/file/intro.md/preview", headers=_h(token),
    )
    assert r.status == 200
    body = await r.json()
    assert body["previewable"] is True
    assert body["kind"] == "markdown"
    assert "# Intro" in body["content"]
    assert body["truncated"] is False
    assert "stream_url" not in body


@pytest.mark.asyncio
async def test_preview_returns_stream_url_for_image(browser_ctx):
    """Images must hand back a stream_url for an <img> tag, not
    inline the bytes (would be a base64 disaster)."""
    client = browser_ctx["client"]
    token = browser_ctx["token"]
    r = await client.get(
        "/api/folders/synced/file/image.png/preview", headers=_h(token),
    )
    assert r.status == 200
    body = await r.json()
    assert body["previewable"] is True
    assert body["kind"] == "image"
    assert "stream_url" in body
    assert "raw" in body["stream_url"]
    assert "content" not in body


@pytest.mark.asyncio
async def test_preview_non_previewable_type_returns_flag(browser_ctx):
    """Files of types not in PREVIEW_KINDS (.bin etc.) return a
    previewable=False marker so the UI can show 'no inline preview
    for this file type' instead of blowing up."""
    client = browser_ctx["client"]
    token = browser_ctx["token"]
    r = await client.get(
        "/api/folders/synced/file/binary.bin/preview", headers=_h(token),
    )
    assert r.status == 200
    body = await r.json()
    assert body["previewable"] is False
    assert body["kind"] is None


@pytest.mark.asyncio
async def test_preview_blocks_path_traversal(browser_ctx):
    """A relative path that resolves outside the folder root must
    be rejected, not served. The hash IS the path so a naive
    join+open would let any file on disk be exfiltrated."""
    client = browser_ctx["client"]
    token = browser_ctx["token"]
    # Try to escape via ../
    r = await client.get(
        "/api/folders/synced/file/..%2Fstate.db/preview", headers=_h(token),
    )
    # 400 (blocked) or 404 (resolved to nothing) — both acceptable;
    # what we MUST NOT see is 200 with content.
    assert r.status in (400, 404)


@pytest.mark.asyncio
async def test_preview_404_for_missing_file(browser_ctx):
    client = browser_ctx["client"]
    token = browser_ctx["token"]
    r = await client.get(
        "/api/folders/synced/file/no-such-file.txt/preview", headers=_h(token),
    )
    assert r.status == 404


@pytest.mark.asyncio
async def test_preview_handles_nested_subdir(browser_ctx):
    """Files inside subdirectories must be reachable via their
    forward-slash path."""
    client = browser_ctx["client"]
    token = browser_ctx["token"]
    r = await client.get(
        "/api/folders/synced/file/sub%2Fnested.txt/preview", headers=_h(token),
    )
    assert r.status == 200
    body = await r.json()
    assert "nested content" in body["content"]


# ── raw streaming endpoint ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_raw_streams_correct_bytes(browser_ctx):
    """Raw endpoint must serve the actual file bytes verbatim with
    a correct Content-Length + Content-Type."""
    client = browser_ctx["client"]
    token = browser_ctx["token"]
    folder_dir = browser_ctx["folder_dir"]
    expected = (folder_dir / "image.png").read_bytes()
    r = await client.get(
        "/api/folders/synced/file/image.png/raw", headers=_h(token),
    )
    assert r.status == 200
    body = await r.read()
    assert body == expected
    # Content-Length matches.
    assert int(r.headers["Content-Length"]) == len(expected)
    # SAMEORIGIN guard present so a hostile page can't iframe these.
    assert r.headers.get("X-Frame-Options") == "SAMEORIGIN"


@pytest.mark.asyncio
async def test_raw_blocks_path_traversal(browser_ctx):
    client = browser_ctx["client"]
    token = browser_ctx["token"]
    r = await client.get(
        "/api/folders/synced/file/..%2Fstate.db/raw", headers=_h(token),
    )
    assert r.status in (400, 404)


# ── reveal endpoint (kill-switch verified, no real Explorer pops) ───


@pytest.mark.asyncio
async def test_reveal_respects_kill_switch(browser_ctx):
    """ONE_LINK_DISABLE_REVEAL=1 must short-circuit the actual
    Explorer/Finder/xdg-open call. The endpoint still returns 200
    with disabled=True so the UI can render a quiet OK."""
    client = browser_ctx["client"]
    token = browser_ctx["token"]
    # The fixture sets ONE_LINK_DISABLE_REVEAL=1.
    r = await client.post(
        "/api/folders/synced/file/intro.md/reveal", headers=_h(token),
    )
    assert r.status == 200
    body = await r.json()
    assert body.get("ok") is True
    assert body.get("disabled") is True


@pytest.mark.asyncio
async def test_reveal_404_for_missing_file(browser_ctx):
    client = browser_ctx["client"]
    token = browser_ctx["token"]
    r = await client.post(
        "/api/folders/synced/file/not-there.txt/reveal", headers=_h(token),
    )
    # Either 404 not found OR 400 bad path — both acceptable; what
    # MUST NOT happen is 200 with the kill switch off in a non-test
    # environment.
    assert r.status in (400, 404)


@pytest.mark.asyncio
async def test_all_endpoints_require_auth(browser_ctx):
    """No browser endpoint may serve content without the bearer
    token; otherwise local privilege escalation."""
    client = browser_ctx["client"]
    for path in (
        "/api/folders/synced/tree",
        "/api/folders/synced/file/intro.md/preview",
        "/api/folders/synced/file/intro.md/raw",
    ):
        r = await client.get(path)  # no Authorization header
        assert r.status == 401, f"{path} served without auth"
