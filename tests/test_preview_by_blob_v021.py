"""Content-addressed file serving for stable previews.

Name-based serving (``/api/files/{name}``) 404s when the on-disk inbox
name differs from the chat's display name — collision suffix
(``{blob8}_{name}``), folder-share subdir, or the *same* display name
received twice (two ``*_photo.png`` files → the suffix resolver finds
>1 → None). The chat then shows "Image preview unavailable" on a file
plainly on disk.

``/api/files/by-blob/{hash}`` serves by content hash — the one id both
ends always agree on — resolving via the transfer ledger's exact
``metadata.path`` then the blob store.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from aiohttp import web

from one_link.state import State


# ─── ledger lookup ──────────────────────────────────────────────────────

def test_get_transfer_by_blob_prefers_complete_with_path(tmp_path):
    s = State(db_path=tmp_path / "s.db")
    try:
        # An older offered row (no usable path) + a newer complete row
        # whose metadata.path points at a real file, same blob.
        s.upsert_transfer(
            id="in:old", direction="in", peer_fp="aa" * 32, kind="file",
            name="image.png", size=7, blob_hash="ab" * 32, status="offered",
            progress_bytes=0, total_bytes=7, chunks_done=0, chunks_total=1,
            metadata={},
        )
        f = tmp_path / "ab12cd34_stored_under_a_different_name.png"
        f.write_bytes(b"PNGDATA")
        s.upsert_transfer(
            id="in:done", direction="in", peer_fp="aa" * 32, kind="file",
            name="image.png", size=7, blob_hash="ab" * 32, status="complete",
            progress_bytes=7, total_bytes=7, chunks_done=1, chunks_total=1,
            metadata={"path": str(f)},
        )
        rec = s.get_transfer_by_blob("ab" * 32)
        assert rec is not None
        assert rec.status == "complete"
        assert rec.metadata.get("path") == str(f)
    finally:
        s.close()


def test_get_transfer_by_blob_falls_back_to_newest_when_no_path(tmp_path):
    s = State(db_path=tmp_path / "s.db")
    try:
        s.upsert_transfer(
            id="in:offer", direction="in", peer_fp="aa" * 32, kind="file",
            name="image.png", size=7, blob_hash="ab" * 32, status="offered",
            progress_bytes=0, total_bytes=7, chunks_done=0, chunks_total=1,
            metadata={},
        )
        rec = s.get_transfer_by_blob("ab" * 32)
        # No on-disk path anywhere → still resolve the (only) row so the
        # blob-store fallback in the handler can take over.
        assert rec is not None and rec.id == "in:offer"
    finally:
        s.close()


def test_get_transfer_by_blob_none_for_unknown(tmp_path):
    s = State(db_path=tmp_path / "s.db")
    try:
        assert s.get_transfer_by_blob("cd" * 32) is None
        assert s.get_transfer_by_blob("") is None
    finally:
        s.close()


# ─── route ordering ─────────────────────────────────────────────────────

def test_by_blob_route_registered_before_name_catchall():
    """The hex by-blob route must register ahead of the greedy
    ``{name:.+}`` catch-all, else the catch-all (whose ``.+`` matches a
    slash) swallows ``by-blob/<hash>``."""
    import inspect

    from one_link import server as srv

    src = inspect.getsource(srv)
    by_blob = src.find('/api/files/by-blob/{blob}')
    catchall = src.find('/api/files/{name:.+}", self._guarded(self.api_file_download)')
    assert by_blob > 0, "by-blob route registration not found"
    assert catchall > 0, "catch-all download route registration not found"
    assert by_blob < catchall, "by-blob route must register before the catch-all"


# ─── handler behavior ───────────────────────────────────────────────────

def _server(monkeypatch, tmp_path, *, state=None, blob_store=None):
    from one_link.server import UIServer

    daemon = SimpleNamespace(
        state=state,
        blob_store=blob_store,
        discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
    )
    return UIServer(daemon)


def _req(blob, *, as_ext=None):
    query = {} if as_ext is None else {"as": as_ext}
    return SimpleNamespace(match_info={"blob": blob}, query=query)


@pytest.mark.asyncio
async def test_by_blob_rejects_non_hex(monkeypatch, tmp_path):
    server = _server(monkeypatch, tmp_path)
    for bad in ["../etc/passwd", "zzz", "AB/CD", "g" * 10, "x" * 65, ""]:
        resp = await server.api_file_by_blob(_req(bad))
        assert resp.status == 400, f"accepted bad hash {bad!r}"


@pytest.mark.asyncio
async def test_by_blob_serves_ledger_path_despite_duplicate_names(monkeypatch, tmp_path):
    """The exact failure: two received files share the display name
    ``photo.png`` (so the name resolver would find >1 and 404), but
    by-blob serves the precise ledger-recorded file."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    f1 = inbox / "ab12cd34_photo.png"
    f1.write_bytes(b"FIRST")
    (inbox / "ef567890_photo.png").write_bytes(b"SECOND")

    s = State(db_path=tmp_path / "s.db")
    s.upsert_transfer(
        id="in:1", direction="in", peer_fp="aa" * 32, kind="file",
        name="photo.png", size=5, blob_hash="ab" * 32, status="complete",
        progress_bytes=5, total_bytes=5, chunks_done=1, chunks_total=1,
        metadata={"path": str(f1)},
    )
    try:
        server = _server(monkeypatch, tmp_path, state=s)
        resp = await server.api_file_by_blob(_req("ab" * 32))
        assert isinstance(resp, web.FileResponse)
        assert resp.status == 200
        assert Path(getattr(resp, "_path")) == f1
        # Content-Type inferred from the ledger row's display name.
        assert resp.headers["Content-Type"] == "image/png"
        # Same-origin framing widened so the lightbox/<img> can load it.
        assert resp.headers["Content-Security-Policy"] == "frame-ancestors 'self'"
    finally:
        s.close()


@pytest.mark.asyncio
async def test_by_blob_as_hint_sets_content_type(monkeypatch, tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    f = inbox / "deadbeef_blob.bin"  # extension-less-ish on-disk name
    f.write_bytes(b"DATA")
    s = State(db_path=tmp_path / "s.db")
    s.upsert_transfer(
        id="in:1", direction="in", peer_fp="aa" * 32, kind="file",
        name="blob.bin", size=4, blob_hash="ab" * 32, status="complete",
        progress_bytes=4, total_bytes=4, chunks_done=1, chunks_total=1,
        metadata={"path": str(f)},
    )
    try:
        server = _server(monkeypatch, tmp_path, state=s)
        resp = await server.api_file_by_blob(_req("ab" * 32, as_ext="webp"))
        assert resp.status == 200
        assert resp.headers["Content-Type"] == "image/webp"
    finally:
        s.close()


@pytest.mark.asyncio
async def test_by_blob_falls_back_to_blob_store(monkeypatch, tmp_path):
    """When the ledger has no on-disk path (e.g. a folder-sync file that
    lives only in the content store), serve straight from the store."""
    from one_link.blobstore import BlobStore

    store = BlobStore(tmp_path / "blobs")
    h = store.put_bytes(b"FOLDER-SYNC-IMAGE")
    server = _server(monkeypatch, tmp_path, state=None, blob_store=store)
    resp = await server.api_file_by_blob(_req(h, as_ext="png"))
    assert isinstance(resp, web.FileResponse)
    assert resp.status == 200
    assert Path(getattr(resp, "_path")) == store.path(h)
    assert resp.headers["Content-Type"] == "image/png"


@pytest.mark.asyncio
async def test_by_blob_404_when_nowhere(monkeypatch, tmp_path):
    server = _server(monkeypatch, tmp_path, state=None, blob_store=None)
    resp = await server.api_file_by_blob(_req("ab" * 32))
    assert resp.status == 404
