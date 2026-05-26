"""v0.21.x folder-relocate flow.

Three layers of coverage:

  - state.set_folder_local_path: atomic path-only update, raises
    KeyError on unknown folder, rejects empty paths
  - FolderEngine.relocate_folder: end-to-end re-attach of the
    filesystem watcher to a new root, rejects non-directory
    targets
  - POST /api/folders/{name}/relocate: HTTP shape — auth required,
    validates body, returns 404 / 400 / 200 with the right body
    structure

Used together they pin the "Folder location → Browse → Move to this
location" path in the Sync settings modal.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.blobstore import BlobStore
from one_link.daemon import Daemon
from one_link.foldersync import FolderEngine
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    return Identity(
        private=sk, public=sk.public_key(), public_bytes=pub,
        fingerprint=fingerprint_of(pub), short_id=fingerprint_of(pub)[:8],
        hostname="relocate-host",
    )


def _h(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


# ── state.set_folder_local_path ──────────────────────────────────


def test_state_set_folder_local_path_updates_row(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    state.add_folder(name="x", local_path=str(src), shared_with=[])
    state.set_folder_local_path("x", str(dst))
    f = state.get_folder("x")
    assert f["local_path"] == str(dst)
    state.close()


def test_state_set_folder_local_path_raises_on_unknown(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    with pytest.raises(KeyError):
        state.set_folder_local_path("ghost", str(tmp_path))
    state.close()


def test_state_set_folder_local_path_rejects_empty(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(name="x", local_path=str(tmp_path / "x"), shared_with=[])
    with pytest.raises(ValueError):
        state.set_folder_local_path("x", "")
    with pytest.raises(ValueError):
        state.set_folder_local_path("x", "   ")
    state.close()


# ── FolderEngine.relocate_folder ─────────────────────────────────


def _make_engine(tmp_path: Path) -> tuple[FolderEngine, State]:
    state = State(db_path=tmp_path / "s.db")
    blob_store = BlobStore(root=tmp_path / "blobs")
    me = _identity()
    loop = asyncio.new_event_loop()
    engine = FolderEngine(
        state=state, blob_store=blob_store,
        my_fingerprint=me.fingerprint, loop=loop,
    )
    return engine, state


def test_engine_relocate_swaps_watcher_root(tmp_path: Path):
    engine, state = _make_engine(tmp_path)
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    engine.add_folder(name="x", local_path=src, shared_with=[])
    assert engine._folders["x"].root == src.resolve()
    row = engine.relocate_folder("x", dst)
    assert row["local_path"] == str(dst.resolve())
    assert engine._folders["x"].root == dst.resolve()
    engine.remove_folder("x")
    state.close()


def test_engine_relocate_creates_missing_target(tmp_path: Path):
    """If the new path doesn't exist yet, relocate must create it
    (mkdir parents=True) — same semantics as add_folder."""
    engine, state = _make_engine(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    engine.add_folder(name="x", local_path=src, shared_with=[])
    new = tmp_path / "fresh" / "subdir"
    assert not new.exists()
    engine.relocate_folder("x", new)
    assert new.is_dir()
    engine.remove_folder("x")
    state.close()


def test_engine_relocate_rejects_file_target(tmp_path: Path):
    """Target path that exists as a FILE (not a directory) must
    raise NotADirectoryError — you can't watch a file as a folder."""
    engine, state = _make_engine(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    engine.add_folder(name="x", local_path=src, shared_with=[])
    file_target = tmp_path / "this-is-a-file.txt"
    file_target.write_text("hello", encoding="utf-8")
    with pytest.raises(NotADirectoryError):
        engine.relocate_folder("x", file_target)
    engine.remove_folder("x")
    state.close()


def test_engine_relocate_raises_on_unknown_folder(tmp_path: Path):
    engine, state = _make_engine(tmp_path)
    with pytest.raises(KeyError):
        engine.relocate_folder("ghost", tmp_path / "anywhere")
    state.close()


# ── POST /api/folders/{name}/relocate endpoint ────────────────────


@pytest_asyncio.fixture
async def relocate_ctx(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    blob_store = BlobStore(root=tmp_path / "blobs")
    daemon = Daemon(me)
    daemon.state = state
    daemon.blob_store = blob_store
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    loop = asyncio.get_running_loop()
    daemon.folder_engine = FolderEngine(
        state=state, blob_store=blob_store,
        my_fingerprint=me.fingerprint, loop=loop,
    )
    src = tmp_path / "src"
    src.mkdir()
    daemon.folder_engine.add_folder(name="x", local_path=src, shared_with=[])
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield {
            "client": client, "daemon": daemon, "state": state,
            "token": server.token, "tmp_path": tmp_path,
        }
    finally:
        daemon.folder_engine.remove_folder("x")
        await client.close()
        state.close()


@pytest.mark.asyncio
async def test_relocate_endpoint_updates_state_and_returns_folder(relocate_ctx):
    ctx = relocate_ctx
    dst = ctx["tmp_path"] / "dst"
    dst.mkdir()
    r = await ctx["client"].post(
        "/api/folders/x/relocate",
        headers=_h(ctx["token"]),
        json={"local_path": str(dst)},
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["ok"] is True
    assert body["folder"]["local_path"] == str(dst.resolve())
    # State row is updated.
    assert ctx["state"].get_folder("x")["local_path"] == str(dst.resolve())


@pytest.mark.asyncio
async def test_relocate_endpoint_rejects_empty_path(relocate_ctx):
    r = await relocate_ctx["client"].post(
        "/api/folders/x/relocate",
        headers=_h(relocate_ctx["token"]),
        json={"local_path": "   "},
    )
    assert r.status == 400
    body = await r.json()
    assert "local_path required" in body.get("error", "")


@pytest.mark.asyncio
async def test_relocate_endpoint_returns_404_for_unknown_folder(relocate_ctx):
    dst = relocate_ctx["tmp_path"] / "dst2"
    dst.mkdir()
    r = await relocate_ctx["client"].post(
        "/api/folders/ghost/relocate",
        headers=_h(relocate_ctx["token"]),
        json={"local_path": str(dst)},
    )
    assert r.status == 404


@pytest.mark.asyncio
async def test_relocate_endpoint_rejects_file_target(relocate_ctx):
    """File (not directory) target must return 400 with the
    NotADirectoryError message, not 500."""
    file_target = relocate_ctx["tmp_path"] / "not-a-dir.txt"
    file_target.write_text("x", encoding="utf-8")
    r = await relocate_ctx["client"].post(
        "/api/folders/x/relocate",
        headers=_h(relocate_ctx["token"]),
        json={"local_path": str(file_target)},
    )
    assert r.status == 400
    body = await r.json()
    assert "not a directory" in body.get("error", "").lower()


@pytest.mark.asyncio
async def test_relocate_endpoint_requires_auth(relocate_ctx):
    """Missing Authorization header must return 401 — the path on
    disk is sensitive and the endpoint mutates daemon state."""
    dst = relocate_ctx["tmp_path"] / "dst3"
    dst.mkdir()
    r = await relocate_ctx["client"].post(
        "/api/folders/x/relocate",
        json={"local_path": str(dst)},
    )
    assert r.status == 401
