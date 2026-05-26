"""v0.21.x ad-hoc folder send via MANIFEST_PUSH ceremony.

daemon.send_adhoc_folder_one_shot_via_manifest is the DEFAULT for
the chat-composer "Folder" attach option: the user picks any folder
on disk → wrapper temp-registers it in state.folders → runs the
initial scan to build the manifest → delegates to the existing
send_folder_one_shot_via_manifest which handles the temp-share-grant
+ MANIFEST_PUSH + grant cleanup → in finally: remove the temp
registration (and stop the watcher).

Coverage:
  - Happy path: temp-register, scan, push, cleanup. Folder gone
    from state after completion.
  - Name collision: if the base name is already in state, the
    wrapper uses ``<base>__adhoc_<8hex>`` to avoid clashing.
  - Path missing: returns error, no registration attempted.
  - Path is a file (not directory): returns error.
  - Push failure: cleanup still removes the temp folder.
  - state.folders is unchanged AFTER a successful send (no leak).
  - state.folders is unchanged AFTER a FAILED send (no leak).
  - Endpoint default: /api/fs/send-folder → mode=manifest_push.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

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
        hostname="adhoc-host",
    )


def _h(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


@pytest_asyncio.fixture
async def adhoc_ctx(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    blob_store = BlobStore(root=tmp_path / "blobs")
    daemon = Daemon(me)
    daemon.state = state
    daemon.blob_store = blob_store
    # Real folder engine — we need add_folder/remove_folder watcher
    # plumbing to actually run.
    daemon.folder_engine = FolderEngine(
        state=state, blob_store=blob_store,
        my_fingerprint=me.fingerprint,
        loop=asyncio.get_running_loop(),
    )
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    peer_fp = "aa" * 32
    state.upsert_peer(
        fingerprint=peer_fp, short_id=peer_fp[:8],
        pubkey=bytes.fromhex(peer_fp), hostname="recipient",
    )
    state.set_peer_trust(peer_fp, "pinned")
    fake_peer = SimpleNamespace(
        short_id=peer_fp[:8], ed_pub_hex=peer_fp,
    )
    daemon._peer_fp_from_peer = lambda p: peer_fp if p is fake_peer else None
    daemon.discovery = MagicMock()
    daemon.discovery.registry = MagicMock()
    daemon.discovery.registry.list = MagicMock(return_value=[fake_peer])
    # Stub push_folder_to_peer so wrapper completes without real wire.
    daemon.push_folder_to_peer = AsyncMock(
        return_value={"ok": True, "blobs_sent": 2, "bytes_sent": 100},
    )
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield {
            "client": client, "daemon": daemon, "state": state,
            "token": server.token, "peer_fp": peer_fp,
            "peer": fake_peer, "tmp_path": tmp_path,
        }
    finally:
        await client.close()
        state.close()


def _make_folder(root: Path, name: str = "src") -> Path:
    p = root / name
    p.mkdir(parents=True, exist_ok=True)
    (p / "a.txt").write_text("alpha", encoding="utf-8")
    (p / "b.txt").write_text("beta", encoding="utf-8")
    return p


# ── happy path + cleanup ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_temp_registers_pushes_and_cleans_up(adhoc_ctx, tmp_path):
    src = _make_folder(tmp_path, "src")
    folders_before = {f["name"] for f in adhoc_ctx["state"].list_folders()}
    result = await adhoc_ctx["daemon"].send_adhoc_folder_one_shot_via_manifest(
        adhoc_ctx["peer"], src, "src",
    )
    assert result["ok"] is True
    assert result["temp_folder_name"] == "src"
    adhoc_ctx["daemon"].push_folder_to_peer.assert_awaited_once()
    folders_after = {f["name"] for f in adhoc_ctx["state"].list_folders()}
    # Temp folder removed — no leak.
    assert folders_after == folders_before


@pytest.mark.asyncio
async def test_name_collision_uses_suffix(adhoc_ctx, tmp_path):
    """When a folder with the base name already exists in state, the
    wrapper picks ``<base>__adhoc_<8hex>`` to avoid clashing."""
    existing_root = _make_folder(tmp_path, "preexisting")
    adhoc_ctx["state"].add_folder(
        name="src", local_path=str(existing_root), shared_with=[],
    )
    new_root = _make_folder(tmp_path, "src_new")
    result = await adhoc_ctx["daemon"].send_adhoc_folder_one_shot_via_manifest(
        adhoc_ctx["peer"], new_root, "src",
    )
    assert result["ok"] is True
    assert result["temp_folder_name"].startswith("src__adhoc_")
    assert len(result["temp_folder_name"]) == len("src__adhoc_") + 8
    # The pre-existing "src" folder is still there + UNCHANGED.
    f = adhoc_ctx["state"].get_folder("src")
    assert f is not None
    assert f["local_path"] == str(existing_root)


# ── failure modes ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_missing_path_returns_error(adhoc_ctx, tmp_path):
    result = await adhoc_ctx["daemon"].send_adhoc_folder_one_shot_via_manifest(
        adhoc_ctx["peer"], tmp_path / "does_not_exist", "ghost",
    )
    assert result["ok"] is False
    assert "directory" in result["error"].lower()
    adhoc_ctx["daemon"].push_folder_to_peer.assert_not_awaited()
    # No spurious folder registered.
    assert adhoc_ctx["state"].get_folder("ghost") is None


@pytest.mark.asyncio
async def test_file_path_rejected(adhoc_ctx, tmp_path):
    """A path that's a FILE (not directory) is rejected upfront."""
    p = tmp_path / "iam-a-file.txt"
    p.write_text("nope", encoding="utf-8")
    result = await adhoc_ctx["daemon"].send_adhoc_folder_one_shot_via_manifest(
        adhoc_ctx["peer"], p, "iam-a-file",
    )
    assert result["ok"] is False
    assert "directory" in result["error"].lower()


@pytest.mark.asyncio
async def test_push_failure_still_cleans_up(adhoc_ctx, tmp_path):
    """If push_folder_to_peer raises, the temp folder is STILL removed."""
    src = _make_folder(tmp_path, "src")
    folders_before = {f["name"] for f in adhoc_ctx["state"].list_folders()}
    adhoc_ctx["daemon"].push_folder_to_peer = AsyncMock(
        side_effect=RuntimeError("simulated"),
    )
    with pytest.raises(RuntimeError):
        await adhoc_ctx["daemon"].send_adhoc_folder_one_shot_via_manifest(
            adhoc_ctx["peer"], src, "src",
        )
    folders_after = {f["name"] for f in adhoc_ctx["state"].list_folders()}
    assert folders_after == folders_before, "leak on push failure"


# ── endpoint default ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_adhoc_uses_no_watcher_path(adhoc_ctx, tmp_path):
    """v0.21.x lightweight path: ad-hoc one-shot send must NOT spawn
    a watchdog Observer thread for the temp folder registration. The
    folder_engine.register_for_one_shot_no_watcher helper installs a
    no-op observer instead. Pin via runtime type check on the
    observer attribute the wrapper installs."""
    src = _make_folder(tmp_path, "src")
    # Hook the no-watcher registration so we can assert it was called.
    real = adhoc_ctx["daemon"].folder_engine.register_for_one_shot_no_watcher
    call_count = {"n": 0}

    def spy(name, root):
        call_count["n"] += 1
        return real(name, root)
    adhoc_ctx["daemon"].folder_engine.register_for_one_shot_no_watcher = spy
    await adhoc_ctx["daemon"].send_adhoc_folder_one_shot_via_manifest(
        adhoc_ctx["peer"], src, "src",
    )
    assert call_count["n"] == 1, (
        "ad-hoc one-shot must use register_for_one_shot_no_watcher, "
        "not folder_engine.add_folder (which spawns a watchdog Observer "
        "thread we'd just tear down)."
    )


@pytest.mark.asyncio
async def test_adhoc_endpoint_default_is_manifest_push(adhoc_ctx, tmp_path):
    """POST /api/fs/send-folder with no mode flags defaults to
    manifest_push — calls send_adhoc_folder_one_shot_via_manifest."""
    src = _make_folder(tmp_path, "src")
    adhoc_ctx["daemon"].send_adhoc_folder_one_shot_via_manifest = AsyncMock(
        return_value={"ok": True, "blobs_sent": 2, "temp_folder_name": "src"},
    )
    r = await adhoc_ctx["client"].post(
        "/api/fs/send-folder",
        headers=_h(adhoc_ctx["token"]),
        json={
            "peer_fp": adhoc_ctx["peer_fp"],
            "local_path": str(src),
        },
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["mode"] == "manifest_push"
    await asyncio.sleep(0.05)
    adhoc_ctx["daemon"].send_adhoc_folder_one_shot_via_manifest.assert_awaited_once()
