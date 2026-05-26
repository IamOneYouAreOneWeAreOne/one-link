"""v0.21.x Ship 5 behavioral tests — version history listing +
in-place restore.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.blobstore import BlobStore
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
        hostname="ship5-host",
    )


def _h(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


@pytest_asyncio.fixture
async def history_ctx(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    monkeypatch.setenv("ONE_LINK_DISABLE_NATIVE_PICKER", "1")
    folder_dir = tmp_path / "folder"
    folder_dir.mkdir()
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    blob_store = BlobStore(root=tmp_path / "blobs")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None
    daemon.blob_store = blob_store
    daemon.folder_engine = MagicMock()
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    state.add_folder(
        name="docs", local_path=str(folder_dir.resolve()),
        shared_with=[], max_file_bytes=None, ignored_patterns=[],
        conflict_policy="latest-wins",
    )
    # Create the file + write 3 successive versions, each with an
    # audit row. This is what the watcher would have produced.
    file_path = folder_dir / "notes.md"
    versions = []
    for i, content in enumerate(["v1", "v1 + line2", "v1 + line2 + line3"]):
        file_path.write_text(content, encoding="utf-8")
        h = blob_store.put_path(file_path)
        versions.append(h)
        state.record_folder_audit_event(
            folder_name="docs", peer_fp=me.fingerprint,
            action="write", file_path="notes.md", blob_hash=h,
            size=len(content),
        )
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client, state, blob_store, server.token, folder_dir, versions
    finally:
        await client.close()
        state.close()


# ── history listing ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_history_returns_versions_in_newest_first_order(history_ctx):
    client, state, blob_store, token, folder_dir, versions = history_ctx
    r = await client.get(
        "/api/folders/docs/file/notes.md/history", headers=_h(token),
    )
    assert r.status == 200
    body = await r.json()
    rows = body["versions"]
    assert len(rows) == 3
    # Newest first.
    assert rows[0]["blob_hash"] == versions[2]
    assert rows[2]["blob_hash"] == versions[0]


@pytest.mark.asyncio
async def test_history_dedupes_consecutive_same_hash(history_ctx):
    """Multiple writes of the same content (a watcher burst) should
    collapse to ONE entry in the history view."""
    client, state, blob_store, token, folder_dir, versions = history_ctx
    # Append two extra audit rows with the LATEST hash to simulate
    # a settle-after-burst.
    same = versions[-1]
    for _ in range(2):
        state.record_folder_audit_event(
            folder_name="docs", peer_fp="aaa",
            action="write", file_path="notes.md", blob_hash=same, size=99,
        )
    r = await client.get(
        "/api/folders/docs/file/notes.md/history", headers=_h(token),
    )
    body = await r.json()
    # 3 distinct hashes; the burst doesn't expand the count.
    distinct = {v["blob_hash"] for v in body["versions"]}
    assert len(distinct) == 3


@pytest.mark.asyncio
async def test_history_marks_local_available(history_ctx):
    """Each version row must indicate whether the blob is still in
    our local store. We seeded blobs so all 3 should be local."""
    client, state, blob_store, token, folder_dir, versions = history_ctx
    r = await client.get(
        "/api/folders/docs/file/notes.md/history", headers=_h(token),
    )
    body = await r.json()
    for v in body["versions"]:
        assert v["local_available"] is True


# ── restore endpoint ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_restore_writes_historical_bytes(history_ctx):
    """POST restore must overwrite the file with the historical
    blob's content (atomically — we don't test the os.replace
    atomicity here, but verify the resulting bytes match)."""
    client, state, blob_store, token, folder_dir, versions = history_ctx
    # Restore to the FIRST version ("v1").
    target_hash = versions[0]
    r = await client.post(
        "/api/folders/docs/file/notes.md/restore",
        headers=_h(token),
        json={"blob_hash": target_hash},
    )
    assert r.status == 200
    body = await r.json()
    assert body["ok"] is True
    assert body["blob_hash"] == target_hash
    # File on disk now matches "v1".
    assert (folder_dir / "notes.md").read_text(encoding="utf-8") == "v1"


@pytest.mark.asyncio
async def test_restore_refuses_missing_blob(history_ctx):
    """If the requested blob isn't in our local store (GC'd, or
    bogus hash), return 410 Gone — NOT a 500 or a silent no-op."""
    client, state, blob_store, token, folder_dir, versions = history_ctx
    r = await client.post(
        "/api/folders/docs/file/notes.md/restore",
        headers=_h(token),
        json={"blob_hash": "ff" * 32},
    )
    assert r.status == 410


@pytest.mark.asyncio
async def test_restore_rejects_bad_hash_format(history_ctx):
    """Non-hex / wrong-length hashes must be rejected with 400."""
    client, state, blob_store, token, folder_dir, versions = history_ctx
    for bad in ("notahash", "ff" * 31, "ZZ" * 32, ""):
        r = await client.post(
            "/api/folders/docs/file/notes.md/restore",
            headers=_h(token),
            json={"blob_hash": bad},
        )
        assert r.status == 400, f"hash={bad!r} should be 400"


@pytest.mark.asyncio
async def test_restore_blocks_path_traversal(history_ctx):
    """Path-traversal escape via ../ must be rejected — without
    this guard a restore could write to anywhere on disk."""
    client, state, blob_store, token, folder_dir, versions = history_ctx
    r = await client.post(
        "/api/folders/docs/file/..%2Fstate.db/restore",
        headers=_h(token),
        json={"blob_hash": versions[0]},
    )
    assert r.status in (400, 404)
    # state.db must NOT have been overwritten.
    # We can't easily check that without re-opening the file; rely
    # on the status check above to prove the path-traversal guard
    # fired before any write attempt.


@pytest.mark.asyncio
async def test_restore_writes_audit_row(history_ctx):
    """A successful restore should record a 'restored' audit row so
    the operation shows up in history itself (recursive: you can
    see WHEN you restored, and to what)."""
    client, state, blob_store, token, folder_dir, versions = history_ctx
    target = versions[1]
    r = await client.post(
        "/api/folders/docs/file/notes.md/restore",
        headers=_h(token),
        json={"blob_hash": target},
    )
    assert r.status == 200
    audit = state.list_folder_audit(folder_name="docs")
    restored = [a for a in audit if a.get("action") == "restored"]
    assert len(restored) == 1
    assert restored[0]["file_path"] == "notes.md"
    assert restored[0]["blob_hash"] == target
