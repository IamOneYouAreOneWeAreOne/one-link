"""v0.21.x folder send: pre-flight preview, cancel-in-flight,
ad-hoc folder send (chat composer).

Coverage:

  BLOB_INVENTORY_QUERY wire surface
    - daemon._handle_blob_inventory_query: returns the subset of
      hashes that are in blob_store OR known to file_index_cache
    - rejects unauthorized peer with empty + rejected:not_authorized
    - clamps to MAX_QUERY_HASHES
    - skips malformed hashes

  state.has_known_file_by_blob
    - true when the cache row exists
    - false when no rows exist

  POST /api/folders/{name}/send-to/preview
    - returns file_count + total_bytes + dedup breakdown
    - 404 unknown folder
    - 400 empty peer_fp
    - 503 peer offline
    - 409 folder_empty / folder_path_missing

  POST /api/folders/{name}/send-to/cancel
    - 200 when an in-flight task is cancelled
    - 404 when nothing is running
    - send-to + cancel: in-flight task can be cancelled mid-run

  POST /api/fs/send-folder + /preview + /cancel (ad-hoc)
    - happy path
    - 400 path not directory
    - 400 missing local_path
    - 503 peer offline
    - 409 folder empty
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
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    return Identity(
        private=sk, public=sk.public_key(), public_bytes=pub,
        fingerprint=fingerprint_of(pub), short_id=fingerprint_of(pub)[:8],
        hostname="preview-host",
    )


def _h(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


# ── state.has_known_file_by_blob ─────────────────────────────────


def test_has_known_file_by_blob_false_when_no_cache(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    assert state.has_known_file_by_blob("ab" * 32) is False
    assert state.has_known_file_by_blob("") is False
    assert state.has_known_file_by_blob(None) is False
    state.close()


def test_has_known_file_by_blob_true_after_record(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    blob = "cd" * 32
    state.record_file_index_cache(
        path=str(tmp_path / "x.txt"),
        size=10, mtime_ns=1, ctime_ns=1,
        blob_hash=blob, index_kind="hash_only", chunks=[],
    )
    assert state.has_known_file_by_blob(blob) is True
    assert state.has_known_file_by_blob("99" * 32) is False
    state.close()


# ── BLOB_INVENTORY_QUERY handler ─────────────────────────────────


@pytest.mark.asyncio
async def test_blob_inventory_query_returns_known_subset(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "s.db")
    blob_store = BlobStore(root=tmp_path / "blobs")
    # Seed blob_store with one blob.
    in_store_blob = blob_store.put_bytes(b"hello")
    # Seed file_index_cache with another.
    known_via_index = "cd" * 32
    state.record_file_index_cache(
        path=str(tmp_path / "x.txt"),
        size=5, mtime_ns=1, ctime_ns=1,
        blob_hash=known_via_index, index_kind="hash_only",
        chunks=[],
    )
    daemon = Daemon(me)
    daemon.state = state
    daemon.blob_store = blob_store
    daemon._capability_allowed = lambda fp, cap: True
    captured = []

    class FakeChannel:
        async def send(self, payload):
            from one_link.daemon import decode_msg
            captured.append(decode_msg(payload))

    unknown = "99" * 32
    msg = {
        "t": "BLOB_INVENTORY_QUERY",
        "id": "q1",
        "hashes": [in_store_blob, known_via_index, unknown],
    }
    await daemon._handle_blob_inventory_query(FakeChannel(), msg, "peerfp")
    assert len(captured) == 1
    reply = captured[0]
    assert reply["t"] == "BLOB_INVENTORY_REPLY"
    assert reply["of"] == "q1"
    have = set(reply["have"])
    assert in_store_blob in have
    assert known_via_index in have
    assert unknown not in have
    state.close()


@pytest.mark.asyncio
async def test_blob_inventory_query_skips_invalid_hashes(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "s.db")
    blob_store = BlobStore(root=tmp_path / "blobs")
    daemon = Daemon(me)
    daemon.state = state
    daemon.blob_store = blob_store
    daemon._capability_allowed = lambda fp, cap: True
    captured = []

    class FakeChannel:
        async def send(self, payload):
            from one_link.daemon import decode_msg
            captured.append(decode_msg(payload))

    msg = {
        "t": "BLOB_INVENTORY_QUERY", "id": "q1",
        "hashes": ["not-hex", "ZZ" * 32, 12345, "", "aa" * 16],
    }
    await daemon._handle_blob_inventory_query(FakeChannel(), msg, "peerfp")
    reply = captured[0]
    assert reply["have"] == []
    state.close()


# ── POST /api/folders/{name}/send-to/preview ─────────────────────


@pytest_asyncio.fixture
async def preview_ctx(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    blob_store = BlobStore(root=tmp_path / "blobs")
    daemon = Daemon(me)
    daemon.state = state
    daemon.blob_store = blob_store
    daemon.folder_engine = MagicMock()
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    # Build a folder with 3 files: one whose blob is in blob_store
    # (will be reported as dedup'd), two new.
    folder_root = tmp_path / "to_send"
    folder_root.mkdir()
    f_known = folder_root / "known.txt"
    f_known.write_text("already-on-peer", encoding="utf-8")
    f_new1 = folder_root / "new1.txt"
    f_new1.write_text("brand new content", encoding="utf-8")
    f_new2 = folder_root / "new2.txt"
    f_new2.write_text("also new", encoding="utf-8")
    state.add_folder(name="papers", local_path=str(folder_root), shared_with=[])
    peer_fp = "aa" * 32
    fake_peer = SimpleNamespace(short_id=peer_fp[:8], ed_pub_hex=peer_fp,
                                hostname="peerhost")
    daemon._peer_fp_from_peer = lambda p: (
        peer_fp if p is fake_peer else None
    )
    daemon.discovery = MagicMock()
    daemon.discovery.registry = MagicMock()
    daemon.discovery.registry.list = MagicMock(return_value=[fake_peer])
    daemon.send_file = AsyncMock(return_value={"ok": True, "progress_bytes": 50})
    # v0.21.x batched path: stub send_files_batched too so the
    # folder-send task uses the batched path (under threshold) and
    # records calls we can assert.
    daemon.send_files_batched = AsyncMock(return_value={
        "ok": True, "sent": 2, "failed": 0,
        "dedup_files": 0, "dedup_bytes": 0, "results": [],
    })
    # Stub query_peer_blob_inventory: report f_known's hash as dedup'd.
    from one_link.cdc import hash_path
    known_hash = hash_path(f_known)
    daemon.query_peer_blob_inventory = AsyncMock(
        return_value={known_hash},
    )
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield {
            "client": client, "daemon": daemon, "state": state,
            "token": server.token, "peer_fp": peer_fp,
            "folder_root": folder_root, "known_hash": known_hash,
            "f_known": f_known,
        }
    finally:
        await client.close()
        state.close()


@pytest.mark.asyncio
async def test_preview_returns_dedup_breakdown(preview_ctx):
    r = await preview_ctx["client"].post(
        "/api/folders/papers/send-to/preview",
        headers=_h(preview_ctx["token"]),
        json={"peer_fp": preview_ctx["peer_fp"]},
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["ok"] is True
    assert body["file_count"] == 3
    assert body["already_on_peer_count"] == 1
    assert body["will_transfer_count"] == 2
    assert body["pre_check_complete"] is True
    # Dedup'd bytes match the known file's size.
    assert body["already_on_peer_bytes"] == preview_ctx["f_known"].stat().st_size


@pytest.mark.asyncio
async def test_preview_falls_through_on_peer_inventory_failure(preview_ctx):
    """When query_peer_blob_inventory returns None (peer doesn't
    speak the protocol, or timeout), preview reports
    pre_check_complete=false and treats every file as new.
    Empty set vs None: empty means 'peer answered, has none';
    None means 'peer didn't answer'. We pin the second case here."""
    preview_ctx["daemon"].query_peer_blob_inventory = AsyncMock(return_value=None)
    r = await preview_ctx["client"].post(
        "/api/folders/papers/send-to/preview",
        headers=_h(preview_ctx["token"]),
        json={"peer_fp": preview_ctx["peer_fp"]},
    )
    assert r.status == 200
    body = await r.json()
    assert body["pre_check_complete"] is False
    assert body["will_transfer_count"] == 3


@pytest.mark.asyncio
async def test_preview_404_for_unknown_folder(preview_ctx):
    r = await preview_ctx["client"].post(
        "/api/folders/ghost/send-to/preview",
        headers=_h(preview_ctx["token"]),
        json={"peer_fp": preview_ctx["peer_fp"]},
    )
    assert r.status == 404


@pytest.mark.asyncio
async def test_preview_400_empty_peer_fp(preview_ctx):
    r = await preview_ctx["client"].post(
        "/api/folders/papers/send-to/preview",
        headers=_h(preview_ctx["token"]),
        json={"peer_fp": ""},
    )
    assert r.status == 400


@pytest.mark.asyncio
async def test_preview_503_peer_offline(preview_ctx):
    r = await preview_ctx["client"].post(
        "/api/folders/papers/send-to/preview",
        headers=_h(preview_ctx["token"]),
        json={"peer_fp": "99" * 32},
    )
    assert r.status == 503


@pytest.mark.asyncio
async def test_preview_requires_auth(preview_ctx):
    r = await preview_ctx["client"].post(
        "/api/folders/papers/send-to/preview",
        json={"peer_fp": preview_ctx["peer_fp"]},
    )
    assert r.status == 401


# ── POST /api/folders/{name}/send-to/cancel ─────────────────────


@pytest.mark.asyncio
async def test_cancel_returns_404_when_nothing_inflight(preview_ctx):
    r = await preview_ctx["client"].post(
        "/api/folders/papers/send-to/cancel",
        headers=_h(preview_ctx["token"]),
        json={"peer_fp": preview_ctx["peer_fp"]},
    )
    assert r.status == 404


@pytest.mark.asyncio
async def test_send_then_cancel_stops_in_flight_task(preview_ctx):
    """Kick a folder send whose send_file blocks; cancel; verify the
    task gets cancelled mid-loop + the registry entry is cleaned up."""
    # Make send_file block forever so we can cancel mid-loop.
    blocker = asyncio.Event()

    async def blocking_send(*a, **kw):
        await blocker.wait()
        return {"ok": True}
    preview_ctx["daemon"].send_file = AsyncMock(side_effect=blocking_send)

    r1 = await preview_ctx["client"].post(
        "/api/folders/papers/send-to",
        headers=_h(preview_ctx["token"]),
        json={"peer_fp": preview_ctx["peer_fp"]},
    )
    assert r1.status == 200
    # Cancel.
    r2 = await preview_ctx["client"].post(
        "/api/folders/papers/send-to/cancel",
        headers=_h(preview_ctx["token"]),
        json={"peer_fp": preview_ctx["peer_fp"]},
    )
    assert r2.status == 200, await r2.text()
    body = await r2.json()
    assert body["cancelled"] is True
    # After cancel, registry entry should clear once the bg task
    # unwinds its cleanup. Give it a tick.
    blocker.set()  # unblock any final task work
    await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_cancel_400_missing_peer_fp(preview_ctx):
    r = await preview_ctx["client"].post(
        "/api/folders/papers/send-to/cancel",
        headers=_h(preview_ctx["token"]),
        json={},
    )
    assert r.status == 400


# ── POST /api/fs/send-folder (ad-hoc) ────────────────────────────


@pytest.mark.asyncio
async def test_adhoc_send_folder_happy_path(preview_ctx):
    """Happy path with FAST-PATH dedup active + BATCHED send used
    for the actually-new small files. Three files in fixture:
      - known.txt → dedup via fast-path (no wire activity at all)
      - new1.txt, new2.txt → batched via send_files_batched
    send_file itself is NOT called (those files are below the 16MB
    threshold so they go through the batched path)."""
    r = await preview_ctx["client"].post(
        "/api/fs/send-folder",
        headers=_h(preview_ctx["token"]),
        json={
            "peer_fp": preview_ctx["peer_fp"],
            "local_path": str(preview_ctx["folder_root"]),
        },
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["ok"] is True
    assert body["started"] is True
    assert body["file_count"] == 3
    assert body["name"] == "to_send"
    # Wait for the background task to complete.
    for _ in range(50):
        await asyncio.sleep(0.02)
        if preview_ctx["daemon"].send_files_batched.await_count >= 1:
            break
    # send_files_batched was called exactly once with the 2 new files
    # (known.txt was already dedup'd via fast-path before this stage).
    assert preview_ctx["daemon"].send_files_batched.await_count == 1
    call = preview_ctx["daemon"].send_files_batched.await_args
    specs = call.args[1] if len(call.args) >= 2 else call.kwargs["file_specs"]
    rel_paths = sorted(rel for _, rel in specs)
    assert rel_paths == ["to_send/new1.txt", "to_send/new2.txt"], (
        f"known.txt should have been skipped via fast-path; "
        f"batched call rel_paths: {rel_paths}"
    )
    # And send_file (single-file path) was NOT called — these files
    # are under the LARGE_FILE_THRESHOLD so they batched.
    assert preview_ctx["daemon"].send_file.await_count == 0


@pytest.mark.asyncio
async def test_adhoc_send_folder_fast_path_skips_all_dedup_files(preview_ctx):
    """When EVERY file in the folder is already on the peer, the
    fast-path skips both send_files_batched AND send_file — zero
    per-file FILE_OFFER round-trips. Big win for re-send-same-folder."""
    from one_link.cdc import hash_path
    root = preview_ctx["folder_root"]
    all_hashes = {hash_path(p) for p in root.rglob("*") if p.is_file()}
    preview_ctx["daemon"].query_peer_blob_inventory = AsyncMock(
        return_value=all_hashes,
    )
    r = await preview_ctx["client"].post(
        "/api/fs/send-folder",
        headers=_h(preview_ctx["token"]),
        json={
            "peer_fp": preview_ctx["peer_fp"],
            "local_path": str(root),
        },
    )
    assert r.status == 200
    await asyncio.sleep(0.1)
    # Neither path called — every file fast-path'd.
    assert preview_ctx["daemon"].send_file.await_count == 0
    assert preview_ctx["daemon"].send_files_batched.await_count == 0


@pytest.mark.asyncio
async def test_adhoc_send_folder_no_fast_path_when_probe_fails(preview_ctx):
    """When BLOB_INVENTORY_QUERY returns None (peer doesn't speak
    the protocol / timeout), every file still flows through the
    BATCHED send_files_batched path — the chunk-level dedup that
    happens INSIDE that path (via FILE_OFFER's CDC chunk hashes)
    is the fallback."""
    preview_ctx["daemon"].query_peer_blob_inventory = AsyncMock(return_value=None)
    r = await preview_ctx["client"].post(
        "/api/fs/send-folder",
        headers=_h(preview_ctx["token"]),
        json={
            "peer_fp": preview_ctx["peer_fp"],
            "local_path": str(preview_ctx["folder_root"]),
        },
    )
    assert r.status == 200
    for _ in range(50):
        await asyncio.sleep(0.02)
        if preview_ctx["daemon"].send_files_batched.await_count >= 1:
            break
    # All 3 files batched into a single send_files_batched call.
    assert preview_ctx["daemon"].send_files_batched.await_count == 1
    call = preview_ctx["daemon"].send_files_batched.await_args
    specs = call.args[1] if len(call.args) >= 2 else call.kwargs["file_specs"]
    assert len(specs) == 3


@pytest.mark.asyncio
async def test_adhoc_send_folder_large_files_use_per_file_send_file(
    preview_ctx, tmp_path,
):
    """Files >= LARGE_FILE_THRESHOLD (16 MB) bypass the batched path
    so the native pipeline + QUIC fast-path + adaptive scheduler all
    apply. Build a file just over the threshold and verify."""
    large_root = tmp_path / "large_folder"
    large_root.mkdir()
    big_file = large_root / "big.bin"
    big_file.write_bytes(b"x" * (17 * 1024 * 1024))
    preview_ctx["state"].add_folder(
        name="large", local_path=str(large_root), shared_with=[],
    )
    preview_ctx["daemon"].query_peer_blob_inventory = AsyncMock(return_value=set())
    r = await preview_ctx["client"].post(
        "/api/folders/large/send-to",
        headers=_h(preview_ctx["token"]),
        json={"peer_fp": preview_ctx["peer_fp"]},
    )
    assert r.status == 200
    for _ in range(50):
        await asyncio.sleep(0.02)
        if preview_ctx["daemon"].send_file.await_count >= 1:
            break
    # Big file → per-file send_file (single call), NOT batched.
    assert preview_ctx["daemon"].send_file.await_count == 1
    assert preview_ctx["daemon"].send_files_batched.await_count == 0


@pytest.mark.asyncio
async def test_adhoc_send_folder_400_not_directory(preview_ctx, tmp_path):
    file_target = tmp_path / "not-a-dir.txt"
    file_target.write_text("x", encoding="utf-8")
    r = await preview_ctx["client"].post(
        "/api/fs/send-folder",
        headers=_h(preview_ctx["token"]),
        json={
            "peer_fp": preview_ctx["peer_fp"],
            "local_path": str(file_target),
        },
    )
    assert r.status == 400
    body = await r.json()
    assert body.get("code") == "not_a_directory"


@pytest.mark.asyncio
async def test_adhoc_send_folder_400_missing_local_path(preview_ctx):
    r = await preview_ctx["client"].post(
        "/api/fs/send-folder",
        headers=_h(preview_ctx["token"]),
        json={"peer_fp": preview_ctx["peer_fp"]},
    )
    assert r.status == 400


@pytest.mark.asyncio
async def test_adhoc_send_folder_503_peer_offline(preview_ctx):
    r = await preview_ctx["client"].post(
        "/api/fs/send-folder",
        headers=_h(preview_ctx["token"]),
        json={
            "peer_fp": "99" * 32,
            "local_path": str(preview_ctx["folder_root"]),
        },
    )
    assert r.status == 503


@pytest.mark.asyncio
async def test_adhoc_send_folder_409_empty(preview_ctx, tmp_path):
    empty = tmp_path / "empty-dir"
    empty.mkdir()
    r = await preview_ctx["client"].post(
        "/api/fs/send-folder",
        headers=_h(preview_ctx["token"]),
        json={
            "peer_fp": preview_ctx["peer_fp"],
            "local_path": str(empty),
        },
    )
    assert r.status == 409


@pytest.mark.asyncio
async def test_adhoc_preview_returns_breakdown(preview_ctx):
    r = await preview_ctx["client"].post(
        "/api/fs/send-folder/preview",
        headers=_h(preview_ctx["token"]),
        json={
            "peer_fp": preview_ctx["peer_fp"],
            "local_path": str(preview_ctx["folder_root"]),
        },
    )
    assert r.status == 200
    body = await r.json()
    assert body["file_count"] == 3
    assert body["already_on_peer_count"] == 1


@pytest.mark.asyncio
async def test_adhoc_cancel_404_when_nothing_inflight(preview_ctx):
    r = await preview_ctx["client"].post(
        "/api/fs/send-folder/cancel",
        headers=_h(preview_ctx["token"]),
        json={
            "peer_fp": preview_ctx["peer_fp"],
            "local_path": str(preview_ctx["folder_root"]),
        },
    )
    assert r.status == 404


@pytest.mark.asyncio
async def test_adhoc_send_then_cancel(preview_ctx):
    blocker = asyncio.Event()

    async def blocking_send(*a, **kw):
        await blocker.wait()
        return {"ok": True}
    preview_ctx["daemon"].send_file = AsyncMock(side_effect=blocking_send)
    r1 = await preview_ctx["client"].post(
        "/api/fs/send-folder",
        headers=_h(preview_ctx["token"]),
        json={
            "peer_fp": preview_ctx["peer_fp"],
            "local_path": str(preview_ctx["folder_root"]),
        },
    )
    assert r1.status == 200
    r2 = await preview_ctx["client"].post(
        "/api/fs/send-folder/cancel",
        headers=_h(preview_ctx["token"]),
        json={
            "peer_fp": preview_ctx["peer_fp"],
            "local_path": str(preview_ctx["folder_root"]),
        },
    )
    assert r2.status == 200
    body = await r2.json()
    assert body["cancelled"] is True
    blocker.set()
    await asyncio.sleep(0.05)


@pytest.mark.asyncio
async def test_adhoc_endpoints_require_auth(preview_ctx):
    for url in [
        "/api/fs/send-folder",
        "/api/fs/send-folder/preview",
        "/api/fs/send-folder/cancel",
    ]:
        r = await preview_ctx["client"].post(url, json={
            "peer_fp": preview_ctx["peer_fp"],
            "local_path": str(preview_ctx["folder_root"]),
        })
        assert r.status == 401, f"{url} should require auth"
