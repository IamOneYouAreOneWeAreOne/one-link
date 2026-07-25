"""v0.21.x smart auto-routing for folder Send.

When the caller doesn't force a mode, the endpoint inspects the
folder + peer state and picks one of {manifest_push, archive,
per_file}. Pin the decision matrix here:

  - >30% bytes already on peer  → manifest_push (chunk dedup wins)
  - >50% compressible bytes + >=64KB total → archive (compression wins)
  - default                     → manifest_push

Explicit mode overrides (archive=true, per_file=true, mode='X') always
win — the auto-router never overrides what the caller asked for.
"""
from __future__ import annotations

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
        hostname="auto-host",
    )


def _h(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


@pytest_asyncio.fixture
async def auto_ctx(tmp_path: Path, monkeypatch):
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
    peer_fp = "aa" * 32
    state.upsert_peer(
        fingerprint=peer_fp, short_id=peer_fp[:8],
        pubkey=bytes.fromhex(peer_fp), hostname="r",
    )
    state.set_peer_trust(peer_fp, "pinned")
    fake_peer = SimpleNamespace(
        short_id=peer_fp[:8], ed_pub_hex=peer_fp,
    )
    daemon._peer_fp_from_peer = lambda p: peer_fp if p is fake_peer else None
    daemon.discovery = MagicMock()
    daemon.discovery.registry = MagicMock()
    daemon.discovery.registry.list = MagicMock(return_value=[fake_peer])
    daemon.query_peer_blob_inventory = AsyncMock(return_value=set())
    # Stub all three send paths so we can verify which one gets called.
    daemon.send_file = AsyncMock(return_value={"ok": True})
    daemon.send_files_batched = AsyncMock(return_value={
        "ok": True, "sent": 0, "failed": 0,
        "dedup_files": 0, "dedup_bytes": 0, "results": [],
    })
    daemon.send_folder_one_shot_via_manifest = AsyncMock(
        return_value={"ok": True, "blobs_sent": 0},
    )
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield {
            "client": client, "daemon": daemon, "state": state,
            "server": server, "token": server.token,
            "peer_fp": peer_fp, "peer": fake_peer,
            "tmp_path": tmp_path,
        }
    finally:
        await client.close()
        state.close()


def _add_folder(state, name, root, files: list[tuple[str, bytes]]):
    root.mkdir(parents=True, exist_ok=True)
    for rel, data in files:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    state.add_folder(name=name, local_path=str(root), shared_with=[])


# ── _pick_folder_send_mode (direct) ──────────────────────────────


@pytest.mark.asyncio
async def test_picker_chooses_manifest_push_when_dedup_high(auto_ctx, tmp_path):
    """Peer already has >30% of bytes → manifest_push (chunk dedup wins)."""
    files = []
    for i in range(3):
        p = tmp_path / f"f{i}.txt"
        p.write_bytes(b"x" * 10_000)
        files.append((p, f"f{i}.txt"))
    # Force the inventory to report all hashes as "have" (100% dedup).
    from one_link.cdc import hash_path
    auto_ctx["daemon"].query_peer_blob_inventory = AsyncMock(
        return_value={hash_path(p) for p, _ in files},
    )
    mode, reasoning = await auto_ctx["server"]._pick_folder_send_mode(
        peer=auto_ctx["peer"], files=files,
    )
    assert mode == "manifest_push"
    assert reasoning["dedup_ratio"] >= 0.3


@pytest.mark.asyncio
async def test_picker_chooses_archive_for_compressible(auto_ctx, tmp_path):
    """Compressible text content > 64 KB → archive (compression wins)."""
    files = []
    for i in range(5):
        p = tmp_path / f"f{i}.py"
        p.write_bytes(b"# python code\n" * 2000)  # ~28KB each, all .py
        files.append((p, f"f{i}.py"))
    mode, reasoning = await auto_ctx["server"]._pick_folder_send_mode(
        peer=auto_ctx["peer"], files=files,
    )
    assert mode == "archive"
    assert reasoning["compressible_ratio"] >= 0.5


@pytest.mark.asyncio
async def test_picker_falls_back_to_manifest_push_for_media(auto_ctx, tmp_path):
    """Folder of already-compressed media (.jpg) with no dedup overlap →
    fallback to manifest_push (archive wouldn't compress; per_file isn't
    a clear win without dedup signal either)."""
    files = []
    for i in range(3):
        p = tmp_path / f"p{i}.jpg"
        p.write_bytes(b"\xff\xd8\xff\xe0" + b"x" * 200_000)  # 200KB fake JPG
        files.append((p, f"p{i}.jpg"))
    mode, reasoning = await auto_ctx["server"]._pick_folder_send_mode(
        peer=auto_ctx["peer"], files=files,
    )
    assert mode == "manifest_push"


@pytest.mark.asyncio
async def test_picker_chooses_manifest_push_for_tiny_folder(auto_ctx, tmp_path):
    """Tiny folder (<64KB) doesn't hit the compression threshold even
    if it's text — falls back to manifest_push."""
    files = []
    for i in range(2):
        p = tmp_path / f"t{i}.txt"
        p.write_bytes(b"tiny text content\n")  # ~18 bytes
        files.append((p, f"t{i}.txt"))
    mode, _ = await auto_ctx["server"]._pick_folder_send_mode(
        peer=auto_ctx["peer"], files=files,
    )
    assert mode == "manifest_push"


# ── endpoint integration ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_endpoint_default_uses_auto_router(auto_ctx, tmp_path):
    """No mode flag in body → endpoint runs the picker. Response
    carries 'auto_routing' dict with the reasoning."""
    src = tmp_path / "papers"
    _add_folder(
        auto_ctx["state"], "papers", src,
        [(f"f{i}.py", b"# code\n" * 5000) for i in range(3)],
    )
    r = await auto_ctx["client"].post(
        "/api/folders/papers/send-to",
        headers=_h(auto_ctx["token"]),
        json={"peer_fp": auto_ctx["peer_fp"]},
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    # Compressible folder → archive.
    assert body["mode"] == "archive"
    assert "auto_routing" in body
    assert body["auto_routing"]["why"]


@pytest.mark.asyncio
async def test_endpoint_explicit_mode_overrides_picker(auto_ctx, tmp_path):
    """archive=true explicitly always wins, even if the picker would
    have picked something else."""
    src = tmp_path / "papers"
    _add_folder(
        auto_ctx["state"], "papers", src,
        [("f.txt", b"tiny")],
    )
    # Force the picker to pick manifest_push (tiny folder).
    r = await auto_ctx["client"].post(
        "/api/folders/papers/send-to",
        headers=_h(auto_ctx["token"]),
        json={"peer_fp": auto_ctx["peer_fp"], "archive": True},
    )
    assert r.status == 200
    body = await r.json()
    assert body["mode"] == "archive"
    assert "archive=true override" in body["auto_routing"]["why"]


@pytest.mark.asyncio
async def test_endpoint_explicit_per_file_overrides_picker(auto_ctx, tmp_path):
    src = tmp_path / "papers"
    _add_folder(
        auto_ctx["state"], "papers", src,
        [(f"f{i}.py", b"# code\n" * 5000) for i in range(3)],
    )
    # Even with compressible content, per_file=true overrides.
    r = await auto_ctx["client"].post(
        "/api/folders/papers/send-to",
        headers=_h(auto_ctx["token"]),
        json={"peer_fp": auto_ctx["peer_fp"], "per_file": True},
    )
    assert r.status == 200
    body = await r.json()
    assert body["mode"] == "per_file"
    assert "per_file=true override" in body["auto_routing"]["why"]


@pytest.mark.asyncio
async def test_preview_endpoint_includes_recommended_mode(auto_ctx, tmp_path):
    """v0.21.x Wave C: preview response now carries auto-router
    recommendation so the confirmation modal can show the user
    'Recommended: Compressed archive · 100% compressible' before
    they click Send."""
    src = tmp_path / "preview_demo"
    _add_folder(
        auto_ctx["state"], "preview_demo", src,
        [(f"f{i}.py", b"# code\n" * 5000) for i in range(3)],
    )
    r = await auto_ctx["client"].post(
        "/api/folders/preview_demo/send-to/preview",
        headers=_h(auto_ctx["token"]),
        json={"peer_fp": auto_ctx["peer_fp"]},
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert "recommended_mode" in body
    assert body["recommended_mode"] in {"archive", "manifest_push", "per_file"}
    assert "recommended_reason" in body
    assert body["recommended_compressible_ratio"] is not None


@pytest.mark.asyncio
async def test_endpoint_mode_string_override_works(auto_ctx, tmp_path):
    """mode='manifest_push' (string flag) also forces."""
    src = tmp_path / "papers"
    _add_folder(
        auto_ctx["state"], "papers", src,
        [(f"f{i}.py", b"# code\n" * 5000) for i in range(3)],
    )
    r = await auto_ctx["client"].post(
        "/api/folders/papers/send-to",
        headers=_h(auto_ctx["token"]),
        json={"peer_fp": auto_ctx["peer_fp"], "mode": "manifest_push"},
    )
    assert r.status == 200
    body = await r.json()
    assert body["mode"] == "manifest_push"
