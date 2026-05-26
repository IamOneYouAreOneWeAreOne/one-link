"""v0.21.x Ship 9 behavioral tests — diff endpoint + auto-merge
classifier edge cases.
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
        hostname="ship9-host",
    )


def _h(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


@pytest_asyncio.fixture
async def diff_ctx(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    blob_store = BlobStore(root=tmp_path / "blobs")
    daemon = Daemon(me)
    daemon.state = state
    daemon.blob_store = blob_store
    daemon.discovery = None
    daemon.folder_engine = MagicMock()
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client, blob_store, server.token
    finally:
        await client.close()
        state.close()


# ── classifier outcomes ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_diff_classifies_identical_blobs(diff_ctx):
    client, blob_store, token = diff_ctx
    a = blob_store.put_bytes(b"hello world\nsecond line\n")
    r = await client.get(
        f"/api/blobs/{a}/diff?against={a}", headers=_h(token),
    )
    assert r.status == 200
    body = await r.json()
    assert body["auto_merge"]["kind"] == "identical"
    assert body["lines_added"] == 0
    assert body["lines_removed"] == 0


@pytest.mark.asyncio
async def test_diff_classifies_b_extends_a(diff_ctx):
    """b strictly contains a as a prefix → b_extends_a hint."""
    client, blob_store, token = diff_ctx
    a = blob_store.put_bytes(b"line1\nline2\n")
    b = blob_store.put_bytes(b"line1\nline2\nline3\nline4\n")
    r = await client.get(
        f"/api/blobs/{a}/diff?against={b}", headers=_h(token),
    )
    body = await r.json()
    assert body["auto_merge"] is not None
    assert body["auto_merge"]["kind"] == "b_extends_a"


@pytest.mark.asyncio
async def test_diff_classifies_a_extends_b(diff_ctx):
    client, blob_store, token = diff_ctx
    a = blob_store.put_bytes(b"line1\nline2\nline3\nline4\n")
    b = blob_store.put_bytes(b"line1\nline2\n")
    r = await client.get(
        f"/api/blobs/{a}/diff?against={b}", headers=_h(token),
    )
    body = await r.json()
    assert body["auto_merge"]["kind"] == "a_extends_b"


@pytest.mark.asyncio
async def test_diff_unrelated_changes_no_auto_merge(diff_ctx):
    """When both sides change different parts of the same file
    (real conflict), auto_merge MUST be null — picking one side
    silently would lose work."""
    client, blob_store, token = diff_ctx
    a = blob_store.put_bytes(b"line1\nMINE\nline3\n")
    b = blob_store.put_bytes(b"line1\nTHEIRS\nline3\n")
    r = await client.get(
        f"/api/blobs/{a}/diff?against={b}", headers=_h(token),
    )
    body = await r.json()
    assert body["auto_merge"] is None


# ── diff content ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_diff_includes_unified_diff_lines(diff_ctx):
    """The unified_diff payload must contain the actual + and -
    line markers so the UI can colourize."""
    client, blob_store, token = diff_ctx
    a = blob_store.put_bytes(b"alpha\nbeta\n")
    b = blob_store.put_bytes(b"alpha\nGAMMA\n")
    r = await client.get(
        f"/api/blobs/{a}/diff?against={b}", headers=_h(token),
    )
    body = await r.json()
    diff = body["unified_diff"]
    assert "-beta" in diff
    assert "+GAMMA" in diff
    assert body["lines_added"] >= 1
    assert body["lines_removed"] >= 1


# ── input validation ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_diff_rejects_bad_hash(diff_ctx):
    """Non-hex / wrong-length hashes must return 400, NOT crash or
    leak any other-blob content via collision attempts."""
    client, blob_store, token = diff_ctx
    valid = blob_store.put_bytes(b"x")
    for bad in ("nope", "ff" * 31, "ZZ" * 32):
        r = await client.get(
            f"/api/blobs/{valid}/diff?against={bad}", headers=_h(token),
        )
        assert r.status == 400, f"hash={bad!r} should be 400"


@pytest.mark.asyncio
async def test_diff_404_when_blob_not_in_store(diff_ctx):
    client, blob_store, token = diff_ctx
    valid = blob_store.put_bytes(b"x")
    missing = "ab" * 32
    r = await client.get(
        f"/api/blobs/{valid}/diff?against={missing}", headers=_h(token),
    )
    assert r.status == 404


@pytest.mark.asyncio
async def test_diff_requires_auth(diff_ctx):
    client, blob_store, token = diff_ctx
    a = blob_store.put_bytes(b"x")
    r = await client.get(f"/api/blobs/{a}/diff?against={a}")
    assert r.status == 401
