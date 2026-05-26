"""v0.21.x: drag-folder upload preserves rel_path end-to-end.

The chat-UI drag-and-drop folder handler used to flatten nested
files (``subdir/file.txt`` → ``subdir_file.txt``) because the wire
protocol carried only the flat file name. v0.21.x adds a ``rel_path``
form field to /api/send-file that gets validated, forwarded to
``daemon.send_file``, and emitted on the FILE_OFFER so the receiver
can mirror the tree under inbox/<rel_path>.

This file pins:

  - Multipart endpoint: 200 with rel_path → send_file is called with
    the cleaned value; 400 on every bad-rel_path variant; the
    rel_path field is OPTIONAL (omit + endpoint still works); the
    upload temp file is cleaned up on the bad-rel_path 400 path.

  - daemon.send_file kwarg: rel_path threads through to the
    FILE_OFFER ``rel_path`` field; default None doesn't emit the
    field; sanitization at the daemon-level rejects bad paths AND
    returns None (defense in depth even when the multipart layer
    has already validated).

  - Throttle policy: send_file does NOT consult
    _sync_paused_or_quiet — clicking Send burst-sends regardless of
    quiet-hours / bandwidth-cap settings. Folder-card Send inherits
    the same behavior by design.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from aiohttp import FormData
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
        hostname="drag-folder-host",
    )


def _h(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


@pytest_asyncio.fixture
async def upload_ctx(tmp_path: Path, monkeypatch):
    """Real State + real UIServer + a stubbed send_file so we can
    assert how rel_path gets forwarded without an actual peer."""
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
    # Pin a peer so the resolve_for_send path returns something.
    peer_fp = "aa" * 32
    state.upsert_peer(
        fingerprint=peer_fp, short_id=peer_fp[:8],
        pubkey=bytes.fromhex(peer_fp), hostname="paired",
    )
    state.set_peer_trust(peer_fp, "pinned")
    # Fake the resolve + send_file pipeline.
    fake_peer = SimpleNamespace(
        short_id=peer_fp[:8], ed_pub_hex=peer_fp, hostname="paired",
    )
    daemon.resolve_for_send = AsyncMock(return_value=fake_peer)
    daemon._peer_fp_from_peer = lambda p: peer_fp if p is fake_peer else None
    daemon._is_pinned = lambda fp: fp == peer_fp
    daemon.send_file = AsyncMock(return_value={"ok": True, "transfer_id": "t1"})
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield {
            "client": client, "daemon": daemon, "state": state,
            "token": server.token, "peer_fp": peer_fp,
            "tmp_path": tmp_path,
        }
    finally:
        await client.close()
        state.close()


def _form(peer: str, payload: bytes, filename: str,
          rel_path: str | None = None) -> FormData:
    fd = FormData()
    fd.add_field("peer", peer)
    if rel_path is not None:
        fd.add_field("rel_path", rel_path)
    fd.add_field("file", payload, filename=filename,
                 content_type="application/octet-stream")
    return fd


# ── Happy path: rel_path forwards to send_file ────────────────────


@pytest.mark.asyncio
async def test_multipart_with_rel_path_forwards_to_send_file(upload_ctx):
    r = await upload_ctx["client"].post(
        "/api/send-file",
        headers=_h(upload_ctx["token"]),
        data=_form(
            upload_ctx["peer_fp"], b"hello world", "a.txt",
            rel_path="papers/2026/a.txt",
        ),
    )
    assert r.status == 200, await r.text()
    upload_ctx["daemon"].send_file.assert_awaited_once()
    kwargs = upload_ctx["daemon"].send_file.await_args.kwargs
    assert kwargs.get("rel_path") == "papers/2026/a.txt"


@pytest.mark.asyncio
async def test_multipart_without_rel_path_passes_none(upload_ctx):
    """Single-file uploads (no rel_path field) must call send_file
    with rel_path=None — flat-placement preserved."""
    r = await upload_ctx["client"].post(
        "/api/send-file",
        headers=_h(upload_ctx["token"]),
        data=_form(upload_ctx["peer_fp"], b"x", "a.txt"),
    )
    assert r.status == 200, await r.text()
    upload_ctx["daemon"].send_file.assert_awaited_once()
    kwargs = upload_ctx["daemon"].send_file.await_args.kwargs
    assert kwargs.get("rel_path") is None


@pytest.mark.asyncio
async def test_multipart_normalizes_backslashes_in_rel_path(upload_ctx):
    """Windows-style backslashes get normalized to forward slashes
    before forwarding — the sanitizer in daemon._safe_transfer_rel_path
    handles the conversion."""
    r = await upload_ctx["client"].post(
        "/api/send-file",
        headers=_h(upload_ctx["token"]),
        data=_form(
            upload_ctx["peer_fp"], b"x", "leaf.bin",
            rel_path="a\\b\\c\\leaf.bin",
        ),
    )
    assert r.status == 200
    kwargs = upload_ctx["daemon"].send_file.await_args.kwargs
    assert kwargs.get("rel_path") == "a/b/c/leaf.bin"


# ── Bad rel_path rejected with 400 (defense in depth) ────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [
    "../escape.txt",
    "a/../../../etc/passwd",
    "/etc/passwd",
    "C:\\Windows\\System32",
    "\\\\server\\share\\file",
    "CON",
    "CON.txt",
    "dir/NUL/file.txt",
    "file\x00.txt",
    "trailing-space.txt ",
    "trailing-dot. ",
    ".",
    "..",
    "./a",
])
async def test_multipart_bad_rel_path_returns_400(upload_ctx, bad):
    """Every variant of bad rel_path must return 400 with
    code=bad_rel_path. The send_file mock must NOT be called."""
    r = await upload_ctx["client"].post(
        "/api/send-file",
        headers=_h(upload_ctx["token"]),
        data=_form(
            upload_ctx["peer_fp"], b"x", "leaf.bin", rel_path=bad,
        ),
    )
    assert r.status == 400, f"bad={bad!r} expected 400 got {r.status}"
    body = await r.json()
    assert body.get("code") == "bad_rel_path", body
    upload_ctx["daemon"].send_file.assert_not_awaited()


@pytest.mark.asyncio
async def test_multipart_bad_rel_path_cleans_up_upload_temp(
    upload_ctx, tmp_path,
):
    """When rel_path validation fails the staged upload temp file
    must be cleaned up — no orphan bytes left in data/uploads/."""
    uploads_dir = upload_ctx["tmp_path"] / "data" / "uploads"
    before = list(uploads_dir.glob("*")) if uploads_dir.exists() else []
    r = await upload_ctx["client"].post(
        "/api/send-file",
        headers=_h(upload_ctx["token"]),
        data=_form(
            upload_ctx["peer_fp"], b"x" * 1024, "leaf.bin",
            rel_path="../escape",
        ),
    )
    assert r.status == 400
    after = list(uploads_dir.glob("*")) if uploads_dir.exists() else []
    # No NEW files in the staging dir after the failed upload.
    assert len(after) <= len(before)


# ── daemon.send_file rel_path kwarg ───────────────────────────────


def test_send_file_signature_accepts_rel_path(upload_ctx):
    """The send_file method must accept rel_path as a keyword-only
    arg with default None. Regression: someone removing the kwarg
    would break the whole folder-send + drag-folder pipeline."""
    import inspect
    sig = inspect.signature(Daemon.send_file)
    assert "rel_path" in sig.parameters
    assert sig.parameters["rel_path"].default is None
    assert sig.parameters["rel_path"].kind == inspect.Parameter.KEYWORD_ONLY


# ── Throttle policy pin ──────────────────────────────────────────


def _send_file_body_without_docstring() -> str:
    """Return send_file's source EXCLUDING its docstring + comments
    so source-text guards don't match prose that DOCUMENTS the
    policy rather than VIOLATES it."""
    import ast
    import inspect
    src = inspect.getsource(Daemon.send_file)
    # Strip leading indentation so ast.parse works on a method
    # extracted from its class body.
    src = inspect.cleandoc(src)
    if not src.startswith("async def"):
        src = "async " + src.split("async ", 1)[1]
    tree = ast.parse(src)
    fn = tree.body[0]
    # Drop the docstring expression if present.
    if (
        fn.body
        and isinstance(fn.body[0], ast.Expr)
        and isinstance(fn.body[0].value, ast.Constant)
        and isinstance(fn.body[0].value.value, str)
    ):
        fn.body = fn.body[1:]
    # Walk the AST and re-emit just the executable body. Any
    # reference to the symbol in real code surfaces in ast.dump.
    return ast.dump(fn)


def test_send_file_does_not_consult_sync_paused_or_quiet(upload_ctx):
    """v0.21.x explicit design: send_file is user-initiated and MUST
    NOT consult _sync_paused_or_quiet. Pin via AST inspection (not
    raw source text) so my own docstring documenting the policy
    isn't matched."""
    body = _send_file_body_without_docstring()
    assert "'_sync_paused_or_quiet'" not in body, (
        "send_file's executable body references _sync_paused_or_quiet — "
        "that gate belongs ONLY on the background sync path "
        "(push_folder_to_peer). Clicking Send must not wait for "
        "quiet hours / bandwidth-pause to end."
    )


def test_send_file_does_not_throttle_per_chunk(upload_ctx):
    """v0.21.x explicit design: send_file does NOT pace its chunks
    against sync_bandwidth_kbps. Pin via AST."""
    body = _send_file_body_without_docstring()
    assert "'_throttle_chunk'" not in body, (
        "send_file's executable body references _throttle_chunk — "
        "that throttle belongs ONLY on the background sync path. "
        "A user-initiated Send must not be paced by a sync "
        "bandwidth cap they set for background ops."
    )
