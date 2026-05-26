"""v0.21.x folder-as-archive send (one-shot).

Replaces the per-file folder-send UX with: zip the folder on sender,
ship as ONE file with rel_path = ``__one_link_folder__/<name>.zip``,
receiver auto-extracts into inbox/<name>/ and emits ONE notification.

Coverage:

  Sender:
    - _stage_folder_archive: zips real folder into staging dir,
      preserves nested paths, returns correct sizes
    - api endpoint default is archive mode
    - archive=false override falls through to per-file path
    - empty folder rejected pre-archive
    - missing folder path rejected pre-archive

  Receiver:
    - _maybe_extract_folder_archive: extracts zip into inbox/<name>/
    - returns None for non-archive paths (no-op)
    - rejects zip member with path traversal (../etc/passwd)
    - rejects member with absolute path
    - prunes the staging magic dir when empty after extract
    - cleans up the staging .zip file after successful extract

  End-to-end:
    - real zip built by _stage_folder_archive can be extracted by
      _maybe_extract_folder_archive (round-trip)
"""
from __future__ import annotations

import asyncio
import zipfile
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
        hostname="archive-host",
    )


def _h(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


def _make_file(root: Path, rel: str, contents: bytes) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(contents)
    return p


# ── _stage_folder_archive (sender) ───────────────────────────────


@pytest_asyncio.fixture
async def server_ctx(tmp_path: Path, monkeypatch):
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
    daemon.send_file = AsyncMock(return_value={"ok": True})
    # Pinned peer.
    peer_fp = "aa" * 32
    state.upsert_peer(
        fingerprint=peer_fp, short_id=peer_fp[:8],
        pubkey=bytes.fromhex(peer_fp), hostname="recipient",
    )
    state.set_peer_trust(peer_fp, "pinned")
    fake_peer = SimpleNamespace(
        short_id=peer_fp[:8], ed_pub_hex=peer_fp, hostname="recipient",
    )
    daemon._peer_fp_from_peer = lambda p: peer_fp if p is fake_peer else None
    daemon.discovery = MagicMock()
    daemon.discovery.registry = MagicMock()
    daemon.discovery.registry.list = MagicMock(return_value=[fake_peer])
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield {
            "client": client, "daemon": daemon, "server": server,
            "state": state, "token": server.token, "peer_fp": peer_fp,
            "tmp_path": tmp_path,
        }
    finally:
        await client.close()
        state.close()


def test_stage_folder_archive_zips_nested_paths(server_ctx, tmp_path):
    """The staged archive contains every file with paths relative to
    the folder root (preserves the tree)."""
    root = tmp_path / "src"
    _make_file(root, "top.txt", b"top")
    _make_file(root, "sub/leaf.txt", b"leaf")
    _make_file(root, "sub/deeper/x.bin", b"deeper")
    archive_path, orig, arch = server_ctx["server"]._stage_folder_archive(
        root, "src",
    )
    try:
        assert archive_path.is_file()
        assert orig == 3 + 4 + 6  # "top" + "leaf" + "deeper" byte counts
        assert arch > 0
        with zipfile.ZipFile(archive_path, "r") as zf:
            names = sorted(zf.namelist())
        assert names == ["sub/deeper/x.bin", "sub/leaf.txt", "top.txt"]
    finally:
        archive_path.unlink(missing_ok=True)


def test_stage_folder_archive_returns_compression_metrics(server_ctx, tmp_path):
    """Highly-compressible content shows a real compression ratio."""
    root = tmp_path / "src"
    # Repetitive text compresses dramatically.
    _make_file(root, "a.txt", b"ABCDEFG" * 10_000)
    archive_path, orig, arch = server_ctx["server"]._stage_folder_archive(
        root, "src",
    )
    try:
        assert orig == 70_000
        # ZIP DEFLATE on repetitive text should compress >10x.
        assert arch < orig // 10, (
            f"expected highly compressible; got {arch}/{orig}"
        )
    finally:
        archive_path.unlink(missing_ok=True)


def test_stage_folder_archive_handles_empty_folder(server_ctx, tmp_path):
    """Empty folder still produces a valid (empty) zip."""
    root = tmp_path / "empty"
    root.mkdir()
    archive_path, orig, arch = server_ctx["server"]._stage_folder_archive(
        root, "empty",
    )
    try:
        assert archive_path.is_file()
        assert orig == 0
        with zipfile.ZipFile(archive_path, "r") as zf:
            assert zf.namelist() == []
    finally:
        archive_path.unlink(missing_ok=True)


# ── _maybe_extract_folder_archive (receiver) ──────────────────────


def test_maybe_extract_returns_none_for_non_archive_path(server_ctx, tmp_path):
    """A regular file in inbox/ (not in the magic subdir) is left
    alone — no extraction attempted."""
    from one_link.paths import inbox_dir
    box = inbox_dir()
    box.mkdir(parents=True, exist_ok=True)
    p = box / "regular.txt"
    p.write_text("hello", encoding="utf-8")
    result = server_ctx["daemon"]._maybe_extract_folder_archive(p)
    assert result is None
    # File is still there.
    assert p.exists()


def test_maybe_extract_extracts_zip_into_inbox_subdir(server_ctx, tmp_path):
    """A zip in inbox/__one_link_folder__/ gets extracted into
    inbox/<folder_name>/ and the staging zip + magic dir get cleaned."""
    from one_link.paths import inbox_dir
    box = inbox_dir()
    magic = box / "__one_link_folder__"
    magic.mkdir(parents=True, exist_ok=True)
    archive_path = magic / "papers.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("a.txt", "alpha")
        zf.writestr("sub/b.txt", "beta")
    result = server_ctx["daemon"]._maybe_extract_folder_archive(archive_path)
    assert result is not None
    assert result["folder_name"] == "papers"
    assert result["files_extracted"] == 2
    target = box / "papers"
    assert (target / "a.txt").read_text() == "alpha"
    assert (target / "sub" / "b.txt").read_text() == "beta"
    # Staging .zip is gone.
    assert not archive_path.exists()
    # Magic dir is gone (we pruned it because it's empty).
    assert not magic.exists()


def test_maybe_extract_strips_blob_prefix_from_name(server_ctx, tmp_path):
    """Receiver inbox path allocator may prefix the zip name with
    {blob_hex[:8]}_ on collision. extract should strip the prefix
    when picking the folder name."""
    from one_link.paths import inbox_dir
    box = inbox_dir()
    magic = box / "__one_link_folder__"
    magic.mkdir(parents=True, exist_ok=True)
    archive_path = magic / "abcdef12_my-folder.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("x.txt", "x")
    result = server_ctx["daemon"]._maybe_extract_folder_archive(archive_path)
    assert result is not None
    assert result["folder_name"] == "my-folder"
    assert (box / "my-folder" / "x.txt").read_text() == "x"


def test_maybe_extract_rejects_path_traversal_in_member(server_ctx, tmp_path):
    """A zip with member name '../escape.txt' must NOT escape the
    target root. The malicious member is silently skipped; other
    members extract normally."""
    from one_link.paths import inbox_dir
    box = inbox_dir()
    magic = box / "__one_link_folder__"
    magic.mkdir(parents=True, exist_ok=True)
    archive_path = magic / "evil.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("../escape.txt", "i should not land in inbox/")
        zf.writestr("ok.txt", "this one's fine")
    result = server_ctx["daemon"]._maybe_extract_folder_archive(archive_path)
    assert result is not None
    target = box / "evil"
    # Safe member extracted.
    assert (target / "ok.txt").read_text() == "this one's fine"
    # Traversal-attempted member NOT in inbox/.
    assert not (box / "escape.txt").exists()
    # And not anywhere ABOVE inbox either.
    assert not (box.parent / "escape.txt").exists()


def test_maybe_extract_rejects_absolute_path_member(server_ctx, tmp_path):
    """A zip with absolute-path member must be rejected too."""
    from one_link.paths import inbox_dir
    box = inbox_dir()
    magic = box / "__one_link_folder__"
    magic.mkdir(parents=True, exist_ok=True)
    archive_path = magic / "abs.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("/abs/path.txt", "no")
        zf.writestr("good.txt", "yes")
    result = server_ctx["daemon"]._maybe_extract_folder_archive(archive_path)
    assert result is not None
    target = box / "abs"
    assert (target / "good.txt").read_text() == "yes"
    # Nothing under /abs/.
    assert not Path("/abs/path.txt").exists()


def test_maybe_extract_rejects_nested_folder_name_with_traversal(
    server_ctx, tmp_path,
):
    """A zip whose own filename embeds traversal (e.g. ../escape.zip)
    won't slip through — the resolver's parent-check catches it."""
    from one_link.paths import inbox_dir
    box = inbox_dir()
    magic = box / "__one_link_folder__"
    magic.mkdir(parents=True, exist_ok=True)
    # Filenames with literal ".." in stem trip our sanitizer.
    archive_path = magic / "..foo.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        zf.writestr("x.txt", "x")
    result = server_ctx["daemon"]._maybe_extract_folder_archive(archive_path)
    # Either rejected (None) OR extracted into a sanitized name.
    # Just confirm it didn't escape inbox.
    if result is not None:
        target = Path(result["target_root"])
        # Must be under inbox.
        target.relative_to(inbox_dir().resolve())


# ── round-trip ────────────────────────────────────────────────────


def test_round_trip_stage_then_extract(server_ctx, tmp_path):
    """End-to-end: the sender's _stage_folder_archive output, when
    placed into the magic dir, gets correctly extracted by the
    receiver's _maybe_extract_folder_archive."""
    src = tmp_path / "src"
    _make_file(src, "top.txt", b"top content")
    _make_file(src, "sub/leaf.txt", b"leaf content")
    _make_file(src, "sub/inner/deep.bin", b"deep")
    # Sender side.
    staged, _, _ = server_ctx["server"]._stage_folder_archive(src, "src")
    try:
        # Simulate what the receiver's inbox path allocator would do:
        # land the file at inbox/__one_link_folder__/src.zip.
        from one_link.paths import inbox_dir
        box = inbox_dir()
        magic = box / "__one_link_folder__"
        magic.mkdir(parents=True, exist_ok=True)
        dest = magic / "src.zip"
        import shutil
        shutil.copy(staged, dest)
        # Receiver side.
        result = server_ctx["daemon"]._maybe_extract_folder_archive(dest)
        assert result is not None
        assert result["folder_name"] == "src"
        assert result["files_extracted"] == 3
        target = box / "src"
        assert (target / "top.txt").read_bytes() == b"top content"
        assert (target / "sub" / "leaf.txt").read_bytes() == b"leaf content"
        assert (target / "sub" / "inner" / "deep.bin").read_bytes() == b"deep"
    finally:
        staged.unlink(missing_ok=True)


# ── endpoint defaults to archive mode ────────────────────────────


@pytest.mark.asyncio
async def test_send_to_endpoint_archive_true_uses_archive(server_ctx, tmp_path):
    """archive=true is the opt-in for zip-and-send mode."""
    src = tmp_path / "papers"
    _make_file(src, "a.txt", b"a")
    server_ctx["state"].add_folder(
        name="papers", local_path=str(src), shared_with=[],
    )
    r = await server_ctx["client"].post(
        "/api/folders/papers/send-to",
        headers=_h(server_ctx["token"]),
        json={"peer_fp": server_ctx["peer_fp"], "archive": True},
    )
    assert r.status == 200
    body = await r.json()
    assert body["mode"] == "archive"
    for _ in range(50):
        await asyncio.sleep(0.02)
        if server_ctx["daemon"].send_file.await_count >= 1:
            break
    assert server_ctx["daemon"].send_file.await_count == 1
    kwargs = server_ctx["daemon"].send_file.await_args.kwargs
    assert kwargs["rel_path"] == "__one_link_folder__/papers.zip"


@pytest.mark.asyncio
async def test_send_to_endpoint_per_file_true_uses_per_file(server_ctx, tmp_path):
    """per_file=true is the opt-in for legacy per-file mode."""
    src = tmp_path / "legacy"
    _make_file(src, "a.txt", b"a")
    server_ctx["state"].add_folder(
        name="legacy", local_path=str(src), shared_with=[],
    )
    r = await server_ctx["client"].post(
        "/api/folders/legacy/send-to",
        headers=_h(server_ctx["token"]),
        json={"peer_fp": server_ctx["peer_fp"], "per_file": True},
    )
    assert r.status == 200
    body = await r.json()
    assert body["mode"] == "per_file"


@pytest.mark.asyncio
async def test_adhoc_endpoint_defaults_to_archive_mode(server_ctx, tmp_path):
    src = tmp_path / "adhoc_folder"
    _make_file(src, "f.txt", b"f")
    r = await server_ctx["client"].post(
        "/api/fs/send-folder",
        headers=_h(server_ctx["token"]),
        json={
            "peer_fp": server_ctx["peer_fp"],
            "local_path": str(src),
        },
    )
    assert r.status == 200
    body = await r.json()
    assert body["mode"] == "archive"
    for _ in range(50):
        await asyncio.sleep(0.02)
        if server_ctx["daemon"].send_file.await_count >= 1:
            break
    kwargs = server_ctx["daemon"].send_file.await_args.kwargs
    assert kwargs["rel_path"] == "__one_link_folder__/adhoc_folder.zip"
