"""v0.21.x one-shot folder send.

Covers the surfaces shipped for "I literally send a folder to a
person, no sync, it gets there":

  - daemon._safe_transfer_rel_path: sanitizer for sender + receiver
    accepts safe relative paths
    rejects every traversal / absolute / control-char / reserved-name
    / oversize / non-string variant
  - daemon._unique_inbox_path(rel_path=...): containment under inbox,
    creates parent directories, handles collisions
  - POST /api/folders/{name}/send-to: HTTP shape — auth, body
    validation, peer-online check, folder-empty check, returns
    file_count + started:true and kicks the background sender
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
        hostname="oneshot-host",
    )


def _h(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


async def _wait_for_await_count(
    mocked: AsyncMock,
    expected: int,
    *,
    timeout: float = 2.0,
) -> None:
    """Wait for a tracked background send without a scheduler-speed race."""
    async with asyncio.timeout(timeout):
        while mocked.await_count < expected:
            await asyncio.sleep(0.01)


# ── _safe_transfer_rel_path sanitizer ───────────────────────────


@pytest.fixture
def daemon_with_state(tmp_path: Path, monkeypatch) -> Daemon:
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    blob_store = BlobStore(root=tmp_path / "blobs")
    d = Daemon(me)
    d.state = state
    d.blob_store = blob_store
    return d


def test_rel_path_accepts_plain_relative(daemon_with_state):
    d = daemon_with_state
    assert d._safe_transfer_rel_path("file.txt") == "file.txt"
    assert d._safe_transfer_rel_path("dir/file.txt") == "dir/file.txt"
    assert d._safe_transfer_rel_path("a/b/c/leaf.bin") == "a/b/c/leaf.bin"


def test_rel_path_normalizes_backslashes(daemon_with_state):
    d = daemon_with_state
    assert d._safe_transfer_rel_path("dir\\file.txt") == "dir/file.txt"
    assert d._safe_transfer_rel_path("a\\b\\c\\leaf.bin") == "a/b/c/leaf.bin"


def test_rel_path_rejects_empty_and_non_string(daemon_with_state):
    d = daemon_with_state
    assert d._safe_transfer_rel_path("") is None
    assert d._safe_transfer_rel_path(None) is None
    assert d._safe_transfer_rel_path(123) is None
    assert d._safe_transfer_rel_path("   ") is None


def test_rel_path_rejects_traversal(daemon_with_state):
    """The .. segment must be rejected anywhere in the path."""
    d = daemon_with_state
    assert d._safe_transfer_rel_path("../etc/passwd") is None
    assert d._safe_transfer_rel_path("a/../../etc/passwd") is None
    assert d._safe_transfer_rel_path("a/..") is None
    assert d._safe_transfer_rel_path("./a") is None
    assert d._safe_transfer_rel_path("..") is None


def test_rel_path_rejects_absolute(daemon_with_state):
    d = daemon_with_state
    assert d._safe_transfer_rel_path("/etc/passwd") is None
    assert d._safe_transfer_rel_path("C:\\Windows\\System32") is None
    assert d._safe_transfer_rel_path("D:/data") is None


def test_rel_path_rejects_unc(daemon_with_state):
    """UNC paths (\\\\server\\share\\...) must be rejected — even
    relative-looking ones could expand into a remote mount."""
    d = daemon_with_state
    assert d._safe_transfer_rel_path("\\\\server\\share\\file") is None
    assert d._safe_transfer_rel_path("//server/share/file") is None


def test_rel_path_rejects_control_chars(daemon_with_state):
    d = daemon_with_state
    assert d._safe_transfer_rel_path("file\x00.txt") is None
    assert d._safe_transfer_rel_path("file\x01.txt") is None
    assert d._safe_transfer_rel_path("dir/\x1f/file.txt") is None


def test_rel_path_rejects_windows_reserved(daemon_with_state):
    """Windows reserved device names (CON, NUL, COM1..9, etc.) must
    be rejected in any segment — opening one yields the device, not
    a file."""
    d = daemon_with_state
    assert d._safe_transfer_rel_path("CON") is None
    assert d._safe_transfer_rel_path("CON.txt") is None
    assert d._safe_transfer_rel_path("dir/NUL/file.txt") is None
    assert d._safe_transfer_rel_path("dir/COM1.log") is None
    assert d._safe_transfer_rel_path("LPT9.dat") is None


def test_rel_path_rejects_trailing_dot_or_space(daemon_with_state):
    """Windows silently strips trailing dots + spaces; a sender
    could ship 'report.pdf ' and collide with 'report.pdf'."""
    d = daemon_with_state
    assert d._safe_transfer_rel_path("file. ") is None
    assert d._safe_transfer_rel_path("file.txt ") is None
    assert d._safe_transfer_rel_path("dir / file.txt") is None
    assert d._safe_transfer_rel_path("dir./file.txt") is None


def test_rel_path_rejects_oversize(daemon_with_state):
    d = daemon_with_state
    long = "/".join(["a" * 50] * 50)  # ~2.5 KB
    assert d._safe_transfer_rel_path(long) is None


# ── _unique_inbox_path with rel_path ─────────────────────────────


def test_unique_inbox_path_creates_nested_directories(
    daemon_with_state, tmp_path, monkeypatch,
):
    """With rel_path, the allocated path is inbox/<rel_path> and
    intermediate directories get created."""
    d = daemon_with_state
    out = d._unique_inbox_path(
        "ab" * 32, "leaf.txt", rel_path="papers/2026/abstract.txt",
    )
    assert out.parent.is_dir()
    assert out.name == "abstract.txt"
    assert "papers" in out.parts
    assert "2026" in out.parts


def test_unique_inbox_path_handles_collision_under_rel_path(
    daemon_with_state, tmp_path, monkeypatch,
):
    """Two distinct offers with the same rel_path get a (1) / (2)
    suffix — same collision-avoidance pattern as flat names."""
    d = daemon_with_state
    out1 = d._unique_inbox_path(
        "aa" * 32, "x.txt", rel_path="dir/x.txt",
    )
    out1.write_text("first", encoding="utf-8")
    out2 = d._unique_inbox_path(
        "bb" * 32, "x.txt", rel_path="dir/x.txt",
    )
    assert out2 != out1
    assert "(1)" in out2.name
    assert out2.parent == out1.parent


def test_unique_inbox_path_falls_through_to_flat_on_unsafe_rel_path(
    daemon_with_state, tmp_path, monkeypatch,
):
    """A rel_path that would resolve OUTSIDE inbox (defense-in-depth
    against a sanitizer regression) falls through to flat placement
    rather than allowing escape."""
    d = daemon_with_state
    # An absolute path tries to escape; resolved-relative-to-inbox
    # raises ValueError → fallback to flat blob-prefixed.
    out = d._unique_inbox_path(
        "cc" * 32, "leaf.txt", rel_path="../../escape.txt",
    )
    # The flat path is inbox/{blob[:8]}_{name}.
    assert out.name.startswith("cccccccc_")
    assert out.name.endswith("leaf.txt")


# ── HTTP endpoint /api/folders/{name}/send-to ──────────────────


@pytest_asyncio.fixture
async def send_ctx(tmp_path: Path, monkeypatch):
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
    # Build a folder on disk with a few files.
    folder_root = tmp_path / "to_send"
    (folder_root / "sub").mkdir(parents=True)
    (folder_root / "a.txt").write_text("hello", encoding="utf-8")
    (folder_root / "sub" / "b.txt").write_text("world", encoding="utf-8")
    state.add_folder(name="papers", local_path=str(folder_root), shared_with=[])
    # Stub _peer_from_fp + send_file so the test doesn't need a real wire.
    peer_fp = "aa" * 32
    fake_peer = SimpleNamespace(short_id=peer_fp[:8], ed_pub_hex=peer_fp,
                                hostname="peerhost")
    daemon._peer_fp_from_peer = lambda p: (
        peer_fp if p is fake_peer else None
    )
    daemon.discovery = MagicMock()
    daemon.discovery.registry = MagicMock()
    daemon.discovery.registry.list = MagicMock(return_value=[fake_peer])
    daemon.send_file = AsyncMock(return_value={"ok": True})
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield {
            "client": client, "daemon": daemon, "state": state,
            "token": server.token, "peer_fp": peer_fp,
            "folder_root": folder_root,
        }
    finally:
        await client.close()
        state.close()


@pytest.mark.asyncio
async def test_per_file_mode_tags_transfers_with_folder_send_group(send_ctx):
    """v0.21.x Wave D: per-file folder send tags every send_file call
    with extra_metadata={folder_send_group: '<scope>:<ident>:<fp16>'}
    so the transfers UI can group N rows into ONE folder summary."""
    r = await send_ctx["client"].post(
        "/api/folders/papers/send-to",
        headers=_h(send_ctx["token"]),
        json={"peer_fp": send_ctx["peer_fp"], "per_file": True},
    )
    assert r.status == 200
    await _wait_for_await_count(send_ctx["daemon"].send_file, 1)
    calls = send_ctx["daemon"].send_file.await_args_list
    assert len(calls) >= 1
    for call in calls:
        extra = call.kwargs.get("extra_metadata")
        assert extra is not None, "send_file missing extra_metadata kwarg"
        assert "folder_send_group" in extra
        assert extra["folder_send_group"].startswith("folder:papers:")


@pytest.mark.asyncio
async def test_send_endpoint_per_file_mode_opt_in(send_ctx):
    """Legacy per-file mode is opt-in via per_file=true."""
    r = await send_ctx["client"].post(
        "/api/folders/papers/send-to",
        headers=_h(send_ctx["token"]),
        json={"peer_fp": send_ctx["peer_fp"], "per_file": True},
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["ok"] is True
    assert body["started"] is True
    assert body["file_count"] == 2
    assert body["mode"] == "per_file"
    await _wait_for_await_count(send_ctx["daemon"].send_file, 2)
    assert send_ctx["daemon"].send_file.await_count == 2
    calls = send_ctx["daemon"].send_file.await_args_list
    rel_paths = sorted(c.kwargs["rel_path"] for c in calls)
    assert rel_paths == ["papers/a.txt", "papers/sub/b.txt"]


@pytest.mark.asyncio
async def test_send_endpoint_archive_mode_opt_in(send_ctx):
    """Archive mode (zip + send-as-one-file) is opt-in via archive=true."""
    r = await send_ctx["client"].post(
        "/api/folders/papers/send-to",
        headers=_h(send_ctx["token"]),
        json={"peer_fp": send_ctx["peer_fp"], "archive": True},
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["mode"] == "archive"
    await _wait_for_await_count(send_ctx["daemon"].send_file, 1)
    assert send_ctx["daemon"].send_file.await_count == 1
    kwargs = send_ctx["daemon"].send_file.await_args.kwargs
    assert kwargs["rel_path"] == "__one_link_folder__/papers.zip"


@pytest.mark.asyncio
async def test_send_endpoint_default_is_manifest_push(send_ctx):
    """v0.21.x: default folder-card Send mode is MANIFEST_PUSH ceremony
    (chunk-level dedup + receiver-side Accept/Decline card). Neither
    send_file nor send_files_batched is called directly — the daemon's
    send_folder_one_shot_via_manifest takes over."""
    send_ctx["daemon"].send_folder_one_shot_via_manifest = AsyncMock(
        return_value={"ok": True, "blobs_sent": 2},
    )
    r = await send_ctx["client"].post(
        "/api/folders/papers/send-to",
        headers=_h(send_ctx["token"]),
        json={"peer_fp": send_ctx["peer_fp"]},
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["mode"] == "manifest_push"
    await asyncio.sleep(0.05)
    send_ctx["daemon"].send_folder_one_shot_via_manifest.assert_awaited_once()
    call = send_ctx["daemon"].send_folder_one_shot_via_manifest.await_args
    # peer + folder_name positional or keyword.
    assert call.args[1] == "papers" or call.kwargs.get("folder_name") == "papers"


@pytest.mark.asyncio
async def test_send_endpoint_returns_404_for_unknown_folder(send_ctx):
    r = await send_ctx["client"].post(
        "/api/folders/ghost/send-to",
        headers=_h(send_ctx["token"]),
        json={"peer_fp": send_ctx["peer_fp"]},
    )
    assert r.status == 404


@pytest.mark.asyncio
async def test_send_endpoint_rejects_empty_peer_fp(send_ctx):
    r = await send_ctx["client"].post(
        "/api/folders/papers/send-to",
        headers=_h(send_ctx["token"]),
        json={"peer_fp": ""},
    )
    assert r.status == 400


@pytest.mark.asyncio
async def test_send_endpoint_503_when_peer_offline(send_ctx):
    """Unknown peer_fp (not in discovery registry) → 503 peer_offline,
    not a silent no-op. We need users to know the recipient must be
    online; with no sync persistence this isn't store-and-forward."""
    r = await send_ctx["client"].post(
        "/api/folders/papers/send-to",
        headers=_h(send_ctx["token"]),
        json={"peer_fp": "ff" * 32},  # not in registry
    )
    assert r.status == 503
    body = await r.json()
    assert body.get("code") == "peer_offline"


@pytest.mark.asyncio
async def test_send_endpoint_409_when_folder_empty(send_ctx, tmp_path):
    """Folder with no files → 409 folder_empty, NOT a silent
    background task that sends zero bytes and never broadcasts
    completion."""
    empty_root = tmp_path / "empty"
    empty_root.mkdir()
    send_ctx["state"].add_folder(
        name="empty", local_path=str(empty_root), shared_with=[],
    )
    r = await send_ctx["client"].post(
        "/api/folders/empty/send-to",
        headers=_h(send_ctx["token"]),
        json={"peer_fp": send_ctx["peer_fp"]},
    )
    assert r.status == 409
    body = await r.json()
    assert body.get("code") == "folder_empty"


@pytest.mark.asyncio
async def test_send_endpoint_409_when_local_path_missing(send_ctx):
    """When the folder's local_path doesn't exist on disk (renamed
    user account, deleted directory) the endpoint must return 409
    with folder_path_missing so the UI can prompt for relocate."""
    bad_root = send_ctx["folder_root"].parent / "vanished"
    send_ctx["state"].set_folder_local_path("papers", str(bad_root))
    r = await send_ctx["client"].post(
        "/api/folders/papers/send-to",
        headers=_h(send_ctx["token"]),
        json={"peer_fp": send_ctx["peer_fp"]},
    )
    assert r.status == 409
    body = await r.json()
    assert body.get("code") == "folder_path_missing"


@pytest.mark.asyncio
async def test_send_endpoint_requires_auth(send_ctx):
    r = await send_ctx["client"].post(
        "/api/folders/papers/send-to",
        json={"peer_fp": send_ctx["peer_fp"]},
    )
    assert r.status == 401
