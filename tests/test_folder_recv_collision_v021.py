"""v0.21.x folder receive: surface file-overwrite collisions.

When folder_engine._materialize is about to overwrite a local file
that exists with a DIFFERENT size than the incoming manifest entry,
fire the _on_collision_detected callback so the daemon broadcasts a
folder_recv_collision WS event. CRDT semantics still rule (the
overwrite proceeds per conflict_policy); the user just sees what
happened so they can recover from chunk cache if needed.

Coverage:
  - Same size, identical content: NO collision fired
  - Different size: collision fired with old/new sizes + incoming blob
  - Brand-new file (no existing dst): NO collision fired
  - Callback wiring: daemon's _on_folder_collision broadcasts the WS
    event with the expected payload
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.blobstore import BlobStore
from one_link.daemon import Daemon
from one_link.foldersync import FolderEngine, ManifestEntry
from one_link.identity import Identity, fingerprint_of
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    return Identity(
        private=sk, public=sk.public_key(), public_bytes=pub,
        fingerprint=fingerprint_of(pub), short_id=fingerprint_of(pub)[:8],
        hostname="collision-host",
    )


def _engine_setup(tmp_path: Path):
    me = _identity()
    state = State(db_path=tmp_path / "s.db")
    blob_store = BlobStore(root=tmp_path / "blobs")
    loop = asyncio.new_event_loop()
    engine = FolderEngine(
        state=state, blob_store=blob_store,
        my_fingerprint=me.fingerprint, loop=loop,
    )
    return engine, state, blob_store, me


# ── _on_collision_detected callback fired correctly ─────────────


def test_collision_fired_for_different_size(tmp_path: Path):
    engine, state, blob_store, _ = _engine_setup(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    # Existing local file at "x.txt" with size 100.
    (src / "x.txt").write_bytes(b"old" * 33)  # 99 bytes — different
    state.add_folder(
        name="demo", local_path=str(src), shared_with=[],
    )
    # Put an INCOMING blob in blob_store so _materialize doesn't
    # short-circuit on "blob not local yet".
    incoming_bytes = b"new content " * 50  # 600 bytes — different size
    incoming_blob = blob_store.put_bytes(incoming_bytes)
    collisions: list[tuple] = []
    engine._on_collision_detected = lambda *args: collisions.append(args)
    entry = ManifestEntry(
        file_path="x.txt",
        blob_hash=incoming_blob,
        size=len(incoming_bytes),
        mtime_ms=1,
        vclock={},
    )
    engine._materialize("demo", entry)
    assert len(collisions) == 1
    folder_name, file_path, existing, incoming, blob_hash = collisions[0]
    assert folder_name == "demo"
    assert file_path == "x.txt"
    assert existing == 99
    assert incoming == len(incoming_bytes)
    assert blob_hash == incoming_blob
    state.close()


def test_no_collision_when_brand_new_file(tmp_path: Path):
    engine, state, blob_store, _ = _engine_setup(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    state.add_folder(
        name="demo", local_path=str(src), shared_with=[],
    )
    incoming_bytes = b"fresh content"
    incoming_blob = blob_store.put_bytes(incoming_bytes)
    collisions: list[tuple] = []
    engine._on_collision_detected = lambda *args: collisions.append(args)
    entry = ManifestEntry(
        file_path="brand_new.txt",
        blob_hash=incoming_blob,
        size=len(incoming_bytes),
        mtime_ms=1,
        vclock={},
    )
    engine._materialize("demo", entry)
    assert collisions == []
    state.close()


def test_no_collision_when_same_size(tmp_path: Path):
    """Same-size content is re-hashed, replaced when different, but the
    legacy collision notification remains size-oriented."""
    engine, state, blob_store, _ = _engine_setup(tmp_path)
    src = tmp_path / "src"
    src.mkdir()
    (src / "x.txt").write_bytes(b"hello world!")  # 12 bytes
    state.add_folder(
        name="demo", local_path=str(src), shared_with=[],
    )
    # Incoming has same SIZE but different content.
    incoming_bytes = b"goodbye now!"  # also 12 bytes
    incoming_blob = blob_store.put_bytes(incoming_bytes)
    collisions: list[tuple] = []
    engine._on_collision_detected = lambda *args: collisions.append(args)
    entry = ManifestEntry(
        file_path="x.txt",
        blob_hash=incoming_blob,
        size=len(incoming_bytes),
        mtime_ms=1,
        vclock={},
    )
    engine._materialize("demo", entry)
    # Same-size path doesn't fire collision (intentional).
    assert collisions == []
    assert (src / "x.txt").read_bytes() == incoming_bytes
    state.close()


# ── daemon._on_folder_collision WS broadcast ─────────────────────


def test_daemon_collision_callback_broadcasts(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    daemon = Daemon(me)
    daemon.ui_server = MagicMock()
    daemon.ui_server.broadcast = MagicMock()
    daemon._on_folder_collision(
        "papers", "report.pdf",
        12345, 67890, "ab" * 32,
    )
    daemon.ui_server.broadcast.assert_called_once()
    payload = daemon.ui_server.broadcast.call_args.args[0]
    assert payload["type"] == "folder_recv_collision"
    assert payload["folder_name"] == "papers"
    assert payload["file_path"] == "report.pdf"
    assert payload["existing_size"] == 12345
    assert payload["incoming_size"] == 67890
    assert payload["incoming_blob"] == "ab" * 32


def test_daemon_collision_callback_no_op_without_ui_server(tmp_path: Path):
    """No ui_server (e.g. test daemon) → callback is no-op, no crash."""
    me = _identity()
    daemon = Daemon(me)
    daemon.ui_server = None

    daemon._on_folder_collision("x", "y", 1, 2, "ab" * 32)

    # Lazily building a UI server on the headless path would start a listener
    # a headless daemon never asked for, and that cannot raise.
    assert daemon.ui_server is None, "a UI server was constructed on the no-op path"
