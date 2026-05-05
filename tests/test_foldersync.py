from __future__ import annotations

import asyncio
from pathlib import Path

from one_link.blobstore import BlobStore
from one_link.crdt import ManifestEntry, VectorClock
from one_link.foldersync import FolderEngine
from one_link.state import State


def _engine(tmp_path: Path):
    state = State(db_path=tmp_path / "state.db")
    blobs = BlobStore(tmp_path / "blobs")
    loop = asyncio.new_event_loop()
    engine = FolderEngine(
        state=state,
        blob_store=blobs,
        my_fingerprint="aa" * 32,
        loop=loop,
    )
    return state, blobs, loop, engine


def test_materialize_rejects_remote_path_traversal(tmp_path: Path):
    state, blobs, loop, engine = _engine(tmp_path)
    try:
        root = tmp_path / "sync"
        state.add_folder(name="docs", local_path=str(root), shared_with=[])
        blob = blobs.put_bytes(b"owned")
        entry = ManifestEntry(
            file_path="../escape.txt",
            blob_hash=blob,
            size=5,
            mtime_ms=1,
            vclock=VectorClock.from_dict({"bb" * 32: 1}),
        )

        engine._materialize("docs", entry)

        assert not (tmp_path / "escape.txt").exists()
        assert not (root / "escape.txt").exists()
    finally:
        state.close()
        loop.close()


def test_remote_tombstone_rejects_path_traversal_delete(tmp_path: Path):
    state, _blobs, loop, engine = _engine(tmp_path)
    try:
        root = tmp_path / "sync"
        root.mkdir()
        outside = tmp_path / "do-not-delete.txt"
        outside.write_text("keep", encoding="utf-8")
        state.add_folder(name="docs", local_path=str(root), shared_with=[])

        engine._delete_on_disk("docs", "../do-not-delete.txt")

        assert outside.read_text(encoding="utf-8") == "keep"
    finally:
        state.close()
        loop.close()
