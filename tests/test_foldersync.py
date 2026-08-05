from __future__ import annotations

import asyncio
from pathlib import Path

import blake3
import pytest

import one_link.foldersync as foldersync_module
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


def test_manifest_root_changes_with_manifest(tmp_path: Path):
    state, _blobs, loop, engine = _engine(tmp_path)
    try:
        root = tmp_path / "sync"
        state.add_folder(name="docs", local_path=str(root), shared_with=[])
        empty = engine.manifest_root("docs")
        state.upsert_manifest_entry(
            folder_name="docs",
            file_path="a.txt",
            blob_hash="aa" * 32,
            size=1,
            mtime_ms=1,
            vclock={"aa": 1},
        )
        changed = engine.manifest_root("docs")
        assert empty != changed
    finally:
        state.close()
        loop.close()


def test_materialize_is_atomic_when_publish_fails(tmp_path: Path, monkeypatch):
    state, blobs, loop, engine = _engine(tmp_path)
    try:
        root = tmp_path / "sync"
        root.mkdir()
        dst = root / "report.bin"
        dst.write_bytes(b"old complete version")
        state.add_folder(name="docs", local_path=str(root), shared_with=[])
        payload = b"new complete version" * 1024
        blob = blobs.put_bytes(payload)
        entry = ManifestEntry(
            file_path="report.bin",
            blob_hash=blob,
            size=len(payload),
            mtime_ms=1,
            vclock=VectorClock.from_dict({"bb" * 32: 1}),
        )

        monkeypatch.setattr(
            foldersync_module,
            "replace_path",
            lambda *_args: (_ for _ in ()).throw(OSError("power loss")),
        )
        with pytest.raises(OSError, match="power loss"):
            engine._materialize("docs", entry)

        assert dst.read_bytes() == b"old complete version"
        assert not list(root.glob(".one-link-*.tmp"))
    finally:
        state.close()
        loop.close()


def test_materialize_does_not_rewrite_verified_existing_file(
    tmp_path: Path, monkeypatch
):
    state, blobs, loop, engine = _engine(tmp_path)
    try:
        root = tmp_path / "sync"
        root.mkdir()
        payload = b"already correct"
        dst = root / "report.bin"
        dst.write_bytes(payload)
        state.add_folder(name="docs", local_path=str(root), shared_with=[])
        blob = blobs.put_bytes(payload)
        entry = ManifestEntry(
            file_path="report.bin",
            blob_hash=blob,
            size=len(payload),
            mtime_ms=1,
            vclock=VectorClock.from_dict({"bb" * 32: 1}),
        )
        monkeypatch.setattr(
            foldersync_module,
            "replace_path",
            lambda *_args: (_ for _ in ()).throw(AssertionError("rewritten")),
        )

        engine._materialize("docs", entry)

        assert dst.read_bytes() == payload
    finally:
        state.close()
        loop.close()


def test_remote_blob_arrival_preserves_interleaved_unindexed_local_edit(
    tmp_path: Path,
) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    try:
        root = tmp_path / "sync"
        root.mkdir()
        dst = root / "draft.txt"
        original = b"indexed local generation"
        dst.write_bytes(original)
        state.add_folder(name="docs", local_path=str(root), shared_with=[])
        local_hash = blobs.put_bytes(original)
        state.record_blob(local_hash, len(original))
        state.upsert_manifest_entry(
            folder_name="docs",
            file_path="draft.txt",
            blob_hash=local_hash,
            size=len(original),
            mtime_ms=1,
            vclock={"aa" * 32: 1},
        )
        remote_bytes = b"remote generation still in flight"
        remote_hash = blake3.blake3(remote_bytes).hexdigest()
        remote = {
            "file_path": "draft.txt",
            "blob_hash": remote_hash,
            "size": len(remote_bytes),
            "mtime_ms": 2,
            "vclock": {"aa" * 32: 1, "bb" * 32: 1},
        }

        wants = engine.receive_remote_manifest(
            folder_name="docs",
            entries=[remote],
            peer_fp="bb" * 32,
        )
        assert [item["blob_hash"] for item in wants] == [remote_hash]

        local_edit = b"local edit made while remote bytes were arriving"
        dst.write_bytes(local_edit)
        assert blobs.put_bytes(remote_bytes) == remote_hash
        engine.materialize_after_blob_arrived(blob_hash=remote_hash)

        assert dst.read_bytes() == local_edit
        row = state.get_manifest_entry("docs", "draft.txt")
        assert row is not None
        assert row["blob_hash"] == blake3.blake3(local_edit).hexdigest()
        assert row["vclock"]["aa" * 32] >= 2
        assert row["vclock"]["bb" * 32] >= 1
    finally:
        state.close()
        loop.close()


def test_remote_tombstone_preserves_edit_raced_before_delete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    try:
        root = tmp_path / "sync"
        root.mkdir()
        dst = root / "notes.txt"
        original = b"old notes"
        dst.write_bytes(original)
        state.add_folder(name="docs", local_path=str(root), shared_with=[])
        local_hash = blobs.put_bytes(original)
        state.record_blob(local_hash, len(original))
        state.upsert_manifest_entry(
            folder_name="docs",
            file_path="notes.txt",
            blob_hash=local_hash,
            size=len(original),
            mtime_ms=1,
            vclock={"aa" * 32: 1},
        )
        real_delete = engine._delete_on_disk

        def edit_then_delete(folder_name: str, rel_path: str) -> None:
            dst.write_bytes(b"new local notes")
            real_delete(folder_name, rel_path)

        monkeypatch.setattr(engine, "_delete_on_disk", edit_then_delete)
        engine.receive_remote_manifest(
            folder_name="docs",
            entries=[{
                "file_path": "notes.txt",
                "blob_hash": None,
                "size": None,
                "mtime_ms": 2,
                "vclock": {"aa" * 32: 1, "bb" * 32: 1},
            }],
            peer_fp="bb" * 32,
        )

        assert dst.read_bytes() == b"new local notes"
        row = state.get_manifest_entry("docs", "notes.txt")
        assert row is not None and row["blob_hash"] is not None
        assert row["vclock"]["aa" * 32] >= 2
        assert row["vclock"]["bb" * 32] >= 1
    finally:
        state.close()
        loop.close()


def test_unchanged_periodic_scan_reuses_stable_materialization_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    try:
        root = tmp_path / "sync"
        root.mkdir()
        path = root / "large.bin"
        path.write_bytes(b"stable" * 1024)
        state.add_folder(name="docs", local_path=str(root), shared_with=[])
        engine.register_for_one_shot_no_watcher("docs", root)
        engine._reconcile_file("docs", path)
        monkeypatch.setattr(
            blobs,
            "put_path",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("unchanged file was rehashed")
            ),
        )

        before = state.get_manifest_entry("docs", "large.bin")
        engine._reconcile_file("docs", path)
        after = state.get_manifest_entry("docs", "large.bin")

        # The throwing `put_path` above proves the file was not REHASHED, but
        # only if reconcile ran at all -- a no-op reconcile would also never
        # call it. Pin the positive outcome too: the entry still exists and is
        # byte-identical, i.e. the stable proof was reused rather than dropped.
        assert before is not None, "the first reconcile recorded nothing to reuse"
        assert after == before, (
            f"the unchanged file's manifest entry moved: {before} -> {after}"
        )
    finally:
        state.close()
        loop.close()


def test_complete_scan_tombstones_file_deleted_while_daemon_was_offline(
    tmp_path: Path,
) -> None:
    state, _blobs, loop, engine = _engine(tmp_path)
    try:
        root = tmp_path / "sync"
        root.mkdir()
        path = root / "offline-delete.txt"
        path.write_bytes(b"remove me")
        state.add_folder(name="docs", local_path=str(root), shared_with=[])
        engine.register_for_one_shot_no_watcher("docs", root)
        engine._scan_full("docs", root)
        assert state.get_manifest_entry("docs", "offline-delete.txt")[
            "blob_hash"
        ] is not None

        path.unlink()
        engine._scan_full("docs", root)

        row = state.get_manifest_entry("docs", "offline-delete.txt")
        assert row is not None and row["blob_hash"] is None
    finally:
        state.close()
        loop.close()


def test_remote_manifest_batch_rolls_back_every_row_on_second_row_failure(
    tmp_path: Path,
) -> None:
    state, _blobs, loop, engine = _engine(tmp_path)
    try:
        root = tmp_path / "sync"
        root.mkdir()
        state.add_folder(name="docs", local_path=str(root), shared_with=[])
        state._conn.execute(
            """
            CREATE TRIGGER fail_second_folder_row
            BEFORE INSERT ON folder_manifest
            WHEN NEW.file_path = 'b.txt'
            BEGIN
                SELECT RAISE(ABORT, 'injected second-row failure');
            END
            """
        )
        entries = [
            {
                "file_path": path,
                "blob_hash": blake3.blake3(path.encode()).hexdigest(),
                "size": 1,
                "mtime_ms": 1,
                "vclock": {"bb" * 32: 1},
            }
            for path in ("a.txt", "b.txt")
        ]

        with pytest.raises(Exception, match="injected second-row failure"):
            engine.receive_remote_manifest(
                folder_name="docs",
                entries=entries,
                peer_fp="bb" * 32,
            )

        assert state.list_manifest("docs") == []
        assert not (root / "a.txt").exists()
        assert not (root / "b.txt").exists()
    finally:
        state.close()
        loop.close()


@pytest.mark.asyncio
async def test_start_falls_back_to_periodic_scan_when_watch_backend_fails(
    tmp_path: Path, monkeypatch, caplog,
):
    state = State(db_path=tmp_path / "state.db")
    blobs = BlobStore(tmp_path / "blobs")
    root = tmp_path / "sync"
    root.mkdir()
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    engine = FolderEngine(
        state=state,
        blob_store=blobs,
        my_fingerprint="aa" * 32,
        loop=asyncio.get_running_loop(),
    )
    scans: list[tuple[str, Path]] = []
    monkeypatch.setattr(
        engine,
        "_start_watch",
        lambda *_args: (_ for _ in ()).throw(OSError("watch limit reached")),
    )
    monkeypatch.setattr(
        engine,
        "_scan_full",
        lambda name, path: scans.append((name, path)),
    )
    try:
        with caplog.at_level("WARNING", logger="one_link.foldersync"):
            await engine.start()

        assert "docs" in engine._folders
        assert scans == [("docs", root)]
        assert "using periodic scans" in caplog.text
    finally:
        await engine.stop()
        state.close()


def test_relocate_rolls_back_state_and_watcher_when_new_watch_fails(
    tmp_path: Path, monkeypatch,
):
    state, _blobs, loop, engine = _engine(tmp_path)
    old_root = tmp_path / "old"
    new_root = tmp_path / "new"
    old_root.mkdir()
    new_root.mkdir()
    engine.add_folder(name="docs", local_path=old_root, shared_with=[])
    real_start_watch = engine._start_watch

    def fail_new_watch(name: str, root: Path) -> None:
        if Path(root).resolve() == new_root.resolve():
            raise OSError("new watch unavailable")
        real_start_watch(name, root)

    monkeypatch.setattr(engine, "_start_watch", fail_new_watch)
    try:
        with pytest.raises(OSError, match="new watch unavailable"):
            engine.relocate_folder("docs", new_root)

        assert state.get_folder("docs")["local_path"] == str(old_root.resolve())
        assert engine._folders["docs"].root == old_root.resolve()
    finally:
        engine.remove_folder("docs")
        state.close()
        loop.close()


def test_relocate_restores_watcher_when_state_update_fails(
    tmp_path: Path, monkeypatch,
):
    state, _blobs, loop, engine = _engine(tmp_path)
    old_root = tmp_path / "old"
    new_root = tmp_path / "new"
    old_root.mkdir()
    new_root.mkdir()
    engine.add_folder(name="docs", local_path=old_root, shared_with=[])
    real_set_path = state.set_folder_local_path

    def fail_new_state(name: str, path: str) -> None:
        if path == str(new_root.resolve()):
            raise RuntimeError("folder database unavailable")
        real_set_path(name, path)

    monkeypatch.setattr(state, "set_folder_local_path", fail_new_state)
    try:
        with pytest.raises(RuntimeError, match="folder database unavailable"):
            engine.relocate_folder("docs", new_root)

        assert state.get_folder("docs")["local_path"] == str(old_root.resolve())
        assert engine._folders["docs"].root == old_root.resolve()
    finally:
        engine.remove_folder("docs")
        state.close()
        loop.close()
