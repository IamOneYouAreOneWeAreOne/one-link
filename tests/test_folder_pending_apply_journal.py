from __future__ import annotations

import asyncio
import os
import threading
from pathlib import Path

import blake3
import pytest

import one_link.foldersync as foldersync_module
from one_link.blobstore import BlobStore
from one_link.foldersync import (
    FolderEngine,
    _has_symlink_in_chain,
    _safe_relpath,
)
from one_link.state import State
from one_link.state_encryption import STATE_SCHEMA_VERSION_CURRENT
from one_link.storage_lifecycle import collect_durable_blob_roots


LOCAL_FP = "aa" * 32
REMOTE_FP = "bb" * 32


def _engine(tmp_path: Path) -> tuple[State, BlobStore, asyncio.AbstractEventLoop, FolderEngine]:
    state = State(db_path=tmp_path / "state.db")
    blobs = BlobStore(tmp_path / "blobs")
    loop = asyncio.new_event_loop()
    engine = FolderEngine(
        state=state,
        blob_store=blobs,
        my_fingerprint=LOCAL_FP,
        loop=loop,
    )
    return state, blobs, loop, engine


def _indexed_local(
    state: State,
    blobs: BlobStore,
    root: Path,
    *,
    payload: bytes = b"local generation",
    rel_path: str = "draft.txt",
) -> str:
    root.mkdir(parents=True, exist_ok=True)
    path = root / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    digest = blobs.put_bytes(payload)
    state.record_blob(digest, len(payload))
    state.upsert_manifest_entry(
        folder_name="docs",
        file_path=rel_path,
        blob_hash=digest,
        size=len(payload),
        mtime_ms=1,
        vclock={LOCAL_FP: 1},
    )
    return digest


def _remote_entry(payload: bytes, *, rel_path: str = "draft.txt") -> dict:
    return {
        "file_path": rel_path,
        "blob_hash": blake3.blake3(payload).hexdigest(),
        "size": len(payload),
        "mtime_ms": 2,
        "vclock": {LOCAL_FP: 1, REMOTE_FP: 1},
    }


def test_v30_schema_has_constrained_pending_apply_journal(tmp_path: Path) -> None:
    state, _blobs, loop, _engine_obj = _engine(tmp_path)
    try:
        assert STATE_SCHEMA_VERSION_CURRENT == 30
        assert state.schema_version() == 30
        columns = {
            str(row[1])
            for row in state._conn.execute(
                "PRAGMA table_info(folder_pending_applies)"
            ).fetchall()
        }
        assert {
            "apply_id",
            "folder_name",
            "file_path",
            "operation",
            "target_blob_hash",
            "target_vclock_json",
            "baseline_blob_hash",
            "baseline_evidence_json",
            "phase",
            "staging_name",
            "recovery_name",
            "attempts",
            "last_error",
        } <= columns
        indexes = {
            str(row[1])
            for row in state._conn.execute(
                "PRAGMA index_list(folder_manifest)"
            ).fetchall()
        }
        assert "idx_folder_manifest_blob_hash" in indexes
    finally:
        state.close()
        loop.close()


def test_missing_remote_blob_journal_survives_restart_then_retires_exactly(
    tmp_path: Path,
) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    root = tmp_path / "sync"
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    _indexed_local(state, blobs, root)
    remote_payload = b"remote generation after restart"
    remote = _remote_entry(remote_payload)
    try:
        wants = engine.receive_remote_manifest(
            folder_name="docs",
            entries=[remote],
            peer_fp=REMOTE_FP,
        )
        assert wants == [remote]
        pending = state.get_folder_pending_apply("docs", "draft.txt")
        assert pending is not None
        assert pending["phase"] == "planned"
        assert pending["target_blob_hash"] == remote["blob_hash"]
    finally:
        state.close()
        loop.close()

    reopened_state = State(db_path=tmp_path / "state.db")
    reopened_blobs = BlobStore(tmp_path / "blobs")
    reopened_loop = asyncio.new_event_loop()
    reopened = FolderEngine(
        state=reopened_state,
        blob_store=reopened_blobs,
        my_fingerprint=LOCAL_FP,
        loop=reopened_loop,
    )
    try:
        assert reopened.recover_pending_applies(folder_name="docs") == 0
        # A normal startup scan must not turn the journal-protected pre-image
        # into a new local CRDT generation while bytes are still in flight.
        reopened.register_for_one_shot_no_watcher("docs", root)
        reopened._scan_full("docs", root)
        assert reopened_state.get_manifest_entry("docs", "draft.txt")[
            "blob_hash"
        ] == remote["blob_hash"]

        assert reopened_blobs.put_bytes(remote_payload) == remote["blob_hash"]
        assert reopened.materialize_after_blob_arrived(
            blob_hash=remote["blob_hash"]
        ) == 1
        assert (root / "draft.txt").read_bytes() == remote_payload
        assert reopened_state.get_folder_pending_apply("docs", "draft.txt") is None
    finally:
        reopened_state.close()
        reopened_loop.close()


def test_new_remote_file_absence_is_not_tombstoned_during_restart_scan(
    tmp_path: Path,
) -> None:
    state, _blobs, loop, engine = _engine(tmp_path)
    root = tmp_path / "sync"
    root.mkdir()
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    remote = _remote_entry(b"not downloaded yet", rel_path="new.bin")
    try:
        engine.receive_remote_manifest(
            folder_name="docs",
            entries=[remote],
            peer_fp=REMOTE_FP,
        )
        assert state.get_folder_pending_apply("docs", "new.bin") is not None
    finally:
        state.close()
        loop.close()

    state2 = State(db_path=tmp_path / "state.db")
    loop2 = asyncio.new_event_loop()
    engine2 = FolderEngine(
        state=state2,
        blob_store=BlobStore(tmp_path / "blobs"),
        my_fingerprint=LOCAL_FP,
        loop=loop2,
    )
    engine2.register_for_one_shot_no_watcher("docs", root)
    try:
        assert engine2.recover_pending_applies(folder_name="docs") == 0
        engine2._scan_full("docs", root)
        row = state2.get_manifest_entry("docs", "new.bin")
        assert row is not None and row["blob_hash"] == remote["blob_hash"]
        assert state2.get_folder_pending_apply("docs", "new.bin") is not None
    finally:
        state2.close()
        loop2.close()


def test_recovery_replays_crash_after_preimage_was_moved(tmp_path: Path) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    root = tmp_path / "sync"
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    local_hash = _indexed_local(state, blobs, root)
    remote_payload = b"new durable generation"
    remote = _remote_entry(remote_payload)
    try:
        engine.receive_remote_manifest(
            folder_name="docs",
            entries=[remote],
            peer_fp=REMOTE_FP,
        )
        assert blobs.put_bytes(remote_payload) == remote["blob_hash"]
        row = state.get_folder_pending_apply("docs", "draft.txt")
        assert row is not None
        recovery_name = ".one-link-crash-recovery.tmp"
        assert state.transition_folder_pending_apply(
            apply_id=row["apply_id"],
            phase="recovery_prepared",
            staging_name=None,
            recovery_name=recovery_name,
        )
        os.replace(root / "draft.txt", root / recovery_name)
        assert state.transition_folder_pending_apply(
            apply_id=row["apply_id"],
            phase="recovery_moved",
            staging_name=None,
            recovery_name=recovery_name,
        )
    finally:
        state.close()
        loop.close()

    state2 = State(db_path=tmp_path / "state.db")
    loop2 = asyncio.new_event_loop()
    engine2 = FolderEngine(
        state=state2,
        blob_store=BlobStore(tmp_path / "blobs"),
        my_fingerprint=LOCAL_FP,
        loop=loop2,
    )
    try:
        assert engine2.recover_pending_applies(folder_name="docs") == 1
        assert (root / "draft.txt").read_bytes() == remote_payload
        assert not (root / recovery_name).exists()
        assert state2.get_folder_pending_apply("docs", "draft.txt") is None
        assert engine2.blobs.has(local_hash)
    finally:
        state2.close()
        loop2.close()


def test_recovery_finalizes_already_published_target_and_preserves_preimage_cas(
    tmp_path: Path,
) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    root = tmp_path / "sync"
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    local_hash = _indexed_local(state, blobs, root)
    remote_payload = b"published before process loss"
    remote = _remote_entry(remote_payload)
    try:
        engine.receive_remote_manifest(
            folder_name="docs",
            entries=[remote],
            peer_fp=REMOTE_FP,
        )
        blobs.put_bytes(remote_payload)
        row = state.get_folder_pending_apply("docs", "draft.txt")
        assert row is not None
        recovery_name = ".one-link-published-backup.tmp"
        os.replace(root / "draft.txt", root / recovery_name)
        (root / "draft.txt").write_bytes(remote_payload)
        assert state.transition_folder_pending_apply(
            apply_id=row["apply_id"],
            phase="published",
            staging_name=None,
            recovery_name=recovery_name,
        )
    finally:
        state.close()
        loop.close()

    state2 = State(db_path=tmp_path / "state.db")
    loop2 = asyncio.new_event_loop()
    engine2 = FolderEngine(
        state=state2,
        blob_store=BlobStore(tmp_path / "blobs"),
        my_fingerprint=LOCAL_FP,
        loop=loop2,
    )
    try:
        assert engine2.recover_pending_applies(folder_name="docs") == 1
        assert (root / "draft.txt").read_bytes() == remote_payload
        assert state2.get_folder_pending_apply("docs", "draft.txt") is None
        assert engine2.blobs.has(local_hash)
        assert not (root / recovery_name).exists()
    finally:
        state2.close()
        loop2.close()


def test_recovery_finishes_journaled_remote_delete(tmp_path: Path, monkeypatch) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    root = tmp_path / "sync"
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    local_hash = _indexed_local(state, blobs, root)
    monkeypatch.setattr(engine, "_delete_on_disk", lambda *_args: False)
    try:
        engine.receive_remote_manifest(
            folder_name="docs",
            entries=[{
                "file_path": "draft.txt",
                "blob_hash": None,
                "size": None,
                "mtime_ms": 2,
                "vclock": {LOCAL_FP: 1, REMOTE_FP: 1},
            }],
            peer_fp=REMOTE_FP,
        )
        row = state.get_folder_pending_apply("docs", "draft.txt")
        assert row is not None and row["operation"] == "delete"
        recovery_name = ".one-link-delete-recovery.tmp"
        assert state.transition_folder_pending_apply(
            apply_id=row["apply_id"],
            phase="recovery_prepared",
            staging_name=None,
            recovery_name=recovery_name,
        )
        os.replace(root / "draft.txt", root / recovery_name)
        assert state.transition_folder_pending_apply(
            apply_id=row["apply_id"],
            phase="recovery_moved",
            staging_name=None,
            recovery_name=recovery_name,
        )
    finally:
        state.close()
        loop.close()

    state2 = State(db_path=tmp_path / "state.db")
    loop2 = asyncio.new_event_loop()
    engine2 = FolderEngine(
        state=state2,
        blob_store=BlobStore(tmp_path / "blobs"),
        my_fingerprint=LOCAL_FP,
        loop=loop2,
    )
    try:
        assert engine2.recover_pending_applies(folder_name="docs") == 1
        assert not (root / "draft.txt").exists()
        assert not (root / recovery_name).exists()
        assert engine2.blobs.has(local_hash)
        assert state2.get_folder_pending_apply("docs", "draft.txt") is None
    finally:
        state2.close()
        loop2.close()


def test_journal_and_manifest_generation_rollback_together(tmp_path: Path) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    root = tmp_path / "sync"
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    local_hash = _indexed_local(state, blobs, root)
    state._conn.execute(
        """
        CREATE TRIGGER fail_pending_apply
        BEFORE INSERT ON folder_pending_applies
        BEGIN
            SELECT RAISE(ABORT, 'injected journal failure');
        END
        """
    )
    try:
        with pytest.raises(Exception, match="injected journal failure"):
            engine.receive_remote_manifest(
                folder_name="docs",
                entries=[_remote_entry(b"remote")],
                peer_fp=REMOTE_FP,
            )
        row = state.get_manifest_entry("docs", "draft.txt")
        assert row is not None and row["blob_hash"] == local_hash
        assert state.list_folder_pending_applies(folder_name="docs") == []
    finally:
        state.close()
        loop.close()


def test_pending_target_and_preimage_are_durable_cas_gc_roots(
    tmp_path: Path,
) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    root = tmp_path / "sync"
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    local_hash = _indexed_local(state, blobs, root)
    remote = _remote_entry(b"remote target still downloading")
    try:
        engine.receive_remote_manifest(
            folder_name="docs",
            entries=[remote],
            peer_fp=REMOTE_FP,
        )
        roots = collect_durable_blob_roots(state)
        assert roots.complete
        assert local_hash in roots.roots
        assert remote["blob_hash"] in roots.roots
        assert local_hash in roots.sources[
            "folder_pending_applies.baseline_blob_hash"
        ]
        assert remote["blob_hash"] in roots.sources[
            "folder_pending_applies.target_blob_hash"
        ]
    finally:
        state.close()
        loop.close()


def test_same_address_remote_manifest_cannot_overwrite_unindexed_local_edit(
    tmp_path: Path,
) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    root = tmp_path / "sync"
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    old_payload = b"indexed version"
    old_hash = _indexed_local(state, blobs, root, payload=old_payload)
    edited = b"unindexed local edit"
    (root / "draft.txt").write_bytes(edited)
    try:
        engine.receive_remote_manifest(
            folder_name="docs",
            entries=[{
                "file_path": "draft.txt",
                "blob_hash": old_hash,
                "size": len(old_payload),
                "mtime_ms": 2,
                "vclock": {LOCAL_FP: 1, REMOTE_FP: 1},
            }],
            peer_fp=REMOTE_FP,
        )
        assert (root / "draft.txt").read_bytes() == edited
        row = state.get_manifest_entry("docs", "draft.txt")
        assert row is not None
        assert row["blob_hash"] == blake3.blake3(edited).hexdigest()
    finally:
        state.close()
        loop.close()


def test_remote_tombstone_cannot_delete_previously_unindexed_local_file(
    tmp_path: Path,
) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    root = tmp_path / "sync"
    root.mkdir()
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    unindexed = root / "draft.txt"
    unindexed.write_bytes(b"local bytes not scanned yet")
    try:
        engine.receive_remote_manifest(
            folder_name="docs",
            entries=[{
                "file_path": "draft.txt",
                "blob_hash": None,
                "size": None,
                "mtime_ms": 2,
                "vclock": {REMOTE_FP: 1},
            }],
            peer_fp=REMOTE_FP,
        )
        assert unindexed.read_bytes() == b"local bytes not scanned yet"
        row = state.get_manifest_entry("docs", "draft.txt")
        assert row is not None and row["blob_hash"] is not None
        assert blobs.has(row["blob_hash"])
    finally:
        state.close()
        loop.close()


def test_publish_window_never_overwrites_reappearing_local_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    root = tmp_path / "sync"
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    original_hash = _indexed_local(state, blobs, root)
    target = root / "draft.txt"
    remote_payload = b"remote winner"
    remote = _remote_entry(remote_payload)
    blobs.put_bytes(remote_payload)
    real_replace = foldersync_module.replace_path
    injected = False

    def replace_then_reappear(source, destination) -> None:
        nonlocal injected
        source_path = Path(source)
        real_replace(source, destination)
        if source_path == target and not injected:
            injected = True
            target.write_bytes(b"local generation created in publish window")

    monkeypatch.setattr(foldersync_module, "replace_path", replace_then_reappear)
    try:
        engine.receive_remote_manifest(
            folder_name="docs",
            entries=[remote],
            peer_fp=REMOTE_FP,
        )
        local_race = b"local generation created in publish window"
        assert target.read_bytes() == local_race
        row = state.get_manifest_entry("docs", "draft.txt")
        assert row is not None
        assert row["blob_hash"] == blake3.blake3(local_race).hexdigest()
        assert state.get_folder_pending_apply("docs", "draft.txt") is None
        assert blobs.has(original_hash)
        assert not list(root.glob(".one-link-*.tmp"))
    finally:
        state.close()
        loop.close()


def test_atomic_publication_never_replaces_last_instant_local_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    root = tmp_path / "sync"
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    original_hash = _indexed_local(state, blobs, root)
    target = root / "draft.txt"
    remote_payload = b"remote no-replace target"
    remote = _remote_entry(remote_payload)
    blobs.put_bytes(remote_payload)
    real_publish = engine._publish_staging_noreplace
    injected = False

    def reappear_at_atomic_publish(staging: Path, destination: Path) -> bool:
        nonlocal injected
        assert destination == target
        if not injected:
            injected = True
            destination.write_bytes(b"last instant local generation")
        return real_publish(staging, destination)

    monkeypatch.setattr(engine, "_publish_staging_noreplace", reappear_at_atomic_publish)
    try:
        engine.receive_remote_manifest(
            folder_name="docs",
            entries=[remote],
            peer_fp=REMOTE_FP,
        )
        local_race = b"last instant local generation"
        assert target.read_bytes() == local_race
        row = state.get_manifest_entry("docs", "draft.txt")
        assert row is not None
        assert row["blob_hash"] == blake3.blake3(local_race).hexdigest()
        assert state.get_folder_pending_apply("docs", "draft.txt") is None
        assert blobs.has(original_hash)
        assert not list(root.glob(".one-link-*.tmp"))
    finally:
        state.close()
        loop.close()


def test_namespace_durability_failure_never_advances_pending_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    root = tmp_path / "sync"
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    local_payload = b"local generation remains authoritative on failure"
    _indexed_local(state, blobs, root, payload=local_payload)
    target = root / "draft.txt"
    remote_payload = b"remote generation cannot bypass write-through"
    remote = _remote_entry(remote_payload)
    blobs.put_bytes(remote_payload)

    def fail_move(source: Path, destination: Path) -> None:
        assert Path(source) == target
        assert Path(destination).name.startswith(".one-link-")
        raise OSError("injected write-through rename failure")

    monkeypatch.setattr(foldersync_module, "replace_path", fail_move)
    try:
        with pytest.raises(OSError, match="write-through rename failure"):
            engine.receive_remote_manifest(
                folder_name="docs",
                entries=[remote],
                peer_fp=REMOTE_FP,
            )

        assert target.read_bytes() == local_payload
        pending = state.get_folder_pending_apply("docs", "draft.txt")
        assert pending is not None
        assert pending["phase"] == "recovery_prepared"
        assert pending["target_blob_hash"] == remote["blob_hash"]
        assert not list(root.glob(".one-link-*.tmp"))
    finally:
        state.close()
        loop.close()


def test_blob_arrival_uses_index_and_counts_only_proven_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    root = tmp_path / "sync"
    root.mkdir()
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    payload = b"one indexed consumer"
    digest = blobs.put_bytes(payload)
    state.upsert_manifest_entry(
        folder_name="docs",
        file_path="ok.bin",
        blob_hash=digest,
        size=len(payload),
        mtime_ms=1,
        vclock={REMOTE_FP: 1},
    )
    state.upsert_manifest_entry(
        folder_name="ghost",
        file_path="missing.bin",
        blob_hash=digest,
        size=len(payload),
        mtime_ms=1,
        vclock={REMOTE_FP: 1},
    )
    monkeypatch.setattr(
        state,
        "list_folders",
        lambda: (_ for _ in ()).throw(AssertionError("full folder scan")),
    )
    monkeypatch.setattr(
        state,
        "list_manifest",
        lambda *_args: (_ for _ in ()).throw(AssertionError("full manifest scan")),
    )
    try:
        assert engine.materialize_after_blob_arrived(blob_hash=digest) == 1
        assert (root / "ok.bin").read_bytes() == payload
        plan = " ".join(
            str(item)
            for row in state._conn.execute(
                "EXPLAIN QUERY PLAN SELECT * FROM folder_manifest "
                "WHERE blob_hash=? ORDER BY folder_name,file_path LIMIT ?",
                (digest, 10),
            ).fetchall()
            for item in row
        )
        assert "idx_folder_manifest_blob_hash" in plan
    finally:
        state.close()
        loop.close()


def test_symlink_chain_depth_bound_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "root"
    path = root.joinpath(*(f"d{index}" for index in range(65)), "file.bin")
    assert _has_symlink_in_chain(path, root) is True


def test_safe_relpath_resolve_error_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_resolve(_self: Path, *_args, **_kwargs) -> Path:
        raise OSError("injected inaccessible path")

    monkeypatch.setattr(Path, "resolve", fail_resolve)
    assert _safe_relpath(tmp_path, tmp_path / "file.bin") is None


def test_incomplete_walk_never_manufactures_offline_tombstone(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    root = tmp_path / "sync"
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    digest = _indexed_local(state, blobs, root)
    (root / "draft.txt").unlink()
    engine.register_for_one_shot_no_watcher("docs", root)

    def incomplete_walk(_root, *, topdown, onerror, followlinks):
        assert topdown is True and followlinks is False
        onerror(PermissionError("injected inaccessible subtree"))
        return iter(())

    monkeypatch.setattr(foldersync_module.os, "walk", incomplete_walk)
    try:
        engine._scan_full("docs", root)
        row = state.get_manifest_entry("docs", "draft.txt")
        assert row is not None and row["blob_hash"] == digest
    finally:
        state.close()
        loop.close()


@pytest.mark.asyncio
async def test_dirty_pump_keeps_event_loop_responsive_during_slow_hash_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = State(db_path=tmp_path / "state.db")
    blobs = BlobStore(tmp_path / "blobs")
    engine = FolderEngine(
        state=state,
        blob_store=blobs,
        my_fingerprint=LOCAL_FP,
        loop=asyncio.get_running_loop(),
    )
    started = threading.Event()
    release = threading.Event()
    worker_threads: list[int] = []

    def slow_batch(_snapshot) -> None:
        worker_threads.append(threading.get_ident())
        started.set()
        release.wait(timeout=2)

    monkeypatch.setattr(foldersync_module, "DEBOUNCE_MS", 0)
    monkeypatch.setattr(engine, "_process_dirty_batch", slow_batch)
    engine._dirty = {"docs": {"ignored": "modified"}}
    task = asyncio.create_task(engine._dirty_pump())
    engine._wake.set()
    try:
        assert await asyncio.to_thread(started.wait, 1.0)
        # This timer can run only if the blocking filesystem batch is off-loop.
        await asyncio.wait_for(asyncio.sleep(0.01), timeout=0.1)
        assert worker_threads != [threading.get_ident()]
    finally:
        release.set()
        engine._stop.set()
        engine._wake.set()
        await asyncio.wait_for(task, timeout=1)
        state.close()


def test_rename_probe_does_zero_hashing_without_delete_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    root = tmp_path / "sync"
    root.mkdir()
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    engine.register_for_one_shot_no_watcher("docs", root)
    changed = root / "changed.txt"
    changed.write_bytes(b"changed")
    calls = 0
    original = blobs.put_path

    def counted(path: Path) -> str:
        nonlocal calls
        calls += 1
        return original(path)

    monkeypatch.setattr(blobs, "put_path", counted)
    try:
        assert engine._detect_renames(
            "docs",
            engine._folders["docs"],
            {str(changed): "modified"},
        ) == []
        assert calls == 0
    finally:
        state.close()
        loop.close()


def test_unmatched_rename_candidate_is_ingested_only_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    root = tmp_path / "sync"
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    _indexed_local(state, blobs, root, payload=b"old", rel_path="old.txt")
    (root / "old.txt").unlink()
    new_path = root / "new.txt"
    new_path.write_bytes(b"different content")
    engine.register_for_one_shot_no_watcher("docs", root)
    calls = 0
    original = blobs.put_path

    def counted(path: Path) -> str:
        nonlocal calls
        calls += 1
        return original(path)

    monkeypatch.setattr(blobs, "put_path", counted)
    try:
        engine._process_dirty_batch({
            "docs": {
                str(root / "old.txt"): "deleted",
                str(new_path): "modified",
            }
        })
        assert calls == 1
        assert state.get_manifest_entry("docs", "new.txt")["blob_hash"] == (
            blake3.blake3(b"different content").hexdigest()
        )
    finally:
        state.close()
        loop.close()


def test_rename_manifest_rows_rollback_as_one_generation(tmp_path: Path) -> None:
    state, blobs, loop, engine = _engine(tmp_path)
    root = tmp_path / "sync"
    state.add_folder(name="docs", local_path=str(root), shared_with=[])
    old_hash = _indexed_local(
        state,
        blobs,
        root,
        payload=b"rename me",
        rel_path="old.txt",
    )
    (root / "old.txt").rename(root / "new.txt")
    state._conn.execute(
        """
        CREATE TRIGGER fail_rename_tombstone
        BEFORE UPDATE ON folder_manifest
        WHEN NEW.file_path = 'old.txt'
        BEGIN
            SELECT RAISE(ABORT, 'injected half-rename fault');
        END
        """
    )
    try:
        with pytest.raises(Exception, match="injected half-rename fault"):
            engine._reconcile_rename(
                "docs",
                None,
                "old.txt",
                "new.txt",
                old_hash,
                root / "new.txt",
            )
        assert state.get_manifest_entry("docs", "new.txt") is None
        old = state.get_manifest_entry("docs", "old.txt")
        assert old is not None and old["blob_hash"] == old_hash
    finally:
        state.close()
        loop.close()
