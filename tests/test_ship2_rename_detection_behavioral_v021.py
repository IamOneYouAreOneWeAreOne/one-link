"""v0.21.x Ship 2 behavioral tests — rename detection round-trip.

Goes beyond source-text pins: constructs a real FolderEngine
against a real State + real BlobStore + real on-disk files,
manually triggers the watcher's snapshot dict (skipping the
Observer thread to keep tests deterministic), and verifies the
manifest state + audit log AFTER reconciliation.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import pytest_asyncio

from one_link.blobstore import BlobStore
from one_link.foldersync import FolderEngine, FolderState
from one_link.state import State


def _hash_bytes(data: bytes) -> str:
    """The BlobStore hashes by BLAKE3 / SHA-256 depending on build —
    we don't care for the tests since we're feeding through put_path
    which returns the canonical hash."""
    import hashlib
    return hashlib.sha256(data).hexdigest()


@pytest_asyncio.fixture
async def engine_ctx(tmp_path: Path):
    """Real engine, real state, real blob_store, real on-disk folder."""
    state = State(db_path=tmp_path / "state.db")
    blob_store = BlobStore(root=tmp_path / "blobs")
    folder_dir = tmp_path / "folder"
    folder_dir.mkdir()

    loop = asyncio.get_running_loop()
    engine = FolderEngine(
        state=state,
        blob_store=blob_store,
        my_fingerprint="aa" * 32,
        loop=loop,
    )

    # Register the folder in state but skip _start_watch (the real
    # Observer thread; tests don't need filesystem events because we
    # manually populate the _dirty snapshot or call _reconcile_*).
    state.add_folder(
        name="test", local_path=str(folder_dir.resolve()),
        shared_with=[], max_file_bytes=None, ignored_patterns=[],
        conflict_policy="latest-wins",
    )
    # Insert a stub FolderState so _detect_renames / _reconcile_*
    # can find the folder by name.
    engine._folders["test"] = FolderState(
        name="test",
        root=folder_dir.resolve(),
        observer=MagicMock(),
        handler=MagicMock(),
    )
    try:
        yield SimpleNamespace(
            engine=engine, state=state, blob_store=blob_store,
            folder_dir=folder_dir,
        )
    finally:
        state.close()


# ── _detect_renames pairing logic ───────────────────────────────────


@pytest.mark.asyncio
async def test_detect_renames_pairs_single_rename(engine_ctx):
    """Classic case: one delete + one create with matching hash →
    one rename pair."""
    folder_dir = engine_ctx.folder_dir
    engine = engine_ctx.engine
    state = engine_ctx.state

    # Create + seed manifest for the OLD path.
    (folder_dir / "intro.txt").write_text("hello world", encoding="utf-8")
    blob_hex = engine.blobs.put_path(folder_dir / "intro.txt")
    state.upsert_manifest_entry(
        folder_name="test", file_path="intro.txt",
        blob_hash=blob_hex, size=11,
        mtime_ms=1, vclock={"aa" * 32: 1},
    )
    # Simulate the rename: old file gone, new file with same content.
    (folder_dir / "intro.txt").unlink()
    (folder_dir / "01-intro.txt").write_text("hello world", encoding="utf-8")

    items = {
        str(folder_dir / "intro.txt"): "deleted",
        str(folder_dir / "01-intro.txt"): "modified",
    }
    fs = engine._folders["test"]
    renames = engine._detect_renames("test", fs, items)
    assert len(renames) == 1
    old_rel, new_rel, hash_match, new_path = renames[0]
    assert old_rel == "intro.txt"
    assert new_rel == "01-intro.txt"
    assert hash_match == blob_hex


@pytest.mark.asyncio
async def test_detect_renames_rejects_different_content(engine_ctx):
    """Delete + create with DIFFERENT content is not a rename; it's
    a deletion plus an unrelated new file. Must not be paired."""
    folder_dir = engine_ctx.folder_dir
    engine = engine_ctx.engine
    state = engine_ctx.state

    (folder_dir / "old.txt").write_text("aaaa", encoding="utf-8")
    blob_hex_old = engine.blobs.put_path(folder_dir / "old.txt")
    state.upsert_manifest_entry(
        folder_name="test", file_path="old.txt",
        blob_hash=blob_hex_old, size=4,
        mtime_ms=1, vclock={"aa" * 32: 1},
    )
    (folder_dir / "old.txt").unlink()
    (folder_dir / "new.txt").write_text("totally different bytes", encoding="utf-8")

    items = {
        str(folder_dir / "old.txt"): "deleted",
        str(folder_dir / "new.txt"): "modified",
    }
    renames = engine._detect_renames("test", engine._folders["test"], items)
    assert renames == [], (
        "different-content delete+create must NOT be paired as a rename"
    )


@pytest.mark.asyncio
async def test_detect_renames_one_to_one_with_duplicates(engine_ctx):
    """If one delete matches MANY creates (duplicate-content files
    appearing simultaneously), only the first create gets paired.
    The rest fall through to the normal create path so they aren't
    silently dropped."""
    folder_dir = engine_ctx.folder_dir
    engine = engine_ctx.engine
    state = engine_ctx.state

    (folder_dir / "orig.txt").write_text("dup", encoding="utf-8")
    h = engine.blobs.put_path(folder_dir / "orig.txt")
    state.upsert_manifest_entry(
        folder_name="test", file_path="orig.txt",
        blob_hash=h, size=3, mtime_ms=1, vclock={"aa" * 32: 1},
    )
    (folder_dir / "orig.txt").unlink()
    (folder_dir / "copy1.txt").write_text("dup", encoding="utf-8")
    (folder_dir / "copy2.txt").write_text("dup", encoding="utf-8")

    items = {
        str(folder_dir / "orig.txt"): "deleted",
        str(folder_dir / "copy1.txt"): "modified",
        str(folder_dir / "copy2.txt"): "modified",
    }
    renames = engine._detect_renames("test", engine._folders["test"], items)
    # Exactly one rename pair; the other create stays unmatched.
    assert len(renames) == 1, (
        "1:1 matching — multiple creates with same hash must NOT all "
        "be tagged as renames of the same delete"
    )


@pytest.mark.asyncio
async def test_detect_renames_skips_unchanged_files(engine_ctx):
    """A file whose manifest entry already has the same hash isn't
    a 'create' — it's a re-touched no-op. Must not be considered as
    a rename candidate."""
    folder_dir = engine_ctx.folder_dir
    engine = engine_ctx.engine
    state = engine_ctx.state

    (folder_dir / "stable.txt").write_text("content", encoding="utf-8")
    h = engine.blobs.put_path(folder_dir / "stable.txt")
    state.upsert_manifest_entry(
        folder_name="test", file_path="stable.txt",
        blob_hash=h, size=7, mtime_ms=1, vclock={"aa" * 32: 1},
    )
    # Trigger a "modified" event but the content hasn't changed.
    items = {str(folder_dir / "stable.txt"): "modified"}
    renames = engine._detect_renames("test", engine._folders["test"], items)
    assert renames == []


# ── _reconcile_rename: vclock + tombstone + audit ───────────────────


@pytest.mark.asyncio
async def test_reconcile_rename_inherits_vclock_into_new_entry(engine_ctx):
    """The new manifest entry must INHERIT the old entry's vclock +
    bump our slot by one. This preserves cross-rename history so
    peers see it as continuous, not a delete+unrelated-create."""
    folder_dir = engine_ctx.folder_dir
    engine = engine_ctx.engine
    state = engine_ctx.state

    (folder_dir / "old.md").write_text("content", encoding="utf-8")
    blob_hex = engine.blobs.put_path(folder_dir / "old.md")
    # Old entry has a rich vclock from prior history.
    old_vclock = {"aa" * 32: 5, "bb" * 32: 3, "cc" * 32: 1}
    state.upsert_manifest_entry(
        folder_name="test", file_path="old.md",
        blob_hash=blob_hex, size=7, mtime_ms=1000,
        vclock=old_vclock,
    )
    # Now simulate the rename on disk.
    (folder_dir / "old.md").rename(folder_dir / "new.md")
    new_path = folder_dir / "new.md"

    engine._reconcile_rename(
        "test", engine._folders["test"], "old.md", "new.md",
        blob_hex, new_path,
    )

    new_entry = state.get_manifest_entry("test", "new.md")
    assert new_entry is not None
    assert new_entry["blob_hash"] == blob_hex
    new_vclock = new_entry["vclock"]
    # OUR slot is bumped by one (5 → 6); OTHER slots unchanged.
    assert new_vclock["aa" * 32] == 6
    assert new_vclock["bb" * 32] == 3
    assert new_vclock["cc" * 32] == 1


@pytest.mark.asyncio
async def test_reconcile_rename_tombstones_old_entry(engine_ctx):
    """The old path must be tombstoned (blob_hash=None) with a
    separately-bumped vclock so the delete propagates to peers."""
    folder_dir = engine_ctx.folder_dir
    engine = engine_ctx.engine
    state = engine_ctx.state

    (folder_dir / "before.txt").write_text("X", encoding="utf-8")
    h = engine.blobs.put_path(folder_dir / "before.txt")
    state.upsert_manifest_entry(
        folder_name="test", file_path="before.txt",
        blob_hash=h, size=1, mtime_ms=1000,
        vclock={"aa" * 32: 2},
    )
    (folder_dir / "before.txt").rename(folder_dir / "after.txt")
    engine._reconcile_rename(
        "test", engine._folders["test"], "before.txt", "after.txt",
        h, folder_dir / "after.txt",
    )

    old_entry = state.get_manifest_entry("test", "before.txt")
    assert old_entry is not None
    assert old_entry["blob_hash"] is None, (
        "old entry must be tombstoned so peers delete it locally"
    )
    # The tombstone clock is bumped TWICE from the original (once
    # for the new entry, once for the tombstone) so both ops
    # propagate independently.
    assert old_entry["vclock"]["aa" * 32] == 4


@pytest.mark.asyncio
async def test_reconcile_rename_writes_renamed_audit_entry(engine_ctx):
    """The audit log must contain a 'renamed' row with the old path
    in the note so users can see WHERE the file came from."""
    folder_dir = engine_ctx.folder_dir
    engine = engine_ctx.engine
    state = engine_ctx.state

    (folder_dir / "src.py").write_text("print('hi')", encoding="utf-8")
    h = engine.blobs.put_path(folder_dir / "src.py")
    state.upsert_manifest_entry(
        folder_name="test", file_path="src.py",
        blob_hash=h, size=11, mtime_ms=1000,
        vclock={"aa" * 32: 1},
    )
    (folder_dir / "src.py").rename(folder_dir / "main.py")
    engine._reconcile_rename(
        "test", engine._folders["test"], "src.py", "main.py",
        h, folder_dir / "main.py",
    )
    audit = state.list_folder_audit(folder_name="test")
    renamed_rows = [r for r in audit if r.get("action") == "renamed"]
    assert len(renamed_rows) == 1
    row = renamed_rows[0]
    assert row["file_path"] == "main.py"
    assert "src.py" in (row.get("note") or "")
    assert row["blob_hash"] == h


@pytest.mark.asyncio
async def test_reconcile_rename_handles_missing_old_entry(engine_ctx):
    """If the old path has no manifest entry (rare race: file
    appeared and disappeared faster than the scanner saw it), the
    rename should not crash — the new entry just starts with an
    empty inherited vclock."""
    folder_dir = engine_ctx.folder_dir
    engine = engine_ctx.engine
    state = engine_ctx.state

    # No prior manifest entry for "phantom.txt".
    (folder_dir / "now-here.txt").write_text("data", encoding="utf-8")
    h = engine.blobs.put_path(folder_dir / "now-here.txt")
    # Should not raise.
    engine._reconcile_rename(
        "test", engine._folders["test"], "phantom.txt", "now-here.txt",
        h, folder_dir / "now-here.txt",
    )
    new_entry = state.get_manifest_entry("test", "now-here.txt")
    assert new_entry is not None
    # Vclock starts at 1 for our slot (empty base + one bump).
    assert new_entry["vclock"].get("aa" * 32) == 1
