"""v0.21.x Ship 2: move/rename detection in the folder watcher.

Pre-v0.21.x, when a user renamed `intro.txt` to `01-intro.txt`,
the watcher saw two separate filesystem events (delete + create)
and processed them independently:
  - intro.txt: tombstoned (blob_hash → None, vclock bumped)
  - 01-intro.txt: new manifest entry with FRESH vclock starting
    from empty {me_fp: 1}

That broke per-file history at the rename boundary — peers saw
'file deleted, unrelated file created with the same content' instead
of 'file renamed'. The blob bytes themselves never re-transferred
(content-addressed store dedupes), but the audit trail was wrong.

v0.21.x detects the delete+create pair inside the same debounce
window, matches on identical blob_hash, and emits a SINGLE rename
operation:
  - New entry inherits the OLD entry's vclock + bumps once,
    preserving continuous history across the rename
  - Old entry tombstoned with a separately-bumped clock so the
    tombstone propagates independently
  - 'renamed' audit-log entry with the old path in the note

This pins the structural shape so a future refactor can't quietly
revert to the lossy delete+create path.
"""
from __future__ import annotations

from pathlib import Path

import pytest


_FOLDERSYNC = (
    Path(__file__).resolve().parents[1]
    / "src" / "one_link" / "foldersync.py"
)


@pytest.fixture(scope="module")
def foldersync_src() -> str:
    return _FOLDERSYNC.read_text(encoding="utf-8")


def test_dirty_pump_calls_detect_renames(foldersync_src):
    """_dirty_pump must invoke _detect_renames on each debounce
    snapshot before the default delete/reconcile loop. Without
    this hook, the rename path is never reachable."""
    idx = foldersync_src.find("async def _dirty_pump(")
    assert idx > 0
    body = foldersync_src[idx:idx + 4000]
    assert "_detect_renames(" in body, (
        "_dirty_pump must call _detect_renames so rename pairs are "
        "matched before being processed as separate delete + create"
    )
    # The matched pair paths must be SKIPPED from the regular loop
    # so they don't get tombstoned/reconciled twice.
    assert "renamed_handled" in body, (
        "matched rename pair paths must be tracked + skipped in the "
        "default-processing loop"
    )


def test_detect_renames_pairs_by_blob_hash(foldersync_src):
    """_detect_renames must pair deleted paths with newly-created
    paths whose blob_hash matches. Pin the helper signature + the
    blob_hash-pairing logic."""
    assert "def _detect_renames(" in foldersync_src, (
        "_detect_renames helper missing"
    )
    idx = foldersync_src.find("def _detect_renames(")
    end = foldersync_src.find("\n    def _reconcile_rename(", idx)
    body = foldersync_src[idx:end if end > 0 else idx + 4000]
    # Pin the pairing logic: deletes + creates, matched by hash.
    assert "deletes" in body and "creates" in body, (
        "_detect_renames must collect both deletes and creates"
    )
    assert "old_hash == new_hash" in body or "old_hash != new_hash" in body, (
        "_detect_renames must match by blob_hash equality"
    )
    # 1:1 pairing — used_creates set prevents one delete matching
    # multiple creates (would falsely treat copies as renames).
    assert "used_creates" in body, (
        "_detect_renames must track used creates to enforce 1:1 "
        "pairing — without this, copies could be misidentified as "
        "renames when one delete + many creates share content"
    )


def test_reconcile_rename_inherits_vclock(foldersync_src):
    """_reconcile_rename must INHERIT the old entry's vclock when
    writing the new entry — that's what gives peers a continuous
    history view across the rename. Pin the inheritance source so
    a refactor can't revert to a fresh empty vclock."""
    idx = foldersync_src.find("def _reconcile_rename(")
    assert idx > 0
    body = foldersync_src[idx:idx + 3000]
    # Reads the old entry's vclock as the base.
    assert "get_manifest_entry(folder_name, old_rel)" in body, (
        "_reconcile_rename must read the old entry to inherit its vclock"
    )
    assert "VectorClock.from_dict(old_entry" in body, (
        "the OLD entry's vclock must be parsed and used as the base "
        "for the new entry; an empty vclock would lose history"
    )
    # Increments separately for the new entry and the tombstone so
    # each propagates independently.
    assert body.count(".increment(self.me_fp)") >= 2, (
        "the new entry's vclock AND the tombstone's vclock must each "
        "be incremented; a shared bump can let one operation arrive "
        "without the other"
    )


def test_reconcile_rename_writes_renamed_audit_entry(foldersync_src):
    """The audit trail must record the rename as a single
    'renamed' event with the old path in the note, NOT as
    independent delete + create rows."""
    idx = foldersync_src.find("def _reconcile_rename(")
    body = foldersync_src[idx:idx + 3000]
    assert "record_folder_audit_event(" in body, (
        "rename must produce an audit row via record_folder_audit_event"
    )
    assert "renamed" in body, (
        "the audit action label must be 'renamed' (not 'delete' or 'write')"
    )
    assert "renamed from" in body, (
        "the audit note must include the old path so users can see "
        "WHERE the file came from"
    )


def test_reconcile_rename_tombstones_old_path(foldersync_src):
    """Even though peers see the rename as inheritance, the old
    path still needs a tombstone for the delete-half of the rename
    to propagate (filesystems on other devices need to remove the
    old file). Pin the tombstone is written with blob_hash=None."""
    idx = foldersync_src.find("def _reconcile_rename(")
    body = foldersync_src[idx:idx + 3000]
    assert "upsert_manifest_entry(" in body, (
        "rename must upsert manifest entries"
    )
    # The tombstone shape: blob_hash=None.
    assert "blob_hash=None" in body, (
        "the tombstone half of the rename must use blob_hash=None — "
        "that's how peers know to remove the old path locally"
    )
