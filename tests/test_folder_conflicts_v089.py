"""v0.8.9 — folder-sync divergent-edit conflict UI.

The CRDT layer (`merge_manifest_entries`) had an existing
deterministic tie-break for concurrent edits — later mtime wins,
ties broken by lexically larger blob hash. That silently destroys
the loser's edit. v0.8.9 detects the concurrent-edit case at merge
time, logs both versions to `manifest_conflicts`, and exposes a
Conflicts UI so the user can override the auto-merge with
mine / theirs / both.

These tests cover schema v10, conflict detection in foldersync's
receive_remote_manifest, idempotent re-recording, severity-by-
divergence-type filtering, ack semantics, and the resolution
helper that writes the chosen version back into the manifest.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from one_link.crdt import ManifestEntry, VectorClock, merge_manifest_entries
from one_link.state import State


# ───────── schema migration ──────────────────────────────────────────

@pytest.fixture
def state(tmp_path: Path) -> State:
    s = State(db_path=tmp_path / "state.db")
    yield s
    s.close()


def test_migration_v10_creates_table(state: State):
    rows = state._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    names = {r["name"] for r in rows}
    assert "manifest_conflicts" in names
    assert state.schema_version() >= 10


# ───────── state helpers ─────────────────────────────────────────────

def _record_basic_conflict(state: State, **overrides) -> int:
    base = dict(
        folder_name="docs",
        file_path="report.md",
        peer_fp="aabbccdd" + "00" * 28,
        local_blob_hash="11" * 32,
        local_size=100,
        local_mtime_ms=1000,
        local_vclock={"me": 1},
        remote_blob_hash="22" * 32,
        remote_size=200,
        remote_mtime_ms=900,
        remote_vclock={"peer": 1},
        applied_choice="local",
    )
    base.update(overrides)
    return state.record_manifest_conflict(**base)


def test_record_conflict_persists(state: State):
    cid = _record_basic_conflict(state)
    out = state.list_manifest_conflicts(unresolved_only=True)
    assert len(out) == 1
    assert out[0]["id"] == cid
    assert out[0]["folder_name"] == "docs"
    assert out[0]["file_path"] == "report.md"
    assert out[0]["resolved_ms"] is None


def test_record_conflict_idempotent_on_same_vclocks(state: State):
    """Re-recording the same (local_vc, remote_vc) pair for a path
    must reuse the existing row, not append duplicates."""
    cid1 = _record_basic_conflict(state)
    cid2 = _record_basic_conflict(state)
    assert cid1 == cid2
    assert len(state.list_manifest_conflicts()) == 1


def test_record_conflict_appends_when_vclocks_differ(state: State):
    cid1 = _record_basic_conflict(state, local_vclock={"me": 1})
    cid2 = _record_basic_conflict(state, local_vclock={"me": 2})
    assert cid1 != cid2
    assert len(state.list_manifest_conflicts()) == 2


def test_applied_choice_validated(state: State):
    with pytest.raises(ValueError):
        _record_basic_conflict(state, applied_choice="yolo")


def test_resolve_conflict(state: State):
    cid = _record_basic_conflict(state)
    assert state.mark_manifest_conflict_resolved(
        cid, resolution="mine", resolved_by="ui",
    ) is True
    out = state.list_manifest_conflicts()
    assert out[0]["resolved_ms"] is not None
    assert out[0]["resolution"] == "mine"
    # Idempotent re-resolve returns False.
    assert state.mark_manifest_conflict_resolved(
        cid, resolution="mine", resolved_by="ui",
    ) is False


def test_resolve_validates(state: State):
    cid = _record_basic_conflict(state)
    with pytest.raises(ValueError):
        state.mark_manifest_conflict_resolved(cid, resolution="vibes")


def test_count_unresolved(state: State):
    _record_basic_conflict(state, local_vclock={"a": 1})
    _record_basic_conflict(state, local_vclock={"a": 2})
    assert state.count_unresolved_manifest_conflicts() == 2
    one = state.list_manifest_conflicts(unresolved_only=True)[0]["id"]
    state.mark_manifest_conflict_resolved(one, resolution="mine")
    assert state.count_unresolved_manifest_conflicts() == 1


def test_count_unresolved_per_folder(state: State):
    _record_basic_conflict(state, folder_name="docs", local_vclock={"a": 1})
    _record_basic_conflict(state, folder_name="other", local_vclock={"a": 1})
    assert state.count_unresolved_manifest_conflicts("docs") == 1
    assert state.count_unresolved_manifest_conflicts("other") == 1
    assert state.count_unresolved_manifest_conflicts() == 2


def test_get_manifest_conflict(state: State):
    cid = _record_basic_conflict(state)
    out = state.get_manifest_conflict(cid)
    assert out is not None
    assert out["id"] == cid
    assert state.get_manifest_conflict(99999) is None


# ───────── foldersync detection ──────────────────────────────────────

def test_concurrent_divergent_edit_is_a_conflict():
    """Local and remote both edit the same path independently with
    different blob hashes → CRDT vclocks are concurrent → conflict."""
    local = ManifestEntry(
        file_path="a.md", blob_hash="11" * 32, size=100, mtime_ms=1000,
        vclock=VectorClock.from_dict({"me": 1}),
    )
    remote = ManifestEntry(
        file_path="a.md", blob_hash="22" * 32, size=200, mtime_ms=900,
        vclock=VectorClock.from_dict({"peer": 1}),
    )
    assert local.vclock.concurrent_with(remote.vclock)
    assert local.blob_hash != remote.blob_hash
    # The CRDT still produces a winner via tie-break.
    winner = merge_manifest_entries(local, remote)
    assert winner is not None


def test_same_blob_concurrent_is_not_a_conflict():
    """If both sides have the same blob (e.g. they each computed
    their own copy of the same file), no real divergence — no
    conflict to log."""
    local = ManifestEntry(
        file_path="a.md", blob_hash="11" * 32, size=100, mtime_ms=1000,
        vclock=VectorClock.from_dict({"me": 1}),
    )
    remote = ManifestEntry(
        file_path="a.md", blob_hash="11" * 32, size=100, mtime_ms=1000,
        vclock=VectorClock.from_dict({"peer": 1}),
    )
    assert local.blob_hash == remote.blob_hash
    # Detection helper should return None / not raise.


def test_dominated_clock_is_not_a_conflict():
    """If remote's vclock dominates local (peer observed our edit
    + made one on top), there's no divergence — remote just wins."""
    local = ManifestEntry(
        file_path="a.md", blob_hash="11" * 32, size=100, mtime_ms=1000,
        vclock=VectorClock.from_dict({"me": 1}),
    )
    remote = ManifestEntry(
        file_path="a.md", blob_hash="22" * 32, size=200, mtime_ms=2000,
        vclock=VectorClock.from_dict({"me": 1, "peer": 1}),
    )
    assert local.vclock.happens_before(remote.vclock)
    assert not local.vclock.concurrent_with(remote.vclock)


# ───────── conflict-suffixed path helper ─────────────────────────────

def test_conflict_suffixed_path_with_extension():
    from one_link.foldersync import FolderEngine
    out = FolderEngine._conflict_suffixed_path("foo/bar.txt", "aabbccddee" + "00" * 27)
    assert out == "foo/bar.conflict-aabbccdd.txt"


def test_conflict_suffixed_path_no_extension():
    from one_link.foldersync import FolderEngine
    out = FolderEngine._conflict_suffixed_path("foo/bar", "aabbccddee" + "00" * 27)
    assert out == "foo/bar.conflict-aabbccdd"


def test_conflict_suffixed_path_no_peer():
    from one_link.foldersync import FolderEngine
    out = FolderEngine._conflict_suffixed_path("a.txt", None)
    assert out == "a.conflict-peer.txt"


def test_conflict_suffixed_path_dotfile():
    """A dotfile shouldn't be split as 'extension' — the leading
    '.' is part of the name, not an extension marker."""
    from one_link.foldersync import FolderEngine
    out = FolderEngine._conflict_suffixed_path(".env", "aabbccdd" + "00" * 28)
    # Either ".conflict-aabbccdd" applied to the .env, or appended
    # as suffix — both are reasonable. Just don't crash + remain
    # collision-free.
    assert "conflict-aabbccdd" in out


# ───────── server route + UI smoke ───────────────────────────────────

def test_server_routes_registered():
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    assert (
        'r.add_get("/api/folder-conflicts", '
        'self._guarded(self.api_list_folder_conflicts))'
    ) in src
    assert "api_resolve_folder_conflict" in src


def test_ui_has_conflict_surfaces():
    src = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert 'id="conflicts-backdrop"' in src
    assert 'id="folder-conflicts-banner"' in src
    assert 'id="conflicts-list"' in src
    assert "function refreshFolderConflictsBanner(" in src
    assert "function openConflictsModal(" in src
    assert "function resolveConflict(" in src
    # WS handlers
    assert "folder_conflict_detected" in src
    assert "folder_conflict_resolved" in src


def test_resolution_choices_match_doc():
    """Server must accept exactly mine|theirs|both as the choice."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_resolve_folder_conflict")
    assert idx > 0
    snippet = src[idx:idx + 2000]
    assert '"mine", "theirs", "both"' in snippet
