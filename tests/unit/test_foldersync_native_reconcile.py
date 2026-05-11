"""Phase D #3 (ADR-0022) — active native reconciliation cross-check.

Exercises the ``FolderEngine._native_reconcile_check`` path the daemon
runs alongside the legacy merge to confirm zero CRDT-vs-legacy
disagreement under live workloads. The counters surface via
``native_mirror_stats``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from one_link.blobstore import BlobStore
from one_link.crdt import ManifestEntry, VectorClock
from one_link.foldersync import FolderEngine
from one_link.state import State


def _native_available() -> bool:
    try:
        from one_link import crdt_native

        return crdt_native.HAS_NATIVE
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.crdt not installed (build via maturin)",
)


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


def _entry(path: str, blob: str | None = "abc", size: int = 1024, mtime: int = 100):
    return ManifestEntry(
        file_path=path,
        blob_hash=blob,
        size=size,
        mtime_ms=mtime,
        vclock=VectorClock.from_dict({"alice": 1}),
    )


def test_reconcile_check_counter_increments_on_remote_merge(tmp_path: Path):
    """Every ``receive_remote_manifest`` entry runs the native OR-set
    cross-check exactly once. After two entries land, ``checks==2`` and
    ``disagreements==0`` (both sides agree about presence)."""
    state, _blobs, loop, engine = _engine(tmp_path)
    try:
        state.add_folder(name="docs", local_path=str(tmp_path / "docs"), shared_with=[])
        entries = [_entry("a.pdf").to_dict(), _entry("b.pdf").to_dict()]
        engine.receive_remote_manifest(folder_name="docs", entries=entries)
        stats = engine.native_mirror_stats()
        assert stats["reconcile_checks"] >= 2
        assert stats["reconcile_disagreements"] == 0
    finally:
        state.close()
        loop.close()


def test_reconcile_check_agrees_on_tombstone(tmp_path: Path):
    """Tombstone-only entries (no prior local copy) — both legacy
    merge and native OR-set report absent → no disagreement."""
    state, _blobs, loop, engine = _engine(tmp_path)
    try:
        state.add_folder(name="docs", local_path=str(tmp_path / "docs"), shared_with=[])
        tomb = ManifestEntry(
            file_path="ghost.pdf",
            blob_hash=None,
            size=0,
            mtime_ms=1,
            vclock=VectorClock.from_dict({"alice": 1}),
        )
        engine.receive_remote_manifest(
            folder_name="docs", entries=[tomb.to_dict()]
        )
        stats = engine.native_mirror_stats()
        assert stats["reconcile_checks"] >= 1
        assert stats["reconcile_disagreements"] == 0
    finally:
        state.close()
        loop.close()


def test_reconcile_check_stats_exposes_counters(tmp_path: Path):
    """Counters surface via ``native_mirror_stats`` even before any
    merge has run — so operators can poll the diagnostic from boot."""
    state, _blobs, loop, engine = _engine(tmp_path)
    try:
        stats = engine.native_mirror_stats()
        assert stats["reconcile_checks"] == 0
        assert stats["reconcile_disagreements"] == 0
        assert "divergence_events" in stats
    finally:
        state.close()
        loop.close()
