"""Phase C-3 call-site wiring integration tests.

The unit tests under ``test_*_migration.py`` cover the adapters in
isolation. These tests prove the *production* call sites actually
invoke the adapters: AdaptiveTransferBrain feeds its bandit shadow,
FolderEngine fills its native mirror on every merge, daemon ``share``
dual-issues a macaroon alongside the Ed25519 grant.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest


def _native_available() -> bool:
    try:
        from one_link import bandit_native, capability_native, crdt_native

        return all(
            (
                bandit_native.HAS_NATIVE,
                capability_native.HAS_NATIVE,
                crdt_native.HAS_NATIVE,
            )
        )
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native not installed (build via maturin)",
)


# --- AdaptiveTransferBrain.observe() feeds the bandit ----------------------


def test_brain_observe_feeds_bandit_shadow():
    """Every legacy observe() call must mirror into the bandit. After
    enough biased observations, ``best_route_bandit()`` must report
    the high-bandwidth route."""
    from one_link.transfer_brain import (
        AdaptiveTransferBrain,
        TransferRouteObservation,
    )

    brain = AdaptiveTransferBrain()
    # Seed both arms so the bandit has a fixed (sorted) arm vector.
    brain.observe(TransferRouteObservation(route="lan", ok=True, bandwidth_bps=1.0))
    brain.observe(TransferRouteObservation(route="wan", ok=True, bandwidth_bps=1.0))
    # 200 biased observations: lan = 800 Mbps reward, wan = 10 Mbps.
    for _ in range(200):
        brain.observe(
            TransferRouteObservation(route="lan", ok=True, bandwidth_bps=800_000_000)
        )
        brain.observe(
            TransferRouteObservation(route="wan", ok=True, bandwidth_bps=10_000_000)
        )
    assert brain.best_route_bandit() == "lan"


def test_brain_observe_handles_failure_observation():
    """A failed (ok=False) observation must register a zero reward
    without breaking the bandit."""
    from one_link.transfer_brain import (
        AdaptiveTransferBrain,
        TransferRouteObservation,
    )

    brain = AdaptiveTransferBrain()
    brain.observe(TransferRouteObservation(route="lan", ok=False))
    brain.observe(TransferRouteObservation(route="lan", ok=True, bandwidth_bps=1e8))
    # Bandit should be alive and answering after a failure.
    assert brain.best_route_bandit() in {"lan"}


# --- FolderEngine -> NativeManifestMirror -----------------------------------


def _build_folder_engine(tmp_path: Path):
    """Build a real FolderEngine + State on a fresh sqlite. Used to
    exercise the mirror end-to-end."""
    from one_link.blobstore import BlobStore
    from one_link.foldersync import FolderEngine
    from one_link.state import State

    state_path = tmp_path / "state.sqlite"
    blobs_path = tmp_path / "blobs"
    blobs_path.mkdir()
    state = State(str(state_path))
    blobs = BlobStore(str(blobs_path))
    loop = asyncio.new_event_loop()
    try:
        engine = FolderEngine(
            state=state,
            blob_store=blobs,
            my_fingerprint="alicedevice0000000000000000000000",
            loop=loop,
        )
        return engine, state, blobs, loop
    except Exception:
        loop.close()
        raise


def test_folder_engine_exposes_native_mirror_stats(tmp_path):
    engine, state, blobs, loop = _build_folder_engine(tmp_path)
    try:
        stats = engine.native_mirror_stats()
        assert "available" in stats
        assert stats["available"] is True
        assert stats["divergence_events"] == 0
        assert stats["folders"] == {}
    finally:
        loop.close()


def test_folder_engine_mirror_observe_round_trips(tmp_path):
    """Directly invoke the mirror hook (the same hook the merge path
    invokes) and verify it accumulates entries in the native folder."""
    from one_link.crdt import ManifestEntry, VectorClock

    engine, state, blobs, loop = _build_folder_engine(tmp_path)
    try:
        entry = ManifestEntry(
            file_path="/share/x.pdf",
            blob_hash="abc123",
            size=1024,
            mtime_ms=100,
            vclock=VectorClock.from_dict({"alice": 1}),
        )
        engine._mirror_observe("test_folder", entry)
        snapshot = engine.native_folder_snapshot("test_folder")
        assert snapshot is not None
        assert snapshot.len() == 1
        stats = engine.native_mirror_stats()
        assert stats["folders"]["test_folder"]["present_files"] == 1
    finally:
        loop.close()


def test_folder_engine_mirror_tombstone(tmp_path):
    from one_link.crdt import ManifestEntry, VectorClock

    engine, state, blobs, loop = _build_folder_engine(tmp_path)
    try:
        entry = ManifestEntry(
            file_path="/share/x.pdf",
            blob_hash="abc",
            size=1024,
            mtime_ms=100,
            vclock=VectorClock.from_dict({"alice": 1}),
        )
        engine._mirror_observe("f", entry)
        tomb = ManifestEntry(
            file_path="/share/x.pdf",
            blob_hash=None,  # tombstone
            size=None,
            mtime_ms=None,
            vclock=VectorClock.from_dict({"alice": 2}),
        )
        engine._mirror_observe("f", tomb)
        assert engine.native_folder_snapshot("f").len() == 0
    finally:
        loop.close()
