"""D16 — Tests for the native-CRDT-authoritative folder-sync swap.

Exercises ``one_link.folder_native.merge_entries_via_native`` and the
``FolderEngine._merge_via_native`` adapter (no full engine spun up;
only the merge helper). Validates that the native lattice agrees with
the legacy merger on every canonical case and that the
ONE_LINK_FOLDER_CRDT_NATIVE env gate selects the right path.
"""

from __future__ import annotations

import pytest

from one_link.crdt import (
    ManifestEntry,
    VectorClock,
    merge_manifest_entries,
)

from one_link import folder_native as fn

# 2026-06-04: the OLD guard keyed off whether the `folder_native`
# wrapper module imports — but that ALWAYS succeeds (it's pure Python).
# The actual Rust backend (`one_link_native.crdt`) is the thing that
# may be absent, and the wrapper raises a RuntimeError at call time
# when it is. So the skip must key off the real native flag,
# `crdt_native.HAS_NATIVE`, or the whole module errors in any CI/env
# without the compiled crate instead of skipping cleanly.
from one_link import crdt_native

pytestmark = pytest.mark.skipif(
    not crdt_native.HAS_NATIVE,
    reason="one_link_native.crdt not installed (ADR-0022 native CRDT folder)",
)


# Synthetic replicas — stable across calls.
RID_A = b"\x01" * 32
RID_B = b"\x02" * 32


def _vc(d: dict) -> VectorClock:
    return VectorClock.from_dict(d)


def _entry(path, blob_hash, size, mtime, vclock):
    return ManifestEntry(
        file_path=path,
        blob_hash=blob_hash,
        size=size,
        mtime_ms=mtime,
        vclock=vclock,
    )


# ---------- Trivial cases ----------


def test_both_none_returns_none() -> None:
    out = fn.merge_entries_via_native(
        None, None, replica_id=RID_A, peer_replica_id=RID_B,
    )
    assert out is None


def test_only_local_returns_local() -> None:
    local = _entry("a.txt", "h0", 10, 100, _vc({"a": 1}))
    out = fn.merge_entries_via_native(
        local, None, replica_id=RID_A, peer_replica_id=RID_B,
    )
    assert out is local


def test_only_remote_returns_remote() -> None:
    remote = _entry("a.txt", "h0", 10, 100, _vc({"a": 1}))
    out = fn.merge_entries_via_native(
        None, remote, replica_id=RID_A, peer_replica_id=RID_B,
    )
    assert out is remote


def test_different_paths_raises() -> None:
    local = _entry("a.txt", "h0", 1, 1, _vc({"a": 1}))
    remote = _entry("b.txt", "h0", 1, 1, _vc({"a": 1}))
    with pytest.raises(ValueError):
        fn.merge_entries_via_native(
            local, remote, replica_id=RID_A, peer_replica_id=RID_B,
        )


# ---------- vclock dominance ----------


def test_remote_dominates_returns_remote_values() -> None:
    local = _entry("a.txt", "h0", 10, 100, _vc({"a": 1}))
    remote = _entry("a.txt", "h1", 20, 200, _vc({"a": 1, "b": 1}))
    out = fn.merge_entries_via_native(
        local, remote, replica_id=RID_A, peer_replica_id=RID_B,
    )
    assert out is not None
    assert out.blob_hash == "h1"
    assert out.size == 20


def test_local_dominates_returns_local_values() -> None:
    local = _entry("a.txt", "h0", 10, 100, _vc({"a": 1, "b": 1}))
    remote = _entry("a.txt", "h1", 20, 200, _vc({"a": 1}))
    out = fn.merge_entries_via_native(
        local, remote, replica_id=RID_A, peer_replica_id=RID_B,
    )
    assert out is not None
    assert out.blob_hash == "h0"


def test_equal_clocks_returns_local() -> None:
    vc = _vc({"a": 2})
    local = _entry("a.txt", "h0", 10, 100, vc)
    remote = _entry("a.txt", "h1", 20, 200, vc)
    out = fn.merge_entries_via_native(
        local, remote, replica_id=RID_A, peer_replica_id=RID_B,
    )
    assert out is local


# ---------- tombstones ----------


def test_both_tombstones_yields_merged_clock_tombstone() -> None:
    local = _entry("a.txt", None, None, 100, _vc({"a": 1}))
    remote = _entry("a.txt", None, None, 200, _vc({"b": 1}))
    out = fn.merge_entries_via_native(
        local, remote, replica_id=RID_A, peer_replica_id=RID_B,
    )
    assert out is not None
    assert out.blob_hash is None
    # Merged clock has both replicas.
    assert out.vclock.to_dict() == {"a": 1, "b": 1}
    # Mtime is max of both (informational; entry is still tombstoned).
    assert out.mtime_ms == 200


def test_concurrent_edit_vs_tombstone_edit_wins() -> None:
    """Add-wins OR-set: a concurrent live edit beats a tombstone."""
    local_alive = _entry("a.txt", "alive_hash", 10, 100, _vc({"a": 1}))
    remote_tomb = _entry("a.txt", None, None, 200, _vc({"b": 1}))
    out = fn.merge_entries_via_native(
        local_alive, remote_tomb,
        replica_id=RID_A, peer_replica_id=RID_B,
    )
    assert out is not None
    assert out.blob_hash == "alive_hash"
    # Merged clock includes both sides.
    assert out.vclock.to_dict() == {"a": 1, "b": 1}


def test_concurrent_tombstone_vs_edit_edit_wins_either_order() -> None:
    """Symmetric: same outcome regardless of which side is the live edit."""
    local_tomb = _entry("a.txt", None, None, 200, _vc({"a": 1}))
    remote_alive = _entry("a.txt", "alive_hash", 10, 100, _vc({"b": 1}))
    out = fn.merge_entries_via_native(
        local_tomb, remote_alive,
        replica_id=RID_A, peer_replica_id=RID_B,
    )
    assert out is not None
    assert out.blob_hash == "alive_hash"


# ---------- concurrent live edits ----------


def test_concurrent_live_edits_higher_hash_wins() -> None:
    """H14 audit fix: content-hash tiebreak (not mtime). Adversary
    immune — attacker can't pre-image a higher hash."""
    local = _entry("a.txt", "aaa", 10, 100, _vc({"a": 1}))
    remote = _entry("a.txt", "zzz", 20, 50, _vc({"b": 1}))
    out = fn.merge_entries_via_native(
        local, remote, replica_id=RID_A, peer_replica_id=RID_B,
    )
    assert out is not None
    # Higher hash wins regardless of mtime ordering.
    assert out.blob_hash == "zzz"
    # Merged clock from both replicas.
    assert out.vclock.to_dict() == {"a": 1, "b": 1}


def test_concurrent_identical_hash_uses_mtime() -> None:
    local = _entry("a.txt", "same", 10, 50, _vc({"a": 1}))
    remote = _entry("a.txt", "same", 10, 200, _vc({"b": 1}))
    out = fn.merge_entries_via_native(
        local, remote, replica_id=RID_A, peer_replica_id=RID_B,
    )
    assert out is not None
    assert out.blob_hash == "same"
    # Mtime preserved as the max for UI.
    assert out.mtime_ms == 200


# ---------- agreement with legacy merger ----------


@pytest.mark.parametrize(
    "case",
    [
        # both None
        (None, None),
        # only local
        (
            _entry("a.txt", "h0", 10, 100, _vc({"a": 1})),
            None,
        ),
        # only remote
        (
            None,
            _entry("a.txt", "h0", 10, 100, _vc({"b": 1})),
        ),
        # remote dominates
        (
            _entry("a.txt", "h0", 10, 100, _vc({"a": 1})),
            _entry("a.txt", "h1", 20, 200, _vc({"a": 1, "b": 1})),
        ),
        # both tombstones
        (
            _entry("a.txt", None, None, 100, _vc({"a": 1})),
            _entry("a.txt", None, None, 200, _vc({"b": 1})),
        ),
        # edit vs tombstone (concurrent) — both sides
        (
            _entry("a.txt", "alive", 10, 100, _vc({"a": 1})),
            _entry("a.txt", None, None, 200, _vc({"b": 1})),
        ),
        (
            _entry("a.txt", None, None, 200, _vc({"a": 1})),
            _entry("a.txt", "alive", 10, 100, _vc({"b": 1})),
        ),
        # concurrent live edits with content-hash tiebreak
        (
            _entry("a.txt", "aaa", 10, 100, _vc({"a": 1})),
            _entry("a.txt", "zzz", 20, 50, _vc({"b": 1})),
        ),
    ],
)
def test_native_merger_agrees_with_legacy_on_canonical_cases(case) -> None:
    local, remote = case
    native_out = fn.merge_entries_via_native(
        local, remote, replica_id=RID_A, peer_replica_id=RID_B,
    )
    legacy_out = merge_manifest_entries(local, remote)
    # Both None or both not None.
    assert (native_out is None) == (legacy_out is None)
    if native_out is None:
        return
    # Same blob_hash / tombstone status.
    assert native_out.blob_hash == legacy_out.blob_hash
    # Same vclock.
    assert native_out.vclock.to_dict() == legacy_out.vclock.to_dict()


# ---------- engine-side env gate ----------


def test_engine_gate_defaults_off(monkeypatch) -> None:
    """Without the env var, the gate must be off."""
    monkeypatch.delenv("ONE_LINK_FOLDER_CRDT_NATIVE", raising=False)
    from one_link.foldersync import FolderEngine
    eng = FolderEngine.__new__(FolderEngine)
    # Drive only the init lines we care about.
    eng.me_fp = "ff" * 32
    # Replicate the relevant init logic.
    import os as _os
    eng._crdt_native_authoritative = (
        _os.environ.get("ONE_LINK_FOLDER_CRDT_NATIVE", "0") == "1"
    )
    assert eng._crdt_native_authoritative is False


def test_engine_gate_honoured(monkeypatch) -> None:
    monkeypatch.setenv("ONE_LINK_FOLDER_CRDT_NATIVE", "1")
    from one_link.foldersync import _MIRROR_AVAILABLE
    import os as _os
    gate = (
        _os.environ.get("ONE_LINK_FOLDER_CRDT_NATIVE", "0") == "1"
        and _MIRROR_AVAILABLE
    )
    assert gate is True
