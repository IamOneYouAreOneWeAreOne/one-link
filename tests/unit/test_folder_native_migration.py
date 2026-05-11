"""Phase C-3 daemon migration: folder_native (ADR-0022 CRDT folder
adapter).

Verifies the legacy ManifestEntry -> native Folder conversion plus
the in-process mirror class.
"""

from __future__ import annotations

import pytest

from one_link import crdt as legacy_crdt


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


def _entry(path: str, blob: str | None = "abc", size: int = 1024, mtime: int = 100):
    """Build a legacy ManifestEntry with a simple vclock."""
    return legacy_crdt.ManifestEntry(
        file_path=path,
        blob_hash=blob,
        size=size,
        mtime_ms=mtime,
        vclock=legacy_crdt.VectorClock.from_dict({"alice": 1}),
    )


def test_file_id_stable_across_replicas():
    """Same file_path produces the same file_id on every replica
    (otherwise the OR-set wouldn't collapse cross-replica adds)."""
    from one_link.folder_native import file_id_for_path

    a = file_id_for_path("/share/report.pdf")
    b = file_id_for_path("/share/report.pdf")
    c = file_id_for_path("/share/other.pdf")
    assert a == b
    assert a != c
    assert len(a) == 32


def test_replica_id_normalisation():
    """A 32-byte fingerprint passes through; other lengths are
    BLAKE3-hashed to 32 bytes."""
    from one_link.folder_native import replica_id_for_fingerprint

    fp = b"\x01" * 32
    assert replica_id_for_fingerprint(fp) == fp
    short = b"alice"
    assert len(replica_id_for_fingerprint(short)) == 32
    assert replica_id_for_fingerprint(short) != fp


def test_manifest_entries_to_native_folder():
    from one_link.folder_native import (
        file_id_for_path,
        manifest_entries_to_native_folder,
    )

    entries = [
        _entry("/share/a.pdf"),
        _entry("/share/b.pdf", size=2048, mtime=200),
    ]
    folder = manifest_entries_to_native_folder(entries, replica_id=b"\x01" * 32)
    assert folder.len() == 2
    assert folder.contains(file_id_for_path("/share/a.pdf"))
    assert folder.contains(file_id_for_path("/share/b.pdf"))


def test_tombstone_entries_remove_files():
    from one_link.folder_native import (
        file_id_for_path,
        manifest_entries_to_native_folder,
    )

    entries = [
        _entry("/share/a.pdf"),
        _entry("/share/b.pdf", blob=None),  # tombstone
    ]
    folder = manifest_entries_to_native_folder(entries, replica_id=b"\x01" * 32)
    assert folder.contains(file_id_for_path("/share/a.pdf"))
    assert not folder.contains(file_id_for_path("/share/b.pdf"))


def test_mirror_class_round_trip():
    from one_link.folder_native import NativeManifestMirror

    mirror = NativeManifestMirror(replica_id=b"\x42" * 32)
    mirror.add_entry(_entry("/share/x.pdf"))
    mirror.add_entry(_entry("/share/y.pdf"))
    assert mirror.contains_path("/share/x.pdf")
    assert mirror.contains_path("/share/y.pdf")
    mirror.remove_entry("/share/x.pdf")
    assert not mirror.contains_path("/share/x.pdf")
    assert mirror.contains_path("/share/y.pdf")


def test_two_replicas_merge_lattice_correctly():
    """Lattice-correctness sanity at the adapter level: building two
    Folders from disjoint manifest sets, merging both ways, must
    produce the same final state (commutativity)."""
    from one_link.folder_native import (
        manifest_entries_to_native_folder,
        merge_native_folders,
    )

    alice = manifest_entries_to_native_folder(
        [_entry("/share/a.pdf"), _entry("/share/b.pdf")],
        replica_id=b"\x01" * 32,
    )
    bob = manifest_entries_to_native_folder(
        [_entry("/share/c.pdf"), _entry("/share/d.pdf")],
        replica_id=b"\x02" * 32,
    )

    # Merge bob -> alice.
    a_into = manifest_entries_to_native_folder(
        [_entry("/share/a.pdf"), _entry("/share/b.pdf")],
        replica_id=b"\x01" * 32,
    )
    merge_native_folders(a_into, bob)
    assert a_into.len() == 4

    # Merge alice -> bob. Must reach the same set.
    b_into = manifest_entries_to_native_folder(
        [_entry("/share/c.pdf"), _entry("/share/d.pdf")],
        replica_id=b"\x02" * 32,
    )
    merge_native_folders(b_into, alice)
    assert b_into.len() == 4


def test_idempotent_remerge_via_twin():
    """Idempotency at the adapter level: merging two folders built
    from the SAME manifest produces the same length. (The full
    a == a.merge(a) law is verified at the Rust level by the 1M-iter
    gate; pyo3's borrow rules forbid the literal self-merge.)"""
    from one_link.folder_native import (
        manifest_entries_to_native_folder,
        merge_native_folders,
    )

    alice = manifest_entries_to_native_folder(
        [_entry("/share/a.pdf")], replica_id=b"\x01" * 32
    )
    twin = manifest_entries_to_native_folder(
        [_entry("/share/a.pdf")], replica_id=b"\x01" * 32
    )
    snap_len = alice.len()
    merge_native_folders(alice, twin)
    assert alice.len() == snap_len
