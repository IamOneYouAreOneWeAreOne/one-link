"""Phase C-3 daemon migration: native CRDT folder adapter (ADR-0022).

Bridges the daemon's legacy ``crdt.py`` Python ``ManifestEntry`` /
``VectorClock`` types to ``one_link_native.crdt.Folder``, the native
add-wins OR-set + vector clock + LWW composition.

Same posture as the other Phase C-3 migrations: the legacy Python
path stays untouched; this module provides a NATIVE-backed
manifest representation that callers can use for:

  - Lattice-correct merges across replicas (commutative + associative
    + idempotent, verified by the 1M-iter ``ol_crdt`` acceptance gate).
  - Sub-millisecond merge cost at typical share-folder sizes (203 us
    at 1000 files per the ``ol_crdt`` criterion benches).
  - A future cutover when ``foldersync.py`` is rewritten to source
    from the native type directly.

Translation:

  - Each ``ManifestEntry`` (file_path, blob_hash, size, mtime_ms,
    vclock) maps to a native ``Folder.add_file(replica, file_id,
    display_name, size_bytes, last_modified_ms)`` call.
  - ``file_id`` is derived as ``BLAKE3(file_path)[:32]`` — stable
    across replicas so the OR-set collapses to one entry per file.
  - ``replica`` is the local device's 32-byte fingerprint, supplied
    by the caller (typically the channel's pair-identity hash).
  - Tombstones (``blob_hash is None``) become ``remove_file`` calls.

The legacy ``vclock`` field becomes informational only — the native
Folder maintains its own vector clock and is the lattice
authority for merge ordering.
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Optional

from . import crdt as legacy_crdt
from . import crdt_native


def file_id_for_path(file_path: str) -> bytes:
    """Stable 32-byte id for a file path. Same path on every replica
    produces the same id so OR-set entries collapse correctly."""
    try:
        import blake3  # type: ignore[import-not-found]

        return blake3.blake3(file_path.encode("utf-8")).digest()
    except ImportError:
        return hashlib.sha256(file_path.encode("utf-8")).digest()


def replica_id_for_fingerprint(peer_fingerprint: bytes) -> bytes:
    """Take a peer fingerprint (any length) and produce a 32-byte
    ReplicaId. We BLAKE3 (or SHA-256 fallback) the input."""
    if len(peer_fingerprint) == 32:
        return peer_fingerprint
    try:
        import blake3  # type: ignore[import-not-found]

        return blake3.blake3(peer_fingerprint).digest()
    except ImportError:
        return hashlib.sha256(peer_fingerprint).digest()


def manifest_entries_to_native_folder(
    entries: Iterable[legacy_crdt.ManifestEntry],
    *,
    replica_id: bytes,
) -> "crdt_native._native_crdt.Folder":  # type: ignore[name-defined]
    """Convert a legacy manifest into a native :class:`Folder`.

    ``replica_id`` is the 32-byte fingerprint of the device producing
    this manifest. Entries with ``blob_hash is None`` (tombstones)
    are followed by an immediate ``remove_file`` so the native
    Folder reflects the deletion."""
    folder = crdt_native.folder()
    rid = replica_id_for_fingerprint(replica_id)
    for entry in entries:
        fid = file_id_for_path(entry.file_path)
        size = int(entry.size or 0)
        mtime = int(entry.mtime_ms or 0)
        folder.add_file(rid, fid, entry.file_path, size, mtime)
        if entry.blob_hash is None:
            folder.remove_file(rid, fid)
    return folder


def native_folder_present_entries(folder) -> tuple[tuple[bytes, str, int, int], ...]:
    """Return the currently-present (file_id, display_name, size,
    mtime_ms) tuples from a native folder. Skips tombstoned files
    automatically (the OR-set handles that)."""
    return tuple(folder.entries())


def merge_native_folders(local, remote) -> None:
    """Merge ``remote`` into ``local`` in place. Lattice-correct by
    construction (commutative + associative + idempotent — see
    :func:`ol_crdt::Folder::merge`)."""
    local.merge(remote)


class NativeManifestMirror:
    """In-process mirror that keeps a native :class:`Folder` in sync
    with the daemon's legacy manifest table.

    Wire this into the daemon as a no-op observer first: every
    ``add_entry`` / ``remove_entry`` is mirrored to the native side.
    Once the native side has been running in production long enough
    to gain operator confidence, the legacy table is removed and
    the mirror becomes authoritative.

    Until then, callers can ``snapshot()`` the native folder for
    lattice-correct merge ops without touching the legacy data
    path.
    """

    def __init__(self, replica_id: bytes) -> None:
        self._rid = replica_id_for_fingerprint(replica_id)
        self._folder = crdt_native.folder()

    @property
    def replica_id(self) -> bytes:
        return self._rid

    def add_entry(self, entry: legacy_crdt.ManifestEntry) -> None:
        fid = file_id_for_path(entry.file_path)
        self._folder.add_file(
            self._rid,
            fid,
            entry.file_path,
            int(entry.size or 0),
            int(entry.mtime_ms or 0),
        )

    def remove_entry(self, file_path: str) -> None:
        fid = file_id_for_path(file_path)
        self._folder.remove_file(self._rid, fid)

    def contains_path(self, file_path: str) -> bool:
        return self._folder.contains(file_path_to_id(file_path))

    def snapshot(self):
        """Return the underlying native folder. Callers can ``merge``
        a remote into a copy for lattice operations."""
        return self._folder

    def merge_from(self, remote_folder) -> None:
        self._folder.merge(remote_folder)


def file_path_to_id(file_path: str) -> bytes:
    """Public alias for :func:`file_id_for_path` — exposed for use
    by callers that interact with the native Folder directly."""
    return file_id_for_path(file_path)
