"""CRDT primitives for folder sync.

VectorClock — partial-order causal clocks keyed by peer fingerprint.
Manifest entries — last-writer-wins-by-vector-clock with deterministic
                   tie-break for concurrent updates.

This is a deliberately small implementation. It's API-compatible with
`coherence_lang.bootstrap.runtime.crdt.VectorClock` so we can swap to
that once cross-repo deployment is wired up.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class VectorClock:
    """Immutable vector clock.

    Stored as a sorted tuple of (node_id, counter) pairs so that equal
    clocks compare equal and hash identically.
    """

    entries: tuple[tuple[str, int], ...] = ()

    @classmethod
    def empty(cls) -> "VectorClock":
        return cls(entries=())

    @classmethod
    def from_dict(cls, d: dict[str, int]) -> "VectorClock":
        return cls(entries=tuple(sorted((k, int(v)) for k, v in d.items() if v > 0)))

    def to_dict(self) -> dict[str, int]:
        return dict(self.entries)

    def get(self, node: str) -> int:
        for k, v in self.entries:
            if k == node:
                return v
        return 0

    def increment(self, node: str) -> "VectorClock":
        d = dict(self.entries)
        d[node] = d.get(node, 0) + 1
        return VectorClock(entries=tuple(sorted(d.items())))

    def merge(self, other: "VectorClock") -> "VectorClock":
        """Pointwise max — lattice join."""
        d = dict(self.entries)
        for k, v in other.entries:
            d[k] = max(d.get(k, 0), v)
        return VectorClock(entries=tuple(sorted(d.items())))

    def happens_before(self, other: "VectorClock") -> bool:
        """True iff self < other (strict): every component <=, at least one <."""
        all_nodes = set(dict(self.entries)) | set(dict(other.entries))
        any_strict_less = False
        for n in all_nodes:
            a, b = self.get(n), other.get(n)
            if a > b:
                return False
            if a < b:
                any_strict_less = True
        return any_strict_less

    def concurrent_with(self, other: "VectorClock") -> bool:
        return (
            not self.happens_before(other)
            and not other.happens_before(self)
            and self != other
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VectorClock):
            return NotImplemented
        return self.entries == other.entries

    def __hash__(self) -> int:
        return hash(self.entries)


# ────────────────────── Manifest entry merge ─────────────────────────


@dataclass(frozen=True)
class ManifestEntry:
    """A single file entry in a folder manifest.

    `blob_hash=None` means tombstone (deleted).
    """
    file_path: str
    blob_hash: Optional[str]   # None → deleted
    size: Optional[int]
    mtime_ms: Optional[int]
    vclock: VectorClock

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "blob_hash": self.blob_hash,
            "size": self.size,
            "mtime_ms": self.mtime_ms,
            "vclock": self.vclock.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ManifestEntry":
        return cls(
            file_path=d["file_path"],
            blob_hash=d.get("blob_hash"),
            size=d.get("size"),
            mtime_ms=d.get("mtime_ms"),
            vclock=VectorClock.from_dict(d.get("vclock") or {}),
        )


def merge_manifest_entries(
    local: Optional[ManifestEntry], remote: Optional[ManifestEntry]
) -> Optional[ManifestEntry]:
    """Merge two entries for the same file_path. Returns the winning entry.

    Rules:
      - If only one side has it: that one wins.
      - If `local.vclock < remote.vclock`: remote wins (it observed local).
      - If `remote.vclock < local.vclock`: local wins.
      - If clocks are equal: any same value works; we return local.
      - If concurrent (neither dominates): deterministic tie-break by
        (mtime_ms, blob_hash) — later mtime wins; ties go to the
        lexically larger hash. If both are tombstones, the result is a
        merged-clock tombstone (deletion is monotonic).
    """
    if local is None and remote is None:
        return None
    if local is None:
        return remote
    if remote is None:
        return local
    if local.file_path != remote.file_path:
        raise ValueError("merge_manifest_entries called on different paths")

    if local.vclock == remote.vclock:
        return local
    if local.vclock.happens_before(remote.vclock):
        return remote
    if remote.vclock.happens_before(local.vclock):
        return local

    # Concurrent. Deterministic tie-break.
    merged_clock = local.vclock.merge(remote.vclock)
    # Both tombstones → keep tombstone with merged clock
    if local.blob_hash is None and remote.blob_hash is None:
        return ManifestEntry(
            file_path=local.file_path,
            blob_hash=None,
            size=None,
            mtime_ms=max(local.mtime_ms or 0, remote.mtime_ms or 0),
            vclock=merged_clock,
        )

    # If exactly one is a tombstone, the live entry wins (concurrent edit
    # vs delete: edit wins so user data isn't lost).
    if local.blob_hash is None:
        return ManifestEntry(
            file_path=remote.file_path,
            blob_hash=remote.blob_hash,
            size=remote.size,
            mtime_ms=remote.mtime_ms,
            vclock=merged_clock,
        )
    if remote.blob_hash is None:
        return ManifestEntry(
            file_path=local.file_path,
            blob_hash=local.blob_hash,
            size=local.size,
            mtime_ms=local.mtime_ms,
            vclock=merged_clock,
        )

    # Both live. Tie-break by mtime, then by hash for determinism.
    l_mt = local.mtime_ms or 0
    r_mt = remote.mtime_ms or 0
    if l_mt != r_mt:
        winner = local if l_mt > r_mt else remote
    elif (local.blob_hash or "") >= (remote.blob_hash or ""):
        winner = local
    else:
        winner = remote
    return ManifestEntry(
        file_path=winner.file_path,
        blob_hash=winner.blob_hash,
        size=winner.size,
        mtime_ms=winner.mtime_ms,
        vclock=merged_clock,
    )
