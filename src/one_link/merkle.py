"""Merkle drift detection for content manifests.

OneField's world-model sync uses a Merkle walk: exchange one root digest,
then descend only into ranges whose hashes differ. One Link can use the same
primitive for folder manifests, blob indexes, and future group state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

import blake3


EMPTY_HASH = blake3.blake3(b"").hexdigest()


@dataclass(frozen=True)
class MerkleTree:
    """A flat binary Merkle tree with deterministic padding."""

    leaves: tuple[str, ...]
    levels: tuple[tuple[str, ...], ...]

    @property
    def root(self) -> str:
        return self.levels[-1][0] if self.levels else EMPTY_HASH

    @property
    def leaf_count(self) -> int:
        return len(self.leaves)


def hash_leaf(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return blake3.blake3(b"leaf\x00" + value).hexdigest()


def hash_pair(left: str, right: str) -> str:
    return blake3.blake3(
        b"node\x00" + bytes.fromhex(left) + bytes.fromhex(right)
    ).hexdigest()


def build_tree(leaf_hashes: Iterable[str]) -> MerkleTree:
    leaves = tuple(_validate_hash(h) for h in leaf_hashes)
    if not leaves:
        return MerkleTree(leaves=(), levels=())

    level = leaves
    levels = [level]
    while len(level) > 1:
        if len(level) % 2:
            level = level + (level[-1],)
        level = tuple(hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2))
        levels.append(level)
    return MerkleTree(leaves=leaves, levels=tuple(levels))


def divergent_leaf_indexes(local: MerkleTree, remote: MerkleTree) -> tuple[int, ...]:
    """Return leaf positions whose digests differ between two trees."""

    max_len = max(local.leaf_count, remote.leaf_count)
    out: list[int] = []
    for i in range(max_len):
        a = local.leaves[i] if i < local.leaf_count else None
        b = remote.leaves[i] if i < remote.leaf_count else None
        if a != b:
            out.append(i)
    return tuple(out)


def manifest_leaf_hashes(items: Sequence[tuple[str, str, int]]) -> tuple[str, ...]:
    """Hash sorted manifest rows of (path, blob_hash, size)."""

    rows = []
    for path, blob_hash, size in items:
        rows.append(f"{path}\x00{blob_hash}\x00{int(size)}")
    return tuple(hash_leaf(row) for row in sorted(rows))


def _validate_hash(h: str) -> str:
    if len(h) != 64:
        raise ValueError(f"Merkle hash must be 64 hex chars, got {len(h)}")
    int(h, 16)
    return h.lower()
