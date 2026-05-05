"""Content-defined chunking and dedup planning.

This is the One Link Python mirror of the OneField CDC-dedup transport
kernel. It does not change the wire protocol by itself; it gives folder sync
and future file transfer a deterministic way to split related files so peers
can exchange "which chunks do you already have?" before sending bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import blake3


MIN_CHUNK_BYTES = 16 * 1024
AVG_CHUNK_BYTES = 64 * 1024
MAX_CHUNK_BYTES = 256 * 1024
ROLLING_WINDOW_BYTES = 64

_MASK_64 = (1 << 64) - 1
_GEAR = tuple(
    int.from_bytes(blake3.blake3(bytes([i])).digest(length=8), "little")
    for i in range(256)
)


@dataclass(frozen=True)
class Chunk:
    """A content-defined byte range and its BLAKE3 digest."""

    index: int
    start: int
    end: int
    hash: str

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(frozen=True)
class DedupPlan:
    """Which chunks need to cross the wire for a receiver's known hash set."""

    total_chunks: int
    missing_chunks: tuple[Chunk, ...]
    total_bytes: int
    bytes_to_send: int

    @property
    def hit_rate(self) -> float:
        if self.total_chunks == 0:
            return 0.0
        return 1.0 - (len(self.missing_chunks) / self.total_chunks)

    @property
    def byte_savings(self) -> int:
        return self.total_bytes - self.bytes_to_send


def _rotl64(value: int, shift: int) -> int:
    shift &= 63
    return ((value << shift) | (value >> (64 - shift))) & _MASK_64


def _roll(rolling: int, incoming: int, outgoing: int | None) -> int:
    rolling = _rotl64(rolling, 1) ^ _GEAR[incoming]
    if outgoing is not None:
        rolling ^= _rotl64(_GEAR[outgoing], ROLLING_WINDOW_BYTES)
    return rolling & _MASK_64


def _should_cut(chunk_len: int, rolling_hash: int) -> bool:
    if chunk_len < MIN_CHUNK_BYTES:
        return False
    if chunk_len >= MAX_CHUNK_BYTES:
        return True
    return (rolling_hash % AVG_CHUNK_BYTES) == 0


def chunk_bytes(data: bytes) -> tuple[Chunk, ...]:
    """Split bytes into deterministic content-defined chunks.

    Boundaries depend on content, not offset, so inserting bytes near the
    front of a file only shifts nearby chunks instead of invalidating the
    entire tail.
    """

    chunks: list[Chunk] = []
    start = 0
    rolling = 0
    window: list[int] = []

    for pos, b in enumerate(data):
        outgoing = None
        if len(window) >= ROLLING_WINDOW_BYTES:
            outgoing = window.pop(0)
        window.append(b)
        rolling = _roll(rolling, b, outgoing)

        end = pos + 1
        if _should_cut(end - start, rolling):
            chunks.append(_make_chunk(len(chunks), start, end, data))
            start = end
            rolling = 0
            window.clear()

    if start < len(data) or not chunks:
        chunks.append(_make_chunk(len(chunks), start, len(data), data))
    return tuple(chunks)


def chunk_path(path: Path, *, read_size: int = 1024 * 1024) -> tuple[Chunk, ...]:
    """Chunk a file from disk. Reads incrementally, then hashes ranges.

    The current implementation keeps file bytes in memory for simplicity and
    deterministic testing. It is isolated here so the future streaming variant
    can land without touching callers.
    """

    hunk = bytearray()
    with open(path, "rb") as f:
        for part in iter(lambda: f.read(read_size), b""):
            hunk.extend(part)
    return chunk_bytes(bytes(hunk))


def build_dedup_plan(chunks: Iterable[Chunk], receiver_hashes: set[str]) -> DedupPlan:
    materialized = tuple(chunks)
    missing = tuple(c for c in materialized if c.hash not in receiver_hashes)
    return DedupPlan(
        total_chunks=len(materialized),
        missing_chunks=missing,
        total_bytes=sum(c.size for c in materialized),
        bytes_to_send=sum(c.size for c in missing),
    )


def _make_chunk(index: int, start: int, end: int, data: bytes) -> Chunk:
    return Chunk(
        index=index,
        start=start,
        end=end,
        hash=blake3.blake3(data[start:end]).hexdigest(),
    )
