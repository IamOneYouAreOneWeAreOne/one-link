"""Adapter for the file-engine v2 native chunk store (ol_chunk_store via one_link_native).

Per ADR-0003 + ADR-0005. Surfaces the integrating chunk store: write +
manifest + flush + has + locate + read. This is what the daemon swaps in
to replace the legacy ``blobstore.py``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal, Optional

log = logging.getLogger(__name__)

try:
    from one_link_native import store as _native_store  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
except ImportError as exc:
    HAS_NATIVE = False
    _native_store = None  # type: ignore[assignment]
    log.info(
        "one_link_native.store unavailable (%s); legacy blobstore.py remains in use. "
        "Build via `cd native && maturin develop --release`.",
        exc,
    )


ChunkRecordKindStr = Literal["blob", "parity", "tombstone"]
ChunkAddressKindStr = Literal["raw", "convergent"]
ChunkAeadKindStr = Literal["aes", "chacha"]
ManifestRecordKindStr = Literal[
    "manifest_version",
    "manifest",
    "capability_grant",
    "grant",
    "capability_revoke",
    "revoke",
    "merkle_revocation",
    "share_link",
    "sentinel",
]
StripeRoleStr = Literal["data", "parity", "not_striped"]


CHUNK_RECORD_HEADER_LEN: Optional[int] = (
    _native_store.CHUNK_RECORD_HEADER_LEN if HAS_NATIVE else None
)
MANIFEST_RECORD_HEADER_LEN: Optional[int] = (
    _native_store.MANIFEST_RECORD_HEADER_LEN if HAS_NATIVE else None
)
STRIPE_DESCRIPTOR_LEN: Optional[int] = (
    _native_store.STRIPE_DESCRIPTOR_LEN if HAS_NATIVE else None
)


@dataclass(frozen=True)
class StoreStats:
    indexed_chunks: int
    manifest_records: int
    bytes_scanned_at_replay: int
    files_truncated: int
    orphaned_manifest_records: int


class ChunkStore:
    """Pythonic wrapper around the native chunk store handle."""

    __slots__ = ("_inner",)

    def __init__(self, inner) -> None:
        self._inner = inner

    @classmethod
    def open(cls, root: str) -> "ChunkStore":
        if not HAS_NATIVE:
            raise RuntimeError(
                "one_link_native is not installed; build via "
                "`cd native && maturin develop --release`"
            )
        return cls(_native_store.open_store(root))

    def append_chunk(
        self,
        chunk_id: bytes,
        ratchet_key_id: bytes,
        length_plaintext: int,
        ciphertext: bytes,
        *,
        record_kind: ChunkRecordKindStr = "blob",
        address_kind: ChunkAddressKindStr = "raw",
        aead_kind: ChunkAeadKindStr = "aes",
        compressed: bool = False,
        format_aware: bool = False,
        stripe=None,
    ) -> int:
        """Append a chunk record. Returns the offset within the active chunk_log file."""
        return self._inner.append_chunk(
            record_kind,
            address_kind,
            aead_kind,
            chunk_id,
            ratchet_key_id,
            length_plaintext,
            ciphertext,
            compressed,
            format_aware,
            stripe,
        )

    def append_manifest(
        self,
        record_kind: ManifestRecordKindStr,
        hlc_timestamp: int,
        actor_id: bytes,
        body: bytes,
        *,
        flags: int = 0,
        chunk_log_anchor: int = 0,
    ) -> None:
        """Append a manifest record. ``chunk_log_anchor=0`` lets the store
        auto-set it to the most-recent chunk_log offset (ADR-0005)."""
        self._inner.append_manifest(
            record_kind, hlc_timestamp, actor_id, body, flags, chunk_log_anchor
        )

    def flush(self) -> None:
        self._inner.flush()

    def has_chunk(self, chunk_id: bytes) -> bool:
        return self._inner.has_chunk(chunk_id)

    def locate_chunk(self, chunk_id: bytes):
        """Return the chunk's :class:`ChunkLocation` or ``None``."""
        return self._inner.locate_chunk(chunk_id)

    def read_chunk(self, chunk_id: bytes):
        """Return the full chunk record (header + ciphertext)."""
        return self._inner.read_chunk(chunk_id)

    def stats(self) -> StoreStats:
        d = self._inner.stats()
        return StoreStats(
            indexed_chunks=d["indexed_chunks"],
            manifest_records=d["manifest_records"],
            bytes_scanned_at_replay=d["bytes_scanned_at_replay"],
            files_truncated=d["files_truncated"],
            orphaned_manifest_records=d["orphaned_manifest_records"],
        )

    def close(self) -> None:
        self._inner.close()

    def __enter__(self) -> "ChunkStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
