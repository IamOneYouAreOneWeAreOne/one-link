"""Durable transfer intent and manifest planning.

One Link's long-term file engine is not "write bytes to this socket"; it is
"deliver this verified object to this peer/group by the strongest safe route."
This module is the deterministic planning core for that shift.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from .cdc import Chunk, FileIndex, index_path
from .capabilities import FILE_CDC, FILES, LOCAL_CAPABILITIES
from .protocol_compat import CompatibilityResult, fallback_order, negotiate


@dataclass(frozen=True)
class FileChunkManifest:
    index: int
    start: int
    end: int
    size: int
    hash: str

    @classmethod
    def from_chunk(cls, c: Chunk) -> "FileChunkManifest":
        return cls(index=c.index, start=c.start, end=c.end, size=c.size, hash=c.hash)


@dataclass(frozen=True)
class FileManifest:
    name: str
    size: int
    blob_hash: str
    chunks: tuple[FileChunkManifest, ...]
    version: int = 1

    @property
    def chunk_count(self) -> int:
        return len(self.chunks)

    def to_wire(self, *, include_chunks: bool = True) -> dict:
        return {
            "version": self.version,
            "name": self.name,
            "size": self.size,
            "blob": self.blob_hash,
            "chunks": [asdict(c) for c in self.chunks] if include_chunks else [],
        }


@dataclass(frozen=True)
class TransferIntent:
    id: str
    peer_fp: str
    source_path: str
    manifest: FileManifest
    compatibility: CompatibilityResult
    methods: tuple[str, ...]

    @property
    def preferred_method(self) -> str:
        return self.methods[0] if self.methods else "waiting"

    @property
    def can_offer_cdc(self) -> bool:
        # Unknown legacy peers may still be older One Link builds that support
        # FILE_WANTS but did not advertise capabilities yet. Keep CDC available
        # in that mode; the receiver can fall back by ACKing the offer.
        return self.compatibility.supports(FILE_CDC) or self.compatibility.mode == "legacy_unknown"

    def metadata(self) -> dict:
        return {
            "intent_id": self.id,
            "path": self.source_path,
            "manifest": self.manifest.to_wire(include_chunks=True),
            "compatibility": {
                "compatible": self.compatibility.compatible,
                "mode": self.compatibility.mode,
                "transfer_mode": self.compatibility.transfer_mode,
                "fallback_order": list(self.methods),
                "reasons": list(self.compatibility.reasons),
            },
            "preferred_method": self.preferred_method,
        }


def build_file_manifest(path: Path, *, file_index: FileIndex | None = None) -> FileManifest:
    path = Path(path)
    idx = file_index or index_path(path)
    return FileManifest(
        name=path.name,
        size=idx.size,
        blob_hash=idx.blob_hash,
        chunks=tuple(FileChunkManifest.from_chunk(c) for c in idx.chunks),
    )


def plan_transfer_intent(
    *,
    path: Path,
    peer_fp: str,
    local_version: str | None,
    peer_version: str | None,
    peer_capabilities: Iterable[str],
    intent_id: str | None = None,
    file_index: FileIndex | None = None,
) -> TransferIntent:
    manifest = build_file_manifest(path, file_index=file_index)
    return plan_transfer_intent_for_manifest(
        manifest=manifest,
        path=path,
        peer_fp=peer_fp,
        local_version=local_version,
        peer_version=peer_version,
        peer_capabilities=peer_capabilities,
        intent_id=intent_id,
    )


def plan_transfer_intent_for_manifest(
    *,
    manifest: FileManifest,
    path: Path,
    peer_fp: str,
    local_version: str | None,
    peer_version: str | None,
    peer_capabilities: Iterable[str],
    intent_id: str | None = None,
) -> TransferIntent:
    """Plan a transfer from a precomputed or thin manifest.

    The live daemon uses this to negotiate protocol compatibility before it
    spends CPU on a full CDC index. If the receiver lacks CDC, a thin manifest
    with only name/size/blob is enough for the durable baseline stream.
    """

    peer_caps_tuple = tuple(peer_capabilities or ())
    compat = negotiate(
        local_version=local_version,
        peer_version=peer_version,
        local_capabilities=LOCAL_CAPABILITIES,
        peer_capabilities=peer_caps_tuple,
        required=[FILES] if (peer_version is not None or peer_caps_tuple) else [],
    )
    methods = fallback_order(compat)
    if compat.mode == "legacy_unknown" and "file_baseline" not in methods:
        methods = ("file_cdc_probe", "file_baseline")
    elif FILE_CDC in compat.common_capabilities and "file_cdc" not in methods:
        methods = ("file_cdc", *methods)
    id_ = intent_id or f"out:{manifest.blob_hash}"
    return TransferIntent(
        id=id_,
        peer_fp=peer_fp,
        source_path=str(Path(path)),
        manifest=manifest,
        compatibility=compat,
        methods=tuple(methods),
    )
