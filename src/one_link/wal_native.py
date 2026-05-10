"""Adapter for the file-engine v2 native crash-only WAL (ol_wal via one_link_native).

Per ADR-0007. Exposes append + flush + rotate + replay with the same
fallback semantics as ``chunk_native`` and ``aead_native``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Literal, Optional

log = logging.getLogger(__name__)

try:
    from one_link_native import wal as _native_wal  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
except ImportError as exc:
    HAS_NATIVE = False
    _native_wal = None  # type: ignore[assignment]
    log.info(
        "one_link_native.wal unavailable (%s); use SQLite or text-log fallbacks "
        "for chat-class workloads. Build via "
        "`cd native && maturin develop --release`.",
        exc,
    )


LogKindStr = Literal["chunk", "manifest"]


FILE_HEADER_LEN: Optional[int] = (
    _native_wal.FILE_HEADER_LEN if HAS_NATIVE else None
)
RECORD_HEADER_LEN: Optional[int] = (
    _native_wal.RECORD_HEADER_LEN if HAS_NATIVE else None
)
RECORD_TRAILER_LEN: Optional[int] = (
    _native_wal.RECORD_TRAILER_LEN if HAS_NATIVE else None
)
MAX_PAYLOAD_LEN: Optional[int] = (
    _native_wal.MAX_PAYLOAD_LEN if HAS_NATIVE else None
)
ROTATION_SIZE: Optional[int] = _native_wal.ROTATION_SIZE if HAS_NATIVE else None


@dataclass(frozen=True)
class WalRecord:
    """A WAL record (kind, flags, payload). Mirrors the native record."""

    kind: int
    flags: int
    payload: bytes


def _record_from_native(rec) -> WalRecord:
    return WalRecord(kind=rec.kind, flags=rec.flags, payload=rec.payload)


def _record_to_native(rec: WalRecord):
    if not HAS_NATIVE:
        raise RuntimeError("one_link_native.wal unavailable")
    return _native_wal.WalRecord(rec.kind, rec.flags, rec.payload)


class Wal:
    """Crash-only WAL writer."""

    __slots__ = ("_inner",)

    def __init__(self, inner) -> None:
        self._inner = inner

    @classmethod
    def create(cls, dir: str, kind: LogKindStr) -> "Wal":
        if not HAS_NATIVE:
            raise RuntimeError("one_link_native.wal unavailable")
        return cls(_native_wal.create(dir, kind))

    @classmethod
    def open(cls, dir: str, kind: LogKindStr) -> "Wal":
        if not HAS_NATIVE:
            raise RuntimeError("one_link_native.wal unavailable")
        return cls(_native_wal.open(dir, kind))

    def append(self, record: WalRecord) -> None:
        self._inner.append(_record_to_native(record))

    def flush(self) -> None:
        self._inner.flush()

    def rotate(self) -> None:
        self._inner.rotate()

    def close(self) -> None:
        self._inner.close()

    def active_file_id(self) -> int:
        return self._inner.active_file_id()

    def active_file_size(self) -> int:
        return self._inner.active_file_size()

    def __enter__(self) -> "Wal":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


def replay_log_dir(dir: str, kind: LogKindStr) -> List[WalRecord]:
    """Replay every WAL file in ``dir`` and return the recovered records.

    Truncates the tail of the last file if the last record's CRC fails
    (the canonical crash-only recovery action).
    """
    if not HAS_NATIVE:
        raise RuntimeError("one_link_native.wal unavailable")
    return [_record_from_native(r) for r in _native_wal.replay_log_dir(dir, kind)]


def log_kind_magic(kind: LogKindStr) -> bytes:
    """Return the 8-byte on-disk magic for the given log kind."""
    if not HAS_NATIVE:
        raise RuntimeError("one_link_native.wal unavailable")
    return _native_wal.log_kind_magic(kind)
