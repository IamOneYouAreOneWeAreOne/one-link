"""Capsule store — serialize, seal, persist, recover.

Wraps the at-rest encryption layer (:mod:`capsule_at_rest`) around
the AsyncCapsule serializer. The daemon's CallManager finalizes a
capsule on async-conversion; this module persists it to disk in
sealed form. Playback re-opens it with the same key.

Wire format inside the seal:
  - Header dict (JSON) with all the capsule scalar fields
  - 4-byte length prefix
  - Audio payload bytes
  - 4-byte length prefix
  - Provenance chain encoded as a JSON array of wire dicts

The whole sequence is fed to ``seal_to_path`` so an attacker with
the device can't read header / audio / provenance without the key.

Pure module: no daemon imports. The daemon's call_manager bridge
calls ``save_sealed_capsule`` on finalization + ``load_sealed_capsule``
on playback.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md Part 14.1 (C5),
           src/one_link/capsule_at_rest.py
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sqlite3
import stat
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional, Protocol

import blake3

from one_link.async_capsule import (
    MAX_CAPSULE_BYTES,
    MAX_CAPSULE_PROVENANCE_ENTRIES,
    AsyncCapsule,
    CapsuleKind,
)
from one_link.capsule_at_rest import (
    MAX_SEALED_PLAINTEXT_BYTES,
    open_from_path,
    seal_to_path,
)
from one_link.frame_provenance import (
    from_wire_dict,
    to_wire_dict,
)


MAX_CAPSULE_HEADER_BYTES = 64 * 1024
MAX_CAPSULE_PROVENANCE_BYTES = 12 * 1024 * 1024
CAPSULE_PLAINTEXT_SCHEMA_VERSION = 2
CAPSULE_KEY_FILENAME = "capsule-master-key.bin"
CAPSULE_DB_FILENAME = "capsules.sqlite3"
CAPSULE_SEALED_DIRNAME = "sealed"
CAPSULE_QUARANTINE_DIRNAME = "quarantine"
MAX_CAPSULE_DELIVERY_ATTEMPTS_QUERY = 64
MAX_CAPSULE_ERROR_CHARS = 320
MAX_SQLITE_TIMESTAMP_MS = 2**63 - 1
_CAPSULE_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_CALL_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


class CapsuleStoreError(RuntimeError):
    """Base class for durable capsule-store failures."""


class CapsuleConflictError(CapsuleStoreError):
    """A capsule id was replayed with different authenticated content."""


class CapsuleNotFoundError(CapsuleStoreError):
    """A requested capsule is not present in the durable index."""


class _LockBox(Protocol):
    def wrap(self, plaintext: bytes) -> bytes: ...
    def unwrap(self, blob: bytes) -> bytes: ...


def _is_link_or_reparse(path: Path, st: Optional[os.stat_result] = None) -> bool:
    """Recognize POSIX links and Windows junction/reparse indirections."""

    observed = path.lstat() if st is None else st
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    attributes = int(getattr(observed, "st_file_attributes", 0))
    return stat.S_ISLNK(observed.st_mode) or (
        os.name == "nt" and bool(attributes & reparse_flag)
    )


def _read_bounded_regular_file(path: Path, *, max_bytes: int) -> bytes:
    before = path.lstat()
    if _is_link_or_reparse(path, before) or not stat.S_ISREG(before.st_mode):
        raise CapsuleStoreError("capsule key path is not a regular file")
    if not (1 <= before.st_size <= max_bytes):
        raise CapsuleStoreError("capsule key envelope has invalid size")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(str(path), flags)
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or int(opened.st_size) != int(before.st_size)
            or int(getattr(opened, "st_dev", 0))
            != int(getattr(before, "st_dev", 0))
            or int(getattr(opened, "st_ino", 0))
            != int(getattr(before, "st_ino", 0))
        ):
            raise CapsuleStoreError("capsule key changed while opening")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            payload = handle.read(max_bytes + 1)
        after = os.fstat(fd)
        if (
            len(payload) != int(opened.st_size)
            or len(payload) > max_bytes
            or int(after.st_size) != int(opened.st_size)
            or int(getattr(after, "st_mtime_ns", 0))
            != int(getattr(opened, "st_mtime_ns", 0))
            or int(getattr(after, "st_ctime_ns", 0))
            != int(getattr(opened, "st_ctime_ns", 0))
        ):
            raise CapsuleStoreError("capsule key changed while reading")
        return payload
    finally:
        os.close(fd)


def _strict_json_object(raw: bytes, *, label: str) -> dict:
    def _pairs(pairs: list[tuple[str, object]]) -> dict:
        out: dict = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"{label} contains duplicate key {key!r}")
            out[key] = value
        return out

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _strict_json_array(raw: bytes, *, label: str) -> list:
    def _pairs(pairs: list[tuple[str, object]]) -> dict:
        out: dict = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"{label} contains duplicate key {key!r}")
            out[key] = value
        return out

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    return value


def _validate_peer_fingerprint(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise ValueError("peer fingerprint must be 64 lowercase hex characters")
    return value


def _coerce_timestamp_ms(value: Optional[int], *, field_name: str) -> int:
    stamp = int(time.time() * 1000) if value is None else value
    if (
        isinstance(stamp, bool)
        or not isinstance(stamp, int)
        or not (0 <= stamp <= MAX_SQLITE_TIMESTAMP_MS)
    ):
        raise ValueError(f"{field_name} must be a non-negative 63-bit integer")
    return stamp


def _validate_capsule_contract(capsule: AsyncCapsule) -> None:
    if _CAPSULE_ID_RE.fullmatch(capsule.capsule_id) is None:
        raise ValueError("capsule_id is not wire-safe")
    if _CALL_ID_RE.fullmatch(capsule.call_id) is None:
        raise ValueError("call_id is not wire-safe")
    _validate_peer_fingerprint(capsule.sender_master_vk_hex)
    _validate_peer_fingerprint(capsule.recipient_master_vk_hex)
    if not (
        0 <= capsule.started_at_ms <= capsule.finalized_at_ms <= 2**63 - 1
    ):
        raise ValueError("capsule capture timestamps are inconsistent")
    if capsule.duration_ms > capsule.finalized_at_ms - capsule.started_at_ms:
        raise ValueError("capsule duration exceeds capture interval")
    if not (
        capsule.finalized_at_ms
        <= capsule.resumable_until_ms
        <= 2**63 - 1
    ):
        raise ValueError("capsule resume window is inconsistent")


def _fsync_parent(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
    fd = os.open(str(path.parent), flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _restrict_private_path(path: Path, mode: int) -> None:
    if os.name != "nt":
        try:
            os.chmod(path, mode)
        except OSError as exc:
            raise CapsuleStoreError(
                f"capsule path permissions could not be restricted: {path.name}"
            ) from exc


def _atomic_private_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_BINARY", 0))
    fd = os.open(str(tmp), flags, 0o600)
    try:
        view = memoryview(payload)
        pos = 0
        while pos < len(view):
            count = os.write(fd, view[pos:])
            if count <= 0:
                raise OSError("short write")
            pos += count
        os.fsync(fd)
    except BaseException:
        try:
            os.close(fd)
        finally:
            try:
                tmp.unlink()
            except OSError:
                pass
        raise
    else:
        os.close(fd)
    try:
        os.replace(tmp, path)
        if os.name != "nt":
            os.chmod(path, 0o600)
        _fsync_parent(path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def load_or_create_capsule_master_seed(
    data_root: Path,
    lockbox: _LockBox,
) -> bytes:
    """Load the stable capsule AEAD root, wrapped by the install LockBox.

    Existing-but-corrupt state fails closed.  Silently minting a replacement
    would make every previously stored capsule permanently unreadable while
    pretending startup succeeded.
    """

    path = Path(data_root) / CAPSULE_KEY_FILENAME
    if path.exists() or path.is_symlink():
        try:
            key = lockbox.unwrap(_read_bounded_regular_file(path, max_bytes=4096))
        except CapsuleStoreError:
            raise
        except Exception as exc:
            raise CapsuleStoreError("capsule key envelope could not be opened") from exc
        if len(key) != 32:
            raise CapsuleStoreError("capsule key has invalid length")
        return key

    key = secrets.token_bytes(32)
    try:
        envelope = lockbox.wrap(key)
        _atomic_private_write(path, envelope)
    except Exception as exc:
        raise CapsuleStoreError("capsule key could not be persisted") from exc
    return key


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def serialize_capsule(capsule: AsyncCapsule) -> bytes:
    """Pack an AsyncCapsule into its sealed-plaintext form. Inverse of
    :func:`deserialize_capsule`."""
    _validate_capsule_contract(capsule)
    header = {
        "schema_version": CAPSULE_PLAINTEXT_SCHEMA_VERSION,
        "capsule_id": capsule.capsule_id,
        "call_id": capsule.call_id,
        "kind": int(capsule.kind),
        "sender_master_vk_hex": capsule.sender_master_vk_hex,
        "recipient_master_vk_hex": capsule.recipient_master_vk_hex,
        "started_at_ms": capsule.started_at_ms,
        "finalized_at_ms": capsule.finalized_at_ms,
        "duration_ms": capsule.duration_ms,
        "audio_codec": capsule.audio_codec,
        "sample_rate_hz": capsule.sample_rate_hz,
        "provenance_segment_sizes": list(capsule.provenance_segment_sizes),
        "recording_state_at_conversion": int(capsule.recording_state_at_conversion),
        "resumable_until_ms": capsule.resumable_until_ms,
        "payload_hash": capsule.payload_hash,
    }
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    prov_list = [to_wire_dict(p) for p in capsule.provenance_chain]
    prov_bytes = json.dumps(prov_list, separators=(",", ":")).encode("utf-8")
    if len(header_bytes) > MAX_CAPSULE_HEADER_BYTES:
        raise ValueError("capsule header exceeds size limit")
    if len(prov_bytes) > MAX_CAPSULE_PROVENANCE_BYTES:
        raise ValueError("capsule provenance exceeds size limit")
    packed = (
        struct.pack("!I", len(header_bytes))
        + header_bytes
        + struct.pack("!I", len(capsule.audio_payload))
        + capsule.audio_payload
        + struct.pack("!I", len(prov_bytes))
        + prov_bytes
    )
    if len(packed) > MAX_SEALED_PLAINTEXT_BYTES:
        raise ValueError("serialized capsule exceeds sealed size limit")
    return packed


def deserialize_capsule(data: bytes) -> AsyncCapsule:
    """Unpack a sealed-plaintext capsule blob back into the
    dataclass. Raises ValueError on malformed input."""
    if not isinstance(data, bytes):
        raise TypeError("capsule blob must be bytes")
    if len(data) > MAX_SEALED_PLAINTEXT_BYTES:
        raise ValueError("capsule blob exceeds size limit")
    pos = 0
    if len(data) < 4:
        raise ValueError("capsule blob truncated at header length")
    (header_len,) = struct.unpack("!I", data[pos:pos + 4])
    pos += 4
    if header_len > MAX_CAPSULE_HEADER_BYTES:
        raise ValueError("capsule header length exceeds limit")
    if pos + header_len > len(data):
        raise ValueError("capsule blob truncated at header body")
    header = _strict_json_object(
        data[pos:pos + header_len],
        label="capsule header",
    )
    expected_header_fields = {
        "schema_version",
        "capsule_id",
        "call_id",
        "kind",
        "sender_master_vk_hex",
        "recipient_master_vk_hex",
        "started_at_ms",
        "finalized_at_ms",
        "duration_ms",
        "audio_codec",
        "sample_rate_hz",
        "provenance_segment_sizes",
        "recording_state_at_conversion",
        "resumable_until_ms",
        "payload_hash",
    }
    if set(header) != expected_header_fields:
        raise ValueError("capsule header fields do not match schema")
    if (
        isinstance(header["schema_version"], bool)
        or not isinstance(header["schema_version"], int)
        or header["schema_version"] != CAPSULE_PLAINTEXT_SCHEMA_VERSION
    ):
        raise ValueError("unsupported capsule plaintext schema version")
    pos += header_len

    if pos + 4 > len(data):
        raise ValueError("capsule blob truncated at audio length")
    (audio_len,) = struct.unpack("!I", data[pos:pos + 4])
    pos += 4
    if audio_len > MAX_CAPSULE_BYTES:
        raise ValueError("capsule audio length exceeds limit")
    if pos + audio_len > len(data):
        raise ValueError("capsule blob truncated at audio body")
    audio = data[pos:pos + audio_len]
    pos += audio_len

    if pos + 4 > len(data):
        raise ValueError("capsule blob truncated at provenance length")
    (prov_len,) = struct.unpack("!I", data[pos:pos + 4])
    pos += 4
    if prov_len > MAX_CAPSULE_PROVENANCE_BYTES:
        raise ValueError("capsule provenance length exceeds limit")
    if pos + prov_len > len(data):
        raise ValueError("capsule blob truncated at provenance body")
    prov_list = _strict_json_array(
        data[pos:pos + prov_len],
        label="capsule provenance",
    )
    if len(prov_list) > MAX_CAPSULE_PROVENANCE_ENTRIES:
        raise ValueError("capsule provenance entry count exceeds limit")
    pos += prov_len

    if pos != len(data):
        raise ValueError(
            f"capsule blob has {len(data) - pos} trailing bytes",
        )

    from one_link.frame_provenance import RecordingState
    for field_name in (
        "kind",
        "started_at_ms",
        "finalized_at_ms",
        "duration_ms",
        "sample_rate_hz",
        "recording_state_at_conversion",
        "resumable_until_ms",
    ):
        value = header[field_name]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"capsule header {field_name} must be an integer")
    raw_segment_sizes = header["provenance_segment_sizes"]
    if not isinstance(raw_segment_sizes, list):
        raise ValueError("capsule header provenance_segment_sizes must be an array")
    if len(raw_segment_sizes) > MAX_CAPSULE_PROVENANCE_ENTRIES:
        raise ValueError("capsule provenance segment count exceeds limit")
    for segment_size in raw_segment_sizes:
        if isinstance(segment_size, bool) or not isinstance(segment_size, int):
            raise ValueError("capsule provenance segment size must be an integer")
    capsule = AsyncCapsule(
        capsule_id=header["capsule_id"],
        call_id=header["call_id"],
        kind=CapsuleKind(header["kind"]),
        sender_master_vk_hex=header["sender_master_vk_hex"],
        recipient_master_vk_hex=header["recipient_master_vk_hex"],
        started_at_ms=header["started_at_ms"],
        finalized_at_ms=header["finalized_at_ms"],
        duration_ms=header["duration_ms"],
        audio_payload=audio,
        audio_codec=header["audio_codec"],
        sample_rate_hz=header["sample_rate_hz"],
        provenance_chain=tuple(from_wire_dict(d) for d in prov_list),
        provenance_segment_sizes=tuple(raw_segment_sizes),
        recording_state_at_conversion=RecordingState(
            header["recording_state_at_conversion"]
        ),
        resumable_until_ms=header["resumable_until_ms"],
        payload_hash=header["payload_hash"],
    )
    _validate_capsule_contract(capsule)
    return capsule


# ---------------------------------------------------------------------------
# Sealed save / load
# ---------------------------------------------------------------------------

def save_sealed_capsule(
    *,
    capsule: AsyncCapsule,
    out_path: Path,
    master_seed: bytes,
) -> None:
    """Serialize + seal + atomically write to disk. The seal binds
    to ``capsule.call_id`` and ``capsule.finalized_at_ms`` so even
    on the same device a different call's seal can't be replayed."""
    plaintext = serialize_capsule(capsule)
    seal_to_path(
        plaintext=plaintext, out_path=out_path,
        master_seed=master_seed,
        call_id=capsule.call_id,
        finalized_at_ms=capsule.finalized_at_ms,
    )


def load_sealed_capsule(
    *,
    sealed_path: Path,
    master_seed: bytes,
    call_id: str,
    finalized_at_ms: int,
) -> AsyncCapsule:
    """Decrypt + deserialize. The caller must supply ``call_id`` and
    ``finalized_at_ms`` separately (they're in the sealed plaintext,
    but also serve as the AAD — so the caller needs them out-of-band
    to derive the key in the first place).

    The daemon's capsule index stores (call_id, finalized_at_ms) in
    plain SQLite next to the sealed-path reference; the sealed body
    holds the actual capsule content.
    """
    plaintext = open_from_path(
        sealed_path=sealed_path,
        master_seed=master_seed,
        call_id=call_id,
        finalized_at_ms=finalized_at_ms,
    )
    return deserialize_capsule(plaintext)


# ---------------------------------------------------------------------------
# Index helpers — what the daemon stores out-of-band
# ---------------------------------------------------------------------------

def capsule_index_entry(capsule: AsyncCapsule, sealed_path: Path) -> dict:
    """The plaintext metadata the daemon stores in its capsule index
    so it can find + decrypt a capsule later. No secrets here; an
    attacker who steals the index alone still cannot read capsule
    audio / provenance without the master_seed.

    Doctrine §3.2.e — the surface labels stay positive: ``label``
    holds the human-friendly text the chat list will show."""
    from one_link.async_capsule import capsule_label
    return {
        "capsule_id": capsule.capsule_id,
        "call_id": capsule.call_id,
        "finalized_at_ms": capsule.finalized_at_ms,
        "duration_ms": capsule.duration_ms,
        "size_bytes": capsule.size_bytes(),
        "kind": int(capsule.kind),
        "sealed_path": str(sealed_path),
        "label": capsule_label(capsule.kind),
        "resumable_until_ms": capsule.resumable_until_ms,
    }


# ---------------------------------------------------------------------------
# Durable repository and delivery outbox
# ---------------------------------------------------------------------------

CapsuleDirection = Literal["outbound", "inbound"]
CapsuleStatus = Literal["staging", "pending", "delivered", "received"]


@dataclass(frozen=True)
class CapsuleRecord:
    capsule_id: str
    peer_fp: str
    direction: CapsuleDirection
    call_id: str
    finalized_at_ms: int
    payload_hash: str
    content_hash: str
    sealed_name: str
    status: CapsuleStatus
    attempts: int
    next_attempt_ms: int
    created_at_ms: int
    updated_at_ms: int
    delivered_at_ms: Optional[int]
    last_error: str


class CapsuleRepository:
    """Crash-consistent encrypted capsule store plus durable send outbox.

    The sealed file is committed before a row leaves ``staging``.  A restart
    reconciles interrupted staging rows, and a sender is marked delivered only
    by an exact peer-bound receipt, never merely because TCP returned an ACK.
    """

    def __init__(self, root: Path, *, master_seed: bytes) -> None:
        if not isinstance(master_seed, bytes) or len(master_seed) < 32:
            raise ValueError("master_seed must be at least 32 bytes")
        self.root = Path(root)
        if self.root.exists() or self.root.is_symlink():
            root_stat = self.root.lstat()
            if (
                _is_link_or_reparse(self.root, root_stat)
                or not stat.S_ISDIR(root_stat.st_mode)
            ):
                raise CapsuleStoreError("capsule root is not a regular directory")
        self.root.mkdir(parents=True, exist_ok=True)
        _restrict_private_path(self.root, 0o700)
        self.sealed_root = self.root / CAPSULE_SEALED_DIRNAME
        self.sealed_root.mkdir(parents=True, exist_ok=True)
        sealed_root_stat = self.sealed_root.lstat()
        if (
            _is_link_or_reparse(self.sealed_root, sealed_root_stat)
            or not stat.S_ISDIR(sealed_root_stat.st_mode)
        ):
            raise CapsuleStoreError("capsule sealed root must not be a symlink")
        _restrict_private_path(self.sealed_root, 0o700)
        self._master_seed = bytes(master_seed)
        self._lock = threading.RLock()
        db_path = self.root / CAPSULE_DB_FILENAME
        if db_path.exists() or db_path.is_symlink():
            db_stat = db_path.lstat()
            if _is_link_or_reparse(db_path, db_stat) or not stat.S_ISREG(db_stat.st_mode):
                raise CapsuleStoreError("capsule index is not a regular file")
        self._db = sqlite3.connect(
            str(db_path),
            timeout=10.0,
            isolation_level=None,
            check_same_thread=False,
        )
        try:
            _restrict_private_path(db_path, 0o600)
        except BaseException:
            self._db.close()
            raise
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA busy_timeout=10000")
        self._create_schema()
        self._recover_staging()

    def _create_schema(self) -> None:
        with self._lock:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS capsule_records (
                    capsule_id TEXT PRIMARY KEY,
                    peer_fp TEXT NOT NULL,
                    direction TEXT NOT NULL CHECK(direction IN ('outbound','inbound')),
                    call_id TEXT NOT NULL,
                    finalized_at_ms INTEGER NOT NULL,
                    payload_hash TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    sealed_name TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL CHECK(status IN
                        ('staging','pending','delivered','received')),
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                    next_attempt_ms INTEGER NOT NULL DEFAULT 0,
                    created_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL,
                    delivered_at_ms INTEGER,
                    last_error TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_capsule_due
                    ON capsule_records(direction, status, next_attempt_ms, created_at_ms);
                CREATE INDEX IF NOT EXISTS idx_capsule_peer
                    ON capsule_records(peer_fp, direction, created_at_ms);
                """
            )

    @staticmethod
    def _sealed_name(capsule_id: str) -> str:
        digest = blake3.blake3(capsule_id.encode("utf-8")).hexdigest()
        return f"{digest}.olcap"

    def _sealed_path(self, sealed_name: str) -> Path:
        if (
            not isinstance(sealed_name, str)
            or len(sealed_name) != 70
            or not sealed_name.endswith(".olcap")
            or any(ch not in "0123456789abcdef" for ch in sealed_name[:-6])
        ):
            raise CapsuleStoreError("invalid sealed capsule filename")
        return self.sealed_root / sealed_name

    @staticmethod
    def _validate_record_binding(
        capsule: AsyncCapsule,
        *,
        capsule_id: str,
        peer_fp: str,
        direction: CapsuleDirection,
        call_id: str,
        finalized_at_ms: int,
        payload_hash: str,
    ) -> None:
        """Bind mutable index metadata back to the authenticated body.

        The SQLite index is operational metadata rather than secret material.
        It must therefore never become an authorization oracle on its own: a
        local attacker who can edit ``peer_fp`` must not be able to redirect a
        still-authentic sealed voice note to a different peer.
        """

        if (
            capsule.capsule_id != capsule_id
            or capsule.call_id != call_id
            or capsule.finalized_at_ms != finalized_at_ms
            or capsule.payload_hash != payload_hash
        ):
            raise CapsuleConflictError(
                "sealed capsule does not match durable index contract"
            )
        body_peer = (
            capsule.recipient_master_vk_hex
            if direction == "outbound"
            else capsule.sender_master_vk_hex
        )
        if body_peer != peer_fp:
            raise CapsuleConflictError(
                "sealed capsule peer binding does not match durable index"
            )

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> CapsuleRecord:
        return CapsuleRecord(
            capsule_id=str(row["capsule_id"]),
            peer_fp=str(row["peer_fp"]),
            direction=str(row["direction"]),  # type: ignore[arg-type]
            call_id=str(row["call_id"]),
            finalized_at_ms=int(row["finalized_at_ms"]),
            payload_hash=str(row["payload_hash"]),
            content_hash=str(row["content_hash"]),
            sealed_name=str(row["sealed_name"]),
            status=str(row["status"]),  # type: ignore[arg-type]
            attempts=int(row["attempts"]),
            next_attempt_ms=int(row["next_attempt_ms"]),
            created_at_ms=int(row["created_at_ms"]),
            updated_at_ms=int(row["updated_at_ms"]),
            delivered_at_ms=(
                int(row["delivered_at_ms"])
                if row["delivered_at_ms"] is not None
                else None
            ),
            last_error=str(row["last_error"] or ""),
        )

    def get(self, capsule_id: str) -> Optional[CapsuleRecord]:
        if not isinstance(capsule_id, str) or not capsule_id:
            return None
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM capsule_records WHERE capsule_id = ?",
                (capsule_id,),
            ).fetchone()
            return self._row_to_record(row) if row is not None else None

    def store_capsule(
        self,
        capsule: AsyncCapsule,
        *,
        peer_fp: str,
        direction: CapsuleDirection,
        now_ms: Optional[int] = None,
    ) -> CapsuleRecord:
        peer_fp = _validate_peer_fingerprint(peer_fp)
        if direction not in {"outbound", "inbound"}:
            raise ValueError("direction must be outbound or inbound")
        self._validate_record_binding(
            capsule,
            capsule_id=capsule.capsule_id,
            peer_fp=peer_fp,
            direction=direction,
            call_id=capsule.call_id,
            finalized_at_ms=capsule.finalized_at_ms,
            payload_hash=capsule.payload_hash,
        )
        plaintext = serialize_capsule(capsule)
        content_hash = blake3.blake3(plaintext).hexdigest()
        sealed_name = self._sealed_name(capsule.capsule_id)
        sealed_path = self._sealed_path(sealed_name)
        stamp = _coerce_timestamp_ms(now_ms, field_name="now_ms")
        ready_status = "pending" if direction == "outbound" else "received"

        with self._lock:
            existing = self.get(capsule.capsule_id)
            if existing is not None:
                contract = (
                    peer_fp,
                    direction,
                    capsule.call_id,
                    capsule.finalized_at_ms,
                    capsule.payload_hash,
                    content_hash,
                    sealed_name,
                )
                existing_contract = (
                    existing.peer_fp,
                    existing.direction,
                    existing.call_id,
                    existing.finalized_at_ms,
                    existing.payload_hash,
                    existing.content_hash,
                    existing.sealed_name,
                )
                if contract != existing_contract:
                    raise CapsuleConflictError(
                        "capsule_id already belongs to different authenticated content"
                    )
                if existing.status == "staging":
                    self._recover_one_staging(existing)
                    refreshed = self.get(capsule.capsule_id)
                    if refreshed is None:
                        # Recovery removed a missing/incomplete staging record;
                        # continue below and recreate it from the caller's bytes.
                        existing = None
                    else:
                        return refreshed
                else:
                    return existing

            self._db.execute(
                """
                INSERT INTO capsule_records(
                    capsule_id, peer_fp, direction, call_id, finalized_at_ms,
                    payload_hash, content_hash, sealed_name, status, attempts,
                    next_attempt_ms, created_at_ms, updated_at_ms,
                    delivered_at_ms, last_error
                ) VALUES(?,?,?,?,?,?,?,?, 'staging', 0, 0, ?, ?, NULL, '')
                """,
                (
                    capsule.capsule_id,
                    peer_fp,
                    direction,
                    capsule.call_id,
                    capsule.finalized_at_ms,
                    capsule.payload_hash,
                    content_hash,
                    sealed_name,
                    stamp,
                    stamp,
                ),
            )
            try:
                save_sealed_capsule(
                    capsule=capsule,
                    out_path=sealed_path,
                    master_seed=self._master_seed,
                )
                self._db.execute(
                    """
                    UPDATE capsule_records
                    SET status = ?, next_attempt_ms = ?, updated_at_ms = ?
                    WHERE capsule_id = ? AND status = 'staging'
                    """,
                    (
                        ready_status,
                        stamp if direction == "outbound" else 0,
                        stamp,
                        capsule.capsule_id,
                    ),
                )
            except BaseException:
                self._db.execute(
                    "DELETE FROM capsule_records WHERE capsule_id = ? AND status = 'staging'",
                    (capsule.capsule_id,),
                )
                try:
                    sealed_path.unlink()
                except OSError:
                    pass
                raise
            record = self.get(capsule.capsule_id)
            if record is None:
                raise CapsuleStoreError("capsule index commit disappeared")
            return record

    def load_capsule(self, record_or_id: CapsuleRecord | str) -> AsyncCapsule:
        record = (
            record_or_id
            if isinstance(record_or_id, CapsuleRecord)
            else self.get(record_or_id)
        )
        if record is None:
            raise CapsuleNotFoundError("capsule does not exist")
        if record.status == "staging":
            raise CapsuleStoreError("capsule is not durably committed")
        capsule = load_sealed_capsule(
            sealed_path=self._sealed_path(record.sealed_name),
            master_seed=self._master_seed,
            call_id=record.call_id,
            finalized_at_ms=record.finalized_at_ms,
        )
        if blake3.blake3(serialize_capsule(capsule)).hexdigest() != record.content_hash:
            raise CapsuleConflictError("sealed capsule does not match durable index")
        self._validate_record_binding(
            capsule,
            capsule_id=record.capsule_id,
            peer_fp=record.peer_fp,
            direction=record.direction,
            call_id=record.call_id,
            finalized_at_ms=record.finalized_at_ms,
            payload_hash=record.payload_hash,
        )
        return capsule

    def due_outbound(
        self,
        *,
        now_ms: Optional[int] = None,
        limit: int = 8,
    ) -> tuple[CapsuleRecord, ...]:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not (1 <= limit <= MAX_CAPSULE_DELIVERY_ATTEMPTS_QUERY)
        ):
            raise ValueError("limit outside supported range")
        stamp = _coerce_timestamp_ms(now_ms, field_name="now_ms")
        with self._lock:
            rows = self._db.execute(
                """
                SELECT * FROM capsule_records
                WHERE direction = 'outbound' AND status = 'pending'
                  AND next_attempt_ms <= ?
                ORDER BY created_at_ms, capsule_id
                LIMIT ?
                """,
                (stamp, limit),
            ).fetchall()
            return tuple(self._row_to_record(row) for row in rows)

    def mark_attempt_failed(
        self,
        capsule_id: str,
        *,
        peer_fp: str,
        error: str,
        now_ms: Optional[int] = None,
    ) -> CapsuleRecord:
        peer_fp = _validate_peer_fingerprint(peer_fp)
        stamp = _coerce_timestamp_ms(now_ms, field_name="now_ms")
        with self._lock:
            record = self.get(capsule_id)
            if record is None or record.direction != "outbound":
                raise CapsuleNotFoundError("outbound capsule does not exist")
            if record.peer_fp != peer_fp:
                raise CapsuleConflictError("capsule attempt peer does not match")
            if record.status == "delivered":
                return record
            attempts = record.attempts + 1
            delay_ms = min(60 * 60 * 1000, 1_000 * (2 ** min(attempts - 1, 12)))
            next_attempt_ms = min(MAX_SQLITE_TIMESTAMP_MS, stamp + delay_ms)
            self._db.execute(
                """
                UPDATE capsule_records
                SET attempts = ?, next_attempt_ms = ?, updated_at_ms = ?, last_error = ?
                WHERE capsule_id = ? AND status = 'pending'
                """,
                (
                    attempts,
                    next_attempt_ms,
                    stamp,
                    str(error)[:MAX_CAPSULE_ERROR_CHARS],
                    capsule_id,
                ),
            )
            refreshed = self.get(capsule_id)
            if refreshed is None:
                raise CapsuleStoreError("capsule attempt row disappeared")
            return refreshed

    def mark_delivered(
        self,
        capsule_id: str,
        *,
        peer_fp: str,
        payload_hash: str,
        now_ms: Optional[int] = None,
    ) -> CapsuleRecord:
        peer_fp = _validate_peer_fingerprint(peer_fp)
        stamp = _coerce_timestamp_ms(now_ms, field_name="now_ms")
        with self._lock:
            record = self.get(capsule_id)
            if record is None or record.direction != "outbound":
                raise CapsuleNotFoundError("outbound capsule does not exist")
            if record.peer_fp != peer_fp or record.payload_hash != payload_hash:
                raise CapsuleConflictError("capsule receipt does not match outbox contract")
            if record.status == "delivered":
                return record
            if record.status != "pending":
                raise CapsuleStoreError("capsule is not awaiting delivery")
            self._db.execute(
                """
                UPDATE capsule_records
                SET status = 'delivered', delivered_at_ms = ?, updated_at_ms = ?,
                    next_attempt_ms = 0, last_error = ''
                WHERE capsule_id = ? AND status = 'pending'
                """,
                (stamp, stamp, capsule_id),
            )
            refreshed = self.get(capsule_id)
            if refreshed is None:
                raise CapsuleStoreError("capsule receipt row disappeared")
            return refreshed

    def list_records(
        self,
        *,
        peer_fp: Optional[str] = None,
        limit: int = 100,
    ) -> tuple[CapsuleRecord, ...]:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not (1 <= limit <= 1000)
        ):
            raise ValueError("limit outside supported range")
        with self._lock:
            if peer_fp is None:
                rows = self._db.execute(
                    "SELECT * FROM capsule_records WHERE status != 'staging' "
                    "ORDER BY created_at_ms DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                peer_fp = _validate_peer_fingerprint(peer_fp)
                rows = self._db.execute(
                    "SELECT * FROM capsule_records WHERE status != 'staging' "
                    "AND peer_fp = ? ORDER BY created_at_ms DESC LIMIT ?",
                    (peer_fp, limit),
                ).fetchall()
            return tuple(self._row_to_record(row) for row in rows)

    def _recover_staging(self) -> None:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM capsule_records WHERE status = 'staging'"
            ).fetchall()
            for row in rows:
                self._recover_one_staging(self._row_to_record(row))

    def _recover_one_staging(self, record: CapsuleRecord) -> None:
        sealed_path = self._sealed_path(record.sealed_name)
        try:
            sealed_stat = sealed_path.lstat()
        except OSError:
            sealed_stat = None
        if (
            sealed_stat is None
            or _is_link_or_reparse(sealed_path, sealed_stat)
            or not stat.S_ISREG(sealed_stat.st_mode)
        ):
            self._db.execute(
                "DELETE FROM capsule_records WHERE capsule_id = ? AND status = 'staging'",
                (record.capsule_id,),
            )
            return
        try:
            capsule = load_sealed_capsule(
                sealed_path=sealed_path,
                master_seed=self._master_seed,
                call_id=record.call_id,
                finalized_at_ms=record.finalized_at_ms,
            )
            observed = blake3.blake3(serialize_capsule(capsule)).hexdigest()
            if observed != record.content_hash:
                raise CapsuleConflictError("staging capsule content mismatch")
            self._validate_record_binding(
                capsule,
                capsule_id=record.capsule_id,
                peer_fp=record.peer_fp,
                direction=record.direction,
                call_id=record.call_id,
                finalized_at_ms=record.finalized_at_ms,
                payload_hash=record.payload_hash,
            )
        except Exception:
            quarantine = self.root / CAPSULE_QUARANTINE_DIRNAME
            quarantine.mkdir(parents=True, exist_ok=True)
            quarantine_stat = quarantine.lstat()
            if (
                _is_link_or_reparse(quarantine, quarantine_stat)
                or not stat.S_ISDIR(quarantine_stat.st_mode)
            ):
                raise CapsuleStoreError(
                    "capsule quarantine root is not a regular directory"
                )
            _restrict_private_path(quarantine, 0o700)
            destination = quarantine / (
                f"{record.sealed_name}.{int(time.time() * 1000)}.invalid"
            )
            try:
                os.replace(sealed_path, destination)
            except OSError:
                pass
            self._db.execute(
                "DELETE FROM capsule_records WHERE capsule_id = ? AND status = 'staging'",
                (record.capsule_id,),
            )
            return
        status = "pending" if record.direction == "outbound" else "received"
        stamp = int(time.time() * 1000)
        self._db.execute(
            """
            UPDATE capsule_records
            SET status = ?, next_attempt_ms = ?, updated_at_ms = ?
            WHERE capsule_id = ? AND status = 'staging'
            """,
            (status, stamp if status == "pending" else 0, stamp, record.capsule_id),
        )

    def close(self) -> None:
        with self._lock:
            self._db.close()
