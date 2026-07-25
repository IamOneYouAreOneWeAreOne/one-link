"""Fail-closed storage ownership and content-addressed-store lifecycle.

There are two deliberately separate responsibilities in this module:

* reclaim browser/daemon upload staging files when the last durable transfer
  reference is removed; and
* audit the blob CAS, produce a deterministic offline collection manifest,
and move proven orphans into a recoverable quarantine.  A separately pinned,
aged purge is available only after that recovery window has elapsed.

Neither path treats mere filesystem location as ownership.  Upload cleanup
requires a regular file reached without a symlink/reparse component and an
exact, readable scan of every remaining transfer row.  CAS collection is an
explicit offline operation: all durable protocol/history roots are captured
in one state snapshot, candidates receive an age grace period and stable file
identity, and execution revalidates both the root set and every object before
an atomic rename. Permanent deletion requires a second explicit operation,
the original manifest digest, a completed journal, another live-root scan,
and a default 30-day quarantine grace.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import sqlite3
import stat
import tempfile
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping, Protocol, Sequence, cast

import blake3

from one_link.blobstore import BlobStore


CAS_GC_SCHEMA = "one-link-cas-gc/v1"
CAS_QUARANTINE_SCHEMA = "one-link-cas-quarantine/v1"
DEFAULT_CAS_GRACE_MS = 7 * 24 * 60 * 60 * 1000
DEFAULT_QUARANTINE_GRACE_MS = 30 * 24 * 60 * 60 * 1000
DEFAULT_CAS_BATCH_LIMIT = 1_000
MAX_CAS_BATCH_LIMIT = 10_000
MAX_JSON_REFERENCE_BYTES = 64 * 1024 * 1024
MAX_PARTIAL_STAGING_ENTRIES = 512
MAX_PARTIAL_METADATA_TEMPS = 64
PATH_PII_MARKER = "~OL1~"
_PHONE_STAGING_NAME = re.compile(r"^[0-9]{10,17}_[0-9a-f]{32}\.upload$")


class StorageLifecycleError(RuntimeError):
    """A storage graph or quarantine invariant could not be proven."""


class _StateLike(Protocol):
    _conn: Any
    _write_lock: Any
    db_path: Path

    def _unwrap_path(self, value: str, *, aad: bytes) -> str: ...


class ReadOnlyStateSnapshot:
    """State-shaped handle backed by a disposable byte-for-byte DB snapshot.

    SQLite and SQLCipher may create/checkpoint WAL/SHM files even for callers
    that only issue SELECTs.  Opening the production pathname would therefore
    make an "audit" observably mutating.  This handle opens only a private
    copy captured while the daemon instance lock is held.
    """

    def __init__(
        self,
        connection: Any,
        *,
        db_path: Path,
        temporary: tempfile.TemporaryDirectory,
    ):
        self._conn = connection
        self.db_path = Path(db_path)
        self._temporary = temporary
        self._write_lock = threading.RLock()

    def close(self) -> None:
        try:
            self._conn.close()
        finally:
            self._temporary.cleanup()

    def __enter__(self) -> "ReadOnlyStateSnapshot":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _unwrap_path(self, value: str, *, aad: bytes) -> str:
        del aad
        return value


def _copy_identity_bound(source: Path, destination: Path) -> None:
    before = source.lstat()
    if _is_reparse_or_symlink(source, before) or not stat.S_ISREG(before.st_mode):
        raise StorageLifecycleError(f"state snapshot source is redirected: {source.name}")
    expected = FileIdentity.from_stat(before)
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(source, flags)
    try:
        with (
            os.fdopen(descriptor, "rb", closefd=False) as reader,
            open(destination, "xb") as writer,
        ):
            if FileIdentity.from_stat(os.fstat(descriptor)) != expected:
                raise StorageLifecycleError(
                    f"state snapshot source changed while opening: {source.name}"
                )
            shutil.copyfileobj(reader, writer, length=1024 * 1024)
            if FileIdentity.from_stat(os.fstat(descriptor)) != expected:
                raise StorageLifecycleError(
                    f"state snapshot source changed while copying: {source.name}"
                )
            writer.flush()
            os.fsync(writer.fileno())
    finally:
        os.close(descriptor)
    after = source.lstat()
    if FileIdentity.from_stat(after) != expected:
        raise StorageLifecycleError(f"state snapshot source changed after copying: {source.name}")


def open_read_only_state_snapshot(
    db_path: Path,
    *,
    passphrase: str | None = None,
) -> ReadOnlyStateSnapshot:
    """Copy state.db(+WAL/SHM) and open only the disposable copy.

    The caller must hold the daemon instance lock so the three source files
    form an offline snapshot. No migration, PRAGMA, marker, key creation,
    backup cleanup, or SQLite connection ever touches production state.
    """

    source_db = Path(db_path)
    if not source_db.is_file():
        raise StorageLifecycleError(f"state database does not exist: {source_db}")
    temporary = tempfile.TemporaryDirectory(prefix="one-link-storage-audit-")
    temp_root = Path(temporary.name)
    copied_db = temp_root / source_db.name
    try:
        _copy_identity_bound(source_db, copied_db)
        for suffix in ("-wal", "-shm"):
            source_sidecar = source_db.with_name(source_db.name + suffix)
            if source_sidecar.exists() or source_sidecar.is_symlink():
                _copy_identity_bound(
                    source_sidecar,
                    copied_db.with_name(copied_db.name + suffix),
                )
        with open(copied_db, "rb") as header_file:
            header = header_file.read(16)
        if header == b"SQLite format 3\x00":
            connection: Any = sqlite3.connect(
                copied_db,
                check_same_thread=False,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
        else:
            if not passphrase:
                raise StorageLifecycleError(
                    "state database is encrypted but no existing read-only key was available"
                )
            try:
                from one_link.state_encryption import open_encrypted_connection

                connection = open_encrypted_connection(copied_db, passphrase)
                import sqlcipher3 as _sqlcipher

                connection.row_factory = _sqlcipher.Row
            except Exception as exc:
                raise StorageLifecycleError("encrypted state snapshot could not be opened") from exc
        # Force schema/header decode now, while snapshot-open failures can
        # still cleanly remove the temporary directory.
        connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return ReadOnlyStateSnapshot(connection, db_path=source_db, temporary=temporary)
    except StorageLifecycleError:
        temporary.cleanup()
        raise
    except Exception as exc:
        temporary.cleanup()
        raise StorageLifecycleError("read-only state snapshot could not be captured") from exc


@dataclass(frozen=True)
class FileIdentity:
    """Stable evidence used to reject path swaps between plan and action."""

    size: int
    mode: int
    device: int
    inode: int
    mtime_ns: int
    ctime_ns: int
    nlink: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "FileIdentity":
        return cls(
            size=int(value.st_size),
            mode=int(value.st_mode),
            device=int(value.st_dev),
            inode=int(value.st_ino),
            mtime_ns=int(value.st_mtime_ns),
            # Windows may report a different ctime through an open handle
            # than through the directory entry for the same unchanged file.
            # File ID + size + mtime remain stable there (the blob store uses
            # the same normalization). POSIX ctime remains valuable evidence.
            ctime_ns=0 if os.name == "nt" else int(value.st_ctime_ns),
            nlink=int(value.st_nlink),
        )

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> "FileIdentity":
        fields = ("size", "mode", "device", "inode", "mtime_ns", "ctime_ns", "nlink")
        if set(value) != set(fields) or any(type(value.get(key)) is not int for key in fields):
            raise StorageLifecycleError("manifest contains an invalid file identity")
        return cls(**{key: int(value[key]) for key in fields})

    def to_json(self) -> dict[str, int]:
        return {
            "size": self.size,
            "mode": self.mode,
            "device": self.device,
            "inode": self.inode,
            "mtime_ns": self.mtime_ns,
            "ctime_ns": self.ctime_ns,
            "nlink": self.nlink,
        }


def _same_object_after_rename(observed: FileIdentity, planned: FileIdentity) -> bool:
    """Compare identity fields that an atomic rename is guaranteed to retain.

    POSIX legitimately updates inode ctime on rename, so ctime is strong
    plan-to-source race evidence but cannot be required at the quarantine
    destination or during rollback.
    """

    return (
        observed.size == planned.size
        and observed.mode == planned.mode
        and observed.device == planned.device
        and observed.inode == planned.inode
        and observed.mtime_ns == planned.mtime_ns
        and observed.nlink == planned.nlink
    )


@dataclass(frozen=True)
class UploadCleanupResult:
    considered: int
    removed: tuple[str, ...]
    retained: tuple[str, ...]
    errors: tuple[str, ...]


@dataclass(frozen=True)
class DurableBlobRoots:
    roots: frozenset[str]
    sources: Mapping[str, tuple[str, ...]]
    errors: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return not self.errors


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest_json(value: Any) -> str:
    return blake3.blake3(_canonical_json(value)).hexdigest()


def _is_lower_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_reparse_or_symlink(path: Path, value: os.stat_result | None = None) -> bool:
    current = value if value is not None else path.lstat()
    if stat.S_ISLNK(current.st_mode):
        return True
    attributes = int(getattr(current, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    if attributes & reparse_flag:
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(callable(is_junction) and is_junction())


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _strict_regular_beneath(root: Path, candidate: Path) -> tuple[Path, FileIdentity]:
    """Return lexical path + identity only when no component can redirect I/O."""

    raw_candidate = Path(candidate)
    if any(part == ".." for part in raw_candidate.parts):
        raise StorageLifecycleError(f"path contains traversal: {candidate}")
    lexical_root = Path(os.path.abspath(os.fspath(root)))
    lexical_candidate = Path(os.path.abspath(os.fspath(raw_candidate)))
    try:
        common = os.path.commonpath((_path_key(lexical_root), _path_key(lexical_candidate)))
    except ValueError as exc:
        raise StorageLifecycleError("path and ownership root are on different volumes") from exc
    if common != _path_key(lexical_root) or lexical_candidate == lexical_root:
        raise StorageLifecycleError(f"path is not strictly beneath ownership root: {candidate}")

    root_stat = lexical_root.lstat()
    if _is_reparse_or_symlink(lexical_root, root_stat) or not stat.S_ISDIR(root_stat.st_mode):
        raise StorageLifecycleError("ownership root is not a real directory")
    relative = lexical_candidate.relative_to(lexical_root)
    current = lexical_root
    for index, component in enumerate(relative.parts):
        if component in ("", ".", ".."):
            raise StorageLifecycleError(f"unsafe path component: {component!r}")
        current = current / component
        current_stat = current.lstat()
        if _is_reparse_or_symlink(current, current_stat):
            raise StorageLifecycleError(f"path contains a symlink/reparse point: {current}")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(current_stat.st_mode):
            raise StorageLifecycleError(f"path parent is not a directory: {current}")
    final_stat = lexical_candidate.lstat()
    if not stat.S_ISREG(final_stat.st_mode):
        raise StorageLifecycleError(f"owned path is not a regular file: {candidate}")
    return lexical_candidate, FileIdentity.from_stat(final_stat)


def _ensure_real_directory_beneath(root: Path, directory: Path) -> Path:
    """Create/validate a directory chain without accepting redirected components."""

    lexical_root = Path(os.path.abspath(os.fspath(root)))
    lexical_directory = Path(os.path.abspath(os.fspath(directory)))
    try:
        relative = lexical_directory.relative_to(lexical_root)
    except ValueError as exc:
        raise StorageLifecycleError("directory escaped its ownership root") from exc
    root_stat = lexical_root.lstat()
    if _is_reparse_or_symlink(lexical_root, root_stat) or not stat.S_ISDIR(root_stat.st_mode):
        raise StorageLifecycleError("directory ownership root is redirected")
    current = lexical_root
    for component in relative.parts:
        if component in ("", ".", ".."):
            raise StorageLifecycleError("directory chain contains an unsafe component")
        current = current / component
        try:
            current.mkdir()
        except FileExistsError:
            pass
        current_stat = current.lstat()
        if _is_reparse_or_symlink(current, current_stat) or not stat.S_ISDIR(
            current_stat.st_mode
        ):
            raise StorageLifecycleError(f"directory chain is redirected: {current}")
    return lexical_directory


def _assert_existing_path_chain_no_redirect(path: Path) -> None:
    """Reject symlink/reparse components in the existing absolute path prefix."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    anchor = Path(absolute.anchor)
    current = anchor
    parts = absolute.parts[1:] if absolute.anchor else absolute.parts
    for component in parts:
        current = current / component
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            break
        if _is_reparse_or_symlink(current, current_stat):
            raise StorageLifecycleError(f"path chain is redirected: {current}")


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0)))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _unlink_identity_bound(path: Path, expected: FileIdentity) -> None:
    """Unlink a regular non-symlink only while its opened identity is stable."""

    before = path.lstat()
    if _is_reparse_or_symlink(path, before) or not stat.S_ISREG(before.st_mode):
        raise StorageLifecycleError("upload changed into a non-regular or redirected path")
    if FileIdentity.from_stat(before) != expected:
        raise StorageLifecycleError("upload identity changed before cleanup")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or FileIdentity.from_stat(opened) != expected:
            raise StorageLifecycleError("upload path changed while opening for cleanup")
    finally:
        os.close(descriptor)
    # Windows does not grant delete sharing on Python's ordinary read handle,
    # so close after binding its identity, then perform one final no-follow
    # lookup immediately before unlink. POSIX gets the same swap check.
    immediately_before = path.lstat()
    if (
        _is_reparse_or_symlink(path, immediately_before)
        or FileIdentity.from_stat(immediately_before) != expected
    ):
        raise StorageLifecycleError("upload path changed immediately before cleanup")
    path.unlink()
    _fsync_directory(path.parent)


def _decode_transfer_path(state: _StateLike, raw_metadata: Any) -> tuple[str | None, str | None]:
    if not isinstance(raw_metadata, str) or len(raw_metadata.encode("utf-8")) > MAX_JSON_REFERENCE_BYTES:
        return None, "transfer metadata is missing, non-text, or oversized"
    try:
        metadata = json.loads(raw_metadata) if raw_metadata else {}
    except (TypeError, ValueError) as exc:
        return None, f"transfer metadata JSON is unreadable: {type(exc).__name__}"
    if not isinstance(metadata, dict):
        return None, "transfer metadata is not an object"
    raw_path = metadata.get("path")
    if raw_path is None or raw_path == "":
        return None, None
    if not isinstance(raw_path, str):
        return None, "transfer metadata.path is not text"
    try:
        aad = getattr(state, "_PATH_PII_AAD_TRANSFER")
        unwrapped = state._unwrap_path(raw_path, aad=aad)
    except Exception as exc:
        return None, f"transfer metadata.path cannot be decrypted: {type(exc).__name__}"
    if not isinstance(unwrapped, str) or unwrapped.startswith(PATH_PII_MARKER):
        return None, "transfer metadata.path remains encrypted/unreadable"
    return unwrapped, None


def reclaim_removed_transfer_uploads(
    state: _StateLike,
    removed_metadata_json: Sequence[str],
    *,
    uploads_root: Path | None = None,
) -> UploadCleanupResult:
    """Reclaim removed terminal transfer sources if the state graph proves ownership.

    The caller must hold ``state._write_lock`` across the transfer DELETE and
    this function.  Every remaining transfer row is decoded before any file
    mutation.  One unreadable row makes the whole cleanup fail closed because
    it could be the final shared reference.
    """

    root = Path(uploads_root or (Path(state.db_path).parent / "uploads"))
    candidates: list[str] = []
    errors: list[str] = []
    for raw in removed_metadata_json:
        decoded, error = _decode_transfer_path(state, raw)
        if error:
            errors.append(f"removed row: {error}")
        elif decoded:
            candidates.append(decoded)
    if not candidates:
        return UploadCleanupResult(0, (), (), tuple(sorted(set(errors))))

    remaining_paths: set[str] = set()
    try:
        rows = state._conn.execute("SELECT id, metadata_json FROM transfers").fetchall()
    except Exception as exc:
        errors.append(f"remaining transfer scan failed: {type(exc).__name__}")
        rows = ()
    for row in rows:
        decoded, error = _decode_transfer_path(state, row["metadata_json"])
        if error:
            errors.append(f"remaining transfer {row['id']}: {error}")
            continue
        if decoded:
            remaining_paths.add(_path_key(Path(decoded)))
    if errors:
        return UploadCleanupResult(
            len(set(candidates)),
            (),
            tuple(sorted(set(candidates))),
            tuple(sorted(set(errors))),
        )

    removed: list[str] = []
    retained: list[str] = []
    for raw_candidate in sorted(set(candidates), key=lambda value: _path_key(Path(value))):
        if _path_key(Path(raw_candidate)) in remaining_paths:
            retained.append(raw_candidate)
            continue
        try:
            safe_path, identity = _strict_regular_beneath(root, Path(raw_candidate))
            _unlink_identity_bound(safe_path, identity)
            removed.append(str(safe_path))
        except (OSError, StorageLifecycleError) as exc:
            retained.append(raw_candidate)
            errors.append(f"{raw_candidate}: {exc}")
    return UploadCleanupResult(
        len(set(candidates)),
        tuple(removed),
        tuple(retained),
        tuple(sorted(set(errors))),
    )


def reclaim_stale_unreferenced_phone_uploads(
    state: _StateLike,
    *,
    uploads_root: Path | None = None,
    active_paths: Sequence[Path] = (),
    grace_ms: int,
    now_ms: int | None = None,
) -> UploadCleanupResult:
    """Remove only aged random phone staging inodes with no durable owner.

    The exact transfer table is scanned while holding the state write lock.
    Any unreadable/decryption-failed row makes the operation fail closed. Only
    server-minted ``<millis>_<128-bit>.upload`` leaves are candidates; recent,
    active, redirected, non-regular, and ledger-referenced paths are retained.
    """

    if isinstance(grace_ms, bool) or not isinstance(grace_ms, int) or grace_ms < 0:
        raise ValueError("phone upload orphan grace must be a non-negative integer")
    observed_now_ms = int(time.time() * 1000) if now_ms is None else int(now_ms)
    cutoff_ns = (observed_now_ms - grace_ms) * 1_000_000
    root = Path(uploads_root or (Path(state.db_path).parent / "uploads"))
    if not root.exists():
        return UploadCleanupResult(0, (), (), ())
    errors: list[str] = []
    removed: list[str] = []
    retained: list[str] = []
    active = {_path_key(Path(path)) for path in active_paths}

    with state._write_lock:
        durable_paths: set[str] = set()
        try:
            rows = state._conn.execute(
                "SELECT id, metadata_json FROM transfers"
            ).fetchall()
        except Exception as exc:
            return UploadCleanupResult(
                0,
                (),
                (),
                (f"transfer reference scan failed: {type(exc).__name__}",),
            )
        for row in rows:
            decoded, error = _decode_transfer_path(state, row["metadata_json"])
            if error:
                errors.append(f"transfer {row['id']}: {error}")
            elif decoded:
                durable_paths.add(_path_key(Path(decoded)))
        if errors:
            return UploadCleanupResult(0, (), (), tuple(sorted(set(errors))))

        try:
            root_stat = root.lstat()
            if _is_reparse_or_symlink(root, root_stat) or not stat.S_ISDIR(
                root_stat.st_mode
            ):
                raise StorageLifecycleError("phone upload root is redirected")
            candidates = sorted(
                (
                    child
                    for child in root.iterdir()
                    if _PHONE_STAGING_NAME.fullmatch(child.name)
                ),
                key=lambda child: child.name,
            )
        except (OSError, StorageLifecycleError) as exc:
            return UploadCleanupResult(0, (), (), (str(exc),))

        for candidate in candidates:
            candidate_key = _path_key(candidate)
            if candidate_key in active or candidate_key in durable_paths:
                retained.append(str(candidate))
                continue
            try:
                safe_path, identity = _strict_regular_beneath(root, candidate)
                if identity.mtime_ns > cutoff_ns:
                    retained.append(str(safe_path))
                    continue
                _unlink_identity_bound(safe_path, identity)
                removed.append(str(safe_path))
            except (OSError, StorageLifecycleError) as exc:
                retained.append(str(candidate))
                errors.append(f"{candidate}: {exc}")

    return UploadCleanupResult(
        len(removed) + len(retained),
        tuple(removed),
        tuple(retained),
        tuple(sorted(set(errors))),
    )


_COLUMN_ROOTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("folder_manifest", ("blob_hash",)),
    (
        "folder_pending_applies",
        ("target_blob_hash", "baseline_blob_hash"),
    ),
    ("folder_audit", ("blob_hash",)),
    ("manifest_conflicts", ("local_blob_hash", "remote_blob_hash")),
    ("transfers", ("blob_hash",)),
    ("chunk_availability", ("blob_hash",)),
    ("file_index_cache", ("blob_hash",)),
)
# ``chunk_sources.chunk_hash`` and ``chunk_availability.chunk_hash`` address
# data_dir/file_chunks, not data_dir/blobs. They are deliberately absent from
# this CAS root graph. ``chunk_availability.blob_hash`` *does* bind a full blob
# and is included above.
_JSON_ROOTS: tuple[tuple[str, str], ...] = (
    ("pending_folder_offers", "entries_json"),
    ("transfers", "metadata_json"),
    ("messages", "metadata_json"),
    ("outbox", "msg_body_json"),
    ("folder_lifecycle_audit", "metadata_json"),
)


def _table_columns(connection: Any, table: str) -> frozenset[str]:
    rows = connection.execute(f'PRAGMA table_info("{table}")').fetchall()
    return frozenset(str(row[1]) for row in rows)


def _walk_json_hashes(value: Any) -> Iterator[str]:
    if _is_lower_hash(value):
        yield value
    elif isinstance(value, dict):
        for key in sorted(value, key=lambda item: str(item)):
            yield from _walk_json_hashes(value[key])
    elif isinstance(value, list):
        for item in value:
            yield from _walk_json_hashes(item)


def collect_durable_blob_roots(state: _StateLike) -> DurableBlobRoots:
    """Capture every durable CAS root and fail closed on partial decoding."""

    source_sets: dict[str, set[str]] = defaultdict(set)
    errors: list[str] = []
    with state._write_lock:
        connection = state._conn
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        for table, columns in _COLUMN_ROOTS:
            if table not in tables:
                errors.append(f"required root table is missing: {table}")
                continue
            available = _table_columns(connection, table)
            for column in columns:
                source = f"{table}.{column}"
                if column not in available:
                    errors.append(f"required root column is missing: {source}")
                    continue
                rows = connection.execute(
                    f'SELECT rowid, "{column}" FROM "{table}"'  # nosec B608
                ).fetchall()
                for row in rows:
                    value = row[1]
                    if value in (None, ""):
                        continue
                    if not _is_lower_hash(value):
                        errors.append(f"{source} row {row[0]} contains a non-canonical hash")
                        continue
                    source_sets[source].add(str(value))

        for table, column in _JSON_ROOTS:
            if table not in tables:
                errors.append(f"required JSON root table is missing: {table}")
                continue
            if column not in _table_columns(connection, table):
                errors.append(f"required JSON root column is missing: {table}.{column}")
                continue
            source = f"{table}.{column}"
            rows = connection.execute(
                f'SELECT rowid, "{column}" FROM "{table}"'  # nosec B608
            ).fetchall()
            for row in rows:
                raw = row[1]
                if raw in (None, ""):
                    continue
                if not isinstance(raw, str):
                    errors.append(f"{source} row {row[0]} is not text")
                    continue
                if len(raw.encode("utf-8")) > MAX_JSON_REFERENCE_BYTES:
                    errors.append(f"{source} row {row[0]} exceeds the JSON safety bound")
                    continue
                try:
                    parsed = json.loads(raw)
                except (TypeError, ValueError):
                    errors.append(f"{source} row {row[0]} contains malformed JSON")
                    continue
                source_sets[source].update(_walk_json_hashes(parsed))

    all_roots: set[str] = set()
    for hashes in source_sets.values():
        all_roots.update(hashes)
    frozen_sources = {
        source: tuple(sorted(hashes))
        for source, hashes in sorted(source_sets.items())
    }
    return DurableBlobRoots(
        frozenset(all_roots),
        frozen_sources,
        tuple(sorted(set(errors))),
    )


def _audit_partial_staging(partial_root: Path) -> list[str]:
    """Audit bounded resumable staging without treating it as live CAS.

    CAS GC is offline, so every durable partial must be a complete metadata /
    data pair. Prefix content is deliberately not re-hashed here—resume open
    performs that exact proof—but metadata checksums, address-derived names,
    regular-file identity, declared bounds, and directory cardinality are all
    fail-closed.
    """

    errors: list[str] = []
    try:
        root_stat = partial_root.lstat()
        if _is_reparse_or_symlink(partial_root, root_stat) or not stat.S_ISDIR(
            root_stat.st_mode,
        ):
            return ["partial blob staging is redirected or not a directory"]
        entries = sorted(partial_root.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        return [f"partial blob staging cannot be inspected: {type(exc).__name__}"]
    if len(entries) > (2 * MAX_PARTIAL_STAGING_ENTRIES + MAX_PARTIAL_METADATA_TEMPS):
        errors.append("partial blob staging entry bound exceeded")

    by_key: dict[str, dict[str, Path]] = defaultdict(dict)
    for entry in entries:
        try:
            entry_stat = entry.lstat()
        except OSError as exc:
            errors.append(
                f"cannot inspect partial staging entry {entry.name}: {type(exc).__name__}",
            )
            continue
        if _is_reparse_or_symlink(entry, entry_stat) or not stat.S_ISREG(
            entry_stat.st_mode,
        ):
            errors.append(f"redirected or non-regular partial staging entry: {entry.name}")
            continue
        if entry.name.startswith("meta_") and entry.name.endswith(".tmp"):
            errors.append(f"incomplete partial metadata publication: {entry.name}")
            continue
        stem, suffix = os.path.splitext(entry.name)
        if not _is_lower_hash(stem) or suffix not in {".part", ".json"}:
            errors.append(f"unexpected partial staging entry: {entry.name}")
            continue
        by_key[stem][suffix] = entry

    if len(by_key) > MAX_PARTIAL_STAGING_ENTRIES:
        errors.append("partial blob staging logical-entry bound exceeded")
    for key, pair in sorted(by_key.items()):
        if set(pair) != {".part", ".json"}:
            errors.append(f"incomplete partial blob staging pair: {key}")
            continue
        try:
            meta_fd = BlobStore._open_regular(pair[".json"])
            with os.fdopen(meta_fd, "rb") as meta_fh:
                metadata = BlobStore._decode_partial_metadata(meta_fh.read(4097))
            if metadata is None:
                raise StorageLifecycleError("metadata checksum or schema is invalid")
            expected_key = BlobStore._partial_identity(
                str(metadata["peer_fp"]),
                str(metadata["blob_hash"]),
                cast(int, metadata["size"]),
            )
            data_stat = pair[".part"].lstat()
            if (
                expected_key != key
                or int(data_stat.st_size) < cast(int, metadata["received"])
                or int(data_stat.st_size) > cast(int, metadata["size"])
            ):
                raise StorageLifecycleError("partial metadata/data identity mismatch")
        except (OSError, TypeError, ValueError, StorageLifecycleError) as exc:
            errors.append(f"invalid partial blob staging pair {key}: {exc}")
    return errors


def _scan_cas_disk(blob_root: Path) -> tuple[dict[str, tuple[Path, FileIdentity]], list[str]]:
    root = Path(os.path.abspath(os.fspath(blob_root)))
    errors: list[str] = []
    objects: dict[str, tuple[Path, FileIdentity]] = {}
    try:
        root_stat = root.lstat()
    except OSError as exc:
        return {}, [f"blob root cannot be inspected: {type(exc).__name__}"]
    if _is_reparse_or_symlink(root, root_stat) or not stat.S_ISDIR(root_stat.st_mode):
        return {}, ["blob root is not a real directory"]
    try:
        shards = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        return {}, [f"blob root cannot be enumerated: {type(exc).__name__}"]
    for shard in shards:
        if shard.name == "_tmp":
            continue
        if shard.name == "_partials":
            errors.extend(_audit_partial_staging(shard))
            continue
        try:
            shard_stat = shard.lstat()
        except OSError as exc:
            errors.append(f"cannot inspect blob shard {shard.name}: {type(exc).__name__}")
            continue
        if (
            len(shard.name) != 2
            or any(character not in "0123456789abcdef" for character in shard.name)
            or _is_reparse_or_symlink(shard, shard_stat)
            or not stat.S_ISDIR(shard_stat.st_mode)
        ):
            errors.append(f"unexpected or redirected blob-root entry: {shard.name}")
            continue
        try:
            entries = sorted(shard.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            errors.append(f"cannot enumerate blob shard {shard.name}: {type(exc).__name__}")
            continue
        for entry in entries:
            digest = shard.name + entry.name
            try:
                entry_stat = entry.lstat()
            except OSError as exc:
                errors.append(f"cannot inspect blob object {digest}: {type(exc).__name__}")
                continue
            if (
                not _is_lower_hash(digest)
                or _is_reparse_or_symlink(entry, entry_stat)
                or not stat.S_ISREG(entry_stat.st_mode)
            ):
                errors.append(f"unexpected or redirected blob object: {shard.name}/{entry.name}")
                continue
            if digest in objects:
                errors.append(f"duplicate blob address on disk: {digest}")
                continue
            objects[digest] = (entry, FileIdentity.from_stat(entry_stat))
    return objects, errors


def _read_blob_index(state: _StateLike) -> tuple[dict[str, dict[str, int]], list[str]]:
    indexed: dict[str, dict[str, int]] = {}
    errors: list[str] = []
    with state._write_lock:
        try:
            rows = state._conn.execute(
                "SELECT hash, size, received_ms FROM blobs ORDER BY hash"
            ).fetchall()
        except Exception as exc:
            return {}, [f"blob index cannot be read: {type(exc).__name__}"]
        for row in rows:
            digest = row["hash"]
            if not _is_lower_hash(digest):
                errors.append("blobs.hash contains a non-canonical address")
                continue
            if type(row["size"]) is not int or int(row["size"]) < 0:
                errors.append(f"blob index has an invalid size: {digest}")
                continue
            indexed[str(digest)] = {
                "size": int(row["size"]),
                "received_ms": int(row["received_ms"]),
            }
    return indexed, errors


def build_cas_gc_manifest(
    state: _StateLike,
    blob_root: Path,
    *,
    now_ms: int | None = None,
    grace_ms: int = DEFAULT_CAS_GRACE_MS,
    batch_limit: int = DEFAULT_CAS_BATCH_LIMIT,
    verify_content: bool = False,
) -> dict[str, Any]:
    """Build a deterministic, bounded and non-mutating CAS collection plan."""

    generated_ms = int(time.time() * 1000) if now_ms is None else int(now_ms)
    grace_ms = max(0, int(grace_ms))
    batch_limit = max(1, min(int(batch_limit), MAX_CAS_BATCH_LIMIT))
    roots = collect_durable_blob_roots(state)
    disk, disk_errors = _scan_cas_disk(blob_root)
    indexed, index_errors = _read_blob_index(state)
    errors = list(roots.errors) + disk_errors + index_errors
    cutoff_ns = (generated_ms - grace_ms) * 1_000_000

    all_candidates: list[dict[str, Any]] = []
    recent_unreferenced = 0
    corrupt_unreferenced: list[str] = []
    for digest, (path, identity) in sorted(disk.items()):
        if digest in roots.roots:
            continue
        effective_change_ns = max(identity.mtime_ns, identity.ctime_ns)
        if effective_change_ns > cutoff_ns:
            recent_unreferenced += 1
            continue
        content_hash: str | None = None
        if verify_content:
            hasher = blake3.blake3()
            try:
                flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
                flags |= int(getattr(os, "O_NOFOLLOW", 0))
                descriptor = os.open(path, flags)
                with os.fdopen(descriptor, "rb") as handle:
                    if FileIdentity.from_stat(os.fstat(handle.fileno())) != identity:
                        raise StorageLifecycleError("object changed while content-auditing")
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        hasher.update(block)
                    if FileIdentity.from_stat(os.fstat(handle.fileno())) != identity:
                        raise StorageLifecycleError("object changed during content audit")
                content_hash = hasher.hexdigest()
            except (OSError, StorageLifecycleError) as exc:
                errors.append(f"content audit failed for {digest}: {exc}")
                continue
            if content_hash != digest:
                corrupt_unreferenced.append(digest)
        all_candidates.append(
            {
                "hash": digest,
                "relative_path": f"{digest[:2]}/{digest[2:]}",
                "identity": identity.to_json(),
                "content_blake3": content_hash,
                "indexed": digest in indexed,
            }
        )

    selected = all_candidates[:batch_limit]
    disk_hashes = set(disk)
    index_hashes = set(indexed)
    stale_index_all = sorted(index_hashes - disk_hashes)
    rooted_missing_all = sorted(roots.roots - disk_hashes)
    unindexed_disk_all = sorted(disk_hashes - index_hashes)
    size_mismatches_all = [
        {
            "hash": digest,
            "index_size": indexed[digest]["size"],
            "disk_size": disk[digest][1].size,
        }
        for digest in sorted(index_hashes & disk_hashes)
        if indexed[digest]["size"] != disk[digest][1].size
    ]
    if size_mismatches_all:
        errors.append("blob index/disk size divergence requires operator review")

    # Diagnostic/index reconciliation arrays are bounded too.  Candidate
    # moves consume the batch first; unused capacity can remove stale index
    # rows that have neither a durable root nor a live disk object.
    diagnostic_limit = min(batch_limit, 1_000)
    stale_budget = max(0, batch_limit - len(selected))
    stale_index = stale_index_all[:stale_budget]
    rooted_missing = rooted_missing_all[:diagnostic_limit]
    unindexed_disk = unindexed_disk_all[:diagnostic_limit]
    size_mismatches = size_mismatches_all[:diagnostic_limit]

    source_counts = {
        source: len(values)
        for source, values in sorted(roots.sources.items())
    }
    body: dict[str, Any] = {
        "schema": CAS_GC_SCHEMA,
        "generated_ms": generated_ms,
        "state_db": str(Path(state.db_path).absolute()),
        "blob_root": str(Path(blob_root).absolute()),
        "grace_ms": grace_ms,
        "batch_limit": batch_limit,
        "verify_content": bool(verify_content),
        "safe_to_execute": not errors,
        "errors": sorted(set(errors)),
        "root_count": len(roots.roots),
        "roots": sorted(roots.roots),
        "root_sources": {
            source: list(values)
            for source, values in sorted(roots.sources.items())
        },
        "root_source_counts": source_counts,
        "root_set_blake3": _digest_json(sorted(roots.roots)),
        "disk_count": len(disk),
        "disk_bytes": sum(identity.size for _, identity in disk.values()),
        "disk_set_blake3": _digest_json(
            [[digest, disk[digest][1].to_json()] for digest in sorted(disk)]
        ),
        "index_count": len(indexed),
        "stale_index_rows": stale_index,
        "stale_index_total": len(stale_index_all),
        "stale_index_set_blake3": _digest_json(stale_index_all),
        "rooted_missing_disk": rooted_missing,
        "rooted_missing_disk_total": len(rooted_missing_all),
        "rooted_missing_disk_set_blake3": _digest_json(rooted_missing_all),
        "unindexed_disk": unindexed_disk,
        "unindexed_disk_total": len(unindexed_disk_all),
        "unindexed_disk_set_blake3": _digest_json(unindexed_disk_all),
        "index_size_mismatches": size_mismatches,
        "index_size_mismatch_total": len(size_mismatches_all),
        "recent_unreferenced_count": recent_unreferenced,
        "corrupt_unreferenced": sorted(corrupt_unreferenced),
        "candidate_total": len(all_candidates),
        "candidate_total_bytes": sum(item["identity"]["size"] for item in all_candidates),
        "candidate_count": len(selected),
        "candidate_bytes": sum(item["identity"]["size"] for item in selected),
        "deferred_candidate_count": len(all_candidates) - len(selected),
        "candidates": selected,
    }
    body["manifest_blake3"] = _digest_json(body)
    return body


def validate_cas_gc_manifest(document: Mapping[str, Any]) -> dict[str, Any]:
    """Return a validated copy and verify the embedded whole-manifest digest."""

    data = dict(document)
    embedded = data.pop("manifest_blake3", None)
    if not _is_lower_hash(embedded) or _digest_json(data) != embedded:
        raise StorageLifecycleError("CAS GC manifest digest mismatch")
    if data.get("schema") != CAS_GC_SCHEMA or data.get("safe_to_execute") is not True:
        raise StorageLifecycleError("CAS GC manifest is unsafe or unsupported")
    candidates = data.get("candidates")
    if not isinstance(candidates, list) or len(candidates) > MAX_CAS_BATCH_LIMIT:
        raise StorageLifecycleError("CAS GC candidate list is invalid or unbounded")
    previous = ""
    for item in candidates:
        if not isinstance(item, dict) or not _is_lower_hash(item.get("hash")):
            raise StorageLifecycleError("CAS GC candidate address is invalid")
        digest = str(item["hash"])
        if digest <= previous:
            raise StorageLifecycleError("CAS GC candidates are not unique and sorted")
        previous = digest
        if item.get("relative_path") != f"{digest[:2]}/{digest[2:]}":
            raise StorageLifecycleError("CAS GC candidate path is not address-derived")
        FileIdentity.from_json(item.get("identity") or {})
        content_hash = item.get("content_blake3")
        if content_hash is not None and not _is_lower_hash(content_hash):
            raise StorageLifecycleError("CAS GC content evidence is malformed")
    data["manifest_blake3"] = embedded
    return data


def write_cas_gc_manifest(path: Path, document: Mapping[str, Any]) -> str:
    """Atomically write an integrity-sealed audit, including unsafe reports.

    An incomplete root scan still needs a machine-readable artifact explaining
    why execution is forbidden.  Execution performs the stricter
    :func:`validate_cas_gc_manifest` check later.
    """

    validated = dict(document)
    embedded = validated.pop("manifest_blake3", None)
    if (
        validated.get("schema") != CAS_GC_SCHEMA
        or not _is_lower_hash(embedded)
        or _digest_json(validated) != embedded
    ):
        raise StorageLifecycleError("cannot write an unsealed CAS GC audit")
    validated["manifest_blake3"] = embedded
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(
        f".{destination.name}.{os.getpid()}.{blake3.blake3(os.urandom(32)).hexdigest()[:12]}.tmp"
    )
    payload = _canonical_json(validated)
    try:
        with open(temporary, "xb") as handle:
            with contextlib.suppress(OSError):
                os.chmod(temporary, 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()
    return str(validated["manifest_blake3"])


def _append_journal(path: Path, event: Mapping[str, Any]) -> None:
    payload = _canonical_json(event) + b"\n"
    with open(path, "ab") as handle:
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _safe_quarantine_destination(root: Path, relative_path: str) -> Path:
    parts = Path(relative_path).parts
    if len(parts) != 2 or any(part in ("", ".", "..") for part in parts):
        raise StorageLifecycleError("invalid quarantine-relative object path")
    destination = root / "objects" / parts[0] / parts[1]
    if os.path.commonpath((_path_key(destination), _path_key(root))) != _path_key(root):
        raise StorageLifecycleError("quarantine destination escaped its root")
    return destination


def quarantine_cas_orphans(
    state: _StateLike,
    document: Mapping[str, Any],
    quarantine_root: Path,
    *,
    expected_manifest_blake3: str,
) -> dict[str, Any]:
    """Move a validated offline CAS batch to recoverable quarantine.

    The operation is resumable.  A crash after a rename but before its journal
    append is recognized by the exact identity at the address-derived
    destination.  The caller must hold the daemon's instance lock for the
    entire operation; the root-set recheck below additionally refuses a stale
    manifest even if this API is misused directly.
    """

    manifest = validate_cas_gc_manifest(document)
    if manifest["manifest_blake3"] != expected_manifest_blake3:
        raise StorageLifecycleError("externally pinned manifest digest mismatch")
    blob_root = Path(str(manifest["blob_root"]))
    root = Path(os.path.abspath(os.fspath(quarantine_root)))
    if os.path.commonpath((_path_key(root), _path_key(blob_root))) == _path_key(blob_root):
        raise StorageLifecycleError("quarantine root must not be inside the live blob store")

    live_roots = collect_durable_blob_roots(state)
    if not live_roots.complete:
        raise StorageLifecycleError("durable root scan became incomplete")
    if _digest_json(sorted(live_roots.roots)) != manifest["root_set_blake3"]:
        raise StorageLifecycleError("durable root set changed after manifest creation")
    candidate_hashes = {str(item["hash"]) for item in manifest["candidates"]}
    if candidate_hashes & live_roots.roots:
        raise StorageLifecycleError("a manifest candidate became a durable root")

    _assert_existing_path_chain_no_redirect(root)
    root.mkdir(parents=True, exist_ok=True)
    _assert_existing_path_chain_no_redirect(root)
    with contextlib.suppress(OSError):
        os.chmod(root, 0o700)
    root_stat = root.lstat()
    if _is_reparse_or_symlink(root, root_stat) or not stat.S_ISDIR(root_stat.st_mode):
        raise StorageLifecycleError("quarantine root is redirected or not a directory")
    try:
        blob_device = blob_root.lstat().st_dev
        quarantine_device = root.lstat().st_dev
    except OSError as exc:
        raise StorageLifecycleError("cannot establish quarantine volume identity") from exc
    if blob_device != quarantine_device:
        raise StorageLifecycleError("quarantine must be on the CAS volume for atomic moves")

    manifest_copy = root / "manifest.json"
    expected_payload = _canonical_json(manifest)
    if manifest_copy.exists():
        if manifest_copy.read_bytes() != expected_payload:
            raise StorageLifecycleError("quarantine contains a different manifest")
    else:
        with open(manifest_copy, "xb") as handle:
            handle.write(expected_payload)
            handle.flush()
            os.fsync(handle.fileno())
        with contextlib.suppress(OSError):
            os.chmod(manifest_copy, 0o600)
        _fsync_directory(root)
    journal = root / "journal.jsonl"
    moved: list[str] = []
    resumed: list[str] = []
    for item in manifest["candidates"]:
        digest = str(item["hash"])
        expected = FileIdentity.from_json(item["identity"])
        source = blob_root / digest[:2] / digest[2:]
        destination = _safe_quarantine_destination(root, str(item["relative_path"]))
        source_exists = source.exists() or source.is_symlink()
        destination_exists = destination.exists() or destination.is_symlink()
        if source_exists and destination_exists:
            raise StorageLifecycleError(f"both live and quarantined copies exist: {digest}")
        if destination_exists:
            destination_stat = destination.lstat()
            if (
                _is_reparse_or_symlink(destination, destination_stat)
                or not stat.S_ISREG(destination_stat.st_mode)
                or not _same_object_after_rename(
                    FileIdentity.from_stat(destination_stat), expected
                )
            ):
                raise StorageLifecycleError(f"quarantined identity mismatch: {digest}")
            resumed.append(digest)
            _append_journal(
                journal,
                {"event": "resume_observed", "hash": digest, "identity": expected.to_json()},
            )
            continue
        safe_source, observed = _strict_regular_beneath(blob_root, source)
        if observed != expected:
            raise StorageLifecycleError(f"live CAS identity changed: {digest}")
        _ensure_real_directory_beneath(root, destination.parent)
        os.replace(safe_source, destination)
        destination_stat = destination.lstat()
        if (
            _is_reparse_or_symlink(destination, destination_stat)
            or not stat.S_ISREG(destination_stat.st_mode)
            or not _same_object_after_rename(
                FileIdentity.from_stat(destination_stat), expected
            )
        ):
            with contextlib.suppress(OSError):
                os.replace(destination, safe_source)
            raise StorageLifecycleError(f"identity changed during CAS quarantine: {digest}")
        _fsync_directory(destination.parent)
        _fsync_directory(safe_source.parent)
        _append_journal(
            journal,
            {"event": "moved", "hash": digest, "identity": expected.to_json()},
        )
        moved.append(digest)

    # ``blobs`` is only an inventory index, never a GC root.  Remove index
    # rows only after every selected object is recoverably present.  Journal
    # the prior values first so an operator can reconstruct them on rollback.
    with state._write_lock:
        live_roots_after = collect_durable_blob_roots(state)
        if (
            not live_roots_after.complete
            or _digest_json(sorted(live_roots_after.roots)) != manifest["root_set_blake3"]
        ):
            raise StorageLifecycleError("durable roots changed before index reconciliation")
        removable_index_hashes = sorted(
            candidate_hashes
            | {
                str(digest)
                for digest in manifest.get("stale_index_rows", [])
                if digest not in live_roots_after.roots
            }
        )
        prior_rows: list[dict[str, int | str]] = []
        for digest in removable_index_hashes:
            row = state._conn.execute(
                "SELECT hash, size, received_ms FROM blobs WHERE hash=?", (digest,)
            ).fetchone()
            if row is not None:
                prior_rows.append(
                    {
                        "hash": str(row["hash"]),
                        "size": int(row["size"]),
                        "received_ms": int(row["received_ms"]),
                    }
                )
        _append_journal(journal, {"event": "index_delete_intent", "rows": prior_rows})
        state._conn.execute("BEGIN IMMEDIATE")
        try:
            state._conn.executemany(
                "DELETE FROM blobs WHERE hash=?",
                [(digest,) for digest in removable_index_hashes],
            )
            state._conn.execute("COMMIT")
        except Exception:
            with contextlib.suppress(Exception):
                state._conn.execute("ROLLBACK")
            raise
        _append_journal(
            journal,
            {"event": "index_deleted", "hashes": removable_index_hashes},
        )

    completion = {
        "schema": CAS_QUARANTINE_SCHEMA,
        "manifest_blake3": manifest["manifest_blake3"],
        "moved": sorted(moved),
        "resumed": sorted(resumed),
        "quarantined": sorted(candidate_hashes),
        "completed_ms": int(time.time() * 1000),
    }
    completion["completion_blake3"] = _digest_json(completion)
    completion_path = root / "complete.json"
    temporary = root / f".complete.{os.getpid()}.tmp"
    with open(temporary, "wb") as handle:
        handle.write(_canonical_json(completion))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, completion_path)
    _fsync_directory(root)
    return completion


def rollback_cas_quarantine(
    state: _StateLike,
    quarantine_root: Path,
    *,
    expected_manifest_blake3: str,
) -> dict[str, Any]:
    """Restore a completed or interrupted quarantine without following links."""

    root = Path(quarantine_root)
    _assert_existing_path_chain_no_redirect(root)
    manifest_path = root / "manifest.json"
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise StorageLifecycleError("quarantine manifest cannot be read") from exc
    manifest = validate_cas_gc_manifest(document)
    if manifest["manifest_blake3"] != expected_manifest_blake3:
        raise StorageLifecycleError("rollback manifest digest mismatch")
    blob_root = Path(str(manifest["blob_root"]))
    restored: list[str] = []
    for item in reversed(manifest["candidates"]):
        digest = str(item["hash"])
        expected = FileIdentity.from_json(item["identity"])
        source = _safe_quarantine_destination(root, str(item["relative_path"]))
        destination = blob_root / digest[:2] / digest[2:]
        if destination.exists() or destination.is_symlink():
            destination_stat = destination.lstat()
            if (
                _is_reparse_or_symlink(destination, destination_stat)
                or not _same_object_after_rename(
                    FileIdentity.from_stat(destination_stat), expected
                )
            ):
                raise StorageLifecycleError(f"live rollback destination is occupied: {digest}")
            if source.exists() or source.is_symlink():
                raise StorageLifecycleError(f"both rollback copies exist: {digest}")
            continue
        if not (source.exists() or source.is_symlink()):
            continue
        safe_source, observed = _strict_regular_beneath(root / "objects", source)
        if not _same_object_after_rename(observed, expected):
            raise StorageLifecycleError(f"quarantine object changed before rollback: {digest}")
        _ensure_real_directory_beneath(blob_root, destination.parent)
        os.replace(safe_source, destination)
        _fsync_directory(destination.parent)
        _fsync_directory(safe_source.parent)
        restored.append(digest)

    prior_rows: dict[str, dict[str, int | str]] = {}
    journal_path = root / "journal.jsonl"
    if journal_path.exists():
        lines = journal_path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            try:
                event = json.loads(line)
            except ValueError as exc:
                # A power loss may tear only the final append.  Earlier
                # records were individually fsynced and remain authoritative.
                if index == len(lines) - 1:
                    break
                raise StorageLifecycleError("quarantine journal is malformed") from exc
            if event.get("event") == "index_delete_intent":
                for row in event.get("rows", []):
                    if isinstance(row, dict) and _is_lower_hash(row.get("hash")):
                        prior_rows[str(row["hash"])] = row
    with state._write_lock:
        state._conn.execute("BEGIN IMMEDIATE")
        try:
            for row in prior_rows.values():
                state._conn.execute(
                    "INSERT OR REPLACE INTO blobs(hash,size,received_ms) VALUES(?,?,?)",
                    (str(row["hash"]), int(row["size"]), int(row["received_ms"])),
                )
            state._conn.execute("COMMIT")
        except Exception:
            with contextlib.suppress(Exception):
                state._conn.execute("ROLLBACK")
            raise
    result = {
        "ok": True,
        "manifest_blake3": expected_manifest_blake3,
        "restored": sorted(restored),
        "index_rows_restored": len(prior_rows),
    }
    _append_journal(journal_path, {"event": "rollback_complete", **result})
    return result


def _read_json_object(path: Path, description: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise StorageLifecycleError(f"{description} cannot be read") from exc
    if not isinstance(value, dict):
        raise StorageLifecycleError(f"{description} is not an object")
    return value


def _read_quarantine_journal(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise StorageLifecycleError("quarantine journal cannot be read") from exc
    events: list[dict[str, Any]] = []
    for index, line in enumerate(lines):
        try:
            event = json.loads(line)
        except ValueError as exc:
            if index == len(lines) - 1:
                break
            raise StorageLifecycleError("quarantine journal is malformed") from exc
        if not isinstance(event, dict):
            raise StorageLifecycleError("quarantine journal event is not an object")
        events.append(event)
    return events


def purge_cas_quarantine(
    state: _StateLike,
    quarantine_root: Path,
    *,
    expected_manifest_blake3: str,
    now_ms: int | None = None,
    quarantine_grace_ms: int = DEFAULT_QUARANTINE_GRACE_MS,
    batch_limit: int = DEFAULT_CAS_BATCH_LIMIT,
) -> dict[str, Any]:
    """Permanently unlink an aged, completed quarantine in bounded batches.

    This is intentionally stricter than quarantine: every candidate must
    remain absent from the live CAS and from the current durable root graph.
    A durable per-object intent makes a crash after unlink resumable, but the
    operation is irreversible once the recovery copy is gone.
    """

    root = Path(os.path.abspath(os.fspath(quarantine_root)))
    _assert_existing_path_chain_no_redirect(root)
    manifest = validate_cas_gc_manifest(
        _read_json_object(root / "manifest.json", "quarantine manifest")
    )
    if manifest["manifest_blake3"] != expected_manifest_blake3:
        raise StorageLifecycleError("purge manifest digest mismatch")
    completion = _read_json_object(root / "complete.json", "quarantine completion")
    completion_digest = completion.pop("completion_blake3", None)
    if (
        completion.get("schema") != CAS_QUARANTINE_SCHEMA
        or completion.get("manifest_blake3") != expected_manifest_blake3
        or not _is_lower_hash(completion_digest)
        or _digest_json(completion) != completion_digest
    ):
        raise StorageLifecycleError("quarantine completion evidence is invalid")
    completed_ms = completion.get("completed_ms")
    if type(completed_ms) is not int:
        raise StorageLifecycleError("quarantine completion time is invalid")
    current_ms = int(time.time() * 1000) if now_ms is None else int(now_ms)
    grace_ms = max(0, int(quarantine_grace_ms))
    if int(completed_ms) > current_ms - grace_ms:
        raise StorageLifecycleError("quarantine recovery grace has not elapsed")

    live_roots = collect_durable_blob_roots(state)
    if not live_roots.complete:
        raise StorageLifecycleError("durable roots are unreadable before purge")
    candidates = {str(item["hash"]): item for item in manifest["candidates"]}
    newly_referenced = sorted(set(candidates) & live_roots.roots)
    if newly_referenced:
        raise StorageLifecycleError("a quarantined blob became a durable root")
    blob_root = Path(str(manifest["blob_root"]))
    for digest in sorted(candidates):
        live_path = blob_root / digest[:2] / digest[2:]
        if live_path.exists() or live_path.is_symlink():
            raise StorageLifecycleError("a quarantined blob also exists in the live CAS")

    journal_path = root / "journal.jsonl"
    events = _read_quarantine_journal(journal_path)
    if any(event.get("event") == "rollback_complete" for event in events):
        raise StorageLifecycleError("a rolled-back quarantine cannot be purged")
    purge_intents = {
        str(event.get("hash"))
        for event in events
        if event.get("event") == "purge_intent" and _is_lower_hash(event.get("hash"))
    }
    limit = max(1, min(int(batch_limit), MAX_CAS_BATCH_LIMIT))
    purged: list[str] = []
    recovered: list[str] = []
    processed = 0
    objects_root = root / "objects"
    for digest, item in sorted(candidates.items()):
        if processed >= limit:
            break
        path = _safe_quarantine_destination(root, str(item["relative_path"]))
        if not (path.exists() or path.is_symlink()):
            if digest not in purge_intents:
                raise StorageLifecycleError(
                    f"quarantine object vanished without a purge intent: {digest}"
                )
            recovered.append(digest)
            continue
        expected = FileIdentity.from_json(item["identity"])
        safe_path, observed = _strict_regular_beneath(objects_root, path)
        if not _same_object_after_rename(observed, expected):
            raise StorageLifecycleError(f"quarantine object changed before purge: {digest}")
        _append_journal(
            journal_path,
            {"event": "purge_intent", "hash": digest, "identity": observed.to_json()},
        )
        before_unlink = safe_path.lstat()
        if (
            _is_reparse_or_symlink(safe_path, before_unlink)
            or not _same_object_after_rename(FileIdentity.from_stat(before_unlink), expected)
        ):
            raise StorageLifecycleError(f"quarantine object raced before purge: {digest}")
        safe_path.unlink()
        _fsync_directory(safe_path.parent)
        _append_journal(journal_path, {"event": "purged", "hash": digest})
        purged.append(digest)
        processed += 1

    remaining = 0
    for digest, item in candidates.items():
        path = _safe_quarantine_destination(root, str(item["relative_path"]))
        if path.exists() or path.is_symlink():
            remaining += 1
    result: dict[str, Any] = {
        "ok": True,
        "manifest_blake3": expected_manifest_blake3,
        "purged": sorted(purged),
        "recovered_prior_purges": sorted(recovered),
        "remaining": remaining,
        "batch_limit": limit,
    }
    if remaining == 0:
        result["completed_ms"] = current_ms
        result["purge_blake3"] = _digest_json(result)
        marker = root / "purge-complete.json"
        temporary = root / f".purge-complete.{os.getpid()}.tmp"
        with open(temporary, "wb") as handle:
            handle.write(_canonical_json(result))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, marker)
        _fsync_directory(root)
    return result
