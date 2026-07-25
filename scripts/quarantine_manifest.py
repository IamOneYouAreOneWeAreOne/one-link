"""Fail-closed, manifest-driven quarantine executor.

The default mode is validation only.  Mutation requires ``--execute`` plus an
externally pinned whole-manifest BLAKE3 and an exact, non-existent quarantine
root.  Execute mode performs a graceful control-channel shutdown and refuses
to fall back to process termination.  It then re-reads the pinned manifest,
revalidates every explicit source and destination, and atomically renames only
the listed files.  No glob is used for selection or movement and this module
contains no deletion path.

The v2 manifest is intentionally the authority for *which* files may move;
the separately supplied manifest digest is the authority for the manifest.
Every move is journaled and verified, with exact reverse-order rollback on a
caught failure.  A successful quarantine remains recoverable until a separate,
explicitly approved deletion operation is performed elsewhere.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import json
import logging
import os
import socket
import sqlite3
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Sequence, TypeGuard

import blake3


log = logging.getLogger(__name__)


SUPPORTED_SCHEMA = "one-link-pytest-pollution-audit/v2"
TARGET_KEYS = frozenset(
    {"kind", "source_path", "relative_destination", "size", "blake3"}
)
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_CONTROL_REPLY_BYTES = 4 * 1024 * 1024
MAX_TARGETS = 1_000_000
HASH_HEX_LEN = 64
AT_FDCWD = -100
RENAME_NOREPLACE = 1
MOVEFILE_WRITE_THROUGH = 0x00000008
ERROR_FILE_EXISTS = 80
ERROR_ALREADY_EXISTS = 183
MAX_RESUME_METADATA_BYTES = 4 * 1024 * 1024
MAX_REFERENCE_TOKENS = 512
STATE_REFERENCE_KEYS = frozenset(
    {
        "transfers_by_blob_or_original_name",
        "chunk_availability_by_chunk_or_blob",
        "chunk_sources_by_chunk",
        "blobs_by_hash",
        "file_index_cache_by_blob",
        "folder_manifest_by_blob",
        "folder_audit_by_blob",
        "manifest_conflicts_by_local_or_remote_blob",
    }
)


class QuarantineError(RuntimeError):
    """A fail-closed validation, shutdown, move, or rollback failure."""


@dataclass(frozen=True)
class QuarantineTarget:
    kind: str
    source_path: Path
    relative_destination: PurePosixPath
    size: int
    blake3: str

    def as_manifest_object(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "source_path": str(self.source_path),
            "relative_destination": self.relative_destination.as_posix(),
            "size": self.size,
            "blake3": self.blake3,
        }


@dataclass(frozen=True)
class PreserveFile:
    source_path: Path
    size: int
    blake3: str


@dataclass(frozen=True)
class QuarantinePlan:
    manifest_path: Path
    manifest_bytes: bytes
    manifest_blake3: str
    schema: str
    app_root: Path
    inbox_root: Path
    state_db: Path
    quarantine_root: Path
    allowed_source_roots: dict[str, Path]
    targets: tuple[QuarantineTarget, ...]
    preserve_files: tuple[PreserveFile, ...]
    target_set_blake3: str
    target_bytes: int


@dataclass(frozen=True)
class CompanionManifest:
    path: Path
    data: bytes
    blake3: str


@dataclass(frozen=True)
class RuntimeSnapshot:
    daemon_pid: int
    supervisor_pid: int | None
    ports: tuple[int, ...]


def _is_lower_hex_digest(value: Any) -> TypeGuard[str]:
    return (
        isinstance(value, str)
        and len(value) == HASH_HEX_LEN
        and all(char in "0123456789abcdef" for char in value)
    )


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _is_within(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((_path_key(path), _path_key(root))) == _path_key(root)
    except ValueError:
        return False


def _is_reparse_or_symlink(path: Path) -> bool:
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode):
        return True
    attributes = int(getattr(st, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    return bool(attributes & reparse_flag)


def _assert_existing_path_chain(path: Path, root: Path) -> Path:
    """Reject lexical escape and any symlink/reparse component root..path."""

    lexical_path = Path(os.path.abspath(os.fspath(path)))
    lexical_root = Path(os.path.abspath(os.fspath(root)))
    if not _is_within(lexical_path, lexical_root):
        raise QuarantineError(f"source escapes allowed root: {path} not under {root}")
    if not lexical_root.is_dir():
        raise QuarantineError(f"allowed source root is not a directory: {root}")
    relative = Path(os.path.relpath(lexical_path, lexical_root))
    if relative == Path("."):
        components: tuple[str, ...] = ()
    else:
        components = relative.parts
    if any(part in ("", ".", "..") for part in components):
        raise QuarantineError(f"unsafe source path components: {path}")
    current = lexical_root
    if _is_reparse_or_symlink(current):
        raise QuarantineError(f"allowed source root is a reparse point: {current}")
    for component in components:
        current = current / component
        if not current.exists():
            raise QuarantineError(f"manifest source does not exist: {current}")
        if _is_reparse_or_symlink(current):
            raise QuarantineError(f"source chain contains a reparse point: {current}")
    resolved_root = lexical_root.resolve(strict=True)
    resolved = lexical_path.resolve(strict=True)
    if not _is_within(resolved, resolved_root):
        raise QuarantineError(f"resolved source escapes allowed root: {resolved}")
    return resolved


def _deepest_existing_ancestor(path: Path) -> Path:
    current = Path(os.path.abspath(os.fspath(path)))
    while not current.exists():
        parent = current.parent
        if parent == current:
            raise QuarantineError(f"no existing ancestor for path: {path}")
        current = parent
    return current


def _assert_destination_ancestor_safe(quarantine_root: Path) -> None:
    current = _deepest_existing_ancestor(quarantine_root)
    while True:
        if _is_reparse_or_symlink(current):
            raise QuarantineError(
                f"quarantine ancestor is a symlink/reparse point: {current}"
            )
        parent = current.parent
        if parent == current:
            break
        current = parent


def _validate_relative_destination(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        raise QuarantineError("relative_destination must be a non-empty string")
    if "\\" in value or "\x00" in value or ":" in value:
        raise QuarantineError(f"unsafe destination spelling: {value!r}")
    destination = PurePosixPath(value)
    if destination.is_absolute():
        raise QuarantineError(f"destination must be relative: {value!r}")
    if any(part in ("", ".", "..") for part in destination.parts):
        raise QuarantineError(f"unsafe destination components: {value!r}")
    return destination


def _destination_for(plan: QuarantinePlan, target: QuarantineTarget) -> Path:
    destination = plan.quarantine_root.joinpath(*target.relative_destination.parts)
    absolute = Path(os.path.abspath(os.fspath(destination)))
    if not _is_within(absolute, plan.quarantine_root):
        raise QuarantineError(f"destination escapes quarantine root: {destination}")
    return absolute


def _digest_bytes(data: bytes) -> str:
    return blake3.blake3(data).hexdigest()


def _digest_file(path: Path) -> str:
    hasher = blake3.blake3()
    with path.open("rb") as handle:
        while block := handle.read(4 * 1024 * 1024):
            hasher.update(block)
    return hasher.hexdigest()


def _read_regular_file(path: Path, *, max_bytes: int = MAX_MANIFEST_BYTES) -> bytes:
    lexical = Path(os.path.abspath(os.fspath(path)))
    if not lexical.exists():
        raise QuarantineError(f"file does not exist: {lexical}")
    if _is_reparse_or_symlink(lexical):
        raise QuarantineError(f"refusing symlink/reparse file: {lexical}")
    before = lexical.stat()
    if not stat.S_ISREG(before.st_mode):
        raise QuarantineError(f"not a regular file: {lexical}")
    if before.st_size > max_bytes:
        raise QuarantineError(f"file exceeds {max_bytes} byte limit: {lexical}")
    with lexical.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise QuarantineError(f"file identity changed while opening: {lexical}")
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise QuarantineError(f"file exceeds {max_bytes} byte limit: {lexical}")
    after = lexical.stat()
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ):
        raise QuarantineError(f"file changed during read: {lexical}")
    return data


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise QuarantineError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _parse_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_object_without_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QuarantineError(f"{label} is not valid canonical UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise QuarantineError(f"{label} root must be a JSON object")
    return parsed


def _absolute_path(value: Any, *, label: str, must_exist: bool) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise QuarantineError(f"{label} must be a non-empty path string")
    path = Path(value)
    if not path.is_absolute():
        raise QuarantineError(f"{label} must be absolute: {value!r}")
    absolute = Path(os.path.abspath(os.fspath(path)))
    if must_exist and not absolute.exists():
        raise QuarantineError(f"{label} does not exist: {absolute}")
    return absolute


def _parse_nonnegative_int(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise QuarantineError(f"{label} must be a non-negative JSON integer")
    return value


def _load_companion(path: Path, expected_blake3: str) -> CompanionManifest:
    if not _is_lower_hex_digest(expected_blake3):
        raise QuarantineError("expected companion BLAKE3 must be 64 lowercase hex")
    data = _read_regular_file(path)
    actual = _digest_bytes(data)
    if actual != expected_blake3:
        raise QuarantineError(
            f"companion manifest digest mismatch: expected {expected_blake3}, got {actual}"
        )
    return CompanionManifest(path=path.resolve(strict=True), data=data, blake3=actual)


def load_plan(
    manifest_path: Path,
    *,
    expected_manifest_blake3: str,
    quarantine_root: Path,
    expected_schema: str = SUPPORTED_SCHEMA,
) -> QuarantinePlan:
    """Load and structurally validate a hash-pinned v2 manifest."""

    if not _is_lower_hex_digest(expected_manifest_blake3):
        raise QuarantineError("expected manifest BLAKE3 must be 64 lowercase hex")
    raw = _read_regular_file(manifest_path)
    actual_manifest_digest = _digest_bytes(raw)
    if actual_manifest_digest != expected_manifest_blake3:
        raise QuarantineError(
            "manifest digest mismatch: "
            f"expected {expected_manifest_blake3}, got {actual_manifest_digest}"
        )
    document = _parse_json_object(raw, label="manifest")
    if document.get("schema") != expected_schema:
        raise QuarantineError(
            f"manifest schema mismatch: expected {expected_schema!r}, "
            f"got {document.get('schema')!r}"
        )

    requested_root = _absolute_path(
        str(quarantine_root), label="quarantine root", must_exist=False
    )
    proposed_root = _absolute_path(
        document.get("proposed_quarantine_root_not_created"),
        label="manifest proposed quarantine root",
        must_exist=False,
    )
    if _path_key(requested_root) != _path_key(proposed_root):
        raise QuarantineError(
            f"quarantine root mismatch: CLI={requested_root}, manifest={proposed_root}"
        )
    if requested_root.exists():
        raise QuarantineError(f"quarantine root already exists: {requested_root}")
    _assert_destination_ancestor_safe(requested_root)

    roots = document.get("roots")
    if not isinstance(roots, dict):
        raise QuarantineError("manifest roots must be an object")
    app_root = _absolute_path(roots.get("app_root"), label="app_root", must_exist=True)
    inbox_root = _absolute_path(roots.get("inbox"), label="inbox", must_exist=True)
    state_db = _absolute_path(
        roots.get("state_db"), label="state_db", must_exist=True
    )
    if not app_root.is_dir() or not inbox_root.is_dir():
        raise QuarantineError("manifest app_root and inbox must be directories")
    resolved_state_db = _assert_existing_path_chain(state_db, app_root)
    if not resolved_state_db.is_file():
        raise QuarantineError("manifest state_db must be a regular file")
    if _is_within(requested_root, app_root) or _is_within(app_root, requested_root):
        raise QuarantineError("quarantine root must be disjoint from the live app root")

    target_schema = document.get("quarantine_target_schema")
    if not isinstance(target_schema, dict):
        raise QuarantineError("quarantine_target_schema must be an object")
    required_keys = target_schema.get("required_keys")
    if not isinstance(required_keys, list) or set(required_keys) != TARGET_KEYS:
        raise QuarantineError("manifest target required_keys do not match v2 contract")
    destination_authority = _absolute_path(
        target_schema.get("destination_must_be_relative_to"),
        label="destination authority",
        must_exist=False,
    )
    if _path_key(destination_authority) != _path_key(requested_root):
        raise QuarantineError("destination authority differs from quarantine root")
    roots_by_kind_raw = target_schema.get("allowed_kinds_and_source_roots")
    if not isinstance(roots_by_kind_raw, dict) or not roots_by_kind_raw:
        raise QuarantineError("allowed_kinds_and_source_roots must be non-empty")
    allowed_roots: dict[str, Path] = {}
    for kind, root_value in roots_by_kind_raw.items():
        if not isinstance(kind, str) or not kind:
            raise QuarantineError("target kind names must be non-empty strings")
        root = _absolute_path(root_value, label=f"root for {kind}", must_exist=True)
        if not root.is_dir() or _is_reparse_or_symlink(root):
            raise QuarantineError(f"unsafe source root for {kind}: {root}")
        if not _is_within(root.resolve(strict=True), app_root.resolve(strict=True)):
            raise QuarantineError(f"source root for {kind} is outside app_root")
        allowed_roots[kind] = root.resolve(strict=True)

    raw_targets = document.get("quarantine_targets")
    if not isinstance(raw_targets, list):
        raise QuarantineError("quarantine_targets must be an array")
    if not (1 <= len(raw_targets) <= MAX_TARGETS):
        raise QuarantineError("quarantine target count is outside the safety bound")
    declared_count = _parse_nonnegative_int(
        document.get("quarantine_target_count"), label="quarantine_target_count"
    )
    if declared_count != len(raw_targets):
        raise QuarantineError("declared quarantine target count does not match array")

    targets: list[QuarantineTarget] = []
    seen_sources: set[str] = set()
    seen_destinations: set[str] = set()
    total_bytes = 0
    for index, raw_target in enumerate(raw_targets):
        if not isinstance(raw_target, dict) or set(raw_target) != TARGET_KEYS:
            raise QuarantineError(f"target {index} does not have the exact v2 schema")
        kind = raw_target.get("kind")
        if not isinstance(kind, str) or kind not in allowed_roots:
            raise QuarantineError(f"target {index} uses an unapproved kind")
        source = _absolute_path(
            raw_target.get("source_path"),
            label=f"target {index} source_path",
            must_exist=False,
        )
        destination = _validate_relative_destination(
            raw_target.get("relative_destination")
        )
        size = _parse_nonnegative_int(raw_target.get("size"), label=f"target {index} size")
        digest = raw_target.get("blake3")
        if not _is_lower_hex_digest(digest):
            raise QuarantineError(f"target {index} BLAKE3 is invalid")
        source_key = _path_key(source)
        destination_key = destination.as_posix().casefold()
        if source_key in seen_sources:
            raise QuarantineError(f"duplicate target source: {source}")
        if destination_key in seen_destinations:
            raise QuarantineError(f"duplicate target destination: {destination}")
        seen_sources.add(source_key)
        seen_destinations.add(destination_key)
        total_bytes += size
        targets.append(
            QuarantineTarget(
                kind=kind,
                source_path=source,
                relative_destination=destination,
                size=size,
                blake3=digest,
            )
        )

    declared_bytes = _parse_nonnegative_int(
        document.get("quarantine_target_bytes"), label="quarantine_target_bytes"
    )
    if declared_bytes != total_bytes:
        raise QuarantineError("declared target byte total does not match target array")
    declared_target_digest = document.get("quarantine_target_set_blake3")
    if not _is_lower_hex_digest(declared_target_digest):
        raise QuarantineError("quarantine_target_set_blake3 is invalid")
    canonical = json.dumps(
        raw_targets,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    actual_target_digest = _digest_bytes(canonical)
    if actual_target_digest != declared_target_digest:
        raise QuarantineError(
            "canonical target-set digest mismatch: "
            f"expected {declared_target_digest}, got {actual_target_digest}"
        )

    reference_audit = document.get("state_reference_audit")
    if not isinstance(reference_audit, dict):
        raise QuarantineError("state_reference_audit is required")
    if reference_audit.get("state_opened_uri_mode_ro_and_query_only") is not True:
        raise QuarantineError("state audit does not prove mode=ro and query_only")
    reference_counts = reference_audit.get("target_reference_counts")
    if not isinstance(reference_counts, dict) or set(reference_counts) != STATE_REFERENCE_KEYS:
        raise QuarantineError(
            "target_reference_counts must contain the exact supported query set"
        )
    for label, value in reference_counts.items():
        if _parse_nonnegative_int(value, label=f"reference count {label}") != 0:
            raise QuarantineError(f"durable state still references quarantine target: {label}")

    raw_preserve = document.get("preserve_genuine_files")
    if not isinstance(raw_preserve, list):
        raise QuarantineError("preserve_genuine_files must be an array")
    preserve_files: list[PreserveFile] = []
    preserve_seen: set[str] = set()
    for index, item in enumerate(raw_preserve):
        if not isinstance(item, dict):
            raise QuarantineError(f"preserve entry {index} must be an object")
        relative = _validate_relative_destination(item.get("relative_path"))
        source = inbox_root.joinpath(*relative.parts)
        source_key = _path_key(source)
        if source_key in seen_sources or source_key in preserve_seen:
            raise QuarantineError(f"preserve entry overlaps or duplicates a target: {source}")
        preserve_seen.add(source_key)
        size = _parse_nonnegative_int(item.get("size"), label=f"preserve {index} size")
        digest = item.get("blake3")
        if not _is_lower_hex_digest(digest):
            raise QuarantineError(f"preserve entry {index} BLAKE3 is invalid")
        ledger_matches = item.get("inbound_complete_ledger_match_count")
        if (
            isinstance(ledger_matches, bool)
            or not isinstance(ledger_matches, int)
            or ledger_matches <= 0
            or item.get("ledger_size_match") is not True
        ):
            raise QuarantineError(f"preserve entry {index} lacks completed-ledger proof")
        preserve_files.append(PreserveFile(source_path=source, size=size, blake3=digest))

    return QuarantinePlan(
        manifest_path=manifest_path.resolve(strict=True),
        manifest_bytes=raw,
        manifest_blake3=actual_manifest_digest,
        schema=expected_schema,
        app_root=app_root.resolve(strict=True),
        inbox_root=inbox_root.resolve(strict=True),
        state_db=resolved_state_db,
        quarantine_root=requested_root,
        allowed_source_roots=allowed_roots,
        targets=tuple(targets),
        preserve_files=tuple(preserve_files),
        target_set_blake3=actual_target_digest,
        target_bytes=total_bytes,
    )


def _assert_same_volume(source: Path, destination_root: Path) -> None:
    destination_ancestor = _deepest_existing_ancestor(destination_root)
    if source.stat().st_dev != destination_ancestor.stat().st_dev:
        raise QuarantineError(
            f"source and quarantine are on different volumes: {source}"
        )


def _validate_target_source(plan: QuarantinePlan, target: QuarantineTarget) -> Path:
    source = _assert_existing_path_chain(
        target.source_path, plan.allowed_source_roots[target.kind]
    )
    st = source.stat()
    if not stat.S_ISREG(st.st_mode):
        raise QuarantineError(f"target source is not a regular file: {source}")
    if st.st_size != target.size:
        raise QuarantineError(
            f"target size changed: {source} expected={target.size} actual={st.st_size}"
        )
    actual_digest = _digest_file(source)
    if actual_digest != target.blake3:
        raise QuarantineError(
            f"target hash changed: {source} expected={target.blake3} "
            f"actual={actual_digest}"
        )
    _assert_same_volume(source, plan.quarantine_root)
    return source


def _validate_preserve_file(plan: QuarantinePlan, preserved: PreserveFile) -> None:
    source = _assert_existing_path_chain(preserved.source_path, plan.inbox_root)
    st = source.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_size != preserved.size:
        raise QuarantineError(f"preserved file size/type changed: {source}")
    actual_digest = _digest_file(source)
    if actual_digest != preserved.blake3:
        raise QuarantineError(f"preserved file hash changed: {source}")


def validate_sources(plan: QuarantinePlan) -> dict[str, int]:
    """Revalidate every explicit target and every preserve proof."""

    if plan.quarantine_root.exists():
        raise QuarantineError(f"quarantine root already exists: {plan.quarantine_root}")
    _assert_destination_ancestor_safe(plan.quarantine_root)
    for target in plan.targets:
        _validate_target_source(plan, target)
        destination = _destination_for(plan, target)
        if destination.exists():
            raise QuarantineError(f"quarantine destination already exists: {destination}")
    for preserved in plan.preserve_files:
        _validate_preserve_file(plan, preserved)
    return {
        "targets": len(plan.targets),
        "target_bytes": plan.target_bytes,
        "preserve_files": len(plan.preserve_files),
    }


def _collect_target_reference_tokens(
    plan: QuarantinePlan,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Derive the exact blob/chunk hashes and original names to re-query.

    The pinned v2 format does not duplicate these fields at top level.  Its
    hash-verified resume sidecars are the authority for blob hashes and
    original names, while a chunk-cache target's two path components are the
    authority for its content-addressed chunk hash.  Ambiguous metadata is a
    refusal, never a reason to skip the post-stop state check.
    """

    hashes: set[str] = set()
    names: set[str] = set()
    for target in plan.targets:
        if target.kind == "chunk_cache":
            source = _assert_existing_path_chain(
                target.source_path, plan.allowed_source_roots[target.kind]
            )
            relative = source.relative_to(plan.allowed_source_roots[target.kind])
            if (
                len(relative.parts) != 2
                or len(relative.parts[0]) != 2
                or len(relative.parts[1]) != 62
            ):
                raise QuarantineError(
                    f"chunk-cache target has a non-content-addressed path: {source}"
                )
            chunk_hash = "".join(relative.parts)
            if not _is_lower_hex_digest(chunk_hash) or chunk_hash != target.blake3:
                raise QuarantineError(
                    f"chunk-cache path/hash authority mismatch: {source}"
                )
            hashes.add(chunk_hash)
        elif target.kind == "resume_sidecar":
            raw = _read_regular_file(
                target.source_path, max_bytes=MAX_RESUME_METADATA_BYTES
            )
            if len(raw) != target.size or _digest_bytes(raw) != target.blake3:
                raise QuarantineError(
                    f"resume sidecar changed while deriving state keys: {target.source_path}"
                )
            metadata = _parse_json_object(raw, label=f"resume sidecar {target.source_path}")
            blob_hex = metadata.get("blob_hex")
            name = metadata.get("name")
            if not _is_lower_hex_digest(blob_hex):
                raise QuarantineError(
                    f"resume sidecar lacks a valid blob_hex: {target.source_path}"
                )
            if target.source_path.stem != blob_hex:
                raise QuarantineError(
                    f"resume sidecar filename/blob authority mismatch: {target.source_path}"
                )
            if (
                not isinstance(name, str)
                or not name
                or len(name) > 4096
                or "\x00" in name
            ):
                raise QuarantineError(
                    f"resume sidecar lacks a safe original name: {target.source_path}"
                )
            chunks = metadata.get("cdc_chunks")
            if not isinstance(chunks, list) or not chunks:
                raise QuarantineError(
                    f"resume sidecar lacks its CDC hash authority: {target.source_path}"
                )
            hashes.add(blob_hex)
            names.add(name)
            for index, chunk in enumerate(chunks):
                sidecar_chunk_hash = (
                    chunk.get("hash") if isinstance(chunk, dict) else None
                )
                if not _is_lower_hex_digest(sidecar_chunk_hash):
                    raise QuarantineError(
                        "resume sidecar contains an invalid CDC hash at "
                        f"{target.source_path} index={index}"
                    )
                hashes.add(sidecar_chunk_hash)
    if not hashes or not names:
        raise QuarantineError(
            "manifest does not provide unambiguous target blob hashes and names"
        )
    if len(hashes) > MAX_REFERENCE_TOKENS or len(names) > MAX_REFERENCE_TOKENS:
        raise QuarantineError("target state-reference token set exceeds safety bound")
    return tuple(sorted(hashes)), tuple(sorted(names))


def _enable_and_prove_query_only(connection: Any) -> None:
    connection.execute("PRAGMA query_only = ON")
    row = connection.execute("PRAGMA query_only").fetchone()
    if row is None or int(row[0]) != 1:
        raise QuarantineError("state connection did not enter PRAGMA query_only mode")


def _state_passphrase_read_only(state_db: Path) -> str:
    """Retrieve an existing repository key without minting or chmod/mkdir calls."""

    try:
        from one_link import keychain
    except Exception as exc:
        raise QuarantineError(
            "repository keychain module is unavailable for encrypted state audit"
        ) from exc
    from_environment = os.environ.get(keychain.ENV_VAR, "").strip()
    if from_environment:
        return from_environment
    backend = keychain._load_keyring()
    if backend is not None:
        try:
            existing = backend.get_password(
                keychain.ONE_LINK_KEYCHAIN_SERVICE,
                keychain.ONE_LINK_KEYCHAIN_USER,
            )
            if existing:
                return existing
        except Exception as exc:
            log.warning(
                "best-effort keyring lookup failed (error_type=%s)",
                type(exc).__name__,
            )
    local_key = state_db.with_name(keychain.LOCAL_KEY_FILENAME)
    if local_key.exists():
        raw = _read_regular_file(local_key, max_bytes=4096)
        try:
            existing = raw.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise QuarantineError("local state key is not valid UTF-8") from exc
        if existing:
            return existing
    raise QuarantineError(
        "no existing key is available for the encrypted read-only state audit"
    )


def _open_state_read_only(state_db: Path) -> Any:
    """Open plaintext or SQLCipher state with URI mode=ro and query_only.

    This deliberately does not instantiate ``State``: that constructor can
    migrate schemas, alter pragmas, remove the clean marker, or mint a key.
    """

    uri = state_db.resolve(strict=True).as_uri() + "?mode=ro"
    plain = None
    try:
        plain = sqlite3.connect(
            uri,
            uri=True,
            check_same_thread=False,
            isolation_level=None,
        )
        _enable_and_prove_query_only(plain)
        plain.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return plain
    except (sqlite3.DatabaseError, sqlite3.OperationalError):
        if plain is not None:
            plain.close()

    passphrase = _state_passphrase_read_only(state_db)
    try:
        import sqlcipher3
        from one_link import state_encryption
    except Exception as exc:
        raise QuarantineError(
            "SQLCipher is unavailable for the encrypted read-only state audit"
        ) from exc
    encrypted = None
    try:
        encrypted = sqlcipher3.connect(
            uri,
            uri=True,
            check_same_thread=False,
            isolation_level=None,
        )
        key_hex = passphrase.encode("utf-8").hex()
        encrypted.execute(f"PRAGMA key = \"x'{key_hex}'\"")
        encrypted.execute(
            f"PRAGMA cipher_page_size = {state_encryption.SQLCIPHER_PAGE_SIZE}"
        )
        encrypted.execute(f"PRAGMA kdf_iter = {state_encryption.SQLCIPHER_KDF_ITER}")
        _enable_and_prove_query_only(encrypted)
        encrypted.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return encrypted
    except Exception as exc:
        if encrypted is not None:
            encrypted.close()
        raise QuarantineError(
            "encrypted state could not be opened in read-only/query_only mode "
            f"({type(exc).__name__})"
        ) from exc


def _require_state_columns(
    connection: Any, table: str, required_columns: frozenset[str]
) -> None:
    rows = connection.execute(f'PRAGMA table_info("{table}")').fetchall()
    available = {str(row[1]) for row in rows}
    missing = required_columns - available
    if missing:
        raise QuarantineError(
            f"state schema lacks required {table} columns: {sorted(missing)}"
        )


def _count_state_matches(
    connection: Any,
    table: str,
    column_tokens: tuple[tuple[str, tuple[str, ...]], ...],
) -> int:
    required = frozenset(column for column, _tokens in column_tokens)
    _require_state_columns(connection, table, required)
    signature = (table, tuple(column for column, _tokens in column_tokens))
    # Identifiers cannot be bound through SQLite's parameter API.  Keep every
    # supported statement literal and pass the token sets through JSON1 so the
    # amount of SQL never depends on the manifest size.  Besides removing an
    # injection surface, this avoids SQLite's host-parameter ceiling for large
    # quarantine batches.
    query = {
        ("transfers", ("blob_hash", "name")): (
            'SELECT COUNT(*) FROM "transfers" '
            'WHERE "blob_hash" IN (SELECT value FROM json_each(?)) '
            'OR "name" IN (SELECT value FROM json_each(?))'
        ),
        ("chunk_availability", ("chunk_hash", "blob_hash")): (
            'SELECT COUNT(*) FROM "chunk_availability" '
            'WHERE "chunk_hash" IN (SELECT value FROM json_each(?)) '
            'OR "blob_hash" IN (SELECT value FROM json_each(?))'
        ),
        ("chunk_sources", ("chunk_hash",)): (
            'SELECT COUNT(*) FROM "chunk_sources" '
            'WHERE "chunk_hash" IN (SELECT value FROM json_each(?))'
        ),
        ("blobs", ("hash",)): (
            'SELECT COUNT(*) FROM "blobs" '
            'WHERE "hash" IN (SELECT value FROM json_each(?))'
        ),
        ("file_index_cache", ("blob_hash",)): (
            'SELECT COUNT(*) FROM "file_index_cache" '
            'WHERE "blob_hash" IN (SELECT value FROM json_each(?))'
        ),
        ("folder_manifest", ("blob_hash",)): (
            'SELECT COUNT(*) FROM "folder_manifest" '
            'WHERE "blob_hash" IN (SELECT value FROM json_each(?))'
        ),
        ("folder_audit", ("blob_hash",)): (
            'SELECT COUNT(*) FROM "folder_audit" '
            'WHERE "blob_hash" IN (SELECT value FROM json_each(?))'
        ),
        ("manifest_conflicts", ("local_blob_hash", "remote_blob_hash")): (
            'SELECT COUNT(*) FROM "manifest_conflicts" '
            'WHERE "local_blob_hash" IN (SELECT value FROM json_each(?)) '
            'OR "remote_blob_hash" IN (SELECT value FROM json_each(?))'
        ),
    }.get(signature)
    if query is None:
        raise QuarantineError(f"unsupported state reference query: {signature!r}")
    parameters = [
        json.dumps(tokens, ensure_ascii=True, separators=(",", ":"))
        for _column, tokens in column_tokens
    ]
    row = connection.execute(query, parameters).fetchone()
    if row is None:
        raise QuarantineError(f"state reference query returned no row for {table}")
    return int(row[0])


def verify_post_stop_state_references(plan: QuarantinePlan) -> dict[str, int]:
    """Re-query every relevant durable table after the graceful shutdown."""

    hashes, names = _collect_target_reference_tokens(plan)
    connection = _open_state_read_only(plan.state_db)
    try:
        counts = {
            "transfers_by_blob_or_original_name": _count_state_matches(
                connection,
                "transfers",
                (("blob_hash", hashes), ("name", names)),
            ),
            "chunk_availability_by_chunk_or_blob": _count_state_matches(
                connection,
                "chunk_availability",
                (("chunk_hash", hashes), ("blob_hash", hashes)),
            ),
            "chunk_sources_by_chunk": _count_state_matches(
                connection, "chunk_sources", (("chunk_hash", hashes),)
            ),
            "blobs_by_hash": _count_state_matches(
                connection, "blobs", (("hash", hashes),)
            ),
            "file_index_cache_by_blob": _count_state_matches(
                connection, "file_index_cache", (("blob_hash", hashes),)
            ),
            "folder_manifest_by_blob": _count_state_matches(
                connection, "folder_manifest", (("blob_hash", hashes),)
            ),
            "folder_audit_by_blob": _count_state_matches(
                connection, "folder_audit", (("blob_hash", hashes),)
            ),
            "manifest_conflicts_by_local_or_remote_blob": _count_state_matches(
                connection,
                "manifest_conflicts",
                (("local_blob_hash", hashes), ("remote_blob_hash", hashes)),
            ),
        }
        _enable_and_prove_query_only(connection)
    finally:
        connection.close()
    referenced = {label: count for label, count in counts.items() if count != 0}
    if referenced:
        raise QuarantineError(
            "post-stop durable state still references quarantine targets: "
            + json.dumps(referenced, separators=(",", ":"), sort_keys=True)
        )
    return counts


def _read_small_decimal(path: Path, *, label: str) -> int | None:
    if not path.exists():
        return None
    raw = _read_regular_file(path, max_bytes=64)
    try:
        value = int(raw.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError) as exc:
        raise QuarantineError(f"invalid {label} file: {path}") from exc
    if not (1 <= value <= 2_147_483_647):
        raise QuarantineError(f"out-of-range {label}: {value}")
    return value


def _read_port(path: Path, *, required: bool) -> int | None:
    value = _read_small_decimal(path, label="port")
    if value is None:
        if required:
            raise QuarantineError(f"required runtime port file is missing: {path}")
        return None
    if not (1 <= value <= 65_535):
        raise QuarantineError(f"out-of-range port in {path}: {value}")
    return value


def _control_request(port: int, command: str, *, timeout: float) -> dict[str, Any]:
    try:
        from one_link.control_ipc import request_control

        parsed = request_control(
            port,
            {"cmd": command},
            timeout=timeout,
        )
    except (OSError, RuntimeError) as exc:
        raise QuarantineError(
            f"graceful control request {command!r} failed on port {port}"
        ) from exc
    if not isinstance(parsed, dict):
        raise QuarantineError("control reply root was not an object")
    return parsed


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        process_query_limited_information = 0x1000
        still_active = 259
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            return ctypes.get_last_error() == 5
        try:
            exit_code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return True
            return exit_code.value == still_active
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _port_accepting(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.15):
            return True
    except OSError:
        return False


def _runtime_is_stopped(
    snapshot: RuntimeSnapshot, *, supervisor_pid_path: Path
) -> bool:
    if _pid_alive(snapshot.daemon_pid):
        return False
    if snapshot.supervisor_pid is not None and _pid_alive(snapshot.supervisor_pid):
        return False
    if snapshot.supervisor_pid is not None and supervisor_pid_path.exists():
        return False
    return not any(_port_accepting(port) for port in snapshot.ports)


def stop_runtime_gracefully(app_root: Path, *, timeout: float) -> RuntimeSnapshot:
    """Request a clean stop and prove daemon, supervisor, and listeners left.

    There is intentionally no force-kill fallback in this module.  If the
    control request or clean-exit proof fails, execution aborts before any
    quarantine directory or move is attempted.
    """

    if timeout <= 0 or timeout > 300:
        raise QuarantineError("stop timeout must be in (0, 300] seconds")
    control_port = _read_port(app_root / "control.port", required=True)
    assert control_port is not None
    status = _control_request(control_port, "status", timeout=min(timeout, 5.0))
    if status.get("ok") is not True:
        raise QuarantineError("daemon status did not prove a healthy control endpoint")
    daemon_pid = status.get("pid")
    if isinstance(daemon_pid, bool) or not isinstance(daemon_pid, int) or daemon_pid <= 0:
        raise QuarantineError("daemon status did not provide a valid PID")
    supervisor_pid_path = app_root / "supervisor.pid"
    supervisor_pid = _read_small_decimal(supervisor_pid_path, label="supervisor PID")
    ports = {control_port}
    for filename in ("server.port", "peer.port", "ui_port.txt"):
        value = _read_port(app_root / filename, required=False)
        if value is not None:
            ports.add(value)
    snapshot = RuntimeSnapshot(
        daemon_pid=daemon_pid,
        supervisor_pid=supervisor_pid,
        ports=tuple(sorted(ports)),
    )
    shutdown = _control_request(control_port, "shutdown", timeout=min(timeout, 5.0))
    if shutdown.get("ok") is not True:
        raise QuarantineError("daemon rejected graceful shutdown; no force fallback allowed")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _runtime_is_stopped(snapshot, supervisor_pid_path=supervisor_pid_path):
            return snapshot
        time.sleep(0.1)
    raise QuarantineError(
        "graceful shutdown proof timed out; refusing to move any production file"
    )


def _mkdir_exact(path: Path) -> None:
    try:
        os.mkdir(path)
    except FileExistsError:
        if not path.is_dir() or _is_reparse_or_symlink(path):
            raise QuarantineError(f"unsafe pre-existing destination directory: {path}")
    with contextlib.suppress(OSError):
        os.chmod(path, 0o700)


def _create_new_quarantine_root(path: Path) -> None:
    """Create only the missing exact path components, never accepting races."""

    if path.exists():
        raise QuarantineError(f"quarantine root already exists: {path}")
    ancestor = _deepest_existing_ancestor(path)
    relative = Path(os.path.relpath(path, ancestor))
    if any(part in ("", ".", "..") for part in relative.parts):
        raise QuarantineError(f"unsafe quarantine-root components: {path}")
    current = ancestor
    for component in relative.parts:
        current = current / component
        try:
            os.mkdir(current)
        except FileExistsError as exc:
            raise QuarantineError(
                f"quarantine component raced into existence: {current}"
            ) from exc
        with contextlib.suppress(OSError):
            os.chmod(current, 0o700)
        if _is_reparse_or_symlink(current):
            raise QuarantineError(f"new quarantine component is unsafe: {current}")


def _mkdir_destination_parents(root: Path, relative_parent: PurePosixPath) -> None:
    current = root
    for component in relative_parent.parts:
        if component in ("", ".", ".."):
            raise QuarantineError("unsafe destination parent component")
        current = current / component
        _mkdir_exact(current)
        if not _is_within(current, root) or _is_reparse_or_symlink(current):
            raise QuarantineError(f"unsafe destination parent: {current}")


def _write_exclusive(path: Path, data: bytes) -> None:
    if not _is_within(path, path.parent):
        raise QuarantineError(f"invalid write path: {path}")
    try:
        with path.open("xb") as handle:
            written = handle.write(data)
            if written != len(data):
                raise OSError(f"short write: {written} of {len(data)}")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise QuarantineError(f"refusing to overwrite quarantine artifact: {path}") from exc


def _journal_append(handle: BinaryIO, event: dict[str, Any]) -> None:
    payload = json.dumps(
        event, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8") + b"\n"
    written = handle.write(payload)
    if written != len(payload):
        raise OSError(f"short journal write: {written} of {len(payload)}")
    handle.flush()
    os.fsync(handle.fileno())


def _atomic_rename_no_replace(source: Path, destination: Path) -> None:
    """Same-volume atomic rename that refuses an existing destination."""

    if destination.exists():
        raise QuarantineError(f"destination already exists: {destination}")
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        move_file_ex = kernel32.MoveFileExW
        move_file_ex.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
        move_file_ex.restype = ctypes.c_int
        ctypes.set_last_error(0)
        if not move_file_ex(
            os.fspath(source), os.fspath(destination), MOVEFILE_WRITE_THROUGH
        ):
            error = ctypes.get_last_error()
            if error in (ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS):
                raise QuarantineError(
                    f"destination raced into existence: {destination}"
                )
            raise OSError(error, ctypes.FormatError(error), os.fspath(source))
        return
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise QuarantineError("renameat2(RENAME_NOREPLACE) is unavailable")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            AT_FDCWD,
            os.fsencode(source),
            AT_FDCWD,
            os.fsencode(destination),
            RENAME_NOREPLACE,
        )
        if result != 0:
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise QuarantineError(f"destination raced into existence: {destination}")
            raise OSError(error, os.strerror(error), os.fspath(source))
        return
    raise QuarantineError(
        "this platform lacks a configured atomic no-replace rename primitive"
    )


def _publish_rename_durably(source_parent: Path, destination_parent: Path) -> str:
    """Publish rename metadata durably before a completion record is written.

    POSIX requires fsync of both affected directories after rename.  Windows
    does not expose a reliably supported directory-fsync contract; the rename
    itself therefore uses ``MoveFileExW(MOVEFILE_WRITE_THROUGH)`` above, the
    strongest documented write-through primitive for this operation.  We
    still revalidate both parent directories here so a post-rename reparse
    race cannot be silently journaled as complete.
    """

    parents: list[Path] = []
    seen: set[str] = set()
    for parent in (source_parent, destination_parent):
        absolute = Path(os.path.abspath(os.fspath(parent)))
        key = _path_key(absolute)
        if key in seen:
            continue
        if not absolute.is_dir() or _is_reparse_or_symlink(absolute):
            raise QuarantineError(f"rename parent is no longer safe: {absolute}")
        seen.add(key)
        parents.append(absolute)
    if os.name == "nt":
        return "MoveFileExW(MOVEFILE_WRITE_THROUGH)"
    directory_flag = int(getattr(os, "O_DIRECTORY", 0))
    for parent in parents:
        descriptor = os.open(parent, os.O_RDONLY | directory_flag)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return "fsync(source_parent,destination_parent)"


def _verify_moved_destination(
    plan: QuarantinePlan, target: QuarantineTarget, destination: Path
) -> None:
    if target.source_path.exists():
        raise QuarantineError(f"source still exists after move: {target.source_path}")
    resolved = _assert_existing_path_chain(destination, plan.quarantine_root)
    st = resolved.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_size != target.size:
        raise QuarantineError(f"quarantine destination size/type mismatch: {resolved}")
    if _digest_file(resolved) != target.blake3:
        raise QuarantineError(f"quarantine destination hash mismatch: {resolved}")


def _rollback_moves(
    plan: QuarantinePlan,
    moved: list[tuple[QuarantineTarget, Path]],
    journal: BinaryIO,
) -> list[str]:
    errors: list[str] = []
    for target, destination in reversed(moved):
        try:
            if target.source_path.exists():
                raise QuarantineError(
                    f"rollback source unexpectedly exists: {target.source_path}"
                )
            resolved_destination = _assert_existing_path_chain(
                destination, plan.quarantine_root
            )
            if (
                resolved_destination.stat().st_size != target.size
                or _digest_file(resolved_destination) != target.blake3
            ):
                raise QuarantineError(
                    f"rollback destination proof failed: {resolved_destination}"
                )
            _journal_append(
                journal,
                {
                    "event": "rollback_intent",
                    "source": str(resolved_destination),
                    "destination": str(target.source_path),
                },
            )
            _atomic_rename_no_replace(resolved_destination, target.source_path)
            durability = _publish_rename_durably(
                resolved_destination.parent, target.source_path.parent
            )
            if (
                not target.source_path.is_file()
                or target.source_path.stat().st_size != target.size
                or _digest_file(target.source_path) != target.blake3
            ):
                raise QuarantineError(
                    f"rollback source verification failed: {target.source_path}"
                )
            _journal_append(
                journal,
                {
                    "event": "rollback_verified",
                    "source": str(target.source_path),
                    "durability": durability,
                },
            )
        except Exception as exc:  # rollback must attempt every completed move
            errors.append(f"{target.source_path}: {type(exc).__name__}: {exc}")
            with contextlib.suppress(Exception):
                _journal_append(
                    journal,
                    {
                        "event": "rollback_failed",
                        "source": str(target.source_path),
                        "error": f"{type(exc).__name__}: {exc}",
                    },
                )
    return errors


def execute_moves(
    plan: QuarantinePlan,
    *,
    companion: CompanionManifest,
    runtime: RuntimeSnapshot,
    post_stop_reference_counts: dict[str, int],
) -> dict[str, Any]:
    """Create a recoverable quarantine and move only explicit targets."""

    if (
        set(post_stop_reference_counts) != STATE_REFERENCE_KEYS
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value != 0
            for value in post_stop_reference_counts.values()
        )
    ):
        raise QuarantineError("move engine lacks an exact zero post-stop state proof")
    if plan.quarantine_root.exists():
        raise QuarantineError(f"quarantine root already exists: {plan.quarantine_root}")
    _create_new_quarantine_root(plan.quarantine_root)
    audit_dir = plan.quarantine_root / "audit"
    _mkdir_exact(audit_dir)
    _write_exclusive(audit_dir / "manifest-v2.json", plan.manifest_bytes)
    _write_exclusive(audit_dir / "manifest-v1.json", companion.data)
    journal_path = audit_dir / "move-journal.jsonl"
    moved: list[tuple[QuarantineTarget, Path]] = []
    try:
        with journal_path.open("xb") as journal:
            _journal_append(
                journal,
                {
                    "event": "start",
                    "manifest_blake3": plan.manifest_blake3,
                    "target_set_blake3": plan.target_set_blake3,
                    "target_count": len(plan.targets),
                    "target_bytes": plan.target_bytes,
                    "daemon_pid": runtime.daemon_pid,
                    "supervisor_pid": runtime.supervisor_pid,
                    "post_stop_state_reference_counts": post_stop_reference_counts,
                },
            )
            try:
                for sequence, target in enumerate(plan.targets):
                    source = _validate_target_source(plan, target)
                    destination = _destination_for(plan, target)
                    _mkdir_destination_parents(
                        plan.quarantine_root, target.relative_destination.parent
                    )
                    if destination.exists():
                        raise QuarantineError(
                            f"destination exists immediately before move: {destination}"
                        )
                    _journal_append(
                        journal,
                        {
                            "event": "move_intent",
                            "sequence": sequence,
                            "source": str(source),
                            "destination": str(destination),
                            "size": target.size,
                            "blake3": target.blake3,
                        },
                    )
                    _atomic_rename_no_replace(source, destination)
                    moved.append((target, destination))
                    durability = _publish_rename_durably(
                        source.parent, destination.parent
                    )
                    _journal_append(
                        journal,
                        {
                            "event": "move_complete",
                            "sequence": sequence,
                            "source": str(source),
                            "destination": str(destination),
                            "durability": durability,
                        },
                    )
                    _verify_moved_destination(plan, target, destination)
                    _journal_append(
                        journal,
                        {"event": "move_verified", "sequence": sequence},
                    )
                for target, destination in moved:
                    _verify_moved_destination(plan, target, destination)
                _journal_append(
                    journal,
                    {"event": "all_moves_verified", "count": len(moved)},
                )
                completion = {
                    "schema": "one-link-quarantine-completion/v1",
                    "manifest_blake3": plan.manifest_blake3,
                    "companion_manifest_blake3": companion.blake3,
                    "target_set_blake3": plan.target_set_blake3,
                    "target_count": len(moved),
                    "target_bytes": plan.target_bytes,
                    "all_sources_absent": True,
                    "all_destinations_hash_verified": True,
                    "post_stop_state_reference_counts": post_stop_reference_counts,
                    "deletion_performed": False,
                    "completed_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
                _write_exclusive(
                    audit_dir / "completion.json",
                    json.dumps(
                        completion,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode("utf-8")
                    + b"\n",
                )
                return completion
            except Exception as exc:
                with contextlib.suppress(Exception):
                    _journal_append(
                        journal,
                        {
                            "event": "failure",
                            "error": f"{type(exc).__name__}: {exc}",
                            "moved_before_failure": len(moved),
                        },
                    )
                rollback_errors = _rollback_moves(plan, moved, journal)
                if rollback_errors:
                    raise QuarantineError(
                        "quarantine failed and rollback was incomplete: "
                        + " | ".join(rollback_errors)
                    ) from exc
                raise QuarantineError(
                    "quarantine failed; every completed move was rolled back: "
                    f"{type(exc).__name__}: {exc}"
                ) from exc
    except FileExistsError as exc:
        raise QuarantineError(f"journal already exists: {journal_path}") from exc


def execute_plan(
    plan: QuarantinePlan,
    *,
    companion: CompanionManifest,
    expected_manifest_blake3: str,
    stop_timeout: float,
) -> dict[str, Any]:
    """Gracefully stop, re-pin/revalidate, and execute exact moves."""

    runtime = stop_runtime_gracefully(plan.app_root, timeout=stop_timeout)
    refreshed = load_plan(
        plan.manifest_path,
        expected_manifest_blake3=expected_manifest_blake3,
        quarantine_root=plan.quarantine_root,
        expected_schema=plan.schema,
    )
    if refreshed.manifest_bytes != plan.manifest_bytes:
        raise QuarantineError("manifest bytes changed across graceful shutdown")
    validate_sources(refreshed)
    refreshed_companion = _load_companion(companion.path, companion.blake3)
    if refreshed_companion.data != companion.data:
        raise QuarantineError("companion manifest changed across graceful shutdown")
    post_stop_reference_counts = verify_post_stop_state_references(refreshed)
    return execute_moves(
        refreshed,
        companion=refreshed_companion,
        runtime=runtime,
        post_stop_reference_counts=post_stop_reference_counts,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--expected-manifest-blake3", required=True)
    parser.add_argument("--quarantine-root", type=Path, required=True)
    parser.add_argument("--companion-manifest", type=Path)
    parser.add_argument("--expected-companion-blake3")
    parser.add_argument("--expected-schema", default=SUPPORTED_SCHEMA)
    parser.add_argument("--stop-timeout", type=float, default=30.0)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="gracefully stop One Link and perform journaled exact moves",
    )
    return parser


def run(argv: Sequence[str] | None = None) -> dict[str, Any]:
    args = _build_parser().parse_args(argv)
    if bool(args.companion_manifest) != bool(args.expected_companion_blake3):
        raise QuarantineError(
            "companion manifest path and expected digest must be supplied together"
        )
    plan = load_plan(
        args.manifest,
        expected_manifest_blake3=args.expected_manifest_blake3,
        quarantine_root=args.quarantine_root,
        expected_schema=args.expected_schema,
    )
    validation = validate_sources(plan)
    if not args.execute:
        return {
            "ok": True,
            "mode": "validate-only",
            "manifest_blake3": plan.manifest_blake3,
            "target_set_blake3": plan.target_set_blake3,
            **validation,
            "production_mutation": False,
        }
    if args.companion_manifest is None or args.expected_companion_blake3 is None:
        raise QuarantineError(
            "execute mode requires a hash-pinned companion v1 manifest copy"
        )
    companion = _load_companion(
        args.companion_manifest, args.expected_companion_blake3
    )
    completion = execute_plan(
        plan,
        companion=companion,
        expected_manifest_blake3=args.expected_manifest_blake3,
        stop_timeout=args.stop_timeout,
    )
    return {"ok": True, "mode": "execute", **completion}


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result = run(argv)
    except QuarantineError as exc:
        print(f"quarantine refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
