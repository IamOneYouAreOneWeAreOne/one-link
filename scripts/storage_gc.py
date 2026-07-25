"""Offline One Link CAS graph auditor and recoverable orphan quarantine.

Audit is the default and performs no mutation. Quarantine/rollback/purge
require an externally pinned manifest BLAKE3 and acquire the daemon's
authoritative OS instance lock for their entire run. Purge is a separate,
bounded permanent-delete step with a default 30-day recovery grace.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator

from one_link.state import State
from one_link.storage_lifecycle import (
    DEFAULT_CAS_BATCH_LIMIT,
    DEFAULT_CAS_GRACE_MS,
    DEFAULT_QUARANTINE_GRACE_MS,
    StorageLifecycleError,
    build_cas_gc_manifest,
    open_read_only_state_snapshot,
    purge_cas_quarantine,
    quarantine_cas_orphans,
    rollback_cas_quarantine,
    write_cas_gc_manifest,
)

log = logging.getLogger(__name__)


@contextmanager
def _offline_daemon_lock(root: Path) -> Iterator[BinaryIO]:
    """Hold the same byte/advisory lock used by the daemon, without rewriting it."""

    path = root / "daemon.lock"
    try:
        root_stat = root.lstat()
        lock_stat = path.lstat()
    except OSError as exc:
        raise StorageLifecycleError("offline daemon lock cannot be inspected") from exc
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    root_redirected = stat.S_ISLNK(root_stat.st_mode) or bool(
        int(getattr(root_stat, "st_file_attributes", 0)) & reparse_flag
    )
    lock_redirected = stat.S_ISLNK(lock_stat.st_mode) or bool(
        int(getattr(lock_stat, "st_file_attributes", 0)) & reparse_flag
    )
    if (
        root_redirected
        or lock_redirected
        or not stat.S_ISDIR(root_stat.st_mode)
        or not stat.S_ISREG(lock_stat.st_mode)
        or lock_stat.st_size < 1
    ):
        raise StorageLifecycleError(
            "a real, existing daemon.lock is required for a provably offline audit; "
            "start and cleanly stop One Link once, then retry"
        )
    # r+b is required by msvcrt.locking but does not itself change content or
    # metadata. We never write/truncate the production lock file.
    handle = open(path, "r+b")
    locked = False
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise StorageLifecycleError(
                    "the One Link daemon is running; CAS audit requires an offline snapshot"
                ) from exc
        elif sys.platform != "win32":
            import fcntl

            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise StorageLifecycleError(
                    "the One Link daemon is running; CAS audit requires an offline snapshot"
                ) from exc
        locked = True
        yield handle
    finally:
        if locked:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                with contextlib.suppress(OSError):
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            elif sys.platform != "win32":
                import fcntl

                with contextlib.suppress(OSError):
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _load_manifest(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise StorageLifecycleError(f"cannot read manifest {path}") from exc
    if not isinstance(value, dict):
        raise StorageLifecycleError("manifest root is not an object")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-root",
        type=Path,
        help="exact existing One Link data directory (default: active profile)",
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)
    audit = subparsers.add_parser("audit", help="write a non-mutating machine manifest")
    audit.add_argument("--manifest", type=Path, required=True)
    audit.add_argument("--grace-ms", type=int, default=DEFAULT_CAS_GRACE_MS)
    audit.add_argument("--batch-limit", type=int, default=DEFAULT_CAS_BATCH_LIMIT)
    audit.add_argument("--verify-content", action="store_true")

    quarantine = subparsers.add_parser(
        "quarantine", help="atomically move one pinned manifest batch"
    )
    quarantine.add_argument("--manifest", type=Path, required=True)
    quarantine.add_argument("--expected-manifest-blake3", required=True)
    quarantine.add_argument("--quarantine-root", type=Path)

    rollback = subparsers.add_parser(
        "rollback", help="restore a completed or interrupted quarantine"
    )
    rollback.add_argument("--quarantine-root", type=Path, required=True)
    rollback.add_argument("--expected-manifest-blake3", required=True)

    purge = subparsers.add_parser(
        "purge", help="permanently delete an aged completed quarantine batch"
    )
    purge.add_argument("--quarantine-root", type=Path, required=True)
    purge.add_argument("--expected-manifest-blake3", required=True)
    purge.add_argument("--grace-ms", type=int, default=DEFAULT_QUARANTINE_GRACE_MS)
    purge.add_argument("--batch-limit", type=int, default=DEFAULT_CAS_BATCH_LIMIT)
    return parser


def _resolve_data_root(explicit: Path | None) -> Path:
    if explicit is not None:
        candidate = explicit
    else:
        home = os.environ.get("ONE_LINK_HOME", "").strip()
        if home:
            candidate = Path(home) / "data"
        else:
            from platformdirs import user_data_dir

            candidate = Path(user_data_dir("One_link", "Coherence"))
    if any(part == ".." for part in candidate.parts):
        raise StorageLifecycleError("data root contains traversal")
    candidate = candidate.expanduser().absolute()
    if not candidate.is_dir():
        raise StorageLifecycleError(f"data root does not exist: {candidate}")
    return candidate


def _existing_passphrase_read_only(root: Path) -> str | None:
    """Read an existing state key without calling the auto-mint path."""

    env_value = os.environ.get("ONE_LINK_PASSPHRASE", "").strip()
    if env_value:
        return env_value
    if os.environ.get("ONE_LINK_DISABLE_AT_REST_ENCRYPTION") == "1":
        return None
    try:
        import keyring  # type: ignore[import-not-found]

        value = keyring.get_password("one_link", "state_db_key")
        if value:
            return str(value)
    except Exception as exc:
        log.warning(
            "best-effort keyring lookup failed (error_type=%s)",
            type(exc).__name__,
        )
    key_path = root / "state.key"
    try:
        value = key_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        root = _resolve_data_root(args.data_root)
        with _offline_daemon_lock(root):
            if args.operation == "audit":
                with open_read_only_state_snapshot(
                    root / "state.db",
                    passphrase=_existing_passphrase_read_only(root),
                ) as snapshot_state:
                    manifest = build_cas_gc_manifest(
                        snapshot_state,
                        root / "blobs",
                        grace_ms=args.grace_ms,
                        batch_limit=args.batch_limit,
                        verify_content=args.verify_content,
                    )
                    digest = write_cas_gc_manifest(args.manifest, manifest)
                    output = {
                        "ok": bool(manifest["safe_to_execute"]),
                        "mode": "audit_only",
                        "manifest": str(args.manifest.absolute()),
                        "manifest_blake3": digest,
                        "candidate_count": manifest["candidate_count"],
                        "candidate_bytes": manifest["candidate_bytes"],
                        "candidate_total": manifest["candidate_total"],
                        "errors": manifest["errors"],
                    }
                    print(json.dumps(output, separators=(",", ":"), sort_keys=True))
                    return 0 if output["ok"] else 2
            if args.operation == "purge":
                with open_read_only_state_snapshot(
                    root / "state.db",
                    passphrase=_existing_passphrase_read_only(root),
                ) as snapshot_state:
                    output = purge_cas_quarantine(
                        snapshot_state,
                        args.quarantine_root,
                        expected_manifest_blake3=args.expected_manifest_blake3,
                        quarantine_grace_ms=args.grace_ms,
                        batch_limit=args.batch_limit,
                    )
                print(json.dumps(output, separators=(",", ":"), sort_keys=True))
                return 0
            # Quarantine and rollback intentionally reconcile the mutable
            # ``blobs`` inventory after recoverable moves. Their contract is
            # maintenance/mutation, so use the normal migration-aware State.
            maintenance_state = State(root / "state.db")
            try:
                if args.operation == "quarantine":
                    manifest = _load_manifest(args.manifest)
                    quarantine_root = args.quarantine_root or (
                        root
                        / "storage-quarantine"
                        / f"cas-{args.expected_manifest_blake3[:20]}"
                    )
                    output = quarantine_cas_orphans(
                        maintenance_state,
                        manifest,
                        quarantine_root,
                        expected_manifest_blake3=args.expected_manifest_blake3,
                    )
                    output["quarantine_root"] = str(quarantine_root.absolute())
                    print(json.dumps(output, separators=(",", ":"), sort_keys=True))
                    return 0
                output = rollback_cas_quarantine(
                    maintenance_state,
                    args.quarantine_root,
                    expected_manifest_blake3=args.expected_manifest_blake3,
                )
                print(json.dumps(output, separators=(",", ":"), sort_keys=True))
                return 0
            finally:
                maintenance_state.close()
    except StorageLifecycleError as exc:
        print(
            json.dumps(
                {"ok": False, "error": str(exc), "operation": args.operation},
                separators=(",", ":"),
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    except Exception as exc:
        # Preserve machine-readable failure semantics without leaking a state
        # key, SQL text, or metadata value through an arbitrary exception.
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": f"maintenance failed closed ({type(exc).__name__})",
                    "operation": args.operation,
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
