"""Fail-closed persistence primitives for long-lived key authority.

The distinction in this module is intentionally strict: ``None`` means the
path was proven absent by ``lstat``.  An existing object that cannot be read,
is not a regular file, changes while it is opened, or contains invalid bytes
is never treated as absence.  Callers must surface those failures rather than
minting replacement authority and orphaning encrypted state or peer trust.

First publication uses a fully-written, fsynced sibling inode followed by an
atomic hard-link into the final name.  A hard-link cannot replace an existing
name, so concurrent first boots converge on one winner without a destructive
check-then-rename race.  Filesystems that cannot provide this primitive fail
closed; a partially written authority file is worse than a clean startup
failure.
"""
from __future__ import annotations

import errno
import os
import secrets
import stat
from pathlib import Path
from typing import Callable


class KeyMaterialError(RuntimeError):
    """Base class for persistent key-authority failures."""


class KeyMaterialAccessError(KeyMaterialError):
    """An existing key artifact could not be safely accessed."""


class KeyMaterialIntegrityError(KeyMaterialError):
    """An existing key artifact failed shape or cryptographic validation."""


class KeyMaterialProtectionError(KeyMaterialError):
    """Platform protection (for example DPAPI or a private ACL) failed."""


class KeyMaterialPersistenceError(KeyMaterialError):
    """Key bytes could not be durably and atomically published."""


BytesValidator = Callable[[bytes], None]
PathHardener = Callable[[Path], None]


def artifact_exists(path: Path, *, label: str) -> bool:
    """Return false only for a proven-absent path; surface every other error."""

    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise KeyMaterialAccessError(f"cannot inspect existing {label}") from exc
    return True


def _is_link_or_reparse(st: os.stat_result) -> bool:
    attrs = int(getattr(st, "st_file_attributes", 0) or 0)
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(st.st_mode) or bool(attrs & reparse)


def _same_inode(before: os.stat_result, opened: os.stat_result) -> bool:
    # Windows and POSIX both expose stable file-index/inode values through
    # Python.  Some unusual filesystems report zero; in that case retain the
    # other structural checks instead of rejecting every legitimate file.
    before_ino = int(getattr(before, "st_ino", 0) or 0)
    opened_ino = int(getattr(opened, "st_ino", 0) or 0)
    if before_ino and opened_ino and before_ino != opened_ino:
        return False
    before_dev = int(getattr(before, "st_dev", 0) or 0)
    opened_dev = int(getattr(opened, "st_dev", 0) or 0)
    return not (before_dev and opened_dev and before_dev != opened_dev)


def _read_fd(fd: int, *, max_bytes: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        try:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
        except OSError as exc:
            raise KeyMaterialAccessError(f"cannot read existing {label}") from exc
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise KeyMaterialIntegrityError(f"existing {label} exceeds its size limit")


def read_bytes_if_exists(
    path: Path,
    *,
    label: str,
    max_bytes: int = 1 << 20,
    harden_path: PathHardener | None = None,
) -> bytes | None:
    """Safely read one regular key file, returning ``None`` only if absent."""

    try:
        before = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise KeyMaterialAccessError(f"cannot inspect existing {label}") from exc
    if _is_link_or_reparse(before) or not stat.S_ISREG(before.st_mode):
        raise KeyMaterialIntegrityError(
            f"existing {label} is not a non-reparse regular file"
        )
    if harden_path is not None:
        try:
            harden_path(path)
        except KeyMaterialError:
            raise
        except Exception as exc:
            raise KeyMaterialProtectionError(
                f"cannot verify private protection for existing {label}"
            ) from exc

    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(str(path), flags)
    except FileNotFoundError as exc:
        # It existed at lstat time.  A concurrent removal is not equivalent to
        # a stable absence on which it is safe to mint new authority.
        raise KeyMaterialAccessError(f"existing {label} disappeared while opening") from exc
    except OSError as exc:
        raise KeyMaterialAccessError(f"cannot open existing {label}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or not _same_inode(before, opened):
            raise KeyMaterialAccessError(f"existing {label} changed while opening")
        data = _read_fd(fd, max_bytes=max_bytes, label=label)
        opened_after = os.fstat(fd)
        if (
            int(opened_after.st_size) != int(opened.st_size)
            or int(opened_after.st_mtime_ns) != int(opened.st_mtime_ns)
        ):
            raise KeyMaterialAccessError(f"existing {label} changed while reading")
        try:
            after = os.lstat(path)
        except OSError as exc:
            raise KeyMaterialAccessError(
                f"existing {label} changed while reading"
            ) from exc
        if _is_link_or_reparse(after) or not _same_inode(opened, after):
            raise KeyMaterialAccessError(f"existing {label} changed while reading")
        return data
    finally:
        os.close(fd)


def _write_all(fd: int, payload: bytes, *, label: str) -> None:
    view = memoryview(payload)
    written = 0
    while written < len(view):
        try:
            count = os.write(fd, view[written:])
        except OSError as exc:
            raise KeyMaterialPersistenceError(f"cannot write new {label}") from exc
        if count <= 0:
            raise KeyMaterialPersistenceError(f"short write while storing new {label}")
        written += count


def _sync_parent(path: Path, *, label: str) -> None:
    if os.name == "nt":
        # Python cannot portably open a Windows directory handle for
        # FlushFileBuffers.  The file itself is fsynced before publication.
        return
    flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
    try:
        fd = os.open(str(path.parent), flags)
    except OSError as exc:
        if exc.errno in {errno.EINVAL, errno.ENOTSUP}:
            return
        raise KeyMaterialPersistenceError(
            f"cannot open {label} directory for durability sync"
        ) from exc
    try:
        try:
            os.fsync(fd)
        except OSError as exc:
            if exc.errno not in {errno.EINVAL, errno.ENOTSUP}:
                raise KeyMaterialPersistenceError(
                    f"cannot durably sync {label} directory"
                ) from exc
    finally:
        os.close(fd)


def sync_existing_authority(path: Path, *, label: str) -> None:
    """Flush an already-published winner before a concurrent caller uses it."""

    # MSVCRT rejects fsync on a read-only descriptor (EBADF); opening the
    # current-user-only authority read/write is required solely for
    # FlushFileBuffers and does not mutate content.
    access = os.O_RDWR if os.name == "nt" else os.O_RDONLY
    flags = access | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        raise KeyMaterialPersistenceError(
            f"cannot open published {label} for durability verification"
        ) from exc
    try:
        try:
            os.fsync(fd)
        except OSError as exc:
            raise KeyMaterialPersistenceError(
                f"cannot durably flush published {label}"
            ) from exc
    finally:
        os.close(fd)
    _sync_parent(path, label=label)


def _write_private_temp(
    path: Path,
    payload: bytes,
    *,
    label: str,
    validate: BytesValidator,
    harden_path: PathHardener | None,
) -> Path:
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise KeyMaterialPersistenceError(f"cannot create {label} directory") from exc
    tmp = path.with_name(f".{path.name}.tmp.{secrets.token_hex(12)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(str(tmp), flags, 0o600)
    except OSError as exc:
        raise KeyMaterialPersistenceError(f"cannot create temporary {label}") from exc
    try:
        _write_all(fd, payload, label=label)
        try:
            os.fsync(fd)
        except OSError as exc:
            raise KeyMaterialPersistenceError(f"cannot durably flush new {label}") from exc
    except Exception:
        os.close(fd)
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    else:
        os.close(fd)

    try:
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        if harden_path is not None:
            harden_path(tmp)
        on_disk = read_bytes_if_exists(tmp, label=f"temporary {label}")
        if on_disk is None or on_disk != payload:
            raise KeyMaterialPersistenceError(f"temporary {label} failed byte validation")
        validate(on_disk)
    except KeyMaterialError:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    except Exception as exc:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise KeyMaterialPersistenceError(f"temporary {label} failed validation") from exc
    return tmp


def atomic_create_bytes(
    path: Path,
    payload: bytes,
    *,
    label: str,
    validate: BytesValidator,
    harden_path: PathHardener | None = None,
) -> bool:
    """Publish bytes without replacement; return false if another won."""

    tmp = _write_private_temp(
        path,
        payload,
        label=label,
        validate=validate,
        harden_path=harden_path,
    )
    try:
        try:
            os.link(tmp, path, follow_symlinks=False)
        except TypeError:  # pragma: no cover - older Python/platform shim
            os.link(tmp, path)
        except FileExistsError:
            return False
        except OSError as exc:
            raise KeyMaterialPersistenceError(
                f"cannot atomically publish new {label} without replacement"
            ) from exc
        _sync_parent(path, label=label)
        on_disk = read_bytes_if_exists(
            path,
            label=label,
            harden_path=harden_path,
        )
        if on_disk is None or on_disk != payload:
            raise KeyMaterialPersistenceError(f"published {label} failed byte validation")
        validate(on_disk)
        return True
    except Exception:
        # Once linked, never delete the final name on a post-publication
        # failure: preserving the exact bytes gives recovery tooling evidence
        # and prevents a subsequent boot from minting a different authority.
        raise
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise KeyMaterialPersistenceError(
                f"cannot remove temporary {label} after publication"
            ) from exc


def atomic_replace_bytes(
    path: Path,
    payload: bytes,
    *,
    label: str,
    validate: BytesValidator,
    harden_path: PathHardener | None = None,
) -> None:
    """Durably replace authority for an explicitly requested rotation."""

    tmp = _write_private_temp(
        path,
        payload,
        label=label,
        validate=validate,
        harden_path=harden_path,
    )
    try:
        try:
            os.replace(tmp, path)
        except OSError as exc:
            raise KeyMaterialPersistenceError(f"cannot atomically replace {label}") from exc
        _sync_parent(path, label=label)
        on_disk = read_bytes_if_exists(
            path,
            label=label,
            harden_path=harden_path,
        )
        if on_disk is None or on_disk != payload:
            raise KeyMaterialPersistenceError(f"replaced {label} failed byte validation")
        validate(on_disk)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
