"""Crash-consistent pathname publication primitives.

Windows does not expose the POSIX ``fsync(directory_fd)`` contract through
Python. Skipping the directory flush after ``os.replace`` is not equivalent:
the file contents may be flushed while the namespace change is still only in
the filesystem cache. For the namespace operation itself, Win32 exposes
``MoveFileExW(..., MOVEFILE_WRITE_THROUGH)``. Microsoft documents that the
call does not return until the move is on disk.

These helpers use that primitive for the actual rename on Windows. They do
not promise more than the operating system and storage device can provide;
hardware that ignores flush requests remains outside a user-mode process's
control. POSIX callers must still fsync the containing directory after a
successful call.

Reference:
https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-movefileexw
"""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path
from typing import Final


MOVEFILE_REPLACE_EXISTING: Final = 0x00000001
MOVEFILE_WRITE_THROUGH: Final = 0x00000008
_IS_WINDOWS: Final = os.name == "nt"


def _windows_extended_path(path: str | os.PathLike[str]) -> str:
    """Return an absolute Win32 extended-length path without reinterpretation."""

    raw = os.fspath(path)
    if not isinstance(raw, str):
        raise TypeError("Windows durable moves require text paths")
    if "\x00" in raw:
        raise ValueError("path contains an embedded NUL")
    absolute = os.path.abspath(raw)
    if absolute.startswith("\\\\?\\"):
        return absolute
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute[2:]
    return "\\\\?\\" + absolute


def _move_file_exw(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    flags: int,
) -> None:
    """Invoke MoveFileExW and preserve Python's useful OSError subclasses."""

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    move_file = kernel32.MoveFileExW
    move_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
    )
    move_file.restype = wintypes.BOOL
    source_text = _windows_extended_path(source)
    destination_text = _windows_extended_path(destination)
    ctypes.set_last_error(0)
    if move_file(source_text, destination_text, wintypes.DWORD(flags)):
        return
    # Win32 APIs are required to set last-error on failure, but never surface
    # a misleading "operation completed successfully" exception if a broken
    # filesystem filter violates that contract.
    error = ctypes.get_last_error() or 31  # ERROR_GEN_FAILURE
    failure = ctypes.WinError(error)
    failure.filename = os.fspath(source)
    failure.filename2 = os.fspath(destination)
    raise failure


def replace_path(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
) -> None:
    """Atomically replace ``destination`` with ``source``.

    Windows performs the rename with a write-through namespace boundary.
    POSIX performs ``os.replace``; the caller must fsync the parent directory.
    The source and destination must be on one volume/filesystem.
    """

    if _IS_WINDOWS:
        _move_file_exw(
            source,
            destination,
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
        return
    os.replace(source, destination)


def publish_file_noreplace(
    staging: Path,
    destination: Path,
) -> bool:
    """Publish a staged regular file without replacing a concurrent winner.

    Return ``True`` when the staging hard link remains and must be unlinked by
    the caller. Windows uses a write-through rename and therefore returns
    ``False``. POSIX uses a same-filesystem hard link, preserving atomic
    no-replace behavior even though plain ``rename`` would overwrite.
    """

    if _IS_WINDOWS:
        _move_file_exw(staging, destination, MOVEFILE_WRITE_THROUGH)
        return False
    os.link(staging, destination, follow_symlinks=False)
    return True


def publish_windows_path_noreplace(
    source: Path,
    destination: Path,
) -> None:
    """Write-through rename a Windows file or directory without replacement."""

    if not _IS_WINDOWS:
        raise OSError("write-through no-replace rename is Windows-only")
    _move_file_exw(source, destination, MOVEFILE_WRITE_THROUGH)
