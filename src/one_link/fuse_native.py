"""D27 — FUSE mount surface adapter.

Bridges the ``ol_fuse`` Rust crate (Linux libfuse + per-platform
scaffolds) to the Python daemon. Surface is designed to fail cleanly
on every platform that doesn't ship a built-in FUSE driver — Windows
needs WinFSP / Dokan, macOS needs FSKit (NOT macFUSE — its commercial
license breaks the no-monthly-bill promise of One Link).

Today this is a scaffold:
  - When the native crate is loaded AND the runtime platform supports
    FUSE (Linux with the ``linux-mount`` cargo feature), ``try_mount``
    does real work.
  - On any other platform, ``try_mount`` returns a
    ``MountUnsupported`` MountResult immediately so the daemon can
    surface a clear "install WinFSP / FSKit" message instead of
    crashing.

The daemon side stays mostly platform-agnostic: it asks
``platform_status()`` first, decides whether to expose the "mount as
filesystem" button at all, and only attempts ``try_mount`` if status
is ``ready``.
"""

from __future__ import annotations

import logging
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

log = logging.getLogger(__name__)

try:
    from one_link_native import fuse as _native_fuse  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
except ImportError as exc:
    HAS_NATIVE = False
    _native_fuse = None  # type: ignore[assignment]
    log.info(
        "one_link_native.fuse not installed (%s); FUSE mount surface "
        "in pure-Python fallback mode (mounts will return unsupported).",
        exc,
    )


@dataclass(frozen=True)
class PlatformStatus:
    """Per-platform mount-support snapshot. Pure introspection — never
    touches the filesystem.

    Fields:
      kind: "linux_ready" | "linux_disabled" | "macos_unsupported"
        | "windows_unsupported" | "other_unsupported"
      ready: True only if a mount call would succeed without
        external native dependencies (today: Linux + cargo feature).
      message: human-readable explanation for the UI / logs.
    """

    kind: str
    ready: bool
    message: str


@dataclass(frozen=True)
class MountResult:
    """Outcome of a ``try_mount`` call.

    Status values:
      "mounted": kernel mount succeeded, FS is live until ``unmount``.
      "unsupported_platform": platform doesn't ship a built-in FUSE
        driver (Windows, macOS).
      "feature_disabled": platform CAN support FUSE but this build of
        the crate didn't enable it (Linux without ``linux-mount``).
      "invalid_mountpoint": the mountpoint doesn't exist or isn't a
        directory.
      "backend_error": fuser returned a backend error; ``detail``
        carries the libfuse message.
      "native_missing": ``one_link_native.fuse`` isn't built yet.
    """

    status: str
    detail: str = ""


_LINUX_READY = PlatformStatus(
    kind="linux_ready", ready=True,
    message="Linux + libfuse3 ready — folder mounts can be exposed.",
)
_LINUX_DISABLED = PlatformStatus(
    kind="linux_disabled", ready=False,
    message=(
        "Linux build of ol_fuse is missing the linux-mount feature. "
        "Rebuild with `cargo build -p ol_fuse --features linux-mount` "
        "to enable kernel mounts."
    ),
)
_MACOS = PlatformStatus(
    kind="macos_unsupported", ready=False,
    message=(
        "macOS does not ship a built-in FUSE driver. Install an "
        "FSKit-based filesystem helper (Apple-maintained, no monthly "
        "bill) to expose folders as filesystems. macFUSE works too "
        "but its commercial dual-license breaks the no-monthly-bill "
        "promise."
    ),
)
_WINDOWS = PlatformStatus(
    kind="windows_unsupported", ready=False,
    message=(
        "Windows requires WinFSP (free, open source) or Dokan to "
        "expose user-mode filesystems. Install WinFSP and rebuild "
        "with the WinFSP-backed binding (ol_winfs, ships in a "
        "follow-up release)."
    ),
)
_OTHER = PlatformStatus(
    kind="other_unsupported", ready=False,
    message=(
        "FUSE mount surface is currently scaffold-only on this "
        "platform. File a feature request with your OS name + "
        "version if you'd like it prioritised."
    ),
)
_NATIVE_MISSING = PlatformStatus(
    kind="native_missing", ready=False,
    message=(
        "one_link_native is not built yet. Run "
        "`cd native && maturin develop --release` from the repo root "
        "to enable the FUSE mount surface."
    ),
)


def platform_status() -> PlatformStatus:
    """Return a snapshot of the current platform's mount-support state.
    Safe to call without the native module installed."""
    if not HAS_NATIVE:
        return _NATIVE_MISSING
    sysname = sys.platform
    machine = platform.system().lower()
    # Authoritative answer comes from the native crate's compile-time
    # cfg — let the crate decide. Fall back to runtime detection if
    # the native binding doesn't yet expose the function.
    fn = getattr(_native_fuse, "platform_status", None)
    if callable(fn):
        try:
            tag = str(fn())
        except Exception:
            tag = ""
        return _status_for_tag(tag, sysname, machine)
    return _status_for_tag("", sysname, machine)


def _status_for_tag(tag: str, sysname: str, machine: str) -> PlatformStatus:
    if tag == "linux_fuser_ready" or (
        not tag and sysname.startswith("linux") and HAS_NATIVE
    ):
        return _LINUX_READY
    if tag == "linux_fuser_disabled":
        return _LINUX_DISABLED
    if tag == "macos_unsupported" or sysname == "darwin" or machine == "darwin":
        return _MACOS
    if tag == "windows_unsupported" or sysname == "win32" or machine == "windows":
        return _WINDOWS
    return _OTHER


def try_mount(
    *,
    mountpoint: Path,
    manifest: dict[str, dict],
    fs_name: str = "one_link_folder",
    read_only: bool = True,
    allow_other: bool = False,
) -> MountResult:
    """Attempt to mount ``manifest`` at ``mountpoint`` via the native
    ol_fuse adapter.

    ``manifest`` is the daemon's flat folder manifest: a dict mapping
    ``file_path`` (str, relative, forward-slashes, no leading slash)
    to ``{"size": int, "mtime_ms": int, "blob_hash": str}``.

    ``read_only`` defaults to True because the daemon's folder-sync
    engine is the authoritative writer; mounting the same backing
    store RW would race the merge path. Future versions may flip
    this to False once chunk-store cooperation lands.

    Returns a :class:`MountResult` describing the outcome. Never raises.
    """
    if not HAS_NATIVE:
        return MountResult("native_missing", detail=_NATIVE_MISSING.message)
    status = platform_status()
    if not status.ready:
        return MountResult(
            {
                "linux_disabled": "feature_disabled",
                "macos_unsupported": "unsupported_platform",
                "windows_unsupported": "unsupported_platform",
                "other_unsupported": "unsupported_platform",
                "native_missing": "native_missing",
            }.get(status.kind, "unsupported_platform"),
            detail=status.message,
        )
    try:
        mp = Path(mountpoint)
        if not mp.is_dir():
            return MountResult(
                "invalid_mountpoint",
                detail=f"mountpoint does not exist or is not a directory: {mp}",
            )
    except Exception as exc:
        return MountResult("invalid_mountpoint", detail=str(exc))
    fn = getattr(_native_fuse, "mount_manifest", None)
    if not callable(fn):
        # Native module is loaded but doesn't expose the mount fn yet —
        # the Linux libfuse adapter is still deferred. Surface that
        # explicitly so the daemon can fall back to "browse via web UI".
        return MountResult(
            "feature_disabled",
            detail=(
                "one_link_native.fuse loaded but no mount_manifest "
                "binding yet — rebuild with --features linux-mount."
            ),
        )
    try:
        fn(
            mountpoint=str(mp),
            manifest=_normalise_manifest(manifest),
            fs_name=str(fs_name),
            read_only=bool(read_only),
            allow_other=bool(allow_other),
        )
        return MountResult("mounted")
    except Exception as exc:
        return MountResult("backend_error", detail=str(exc))


def unmount(*, mountpoint: Path) -> MountResult:
    """Best-effort unmount of ``mountpoint``. On Linux this calls
    ``fusermount -u`` via the native binding (when available); on
    other platforms it always returns ``unsupported_platform``.
    """
    status = platform_status()
    if not status.ready:
        return MountResult(
            {
                "linux_disabled": "feature_disabled",
                "macos_unsupported": "unsupported_platform",
                "windows_unsupported": "unsupported_platform",
                "other_unsupported": "unsupported_platform",
                "native_missing": "native_missing",
            }.get(status.kind, "unsupported_platform"),
            detail=status.message,
        )
    fn = getattr(_native_fuse, "unmount", None)
    if not callable(fn):
        return MountResult(
            "feature_disabled",
            detail="one_link_native.fuse has no unmount binding yet",
        )
    try:
        fn(str(mountpoint))
        return MountResult("unmounted")
    except Exception as exc:
        return MountResult("backend_error", detail=str(exc))


def _normalise_manifest(manifest: dict[str, dict]) -> list[tuple[str, int, int, str]]:
    """Convert a Python manifest dict to the tuple shape the native
    crate expects. Tolerates missing keys (size/mtime default to 0;
    blob_hash to empty string)."""
    out: list[tuple[str, int, int, str]] = []
    for path, row in (manifest or {}).items():
        if not isinstance(path, str) or not path:
            continue
        size = int((row or {}).get("size") or 0)
        mtime = int((row or {}).get("mtime_ms") or 0)
        blob = str((row or {}).get("blob_hash") or "")
        if not blob:
            continue  # tombstone — skip in the read-only view
        out.append((path.lstrip("/"), size, mtime, blob))
    return out


def capabilities() -> dict:
    """Inspection helper for the operator UI / debug API. Exposes the
    platform status + a quick boolean indicating whether a mount call
    would have any chance of succeeding."""
    s = platform_status()
    return {
        "platform": s.kind,
        "ready": s.ready,
        "message": s.message,
        "native_loaded": HAS_NATIVE,
    }


__all__ = [
    "HAS_NATIVE",
    "MountResult",
    "PlatformStatus",
    "capabilities",
    "platform_status",
    "try_mount",
    "unmount",
]
