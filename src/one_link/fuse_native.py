"""D27 — native filesystem mount-surface adapter.

The top-level ``one_link_native`` extension and its optional filesystem
submodule are deliberately reported as separate capabilities. Loading one of
One Link's other native accelerators does not imply that kernel filesystem
mounting is available.

Linux is considered ready only when the filesystem binding reports an enabled
libfuse backend and exposes the complete mount/unmount entrypoint set. The
macOS FSKit and Windows WinFsp/Dokan adapters are currently unimplemented;
installing an operating-system helper cannot make these scaffold crates mount
a folder. Every unsupported or incomplete state therefore fails closed before
touching the filesystem.
"""

from __future__ import annotations

import importlib
import logging
import platform
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Protocol, cast

log = logging.getLogger(__name__)


class _NativeFuseBinding(Protocol):
    """The complete optional filesystem ABI required by this adapter."""

    def platform_status(self) -> str: ...

    def mount_manifest(
        self,
        *,
        mountpoint: str,
        manifest: list[tuple[str, int, int, str]],
        blob_reader: Callable[[str, int, int], bytes],
        fs_name: str,
        read_only: bool,
        allow_other: bool,
    ) -> None: ...

    def unmount(self, mountpoint: str) -> None: ...

    def is_mounted(self, mountpoint: str) -> bool: ...


_native_extension: ModuleType | None
_native_fuse_module: ModuleType | None = None
_native_fuse: _NativeFuseBinding | None = None

try:
    import one_link_native as _loaded_native_extension

    _native_extension = _loaded_native_extension

    # The source tree can be visible as a namespace package without the PyO3
    # binary being installed. The compiled extension always exports its
    # package version, so import success alone is not sufficient evidence.
    HAS_NATIVE_EXTENSION: bool = bool(getattr(_native_extension, "__version__", None))
except ImportError as exc:
    HAS_NATIVE_EXTENSION = False
    _native_extension = None
    log.info(
        "one_link_native is not installed (%s); native filesystem mounting is unavailable.",
        exc,
    )

if HAS_NATIVE_EXTENSION:
    try:
        _native_fuse_module = importlib.import_module("one_link_native.fuse")
    except ImportError as exc:
        log.info(
            "one_link_native is loaded but has no filesystem submodule (%s); "
            "native filesystem mounting is unavailable.",
            exc,
        )

HAS_FILESYSTEM_MODULE: bool = _native_fuse_module is not None
HAS_FILESYSTEM_BINDING: bool = _native_fuse_module is not None and all(
    callable(getattr(_native_fuse_module, name, None))
    for name in ("platform_status", "mount_manifest", "unmount", "is_mounted")
)
if HAS_FILESYSTEM_BINDING:
    # The runtime shape check above is the trust boundary for this optional,
    # feature-gated module.  ``cast`` only teaches the checker that the three
    # verified callables implement the protocol; it does not invent support.
    _native_fuse = cast(_NativeFuseBinding, _native_fuse_module)
# Compatibility alias retained for callers that used the old name. Historically
# this meant ``one_link_native.fuse`` rather than the top-level native extension.
HAS_NATIVE: bool = HAS_FILESYSTEM_BINDING


@dataclass(frozen=True)
class PlatformStatus:
    """Per-platform mount-support snapshot. Pure introspection — never
    touches the filesystem.

    ``backend`` is ``"none"`` whenever no actual filesystem adapter can
    service a mount. ``reason`` is a stable machine-readable explanation;
    callers should not infer readiness from the presence of the general native
    extension.
    """

    kind: str
    ready: bool
    message: str
    backend: str = "none"
    reason: str = "unsupported_platform"


@dataclass(frozen=True)
class MountResult:
    """Outcome of a ``try_mount`` call.

    Status values:
      "mounted": kernel mount succeeded, FS is live until ``unmount``.
      "unsupported_platform": One Link has no implemented adapter for
        this platform (currently Windows and macOS).
      "feature_disabled": platform CAN support FUSE but this build of
        the crate didn't enable it (Linux without ``linux-mount``).
      "invalid_mountpoint": the mountpoint doesn't exist or isn't a
        directory.
      "backend_error": fuser returned a backend error; ``detail``
        carries the libfuse message.
      "native_missing": the native extension or its complete filesystem
        binding is unavailable.
    """

    status: str
    detail: str = ""


_LINUX_READY = PlatformStatus(
    kind="linux_ready",
    ready=True,
    message=(
        "Linux FUSE backend is compiled. Mounting still requires an accessible "
        "/dev/fuse device and a working fusermount helper or mount privilege."
    ),
    backend="fuse",
    reason="ready",
)
_LINUX_DISABLED = PlatformStatus(
    kind="linux_disabled",
    ready=False,
    message=(
        "Linux build of ol_fuse is missing the linux-mount feature. "
        "Kernel mounts are unavailable in this build."
    ),
    backend="none",
    reason="filesystem_feature_disabled",
)
_MACOS = PlatformStatus(
    kind="macos_unsupported",
    ready=False,
    message=(
        "One Link's macOS FSKit adapter is not implemented. Installing a "
        "filesystem helper does not enable folder mounts in this build."
    ),
    backend="none",
    reason="adapter_unimplemented",
)
_WINDOWS = PlatformStatus(
    kind="windows_unsupported",
    ready=False,
    message=(
        "One Link's Windows WinFsp/Dokan adapter is not implemented. "
        "Installing a filesystem driver does not enable folder mounts in "
        "this build."
    ),
    backend="none",
    reason="adapter_unimplemented",
)
_OTHER = PlatformStatus(
    kind="other_unsupported",
    ready=False,
    message=(
        "FUSE mount surface is currently scaffold-only on this "
        "platform. File a feature request with your OS name + "
        "version if you'd like it prioritised."
    ),
    backend="none",
    reason="unsupported_platform",
)
_NATIVE_EXTENSION_MISSING = PlatformStatus(
    kind="native_missing",
    ready=False,
    message=(
        "The one_link_native extension is unavailable, so native filesystem "
        "mounting cannot be used."
    ),
    backend="none",
    reason="native_extension_missing",
)
_FILESYSTEM_MODULE_MISSING = PlatformStatus(
    kind="native_missing",
    ready=False,
    message=(
        "one_link_native is loaded, but this build has no filesystem "
        "submodule. Folder mounting is unavailable."
    ),
    backend="none",
    reason="filesystem_binding_missing",
)
_FILESYSTEM_BINDING_INCOMPLETE = PlatformStatus(
    kind="native_missing",
    ready=False,
    message=(
        "The native filesystem submodule does not expose the complete, "
        "verified mount API. Folder mounting is unavailable."
    ),
    backend="none",
    reason="filesystem_binding_incomplete",
)


def platform_status() -> PlatformStatus:
    """Return a snapshot of the current platform's mount-support state.
    Safe to call without the native module installed."""
    sysname = sys.platform
    machine = platform.system().lower()
    # These platform adapters are known source-level scaffolds. Report that
    # truth independently of whether unrelated one_link_native modules load.
    if sysname == "darwin" or machine == "darwin":
        return _MACOS
    if sysname == "win32" or machine == "windows":
        return _WINDOWS
    if not HAS_NATIVE_EXTENSION:
        return _NATIVE_EXTENSION_MISSING
    if not HAS_FILESYSTEM_MODULE:
        return _FILESYSTEM_MODULE_MISSING
    if not HAS_FILESYSTEM_BINDING:
        return _FILESYSTEM_BINDING_INCOMPLETE
    # Authoritative answer comes from the native crate's compile-time
    # cfg. Never infer readiness from the host OS or extension presence.
    binding = _native_fuse
    if binding is None:
        return _FILESYSTEM_BINDING_INCOMPLETE
    try:
        tag = str(binding.platform_status())
    except Exception:
        log.exception("native filesystem platform-status query failed")
        return _FILESYSTEM_BINDING_INCOMPLETE
    return _status_for_tag(tag, sysname, machine)


def _status_for_tag(tag: str, sysname: str, machine: str) -> PlatformStatus:
    if tag == "linux_fuser_ready":
        return _LINUX_READY
    if tag == "linux_fuser_disabled":
        return _LINUX_DISABLED
    if tag == "macos_unsupported" or sysname == "darwin" or machine == "darwin":
        return _MACOS
    if tag == "windows_unsupported" or sysname == "win32" or machine == "windows":
        return _WINDOWS
    if sysname.startswith("linux"):
        return _FILESYSTEM_BINDING_INCOMPLETE
    return _OTHER


def try_mount(
    *,
    mountpoint: Path,
    manifest: dict[str, dict],
    fs_name: str = "one_link_folder",
    read_only: bool = True,
    allow_other: bool = False,
    blob_reader: Callable[[str, int, int], bytes] | None = None,
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
    if not read_only:
        return MountResult(
            "backend_error",
            detail=(
                "read-write filesystem mounts are not implemented; refusing "
                "an unsafe writable view"
            ),
        )
    if blob_reader is None or not callable(blob_reader):
        return MountResult(
            "backend_error",
            detail=(
                "a callable verified blob_reader(hash, offset, size) -> bytes "
                "is required; manifest metadata alone cannot serve file content"
            ),
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
    binding = _native_fuse
    if binding is None:
        # A Linux module without the complete FUSE entrypoint set is an
        # incomplete or feature-disabled build. Surface that explicitly so
        # the daemon can fall back to "browse via web UI" without claiming
        # that the release wheel's implemented adapter is globally deferred.
        return MountResult(
            "feature_disabled",
            detail=(
                "one_link_native.fuse loaded but no mount_manifest "
                "binding yet — rebuild with --features linux-mount."
            ),
        )
    try:
        native_manifest = _normalise_manifest(manifest)
        native_fs_name = _normalise_fs_name(fs_name)
    except (TypeError, ValueError, OverflowError) as exc:
        return MountResult("invalid_manifest", detail=str(exc))
    try:
        binding.mount_manifest(
            mountpoint=str(mp),
            manifest=native_manifest,
            blob_reader=blob_reader,
            fs_name=native_fs_name,
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
    binding = _native_fuse
    if binding is None:
        return MountResult(
            "feature_disabled",
            detail="one_link_native.fuse has no unmount binding yet",
        )
    try:
        binding.unmount(str(mountpoint))
        return MountResult("unmounted")
    except Exception as exc:
        return MountResult("backend_error", detail=str(exc))


def _normalise_manifest(manifest: dict[str, dict]) -> list[tuple[str, int, int, str]]:
    """Convert a Python manifest dict to the tuple shape the native
    crate expects. Tombstones are omitted, while malformed live rows fail
    closed before native code or the kernel sees them."""
    if not isinstance(manifest, dict):
        raise TypeError("manifest must be a dictionary")
    if len(manifest) > 65_536:
        raise ValueError("manifest exceeds the 65536-entry mount limit")
    out: list[tuple[str, int, int, str]] = []
    for path, row in manifest.items():
        if not isinstance(path, str) or not path:
            raise ValueError("manifest contains an empty or non-string path")
        if len(path.encode("utf-8")) > 4_096:
            raise ValueError(f"manifest path exceeds 4096 UTF-8 bytes: {path!r}")
        if path.startswith("/") or path.endswith("/"):
            raise ValueError(f"manifest path is not canonical and relative: {path!r}")
        if any(ord(char) < 32 or ord(char) == 127 for char in path):
            raise ValueError(f"manifest path contains a control character: {path!r}")
        if any(part in {"", ".", ".."} for part in path.split("/")):
            raise ValueError(f"manifest path contains an unsafe segment: {path!r}")
        if not isinstance(row, dict):
            raise TypeError(f"manifest row for {path!r} must be a dictionary")
        raw_blob = row.get("blob_hash")
        if raw_blob is None or raw_blob == "":
            continue  # tombstone — skip in the read-only view
        if not isinstance(raw_blob, str) or len(raw_blob) != 64 or any(
            char not in "0123456789abcdef" for char in raw_blob
        ):
            raise ValueError(
                f"blob_hash for {path!r} must be 64 lowercase hexadecimal characters"
            )
        size = _manifest_uint(row.get("size", 0), field="size", path=path)
        mtime = _manifest_uint(row.get("mtime_ms", 0), field="mtime_ms", path=path)
        out.append((path, size, mtime, raw_blob))
    paths = {row[0] for row in out}
    for path in paths:
        segments = path.split("/")
        for index in range(1, len(segments)):
            ancestor = "/".join(segments[:index])
            if ancestor in paths:
                raise ValueError(
                    f"manifest path {path!r} descends from file entry {ancestor!r}"
                )
    return sorted(out, key=lambda item: item[0])


def _manifest_uint(value: object, *, field: str, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} for {path!r} must be an integer")
    if value < 0 or value > (1 << 64) - 1:
        raise ValueError(f"{field} for {path!r} is outside the unsigned 64-bit range")
    return value


def _normalise_fs_name(value: object) -> str:
    """Return a bounded mount-display name with no option-injection bytes."""
    raw = str(value or "one_link_folder")
    safe = "".join(
        char if char.isascii() and (char.isalnum() or char in "._-") else "_"
        for char in raw
    ).strip("._-")
    if not safe:
        safe = "one_link_folder"
    return safe[:64]


def capabilities() -> dict:
    """Inspection helper for the operator UI / debug API. Exposes the
    platform status + a quick boolean indicating whether a mount call
    would have any chance of succeeding."""
    s = platform_status()
    return {
        "platform": s.kind,
        "ready": s.ready,
        "backend": s.backend,
        "reason": s.reason,
        "message": s.message,
        # Compatibility key: historically this referred specifically to the
        # filesystem binding, not to all of one_link_native.
        "native_loaded": HAS_FILESYSTEM_BINDING,
        "native_extension_available": HAS_NATIVE_EXTENSION,
        "filesystem_module_available": HAS_FILESYSTEM_MODULE,
        "filesystem_binding_available": HAS_FILESYSTEM_BINDING,
        "read_only": True,
        "requires_verified_blob_reader": True,
    }


__all__ = [
    "HAS_FILESYSTEM_BINDING",
    "HAS_FILESYSTEM_MODULE",
    "HAS_NATIVE",
    "HAS_NATIVE_EXTENSION",
    "MountResult",
    "PlatformStatus",
    "capabilities",
    "platform_status",
    "try_mount",
    "unmount",
]
