"""Read-only, feature-gated filesystem surface.

The module exists on every supported wheel so capability inspection is
stable.  ``platform_status() == "linux_fuser_ready"`` is the only state in
which mount operations can succeed; Windows and macOS remain explicitly
unsupported until their native adapters are implemented.
"""

from collections.abc import Callable, Sequence

MAX_MANIFEST_ENTRIES: int
MAX_FS_PATH_BYTES: int
MAX_FS_NAME_BYTES: int
READ_ONLY: bool

def platform_status() -> str: ...
def mount_manifest(
    *,
    mountpoint: str,
    manifest: Sequence[tuple[str, int, int, str]],
    blob_reader: Callable[[str, int, int], bytes],
    fs_name: str = "one_link_folder",
    read_only: bool = True,
    allow_other: bool = False,
) -> None: ...
def unmount(mountpoint: str) -> None: ...
def is_mounted(mountpoint: str) -> bool: ...

__all__ = [
    "MAX_MANIFEST_ENTRIES",
    "MAX_FS_PATH_BYTES",
    "MAX_FS_NAME_BYTES",
    "READ_ONLY",
    "platform_status",
    "mount_manifest",
    "unmount",
    "is_mounted",
]
