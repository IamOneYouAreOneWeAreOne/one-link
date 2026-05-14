"""Runtime build identity for launcher/backend compatibility checks."""

from __future__ import annotations

import hashlib
from pathlib import Path


_FINGERPRINT_FILES = (
    "__init__.py",
    "app.py",
    "cli.py",
    "daemon.py",
    "server.py",
    "state.py",
    "personal_device_mesh.py",
    "self_mesh_enrollment.py",
    "web/index.html",
)


def package_root() -> Path:
    return Path(__file__).resolve().parent


def source_fingerprint() -> str:
    """Hash files that must match between launcher, UI, and daemon.

    Dev builds often keep the same semantic version while source changes
    quickly. This lets the desktop launcher reject stale background daemons
    even when ``one_link.__version__`` did not move.
    """
    root = package_root()
    h = hashlib.blake2s(digest_size=16)
    for rel in _FINGERPRINT_FILES:
        path = root / rel
        h.update(rel.encode("utf-8"))
        try:
            st = path.stat()
        except OSError:
            h.update(b":missing")
            continue
        h.update(str(st.st_size).encode("ascii"))
        h.update(str(st.st_mtime_ns).encode("ascii"))
    return h.hexdigest()


def runtime_build_identity() -> dict[str, str]:
    return {
        "package_root": str(package_root()),
        "source_fingerprint": source_fingerprint(),
    }
