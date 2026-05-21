"""Adapter for the payload-aware compression dispatcher (``ol_compress``
via ``one_link_native``).

Decision point D14 from `intergration map.txt`. The daemon's chunk
encoder consumes this to pick between lz4 / zstd / none based on
(kind, size, precompressed-hint).
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from one_link_native import compress as _native_compress  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_compress, "__version__", None)
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    _native_compress = None  # type: ignore[assignment]
    log.info(
        "one_link_native.compress not installed (%s); falling back to "
        "static-zstd in the chunk encoder. Build via `cd native && "
        "maturin develop --release`.",
        exc,
    )


def compressor():
    """Construct a Compressor instance. Stateless; safe to cache one
    instance on the daemon.
    """
    _require_native()
    return _native_compress.Compressor()


# Static algorithm constants for callers that don't want to hold a
# Compressor instance (e.g. test code, single-call paths).
ALGORITHMS: tuple[str, ...] = (
    "none",
    "lz4",
    "zstd_balanced",
    "zstd_aggressive",
)


_PRECOMPRESSED_EXTENSIONS: frozenset[str] = frozenset({
    "zip", "7z", "rar", "gz", "xz", "bz2", "zstd",
    "mp4", "mov", "mkv", "avi", "webm",
    "mp3", "aac", "flac", "ogg", "opus",
    "jpg", "jpeg", "png", "webp", "heic", "avif",
    "pdf",
})


def is_precompressed_by_extension(filename: str | None) -> bool:
    """Heuristic: is this file already at high entropy?

    Useful as a hint to ``Compressor.pick(..., precompressed=...)``.
    The daemon's file-offer path consults this on the mime/extension
    before deciding whether to spend cycles re-compressing.
    """
    if not filename:
        return False
    parts = str(filename).rsplit(".", 1)
    if len(parts) != 2:
        return False
    return parts[1].lower() in _PRECOMPRESSED_EXTENSIONS


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.compress required but not installed; "
            "build via `cd native && maturin develop --release`."
        )
