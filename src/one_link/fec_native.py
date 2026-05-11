"""Adapter for the file-engine v2 native FEC codec (``ol_fec`` via
``one_link_native``).

Per ADR-0016: Reed-Solomon over GF(2^8) using a Cauchy systematic
matrix. Phase C item #1; substrate for ADR-0018 erasure-coded durability.

If the native module isn't built, ``HAS_NATIVE`` is False and callers
should not use this layer (no pure-Python fallback ships).
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from one_link_native import fec as _native_fec  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_fec, "__version__", None)
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    _native_fec = None  # type: ignore[assignment]
    log.info(
        "one_link_native.fec not installed (%s); ADR-0016 FEC + ADR-0018 "
        "erasure durability will be unavailable. Build via `cd native && "
        "maturin develop --release`.",
        exc,
    )


def codec(k: int, m: int):
    """Build a Reed-Solomon codec for ``(k, m)``."""
    _require_native()
    return _native_fec.Codec(k, m)


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.fec required for ADR-0016 FEC but not "
            "installed; build via `cd native && maturin develop --release`."
        )
