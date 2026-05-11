"""Adapter for the file-engine v2 native active inference prefetch
predictor (``ol_prefetch`` via ``one_link_native``).

Per ADR-0033 Phase D #3: time-weighted co-occurrence predictor over
(peer, file_id) access traces.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from one_link_native import prefetch as _native_prefetch  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_prefetch, "__version__", None)
    MAX_CO_OCCURRENCE_GAP_MS: int = getattr(
        _native_prefetch, "MAX_CO_OCCURRENCE_GAP_MS", 600_000
    )
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    MAX_CO_OCCURRENCE_GAP_MS = 600_000
    _native_prefetch = None  # type: ignore[assignment]
    log.info(
        "one_link_native.prefetch not installed (%s); ADR-0033 active "
        "inference prefetch unavailable. Build via `cd native && maturin "
        "develop --release`.",
        exc,
    )


def predictor(half_life_ms: int = 60_000, decay_factor: float = 0.5):
    """Build a fresh :class:`Predictor`."""
    _require_native()
    return _native_prefetch.Predictor(half_life_ms, decay_factor)


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.prefetch required for ADR-0033 active inference "
            "prefetch but not installed; build via `cd native && maturin "
            "develop --release`."
        )
