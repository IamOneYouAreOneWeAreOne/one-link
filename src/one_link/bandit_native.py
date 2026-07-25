"""Adapter for the file-engine v2 native bandit (``ol_bandit`` via
``one_link_native``).

Per ADR-0019: Beta-Bernoulli Thompson sampling. The production consumer
currently uses it for the route-choice axis in ``transfer_brain.py``.
Other proposed transfer-knob controllers are not production-active.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from one_link_native import bandit as _native_bandit  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_bandit, "__version__", None)
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    _native_bandit = None  # type: ignore[assignment]
    log.info(
        "one_link_native.bandit not installed (%s); ADR-0019 multi-armed "
        "bandit unavailable. Build via `cd native && maturin develop --release`.",
        exc,
    )


def bandit(n_arms: int, seed: int = 0xBABE_F00D):
    """Build a fresh `n_arms`-armed Thompson sampling bandit."""
    _require_native()
    return _native_bandit.Bandit(n_arms, seed)


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.bandit required for ADR-0019 multi-armed bandit "
            "but not installed; build via `cd native && maturin develop --release`."
        )
