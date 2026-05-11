"""Adapter for the file-engine v2 native hardware-bound key abstraction
(``ol_hwkey`` via ``one_link_native``).

Per ADR-0023: TOFU-degrading hardware-bound keys. This drop exposes the
always-available software TOFU fallback; platform backends slot in behind
Cargo features later.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from one_link_native import hwkey as _native_hwkey  # type: ignore[import-not-found]
    from one_link_native import OlHwKeyError  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
except ImportError as exc:
    HAS_NATIVE = False
    _native_hwkey = None  # type: ignore[assignment]
    OlHwKeyError = RuntimeError  # type: ignore[assignment, misc]
    log.info(
        "one_link_native.hwkey not installed (%s); ADR-0023 hwkey abstraction "
        "unavailable. Build via `cd native && maturin develop --release`.",
        exc,
    )


def tofu_store(root: bytes):
    """Build a fresh TofuStore seeded with the 32-byte `root`."""
    _require_native()
    return _native_hwkey.TofuStore(root)


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.hwkey required for ADR-0023 hardware-bound keys "
            "but not installed; build via `cd native && maturin develop --release`."
        )
