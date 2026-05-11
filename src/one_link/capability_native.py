"""Adapter for the file-engine v2 native capability layer (``ol_capability``
via ``one_link_native``).

Per ADR-0021: macaroon-style HMAC-chained capabilities. Replaces the
daemon's Ed25519 grant scheme in ``One_link/src/one_link/capabilities.py``.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from one_link_native import capability as _native_cap  # type: ignore[import-not-found]
    from one_link_native import OlCapabilityError  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_cap, "__version__", None)
    CAP_ID_LEN: int = getattr(_native_cap, "CAP_ID_LEN", 32)
    ROOT_KEY_LEN: int = getattr(_native_cap, "ROOT_KEY_LEN", 32)
    SIGNATURE_LEN: int = getattr(_native_cap, "SIGNATURE_LEN", 32)
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    CAP_ID_LEN = 32
    ROOT_KEY_LEN = 32
    SIGNATURE_LEN = 32
    _native_cap = None  # type: ignore[assignment]
    OlCapabilityError = RuntimeError  # type: ignore[assignment, misc]
    log.info(
        "one_link_native.capability not installed (%s); ADR-0021 cap layer "
        "unavailable. Build via `cd native && maturin develop --release`.",
        exc,
    )


def root_capability(cap_id: bytes, root_key: bytes):
    """Mint a fresh root capability with no caveats."""
    _require_native()
    return _native_cap.Capability.root(cap_id, root_key)


def decode_capability(wire: bytes):
    """Decode a capability from its wire bytes (signature not verified)."""
    _require_native()
    return _native_cap.Capability.decode(wire)


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.capability required for ADR-0021 capability layer "
            "but not installed; build via `cd native && maturin develop --release`."
        )
