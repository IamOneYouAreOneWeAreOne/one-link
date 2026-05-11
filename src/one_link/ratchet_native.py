"""Adapter for the file-engine v2 native per-chunk ratchet (``ol_ratchet``
via ``one_link_native``).

Per ADR-0020: symmetric BLAKE3 chain ratchet for per-chunk forward
secrecy. Phase C item #6.

Typical usage::

    chain = ratchet_native.from_shared_secret(kem_shared_secret_bytes)
    for chunk in chunks:
        mk = chain.next_message_key()  # 32 bytes
        # use mk as AEAD key for `chunk`
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from one_link_native import ratchet as _native_ratchet  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_ratchet, "__version__", None)
    DEFAULT_SKIPPED_CAP: int = _native_ratchet.DEFAULT_SKIPPED_CAP
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    _native_ratchet = None  # type: ignore[assignment]
    DEFAULT_SKIPPED_CAP = 1024
    log.info(
        "one_link_native.ratchet not installed (%s); ADR-0020 per-chunk "
        "forward-secret ratchet will be unavailable. Build via `cd native "
        "&& maturin develop --release`.",
        exc,
    )


def from_shared_secret(shared_secret: bytes):
    """Bootstrap a chain from a KEM shared secret."""
    _require_native()
    return _native_ratchet.Chain.from_shared_secret(shared_secret)


def skipped_store(cap: int = 1024):
    """Build a bounded skipped-key store."""
    _require_native()
    return _native_ratchet.SkippedKeyStore(cap)


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.ratchet required for ADR-0020 ratchet but "
            "not installed; build via `cd native && maturin develop --release`."
        )
