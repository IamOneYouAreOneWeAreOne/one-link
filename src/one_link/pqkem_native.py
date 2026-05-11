"""Adapter for the file-engine v2 native PQ-hybrid KEM (``ol_pqkem``
via ``one_link_native``).

Per ADR-0017: ML-KEM-768 + X25519 hybrid via BLAKE3 combiner.
Replaces the daemon's placeholder ``pq_hybrid.NullKEM``.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from one_link_native import pqkem as _native_pqkem  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_pqkem, "__version__", None)
    HYBRID_PUBLIC_KEY_LEN: int = _native_pqkem.HYBRID_PUBLIC_KEY_LEN
    HYBRID_SECRET_KEY_LEN: int = _native_pqkem.HYBRID_SECRET_KEY_LEN
    HYBRID_CIPHERTEXT_LEN: int = _native_pqkem.HYBRID_CIPHERTEXT_LEN
    SHARED_SECRET_LEN: int = _native_pqkem.SHARED_SECRET_LEN
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    _native_pqkem = None  # type: ignore[assignment]
    HYBRID_PUBLIC_KEY_LEN = 1216
    HYBRID_SECRET_KEY_LEN = 2432
    HYBRID_CIPHERTEXT_LEN = 1120
    SHARED_SECRET_LEN = 32
    log.info(
        "one_link_native.pqkem not installed (%s); ADR-0017 PQ-hybrid KEM "
        "unavailable. Build via `cd native && maturin develop --release`.",
        exc,
    )


def keypair():
    """Generate a fresh hybrid keypair via OS RNG. Returns
    ``(public_key, secret_key)``."""
    _require_native()
    return _native_pqkem.keypair()


def encapsulate(public_key):
    """Encapsulate against ``public_key``. Returns
    ``(ciphertext, shared_secret_bytes)``."""
    _require_native()
    return _native_pqkem.encapsulate(public_key)


def decapsulate(secret_key, ciphertext) -> bytes:
    """Decapsulate ``ciphertext`` with ``secret_key``. Returns the
    32-byte shared secret."""
    _require_native()
    return _native_pqkem.decapsulate(secret_key, ciphertext)


def public_key_from_bytes(b: bytes):
    """Parse a serialized public key from wire bytes."""
    _require_native()
    return _native_pqkem.HybridPublicKey.from_bytes(b)


def secret_key_from_bytes(b: bytes):
    """Parse a serialized secret key from wire bytes."""
    _require_native()
    return _native_pqkem.HybridSecretKey.from_bytes(b)


def ciphertext_from_bytes(b: bytes):
    """Parse a serialized ciphertext from wire bytes."""
    _require_native()
    return _native_pqkem.HybridCiphertext.from_bytes(b)


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.pqkem required for ADR-0017 PQ-hybrid KEM "
            "but not installed; build via `cd native && maturin develop --release`."
        )
