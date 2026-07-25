"""Adapter for the file-engine v2 native PQ-hybrid KEM (``ol_pqkem``
via ``one_link_native``).

Per ADR-0017: ML-KEM-768 + X25519 hybrid via BLAKE3 combiner.
Replaces the daemon's placeholder ``pq_hybrid.NullKEM``.
"""

from __future__ import annotations

import hmac
import logging
from functools import lru_cache

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
    # WARNING, not INFO: losing the native PQ engine is a security-relevant
    # capability downgrade (harvest-now-decrypt-later exposure), not routine
    # info. default_kem() now fails closed on this unless a caller explicitly
    # opts into the classical-only downgrade.
    log.warning(
        "one_link_native.pqkem not installed (%s); ADR-0017 PQ-hybrid KEM "
        "UNAVAILABLE -- PQ protection is OFF unless the native engine is built "
        "(`cd native && maturin develop --release`). default_kem() will fail "
        "closed rather than silently downgrade to X25519-only.",
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


def runtime_is_usable() -> bool:
    """Return whether the loaded native ABI passes an actual KEM self-test.

    Import success alone is not enough to advertise a cryptographic wire
    capability: stale wheels, partial extension modules, and ABI-shape drift
    must all fail closed.  The round trip is cached per process after the
    first successful probe, while ``HAS_NATIVE=False`` is always observed
    immediately (including in tests and controlled fault injection).
    """
    if not HAS_NATIVE or _native_pqkem is None:
        return False
    return _runtime_self_test_cached()


@lru_cache(maxsize=1)
def _runtime_self_test_cached() -> bool:
    try:
        if (
            HYBRID_PUBLIC_KEY_LEN != 1216
            or HYBRID_SECRET_KEY_LEN != 2432
            or HYBRID_CIPHERTEXT_LEN != 1120
            or SHARED_SECRET_LEN != 32
        ):
            raise RuntimeError("unexpected ML-KEM hybrid ABI sizes")
        required = (
            "HybridPublicKey",
            "HybridSecretKey",
            "HybridCiphertext",
            "keypair",
            "encapsulate",
            "decapsulate",
        )
        if any(not hasattr(_native_pqkem, name) for name in required):
            raise RuntimeError("native pqkem module is missing required symbols")
        public_key, secret_key = _native_pqkem.keypair()
        ciphertext, sender_secret = _native_pqkem.encapsulate(public_key)
        receiver_secret = _native_pqkem.decapsulate(secret_key, ciphertext)
        public_bytes = bytes(public_key.to_bytes())
        ciphertext_bytes = bytes(ciphertext.to_bytes())
        sender_bytes = bytes(sender_secret)
        receiver_bytes = bytes(receiver_secret)
        if len(public_bytes) != HYBRID_PUBLIC_KEY_LEN:
            raise RuntimeError("native pqkem public key length mismatch")
        if len(ciphertext_bytes) != HYBRID_CIPHERTEXT_LEN:
            raise RuntimeError("native pqkem ciphertext length mismatch")
        if len(sender_bytes) != SHARED_SECRET_LEN:
            raise RuntimeError("native pqkem shared secret length mismatch")
        if not hmac.compare_digest(sender_bytes, receiver_bytes):
            raise RuntimeError("native pqkem encapsulation/decapsulation mismatch")
        return True
    except Exception as exc:
        log.error(
            "one_link_native.pqkem runtime self-test failed; live PQ capability "
            "will not be advertised: %s",
            exc,
        )
        return False


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.pqkem required for ADR-0017 PQ-hybrid KEM "
            "but not installed; build via `cd native && maturin develop --release`."
        )
