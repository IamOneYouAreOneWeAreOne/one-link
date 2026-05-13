"""Adapter for Ed25519 + ML-DSA-65 hybrid signatures (row 1).

Per `COHERENCE_MESH_PLAN.md` row 1. Master identity needs to survive
a future cryptanalytic break of Ed25519. ML-DSA-65 (NIST FIPS 204)
gives us lattice-based PQ signatures with strong NIST analysis.

Hybrid: a hybrid signature requires BOTH halves (Ed25519 + ML-DSA-65)
to verify. An attacker must break BOTH schemes to forge.

## Sizes

| What            | Bytes   |
|-----------------|---------|
| Signing key     | 64      |
| Verifying key   | 1984    |
| Signature       | 3373    |

## When to use

- **Master identity** (rare ops: device pair, social-recovery share
  commits, capability root) — yes, use hybrid.
- **Per-message signing** (chat messages, file chunks) — no, the
  3373-byte signature is too heavy + ML-DSA seed expansion is ~ms
  per sign. Use Ed25519 alone + Double Ratchet.

## Usage

.. code-block:: python

    from one_link import pqsig_native as pq

    # Generate master identity once, store sk_bytes encrypted at rest.
    sk_bytes, vk_bytes = pq.generate_keypair()

    # Sign a capability commit (rare op).
    sig = pq.sign(sk_bytes, message=b"capability:contact:josh")

    # Verifier (could be another device or peer) checks the hybrid sig.
    pq.verify(vk_bytes, message=b"capability:contact:josh", sig=sig)
"""

from __future__ import annotations

import logging
from typing import Tuple

log = logging.getLogger(__name__)

try:
    from one_link_native import pqsig as _native_pqsig  # type: ignore[import-not-found,attr-defined]

    HAS_NATIVE: bool = True
    HYBRID_SK_LEN: int = _native_pqsig.HYBRID_SK_LEN
    HYBRID_VK_LEN: int = _native_pqsig.HYBRID_VK_LEN
    HYBRID_SIG_LEN: int = _native_pqsig.HYBRID_SIG_LEN
except ImportError as exc:
    HAS_NATIVE = False
    _native_pqsig = None  # type: ignore[assignment]
    HYBRID_SK_LEN = 64
    HYBRID_VK_LEN = 1984
    HYBRID_SIG_LEN = 3373
    log.info(
        "one_link_native.pqsig not installed (%s); PQ-hybrid signatures "
        "unavailable. Build via `cd native && maturin develop --release`.",
        exc,
    )


class NativeMissingError(RuntimeError):
    """Raised when the native pqsig surface is not available."""


def _require_native() -> None:
    if not HAS_NATIVE:
        raise NativeMissingError(
            "one_link_native.pqsig unavailable; rebuild via "
            "`cd native && maturin develop --release`"
        )


def generate_keypair() -> Tuple[bytes, bytes]:
    """Generate a fresh hybrid Ed25519 + ML-DSA-65 keypair.

    Returns `(sk_64, vk_1984)`. Store sk encrypted at rest.
    """
    _require_native()
    sk, vk = _native_pqsig.generate_keypair()
    return bytes(sk), bytes(vk)


def derive_vk(sk: bytes) -> bytes:
    """Derive the hybrid verifying key from a 64-byte signing key."""
    _require_native()
    if len(sk) != HYBRID_SK_LEN:
        raise ValueError(f"sk must be {HYBRID_SK_LEN} bytes, got {len(sk)}")
    return bytes(_native_pqsig.derive_vk(sk))


def sign(sk: bytes, message: bytes) -> bytes:
    """Hybrid-sign `message` with the 64-byte signing key. Returns
    the 3373-byte signature (Ed25519_sig || ML-DSA-65_sig)."""
    _require_native()
    if len(sk) != HYBRID_SK_LEN:
        raise ValueError(f"sk must be {HYBRID_SK_LEN} bytes, got {len(sk)}")
    return bytes(_native_pqsig.sign(sk, message))


def verify(vk: bytes, message: bytes, sig: bytes) -> None:
    """Verify a hybrid signature. Raises ValueError on any failure
    (length mismatch, Ed25519 fail, ML-DSA fail).

    Both halves must pass — an attacker must break BOTH to forge.
    """
    _require_native()
    if len(vk) != HYBRID_VK_LEN:
        raise ValueError(f"vk must be {HYBRID_VK_LEN} bytes, got {len(vk)}")
    if len(sig) != HYBRID_SIG_LEN:
        raise ValueError(f"sig must be {HYBRID_SIG_LEN} bytes, got {len(sig)}")
    _native_pqsig.verify(vk, message, sig)


__all__ = [
    "HAS_NATIVE",
    "NativeMissingError",
    "generate_keypair",
    "derive_vk",
    "sign",
    "verify",
    "HYBRID_SK_LEN",
    "HYBRID_VK_LEN",
    "HYBRID_SIG_LEN",
]
