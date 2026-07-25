"""Adapter for the file-engine v2 native erasure codec (``ol_erasure``
via ``one_link_native``).

Per ADR-0018: chunk-level Reed-Solomon stripe encode + decode with
three durability profiles (EPHEMERAL, STANDARD, ARCHIVAL).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from one_link_native.erasure import StripeParams

log = logging.getLogger(__name__)

EPHEMERAL: StripeParams | None
STANDARD: StripeParams | None
ARCHIVAL: StripeParams | None

try:
    from one_link_native import erasure as _native_erasure  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_erasure, "__version__", None)
    EPHEMERAL = _native_erasure.StripeParams.EPHEMERAL
    STANDARD = _native_erasure.StripeParams.STANDARD
    ARCHIVAL = _native_erasure.StripeParams.ARCHIVAL
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    _native_erasure = None  # type: ignore[assignment]
    EPHEMERAL = None
    STANDARD = None
    ARCHIVAL = None
    log.info(
        "one_link_native.erasure not installed (%s); ADR-0018 erasure-coded "
        "durability unavailable. Build via `cd native && maturin develop --release`.",
        exc,
    )


def params(k: int, m: int):
    """Build a custom StripeParams (`k` data + `m` parity shards)."""
    _require_native()
    return _native_erasure.StripeParams(k, m)


def encode(plaintext: bytes, params):
    """Encode `plaintext` into a list of `k + m` Shard objects."""
    _require_native()
    return _native_erasure.encode_stripe(plaintext, params)


def decode(params, present_shards) -> bytes:
    """Decode a stripe back to plaintext. `present_shards` is a list
    of length `k + m`; entries may be ``Shard`` or ``None``."""
    _require_native()
    return _native_erasure.decode_stripe(params, list(present_shards))


def stripe_id(plaintext: bytes, params) -> bytes:
    """Compute the canonical 32-byte StripeId for a `(plaintext, params)`
    tuple."""
    _require_native()
    return _native_erasure.stripe_id(plaintext, params)


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.erasure required for ADR-0018 erasure-coded "
            "durability but not installed; build via `cd native && maturin develop --release`."
        )
