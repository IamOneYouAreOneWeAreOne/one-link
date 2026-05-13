"""Adapter for the file-engine v2 native LT fountain codec (``ol_fountain``
via ``one_link_native``).

Per ADR-0015: LT codes for swarm-resilient chunk distribution. The
encoder produces a deterministic stream of XORed symbols seeded by
``symbol_id``; the decoder reconstructs the original chunk from any
sufficient subset via belief propagation.

If the native module isn't built, ``HAS_NATIVE`` is False; daemon code
paths that need fountain encoding should degrade gracefully to
``ChunkResponse`` (the Phase B request/response fallback).

ADR cross-references:

- ADR-0015 (LT codes; Robust Soliton; 1 KiB symbols; c=0.03 δ=0.05)
- ADR-0006 (BLAKE3 ``ol-fountain-lt-v1`` derive context for symbol seeds)
- ADR-0008 (pyo3 + maturin + abi3 FFI contract)
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from one_link_native import fountain as _native_fountain  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_fountain, "__version__", None)
    PACKET_HEADER_LEN: int = _native_fountain.PACKET_HEADER_LEN
    MAX_ENCODED_PER_CHUNK: int = _native_fountain.MAX_ENCODED_PER_CHUNK
    SOLITON_C: float = _native_fountain.C
    SOLITON_DELTA: float = _native_fountain.DELTA
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    _native_fountain = None  # type: ignore[assignment]
    PACKET_HEADER_LEN = 44
    MAX_ENCODED_PER_CHUNK = 2048
    SOLITON_C = 0.03
    SOLITON_DELTA = 0.05
    log.info(
        "one_link_native.fountain not installed (%s); ADR-0015 LT fountain "
        "codes unavailable. Build via `cd native && maturin develop --release`.",
        exc,
    )

# The default symbol length per ADR-0015 v1.
SYMBOL_LEN: int = 1024


def make_encoder(source: bytes, symbol_len: int = SYMBOL_LEN):
    """Build an LT encoder over ``source`` with the given symbol length."""
    _require_native()
    return _native_fountain.LtEncoder(source, symbol_len)


def make_decoder(k: int, symbol_len: int, source_length: int):
    """Build an LT decoder for a chunk with ``k`` source symbols."""
    _require_native()
    return _native_fountain.LtDecoder(k, symbol_len, source_length)


def encode_packet(
    chunk_id: bytes,
    k: int,
    symbol_id: int,
    source_length: int,
    payload: bytes,
) -> bytes:
    """Encode an on-wire fountain packet."""
    _require_native()
    return _native_fountain.encode_packet(chunk_id, k, symbol_id, source_length, payload)


def decode_packet(encoded: bytes):
    """Decode an on-wire fountain packet.

    Returns ``(chunk_id, k, symbol_id, source_length, payload)``.
    """
    _require_native()
    return _native_fountain.decode_packet(encoded)


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.fountain is required for ADR-0015 LT codes "
            "but isn't installed; build via `cd native && maturin develop --release`."
        )
