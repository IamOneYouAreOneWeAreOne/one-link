"""Adapter for the file-engine v2 native Bloom filter (``ol_bloom`` via
``one_link_native``).

Per ADR-0011: this is the transfer-init handshake's Bloom layer. A peer
encodes the chunk_ids it already has, sends the filter; the remote side
walks its inventory and returns the chunk_ids not in the filter.

If the native module isn't built, ``HAS_NATIVE`` is False and callers
should fall back to a pure-Python implementation (none ships in v0.21.0
yet; daemon code paths that require it will skip / fail loud).

ADR cross-references:

- ADR-0011 (Bloom transfer init; Kirsch+Mitzenmacher double hash; 1% FP)
- ADR-0006 (BLAKE3 derive contexts ``ol-bloom-h1-v1`` / ``ol-bloom-h2-v1``)
- ADR-0008 (pyo3 + maturin + abi3 FFI contract)
"""

from __future__ import annotations

import logging
from typing import Iterable

log = logging.getLogger(__name__)

try:
    from one_link_native import bloom as _native_bloom  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_bloom, "__version__", None)
    BLOOM_HEADER_LEN: int = _native_bloom.BLOOM_HEADER_LEN
    MAX_FILTER_BYTES: int = _native_bloom.MAX_FILTER_BYTES
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    _native_bloom = None  # type: ignore[assignment]
    BLOOM_HEADER_LEN = 12
    MAX_FILTER_BYTES = 1024 * 1024
    log.info(
        "one_link_native.bloom not installed (%s); ADR-0011 Bloom-init "
        "handshake will be unavailable until the native crate is built. "
        "Install via `cd native && maturin develop --release`.",
        exc,
    )


def new(n: int, target_fp: float | None = None):
    """Build an empty Bloom filter sized for ``n`` chunk_ids."""
    _require_native()
    if target_fp is None:
        return _native_bloom.Bloom(n)
    return _native_bloom.Bloom(n, target_fp)


def build_from_ids(ids: Iterable[bytes], target_fp: float | None = None):
    """Build a Bloom filter containing the supplied chunk_ids.

    ``ids`` may be any iterable of 32-byte ``bytes`` objects.
    """
    _require_native()
    ids = list(ids)
    f = new(max(len(ids), 1), target_fp=target_fp)
    for cid in ids:
        f.insert(cid)
    return f


def decode(encoded: bytes):
    """Decode a wire-format Bloom filter."""
    _require_native()
    return _native_bloom.Bloom.decode(encoded)


def optimal_m_bits(n: int, target_fp: float = 0.01) -> int:
    """Sizing helper: optimal ``m_bits`` for ``n`` elements + FP target."""
    _require_native()
    return _native_bloom.optimal_m_bits(n, target_fp)


def optimal_k(n: int, m_bits: int) -> int:
    """Sizing helper: optimal ``k`` (hash count) for ``n`` + ``m_bits``."""
    _require_native()
    return _native_bloom.optimal_k(n, m_bits)


def default_target_fp_rate() -> float:
    """Default target false-positive rate (1%)."""
    _require_native()
    return _native_bloom.default_target_fp_rate()


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.bloom is required for ADR-0011 Bloom-init but "
            "isn't installed; build via `cd native && maturin develop --release`."
        )
