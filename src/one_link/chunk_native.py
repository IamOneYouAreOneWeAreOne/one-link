"""Adapter for the file-engine v2 native chunk-layer (ol_chunk via one_link_native).

Per FILE_ENGINE_V2_PLAN.md: the existing Python ``cdc.py`` (custom Gear-CDC)
remains available as the v0.20.x compatibility kernel. This module surfaces
the new FastCDC v2020 kernel from the Rust crate ``ol_chunk``, exposed
through the ``one_link_native`` pyo3 binding.

If the native module isn't built (e.g. dev environment without Rust),
``HAS_NATIVE`` is False and callers can fall back to the legacy Python
kernel. The daemon's import sites should use this module's helpers and let
the adapter pick the available implementation, never importing the Rust
module directly.

Acceptance gates and ADR cross-references:

- ADR-0001 (CDC kernel choice; FastCDC v2020 with 8 / 64 / 256 KiB params)
- ADR-0006 (BLAKE3 domain-separated derivation)
- ADR-0008 (Python ↔ Rust FFI contract; pyo3 + maturin + abi3)

This module deliberately exposes a small surface; downstream code uses these
functions and never poke at internal pyo3 attributes. That keeps the daemon
decoupled from the Rust crate's exact API shape across native version
upgrades.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Iterator, Protocol, cast

log = logging.getLogger(__name__)


class _NativeBoundaryView(Protocol):
    @property
    def start(self) -> int: ...

    @property
    def end(self) -> int: ...

    @property
    def raw_address(self) -> bytes: ...


class _NativeChunkModule(Protocol):
    CDC_MIN_SIZE: int
    CDC_AVG_SIZE: int
    CDC_MAX_SIZE: int
    AEAD_FRAME_PLAINTEXT_LEN: int
    AEAD_TAG_LEN: int

    def cdc_iter(self, buf: bytes | bytearray | memoryview) -> Iterable[_NativeBoundaryView]: ...
    def chunk_address_raw(self, buf: bytes | bytearray | memoryview) -> bytes: ...
    def chunk_address_convergent(self, buf: bytes | bytearray | memoryview) -> bytes: ...
    def derive_aead_key(self, ratchet_chain_key: bytes, chunk_id_full: bytes) -> bytes: ...
    def derive_ratchet_key_id(self, ratchet_chain_key: bytes, chunk_id_full: bytes) -> bytes: ...
    def derive_stripe_seed(self, chunk_id_full: bytes, stripe_k: int) -> tuple[int, int]: ...
    def frame_count(self, plaintext_len: int) -> int: ...


_native_chunk: _NativeChunkModule | None = None

try:
    import one_link_native as _native_package
    from one_link_native import chunk as _loaded_native_chunk

    _native_chunk = cast(_NativeChunkModule, _loaded_native_chunk)
    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = _native_package.chunk_version
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    log.info(
        "one_link_native not installed (%s); file-engine v2 callers fall back "
        "to the legacy cdc.py Python kernel. Install via `cd native && maturin "
        "develop --release` to enable the native hot-path crates.",
        exc,
    )


@dataclass(frozen=True)
class NativeBoundary:
    """A CDC chunk boundary surfaced via the native module.

    Mirrors :class:`one_link_native.chunk.Boundary` but is a pure Python
    dataclass so callers can pickle, dataclasses.asdict, etc. without
    crossing the FFI boundary repeatedly.
    """

    start: int
    end: int
    raw_address: bytes  # 32 bytes

    @property
    def length(self) -> int:
        return self.end - self.start

    @property
    def raw_address_hex(self) -> str:
        return self.raw_address.hex()


# CDC parameters surfaced for inspection / Python-side regression testing.
# Empty tuple if native module not built (callers must check HAS_NATIVE first).
if _native_chunk is None:
    CDC_PARAMS: tuple[int, int, int] | tuple[()] = ()
    AEAD_FRAME_PLAINTEXT_LEN: int | None = None
    AEAD_TAG_LEN: int | None = None
else:
    CDC_PARAMS = (
        _native_chunk.CDC_MIN_SIZE,
        _native_chunk.CDC_AVG_SIZE,
        _native_chunk.CDC_MAX_SIZE,
    )
    AEAD_FRAME_PLAINTEXT_LEN = _native_chunk.AEAD_FRAME_PLAINTEXT_LEN
    AEAD_TAG_LEN = _native_chunk.AEAD_TAG_LEN


def _require_native() -> _NativeChunkModule:
    module = _native_chunk
    if not HAS_NATIVE or module is None:
        raise RuntimeError("one_link_native not installed")
    return module


def cdc_iter(buf: bytes | bytearray | memoryview) -> Iterator[NativeBoundary]:
    """Iterate ADR-0001 chunk boundaries over a byte buffer using the native kernel.

    Releases the GIL during the scan (handled by the underlying Rust
    binding). Raises :class:`RuntimeError` if the native module isn't
    available; check :data:`HAS_NATIVE` before calling.
    """
    module = _native_chunk
    if not HAS_NATIVE or module is None:
        raise RuntimeError(
            "one_link_native is not installed; cannot run native CDC. "
            "Install via `cd native && maturin develop --release` "
            "or use the legacy `one_link.cdc.chunk_bytes` fallback."
        )
    for boundary in module.cdc_iter(buf):
        yield NativeBoundary(
            start=boundary.start,
            end=boundary.end,
            raw_address=boundary.raw_address,
        )


def chunk_address_raw(buf: bytes | bytearray | memoryview) -> bytes:
    """Compute the raw BLAKE3-256 chunk address (per ADR-0006 Rule 1)."""
    return _require_native().chunk_address_raw(buf)


def chunk_address_convergent(buf: bytes | bytearray | memoryview) -> bytes:
    """Compute the convergent BLAKE3-256 chunk address (per ADR-0006 Rule 2)."""
    return _require_native().chunk_address_convergent(buf)


def derive_aead_key(ratchet_chain_key: bytes, chunk_id_full: bytes) -> bytes:
    """Derive a per-chunk AEAD key per ADR-0006 Rule 3. 32 bytes."""
    return _require_native().derive_aead_key(ratchet_chain_key, chunk_id_full)


def derive_ratchet_key_id(ratchet_chain_key: bytes, chunk_id_full: bytes) -> bytes:
    """Derive the 16-byte ratchet_key_id per ADR-0006 Rule 4."""
    return _require_native().derive_ratchet_key_id(ratchet_chain_key, chunk_id_full)


def derive_stripe_seed(chunk_id_full: bytes, stripe_k: int) -> tuple[int, int]:
    """Derive ``(stripe_seed, position)`` per ADR-0004 + ADR-0006 Rule 5."""
    return _require_native().derive_stripe_seed(chunk_id_full, stripe_k)


def frame_count(plaintext_len: int) -> int:
    """Compute the AEAD frame count for a plaintext chunk per ADR-0002."""
    return _require_native().frame_count(plaintext_len)


def diagnostics() -> dict[str, object]:
    """Return a structured snapshot of the native chunk module status.

    Useful for the daemon's ``/api/diagnostics`` and the ``one-link doctor``
    CLI command. All keys are stable strings; values are JSON-serializable.
    """
    if not HAS_NATIVE:
        return {
            "native_available": False,
            "version": None,
            "fallback_kernel": "one_link.cdc (Gear-CDC, 16/64/256 KiB)",
            "install_hint": "cd native && maturin develop --release",
        }
    return {
        "native_available": True,
        "version": NATIVE_VERSION,
        "kernel": "FastCDC v2020 + Gear-256",
        "cdc_min_avg_max": CDC_PARAMS,
        "aead_frame_plaintext_len": AEAD_FRAME_PLAINTEXT_LEN,
        "aead_tag_len": AEAD_TAG_LEN,
    }
