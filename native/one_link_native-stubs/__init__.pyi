# Type stubs for one_link_native (the pyo3 binding crate).
#
# Surfaces precise Python-typed APIs for the Rust crates so editors,
# pyright, mypy, and the existing One Link daemon get full type checking.
# Per ADR-0008.

from __future__ import annotations

from typing import Iterator, Sequence

__version__: str
chunk_version: str

class OlError(Exception):
    """Base class for all one_link_native errors."""

class OlChunkError(OlError):
    """Errors from the ol_chunk crate (CDC, BLAKE3, frame layout)."""

class chunk:
    """``one_link_native.chunk`` submodule namespace (re-imported from Rust)."""

    CDC_MIN_SIZE: int
    """Minimum CDC chunk size in bytes (8 KiB per ADR-0001)."""

    CDC_AVG_SIZE: int
    """Average CDC chunk size in bytes (64 KiB per ADR-0001)."""

    CDC_MAX_SIZE: int
    """Maximum CDC chunk size in bytes (256 KiB per ADR-0001)."""

    AEAD_FRAME_PLAINTEXT_LEN: int
    """AEAD frame plaintext payload size in bytes (16 KiB per ADR-0002)."""

    AEAD_TAG_LEN: int
    """AEAD authentication tag length in bytes (16 per ADR-0002)."""

    class Boundary:
        """One CDC chunk boundary: ``(start, end, raw_address)``."""

        @property
        def start(self) -> int: ...
        @property
        def end(self) -> int: ...
        @property
        def length(self) -> int: ...
        @property
        def raw_address(self) -> bytes:
            """BLAKE3-256 hash of the chunk plaintext (32 bytes)."""

        def raw_address_hex(self) -> str: ...

    class BoundaryIterator:
        """Iterator over Boundary objects produced by :func:`cdc_iter`."""

        def __iter__(self) -> Iterator[chunk.Boundary]: ...
        def __next__(self) -> chunk.Boundary: ...
        def __len__(self) -> int: ...

    @staticmethod
    def cdc_iter(buf: bytes | bytearray | memoryview) -> chunk.BoundaryIterator:
        """Scan a byte buffer with default ADR-0001 CDC parameters.

        Releases the GIL during the scan. Buffer must be C-contiguous.
        """

    @staticmethod
    def chunk_address_raw(buf: bytes | bytearray | memoryview) -> bytes:
        """Compute the raw BLAKE3-256 chunk address for a buffer (32 bytes)."""

    @staticmethod
    def chunk_address_convergent(buf: bytes | bytearray | memoryview) -> bytes:
        """Compute the convergent BLAKE3-256 chunk address for a buffer (32 bytes).

        Domain-separated from raw address per ADR-0006.
        """

    @staticmethod
    def derive_aead_key(ratchet_chain_key: bytes, chunk_id_full: bytes) -> bytes:
        """Derive a per-chunk AEAD key (32 bytes) per ADR-0006 Rule 3.

        Both inputs must be exactly 32 bytes.
        """

    @staticmethod
    def derive_ratchet_key_id(ratchet_chain_key: bytes, chunk_id_full: bytes) -> bytes:
        """Derive the 16-byte ratchet_key_id for a chunk per ADR-0006 Rule 4."""

    @staticmethod
    def derive_stripe_seed(chunk_id_full: bytes, stripe_k: int) -> tuple[int, int]:
        """Derive ``(stripe_seed, position)`` per ADR-0004 + ADR-0006 Rule 5.

        :param chunk_id_full: 32-byte BLAKE3 chunk address.
        :param stripe_k: Number of data shards per stripe (≥ 1).
        :return: ``(stripe_seed_u64, position_u8)`` where ``position`` is in ``[0, stripe_k)``.
        """

    @staticmethod
    def frame_count(plaintext_len: int) -> int:
        """Compute the AEAD frame count for a plaintext chunk of given length."""
