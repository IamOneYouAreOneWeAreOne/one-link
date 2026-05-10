"""Adapter for the file-engine v2 native AEAD pipeline (ol_aead via one_link_native).

Per ADR-0002 (16 KiB AEAD frames inside CDC chunks; AES-256-GCM primary,
ChaCha20-Poly1305 fallback) and ADR-0006 (per-chunk key derivation). This
module exposes a small, stable Python surface so the daemon and tests
import the same shape regardless of whether the native module is built.

Falls back to ``RuntimeError`` if the native crate is missing; callers
should check :data:`HAS_NATIVE` first and either route around (Phase B
adds a slow-path Python AEAD using the cryptography library if absolutely
necessary; for now: build the crate via ``cd native && maturin develop --release``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal, Tuple

log = logging.getLogger(__name__)

try:
    from one_link_native import aead as _native_aead  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
except ImportError as exc:
    HAS_NATIVE = False
    _native_aead = None  # type: ignore[assignment]
    log.info(
        "one_link_native.aead unavailable (%s); the file-engine v2 AEAD pipeline "
        "is currently CRDT-only or chat-class. Build via "
        "`cd native && maturin develop --release` for Phase A1 hot-path AEAD.",
        exc,
    )


AeadKindStr = Literal["aes", "chacha"]


# Constants surfaced for downstream callers / tests. ``None`` if native
# module isn't available.
FRAME_KEY_LEN: int | None = (
    _native_aead.FRAME_KEY_LEN if HAS_NATIVE else None
)
AEAD_TAG_LEN: int | None = _native_aead.AEAD_TAG_LEN if HAS_NATIVE else None
AEAD_FRAME_PLAINTEXT_LEN: int | None = (
    _native_aead.AEAD_FRAME_PLAINTEXT_LEN if HAS_NATIVE else None
)
MAX_CHUNK_PLAINTEXT_LEN: int | None = (
    _native_aead.MAX_CHUNK_PLAINTEXT_LEN if HAS_NATIVE else None
)


@dataclass(frozen=True)
class AeadDiagnostics:
    """A snapshot of the AEAD subsystem state.

    ``host_has_hardware_aes`` reflects runtime detection of AES-NI /
    ARM crypto extensions; ``preferred_kind`` is the AEAD the engine
    selects by default on this host.
    """

    native_available: bool
    preferred_kind: str | None
    host_has_hardware_aes: bool
    frame_key_len: int | None
    aead_tag_len: int | None
    aead_frame_plaintext_len: int | None
    max_chunk_plaintext_len: int | None


def diagnostics() -> AeadDiagnostics:
    """Return a structured snapshot of the AEAD subsystem."""
    if not HAS_NATIVE:
        return AeadDiagnostics(
            native_available=False,
            preferred_kind=None,
            host_has_hardware_aes=False,
            frame_key_len=None,
            aead_tag_len=None,
            aead_frame_plaintext_len=None,
            max_chunk_plaintext_len=None,
        )
    return AeadDiagnostics(
        native_available=True,
        preferred_kind=_native_aead.default_aead_kind(),
        host_has_hardware_aes=_native_aead.host_has_hardware_aes(),
        frame_key_len=FRAME_KEY_LEN,
        aead_tag_len=AEAD_TAG_LEN,
        aead_frame_plaintext_len=AEAD_FRAME_PLAINTEXT_LEN,
        max_chunk_plaintext_len=MAX_CHUNK_PLAINTEXT_LEN,
    )


class AeadCipher:
    """Thin Python wrapper over the native :class:`one_link_native.aead.AeadCipher`.

    Construct via :meth:`with_kind` or :meth:`default_for_host`. Reuse a
    single instance across many encrypt/decrypt calls to amortize the
    one-time round-key expansion cost.
    """

    __slots__ = ("_inner",)

    def __init__(self, inner) -> None:
        self._inner = inner

    @classmethod
    def with_kind(cls, key: bytes, kind: AeadKindStr) -> "AeadCipher":
        """Construct an explicit-kind cipher.

        :param key: 32-byte AEAD key.
        :param kind: ``"aes"`` for AES-256-GCM or ``"chacha"`` for ChaCha20-Poly1305.
        :raises RuntimeError: if the native module isn't built.
        :raises ValueError: on bad key length or unknown kind.
        """
        if not HAS_NATIVE:
            raise RuntimeError(
                "one_link_native is not installed; build via "
                "`cd native && maturin develop --release`"
            )
        return cls(_native_aead.new_cipher(key, kind))

    @classmethod
    def default_for_host(cls, key: bytes) -> "AeadCipher":
        """Construct a cipher of the host's preferred AEAD kind.

        AES-256-GCM if hardware AES is detected; ChaCha20-Poly1305 otherwise.
        """
        if not HAS_NATIVE:
            raise RuntimeError("one_link_native is not installed")
        return cls(_native_aead.default_cipher_for_host(key))

    @property
    def kind(self) -> str:
        return self._inner.kind

    def encrypt_chunk(self, chunk_id: bytes, plaintext: bytes | bytearray | memoryview) -> bytes:
        """Encrypt a complete chunk plaintext into the on-wire layout.

        ``chunk_id`` is the 32-byte BLAKE3 chunk address (used as AAD +
        nonce input). Returns ciphertext of length
        ``len(plaintext) + frame_count * 16``.
        """
        return self._inner.encrypt_chunk(chunk_id, plaintext)

    def decrypt_chunk(
        self,
        chunk_id: bytes,
        plaintext_len: int,
        ciphertext: bytes | bytearray | memoryview,
    ) -> bytes:
        """Decrypt a complete chunk ciphertext."""
        return self._inner.decrypt_chunk(chunk_id, plaintext_len, ciphertext)

    def encrypt_frame(
        self,
        chunk_id: bytes,
        frame_index: int,
        plaintext: bytes | bytearray | memoryview,
    ) -> Tuple[bytes, bytes]:
        """Encrypt a single frame. Returns ``(ciphertext, tag)``."""
        return self._inner.encrypt_frame(chunk_id, frame_index, plaintext)

    def decrypt_frame(
        self,
        chunk_id: bytes,
        frame_index: int,
        ciphertext: bytes | bytearray | memoryview,
        tag: bytes,
    ) -> bytes:
        """Decrypt a single frame."""
        return self._inner.decrypt_frame(chunk_id, frame_index, ciphertext, tag)

    def __repr__(self) -> str:
        return f"AeadCipher(kind={self.kind!r})"
