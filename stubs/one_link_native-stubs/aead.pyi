"""Type stubs for ``one_link_native.aead`` (ADR-0002)."""

from typing import Literal

__version__: str
NONCE_LEN: int
TAG_LEN: int


AeadKind = Literal["AES-GCM-256", "ChaCha20-Poly1305"]


class ChunkAeadKey:
    @staticmethod
    def from_bytes(raw: bytes) -> "ChunkAeadKey": ...


class AeadCipher:
    def __init__(self, kind: AeadKind, key: ChunkAeadKey) -> None: ...

    def encrypt_chunk(self, chunk_id: bytes, plaintext: bytes | bytearray | memoryview) -> bytes: ...
    def decrypt_chunk(
        self,
        chunk_id: bytes,
        plaintext_len: int,
        ciphertext: bytes | bytearray | memoryview,
    ) -> bytes: ...
