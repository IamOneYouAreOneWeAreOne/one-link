"""Type stubs for ``one_link_native.pqkem`` (ADR-0017)."""

from typing import Tuple, final

__version__: str
HYBRID_PUBLIC_KEY_LEN: int
HYBRID_SECRET_KEY_LEN: int
HYBRID_CIPHERTEXT_LEN: int
SHARED_SECRET_LEN: int


@final
class HybridPublicKey:
    @staticmethod
    def from_bytes(bytes: bytes) -> "HybridPublicKey": ...
    def to_bytes(self) -> bytes: ...


@final
class HybridSecretKey:
    @staticmethod
    def from_bytes(bytes: bytes) -> "HybridSecretKey": ...
    def to_bytes(self) -> bytes: ...


@final
class HybridCiphertext:
    @staticmethod
    def from_bytes(bytes: bytes) -> "HybridCiphertext": ...
    def to_bytes(self) -> bytes: ...


def keypair() -> Tuple[HybridPublicKey, HybridSecretKey]: ...
def encapsulate(pk: HybridPublicKey) -> Tuple[HybridCiphertext, bytes]: ...
def decapsulate(sk: HybridSecretKey, ct: HybridCiphertext) -> bytes: ...
