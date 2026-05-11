"""Type stubs for ``one_link_native.pqkem`` (ADR-0017)."""

from typing import Tuple

__version__: str
HYBRID_PUBLIC_KEY_LEN: int
HYBRID_SECRET_KEY_LEN: int
HYBRID_CIPHERTEXT_LEN: int
SHARED_SECRET_LEN: int


class HybridPublicKey:
    @staticmethod
    def from_bytes(b: bytes) -> "HybridPublicKey": ...
    def to_bytes(self) -> bytes: ...


class HybridSecretKey:
    @staticmethod
    def from_bytes(b: bytes) -> "HybridSecretKey": ...
    def to_bytes(self) -> bytes: ...


class HybridCiphertext:
    @staticmethod
    def from_bytes(b: bytes) -> "HybridCiphertext": ...
    def to_bytes(self) -> bytes: ...


def keypair() -> Tuple[HybridPublicKey, HybridSecretKey]: ...
def encapsulate(public_key: HybridPublicKey) -> Tuple[HybridCiphertext, bytes]: ...
def decapsulate(secret_key: HybridSecretKey, ciphertext: HybridCiphertext) -> bytes: ...
