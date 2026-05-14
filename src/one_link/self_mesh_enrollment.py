"""Personal Device Mesh enrollment helpers.

These functions keep the ceremony deterministic and small enough for
the daemon, API, and tests to share: create/import a root identity,
mint device certificates, and derive safe public summaries.
"""

from __future__ import annotations

import base64
import secrets
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.identity_dag import encode_device_cert, verify_device_cert


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


@dataclass(frozen=True)
class MeshRoot:
    root_seed: bytes
    root_pub: bytes

    def __post_init__(self) -> None:
        if len(self.root_seed) != 32:
            raise ValueError("root_seed must be 32 bytes")
        if len(self.root_pub) != 32:
            raise ValueError("root_pub must be 32 bytes")

    @classmethod
    def create(cls) -> "MeshRoot":
        seed = secrets.token_bytes(32)
        pub = Ed25519PrivateKey.from_private_bytes(
            seed
        ).public_key().public_bytes_raw()
        return cls(root_seed=seed, root_pub=pub)

    @classmethod
    def from_seed(cls, seed: bytes) -> "MeshRoot":
        if len(seed) != 32:
            raise ValueError("root_seed must be 32 bytes")
        pub = Ed25519PrivateKey.from_private_bytes(
            seed
        ).public_key().public_bytes_raw()
        return cls(root_seed=seed, root_pub=pub)


def mint_device_cert(
    *,
    root_seed: bytes,
    root_pub: bytes,
    device_pub: bytes,
    device_kind: str,
    expires_ms: int = 0,
) -> bytes:
    return encode_device_cert(
        root_priv_seed=root_seed,
        root_pub=root_pub,
        device_pub=device_pub,
        device_kind=device_kind,
        added_ms=int(time.time() * 1000),
        expires_ms=expires_ms,
    )


def verify_enrollment_cert(
    cert: bytes,
    *,
    expected_root_pub: bytes | None = None,
) -> dict[str, Any]:
    parsed = verify_device_cert(cert, expected_root_pub=expected_root_pub)
    return {
        "root_pub": parsed.root_pub,
        "device_pub": parsed.device_pub,
        "device_kind": parsed.device_kind,
        "added_ms": parsed.added_ms,
        "expires_ms": parsed.expires_ms,
    }


__all__ = [
    "MeshRoot",
    "b64u",
    "b64u_decode",
    "mint_device_cert",
    "verify_enrollment_cert",
]
