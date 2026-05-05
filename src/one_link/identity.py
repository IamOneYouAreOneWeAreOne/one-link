"""Ed25519 device identity.

Each computer generates a long-term Ed25519 keypair on first run.
The public key's BLAKE3 fingerprint (first 8 hex chars) is the device ID
shown to the user. The private key never leaves disk.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from pathlib import Path

import blake3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from one_link.paths import key_path


@dataclass(frozen=True)
class Identity:
    private: Ed25519PrivateKey
    public: Ed25519PublicKey
    public_bytes: bytes
    fingerprint: str
    short_id: str
    hostname: str

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


def _fingerprint(public_bytes: bytes) -> str:
    return blake3.blake3(public_bytes).hexdigest()


def load_or_create(path: Path | None = None) -> Identity:
    p = path or key_path()
    if p.exists():
        priv = serialization.load_pem_private_key(p.read_bytes(), password=None)
        if not isinstance(priv, Ed25519PrivateKey):
            raise RuntimeError(f"unexpected key type at {p}: {type(priv).__name__}")
    else:
        priv = Ed25519PrivateKey.generate()
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        p.write_bytes(pem)
        try:
            os.chmod(p, 0o600)
        except (OSError, NotImplementedError):
            pass
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fp = _fingerprint(pub_bytes)
    return Identity(
        private=priv,
        public=pub,
        public_bytes=pub_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname=socket.gethostname(),
    )


def verify(public_bytes: bytes, signature: bytes, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, data)
        return True
    except Exception:
        return False


def fingerprint_of(public_bytes: bytes) -> str:
    return _fingerprint(public_bytes)
