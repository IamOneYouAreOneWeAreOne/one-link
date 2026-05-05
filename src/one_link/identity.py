"""Ed25519 device identity.

Each computer generates a long-term Ed25519 keypair on first run.
The public key's BLAKE3 fingerprint (first 8 hex chars) is the device ID
shown to the user. The private key never leaves disk.

Optional passphrase encryption-at-rest:
    Set the ONE_LINK_PASSPHRASE environment variable before launching the
    daemon and the private key file is wrapped with PKCS#8
    BestAvailableEncryption (currently AES-256 + PBKDF2). The same
    variable must be set on subsequent launches to decrypt.

    If you switch from unencrypted to encrypted, the existing file is
    transparently re-saved with encryption on next successful load.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import blake3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from one_link.paths import key_path

PASSPHRASE_ENV = "ONE_LINK_PASSPHRASE"


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


def _resolve_passphrase(passphrase: Optional[bytes | str]) -> Optional[bytes]:
    if passphrase is None:
        env = os.environ.get(PASSPHRASE_ENV)
        if env:
            return env.encode("utf-8")
        return None
    if isinstance(passphrase, str):
        return passphrase.encode("utf-8")
    return passphrase


def _save_key(p: Path, priv: Ed25519PrivateKey, passphrase: Optional[bytes]) -> None:
    enc = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(pem)
    try:
        os.chmod(p, 0o600)
    except (OSError, NotImplementedError):
        pass


def load_or_create(
    path: Optional[Path] = None,
    *,
    passphrase: Optional[bytes | str] = None,
) -> Identity:
    p = path or key_path()
    pw = _resolve_passphrase(passphrase)

    if p.exists():
        data = p.read_bytes()
        # Try the passphrase we have first; fall back to no-password to
        # support transparent migration unencrypted → encrypted.
        priv = None
        first_err: Optional[Exception] = None
        try:
            priv = serialization.load_pem_private_key(data, password=pw)
        except (TypeError, ValueError) as e:
            first_err = e
            try:
                priv = serialization.load_pem_private_key(data, password=None)
                # File was unencrypted on disk; if a passphrase is set now,
                # re-save encrypted for "transparent migration."
                if pw:
                    _save_key(p, priv, pw)
            except (TypeError, ValueError):
                pass
        if priv is None:
            # Encrypted but wrong/missing passphrase
            raise RuntimeError(
                f"identity key at {p} is encrypted; set {PASSPHRASE_ENV} "
                f"with the correct passphrase ({first_err})"
            )
        if not isinstance(priv, Ed25519PrivateKey):
            raise RuntimeError(f"unexpected key type at {p}: {type(priv).__name__}")
    else:
        priv = Ed25519PrivateKey.generate()
        _save_key(p, priv, pw)
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
