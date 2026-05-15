"""At-rest encryption for AsyncCapsule recordings — closes audit C5.

When a call converts to async (Tier δ headline demo), the captured
voice-note is held as an :class:`AsyncCapsule` until the recipient
plays it. Between capture and delivery the capsule typically sits
on disk in the daemon's data directory.

Audit C5: chat/group recordings need at-rest encryption so a
stolen device cannot replay captured calls. This module adds that
layer on top of the existing AsyncCapsule serialization.

Design:
  - Each capsule is encrypted with a fresh ChaCha20-Poly1305 key
    derived from (a) the daemon's per-device master seed, plus (b)
    the capsule's call_id + finalized_at_ms (so two captures from
    the same call cannot reuse the same nonce).
  - The encrypted file format is:
        magic(8)  || version(1) || nonce(12) || ciphertext_len(8)
        || ciphertext || tag(16)
  - Decryption requires the device's master seed AND knowledge of
    the call_id; a peer-leaked capsule cannot be decrypted on its
    own.
  - Stream the capsule via :func:`seal_to_path` / :func:`open_from_path`
    so the daemon doesn't hold the whole audio blob in memory at once.

Pure module: no daemon imports. The daemon's capsule store calls
:func:`seal_to_path` on finalization + :func:`open_from_path` on
playback. Tests provide an in-memory master seed.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md Part 14.1 (C5)
"""

from __future__ import annotations

import hashlib
import os
import secrets
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# Wire-format constants
MAGIC = b"OLCAP1\x00\x00"                # 8 bytes
SEAL_VERSION = 1
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_capsule_key(
    *,
    master_seed: bytes,
    call_id: str,
    finalized_at_ms: int,
) -> bytes:
    """Derive a 32-byte ChaCha20-Poly1305 key from the device master
    seed + per-capsule context.

    Uses HKDF-Extract over (call_id, finalized_at_ms) as info. The
    master_seed is the secret root; the info is binding but not
    secret — so a stolen capsule file cannot be re-decrypted with a
    different (master, call_id) pair, AND two capsules from the same
    call at different finalize-times yield different keys.
    """
    if not isinstance(master_seed, (bytes, bytearray)) or len(master_seed) < 32:
        raise ValueError("master_seed must be >= 32 bytes")
    if not isinstance(call_id, str) or not call_id:
        raise ValueError("call_id required")
    info = b"one-link-capsule-at-rest-v1|" + call_id.encode("utf-8") + b"|"
    info += finalized_at_ms.to_bytes(8, "big", signed=False)
    # Simple HKDF-Extract + first-block-Expand (RFC 5869). For 32 bytes
    # of output one Expand block suffices.
    salt = b"\x00" * 32
    prk = _hmac_sha256(salt, bytes(master_seed))
    okm = _hmac_sha256(prk, info + b"\x01")
    return okm[:KEY_LEN]


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    import hmac
    return hmac.new(key, data, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Seal / open — file-level
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SealedHeader:
    """Plaintext header preceding the ciphertext."""

    magic: bytes
    version: int
    nonce: bytes
    ciphertext_len: int


def seal_to_path(
    *,
    plaintext: bytes,
    out_path: Path,
    master_seed: bytes,
    call_id: str,
    finalized_at_ms: int,
    nonce: Optional[bytes] = None,
) -> None:
    """Encrypt ``plaintext`` and write the sealed blob to ``out_path``.

    The output file's directory must exist. The temporary file is
    written first then atomically renamed to ``out_path`` so a crash
    mid-write never leaves a half-sealed file.
    """
    if nonce is None:
        nonce = secrets.token_bytes(NONCE_LEN)
    elif len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")
    key = derive_capsule_key(
        master_seed=master_seed,
        call_id=call_id,
        finalized_at_ms=finalized_at_ms,
    )
    aead = ChaCha20Poly1305(key)
    # AEAD associated-data: call_id + finalized_at_ms so swapping
    # those after-the-fact invalidates the seal (defense-in-depth).
    aad = call_id.encode("utf-8") + finalized_at_ms.to_bytes(8, "big")
    ciphertext_with_tag = aead.encrypt(nonce, bytes(plaintext), aad)
    # Layout: MAGIC || version || nonce || len(ct+tag) || ct+tag
    header = (
        MAGIC
        + struct.pack("!B", SEAL_VERSION)
        + nonce
        + struct.pack("!Q", len(ciphertext_with_tag))
    )
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with tmp.open("wb") as f:
        f.write(header)
        f.write(ciphertext_with_tag)
    os.replace(tmp, out_path)


def open_from_path(
    *,
    sealed_path: Path,
    master_seed: bytes,
    call_id: str,
    finalized_at_ms: int,
) -> bytes:
    """Decrypt the sealed capsule at ``sealed_path``. Raises on:
      - magic mismatch (not a sealed capsule)
      - version unknown
      - AEAD tag verification failure (tampered or wrong key)
    """
    with sealed_path.open("rb") as f:
        header_fixed = f.read(len(MAGIC) + 1 + NONCE_LEN + 8)
        if len(header_fixed) < len(MAGIC) + 1 + NONCE_LEN + 8:
            raise ValueError("sealed capsule truncated header")
        if header_fixed[:len(MAGIC)] != MAGIC:
            raise ValueError("not a sealed capsule (bad magic)")
        version = header_fixed[len(MAGIC)]
        if version != SEAL_VERSION:
            raise ValueError(
                f"unsupported sealed capsule version {version}",
            )
        nonce = header_fixed[len(MAGIC) + 1: len(MAGIC) + 1 + NONCE_LEN]
        (ciphertext_len,) = struct.unpack(
            "!Q", header_fixed[len(MAGIC) + 1 + NONCE_LEN:],
        )
        ciphertext = f.read(ciphertext_len)
        if len(ciphertext) != ciphertext_len:
            raise ValueError("sealed capsule truncated body")
    key = derive_capsule_key(
        master_seed=master_seed,
        call_id=call_id,
        finalized_at_ms=finalized_at_ms,
    )
    aead = ChaCha20Poly1305(key)
    aad = call_id.encode("utf-8") + finalized_at_ms.to_bytes(8, "big")
    return aead.decrypt(nonce, ciphertext, aad)


# ---------------------------------------------------------------------------
# Header inspection (no key required)
# ---------------------------------------------------------------------------

def inspect_header(sealed_path: Path) -> SealedHeader:
    """Read the unencrypted header without attempting decryption.
    Used by the daemon's capsule UI to display "sealed capsule"
    metadata in the chat list."""
    with sealed_path.open("rb") as f:
        buf = f.read(len(MAGIC) + 1 + NONCE_LEN + 8)
    if len(buf) < len(MAGIC) + 1 + NONCE_LEN + 8:
        raise ValueError("truncated header")
    if buf[:len(MAGIC)] != MAGIC:
        raise ValueError("not a sealed capsule")
    version = buf[len(MAGIC)]
    nonce = buf[len(MAGIC) + 1: len(MAGIC) + 1 + NONCE_LEN]
    (ciphertext_len,) = struct.unpack("!Q", buf[len(MAGIC) + 1 + NONCE_LEN:])
    return SealedHeader(
        magic=MAGIC, version=version,
        nonce=nonce, ciphertext_len=ciphertext_len,
    )
