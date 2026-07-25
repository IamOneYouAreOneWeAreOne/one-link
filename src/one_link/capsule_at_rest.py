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
  - Bound the complete sealed plaintext before AEAD.  ``ChaCha20Poly1305`` is
    a one-shot API, so this format intentionally caps memory instead of making
    a false streaming claim.  The capsule schema's 16 MiB audio ceiling plus
    bounded metadata keeps the worst case finite.

Pure module: no daemon imports. The daemon's capsule store calls
:func:`seal_to_path` on finalization + :func:`open_from_path` on
playback. Tests provide an in-memory master seed.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md Part 14.1 (C5)
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
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
HEADER_LEN = len(MAGIC) + 1 + NONCE_LEN + 8
# Audio is capped at 16 MiB by async_capsule.  Leave another 16 MiB for the
# (also bounded) provenance JSON and scalar header, while refusing forged file
# lengths before allocating them.
MAX_SEALED_PLAINTEXT_BYTES = 32 * 1024 * 1024
MAX_SEALED_CIPHERTEXT_BYTES = MAX_SEALED_PLAINTEXT_BYTES + TAG_LEN


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
    if (
        not isinstance(call_id, str)
        or not call_id
        or len(call_id) > 128
        or any(ord(ch) < 0x20 for ch in call_id)
    ):
        raise ValueError("call_id required")
    if (
        isinstance(finalized_at_ms, bool)
        or not isinstance(finalized_at_ms, int)
        or not (0 <= finalized_at_ms <= 2**63 - 1)
    ):
        raise ValueError("finalized_at_ms must be a non-negative 63-bit integer")
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


def _fsync_parent(path: Path) -> None:
    """Durably publish a rename where the platform exposes directory fsync."""

    if os.name == "nt":
        return
    flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
    fd = os.open(str(path.parent), flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        count = os.write(fd, view[written:])
        if count <= 0:
            raise OSError("short write while sealing capsule")
        written += count


def _validate_regular_path(path: Path) -> os.stat_result:
    """Reject links, Windows reparse points, and special files."""

    st = path.lstat()
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    attributes = int(getattr(st, "st_file_attributes", 0))
    is_reparse = os.name == "nt" and bool(attributes & reparse_flag)
    if stat.S_ISLNK(st.st_mode) or is_reparse or not stat.S_ISREG(st.st_mode):
        raise ValueError("sealed capsule path is not a regular file")
    return st


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
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    if len(plaintext) > MAX_SEALED_PLAINTEXT_BYTES:
        raise ValueError("sealed capsule plaintext exceeds size limit")
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
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists() or out_path.is_symlink():
        existing = out_path.lstat()
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        attributes = int(getattr(existing, "st_file_attributes", 0))
        is_reparse = os.name == "nt" and bool(attributes & reparse_flag)
        if (
            stat.S_ISLNK(existing.st_mode)
            or is_reparse
            or not stat.S_ISREG(existing.st_mode)
        ):
            raise ValueError("sealed capsule destination is not a regular file")
    tmp = out_path.with_name(
        f".{out_path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_BINARY", 0))
    fd = os.open(str(tmp), flags, 0o600)
    try:
        _write_all(fd, header)
        _write_all(fd, ciphertext_with_tag)
        os.fsync(fd)
    except BaseException:
        try:
            os.close(fd)
        finally:
            try:
                tmp.unlink()
            except OSError:
                pass
        raise
    else:
        os.close(fd)
    try:
        os.replace(tmp, out_path)
        if os.name != "nt":
            os.chmod(out_path, 0o600)
        _fsync_parent(out_path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


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
    sealed_path = Path(sealed_path)
    path_stat = _validate_regular_path(sealed_path)
    if path_stat.st_size < HEADER_LEN:
        raise ValueError("sealed capsule truncated header")
    if path_stat.st_size > HEADER_LEN + MAX_SEALED_CIPHERTEXT_BYTES:
        raise ValueError("sealed capsule exceeds size limit")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(str(sealed_path), flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError("sealed capsule path is not a regular file")
        if (
            int(opened.st_size) != int(path_stat.st_size)
            or int(getattr(opened, "st_dev", 0)) != int(getattr(path_stat, "st_dev", 0))
            or int(getattr(opened, "st_ino", 0)) != int(getattr(path_stat, "st_ino", 0))
        ):
            raise ValueError("sealed capsule changed while opening")
        with os.fdopen(fd, "rb", closefd=False) as f:
            header_fixed = f.read(HEADER_LEN)
        if len(header_fixed) < HEADER_LEN:
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
        if not (TAG_LEN <= ciphertext_len <= MAX_SEALED_CIPHERTEXT_BYTES):
            raise ValueError("sealed capsule ciphertext length outside limit")
        expected_file_size = HEADER_LEN + ciphertext_len
        if int(opened.st_size) < expected_file_size:
            raise ValueError("sealed capsule truncated body")
        if int(opened.st_size) > expected_file_size:
            raise ValueError("sealed capsule has trailing bytes")
        with os.fdopen(fd, "rb", closefd=False) as f:
            f.seek(HEADER_LEN)
            ciphertext = f.read(ciphertext_len)
        if len(ciphertext) != ciphertext_len:
            raise ValueError("sealed capsule truncated body")
        after = os.fstat(fd)
        if (
            int(after.st_size) != int(opened.st_size)
            or int(getattr(after, "st_mtime_ns", 0))
            != int(getattr(opened, "st_mtime_ns", 0))
            or int(getattr(after, "st_ctime_ns", 0))
            != int(getattr(opened, "st_ctime_ns", 0))
        ):
            raise ValueError("sealed capsule changed while reading")
    finally:
        os.close(fd)
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
    sealed_path = Path(sealed_path)
    path_stat = _validate_regular_path(sealed_path)
    if path_stat.st_size > HEADER_LEN + MAX_SEALED_CIPHERTEXT_BYTES:
        raise ValueError("sealed capsule exceeds size limit")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(str(sealed_path), flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError("sealed capsule path is not a regular file")
        if (
            int(opened.st_size) != int(path_stat.st_size)
            or int(getattr(opened, "st_dev", 0))
            != int(getattr(path_stat, "st_dev", 0))
            or int(getattr(opened, "st_ino", 0))
            != int(getattr(path_stat, "st_ino", 0))
        ):
            raise ValueError("sealed capsule changed while opening")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            buf = handle.read(HEADER_LEN)
        after = os.fstat(fd)
        if (
            int(after.st_size) != int(opened.st_size)
            or int(getattr(after, "st_mtime_ns", 0))
            != int(getattr(opened, "st_mtime_ns", 0))
            or int(getattr(after, "st_ctime_ns", 0))
            != int(getattr(opened, "st_ctime_ns", 0))
        ):
            raise ValueError("sealed capsule changed while reading")
    finally:
        os.close(fd)
    if len(buf) < HEADER_LEN:
        raise ValueError("truncated header")
    if buf[:len(MAGIC)] != MAGIC:
        raise ValueError("not a sealed capsule")
    version = buf[len(MAGIC)]
    if version != SEAL_VERSION:
        raise ValueError(f"unsupported sealed capsule version {version}")
    nonce = buf[len(MAGIC) + 1: len(MAGIC) + 1 + NONCE_LEN]
    (ciphertext_len,) = struct.unpack("!Q", buf[len(MAGIC) + 1 + NONCE_LEN:])
    if not (TAG_LEN <= ciphertext_len <= MAX_SEALED_CIPHERTEXT_BYTES):
        raise ValueError("sealed capsule ciphertext length outside limit")
    if int(opened.st_size) != HEADER_LEN + ciphertext_len:
        raise ValueError("sealed capsule length mismatch")
    return SealedHeader(
        magic=MAGIC, version=version,
        nonce=nonce, ciphertext_len=ciphertext_len,
    )
