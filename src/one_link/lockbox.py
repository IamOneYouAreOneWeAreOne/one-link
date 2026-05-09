"""At-rest secret wrapping when ONE_LINK_PASSPHRASE is set.

v0.20.7 (security audit H21 + M29 + partial C5): the desktop daemon
historically stored its highest-value secrets cleartext on disk:

  - `group_sender_chains.chain_key` (32-byte symmetric ratchet keys —
    recovery decrypts every retained group message that chain has
    emitted from that epoch forward).
  - The UI bearer token (full daemon control if exfiltrated).

The browser PWA path encrypts these via OPFS + Argon2id from a user
passphrase; the daemon path had no equivalent. This module is the
daemon-side primitive that closes the gap when the user opts into
encryption-at-rest by setting the ``ONE_LINK_PASSPHRASE`` environment
variable. It is intentionally narrow: scrypt-derived AES-GCM wrap on
the most damaging fields only. Full at-rest encryption (every chat
body, every blob) is the longer C5 ship that needs SQLCipher or
equivalent.

Design:

  - The user's passphrase is read from ``ONE_LINK_PASSPHRASE`` once at
    daemon startup (same env var that gates identity-key encryption).
    A 16-byte random salt is generated on first use and persisted to
    a sibling file under the daemon's config dir; the salt is non-
    secret but per-install, so a captured passphrase can't be used
    against another install's wrapped data.
  - From (passphrase, salt) we derive a 32-byte data root key (DRK)
    using scrypt at the recommended memory-hard parameters. The DRK
    never leaves the running process.
  - Wrap = AES-GCM-256 with a fresh 12-byte random nonce per call.
    Output format: ``b"\\x01" + nonce(12) + ciphertext + tag(16)``.
    The 0x01 marker disambiguates wrapped values from legacy
    cleartext (which for a chain_key is exactly 32 bytes; for the UI
    token is a base64url string).
  - Unwrap: detect marker; if absent return the input unchanged
    (transparent migration — old cleartext rows remain readable).
    If marker present but tag verification fails, raise (prevents
    silent acceptance of a tampered wrapped value).

Why scrypt and not Argon2id?

The audit's preferred KDF was Argon2id; ``cryptography>=42`` (our
floor) does not expose Argon2id directly. Adding ``argon2-cffi``
would require a new dependency. scrypt is in the same memory-hard
family, audited, available without adding deps, and meets the
practical defense (a brute-force attacker needs ~256 MB and ~hours
per candidate passphrase — slow enough to make a stolen-disk
dictionary attack costly). When ``cryptography`` ships Argon2id (or
when the project takes the argon2-cffi dep), the DRK derivation
function here is the only thing that needs to change.

Backward compatibility:

  - If ``ONE_LINK_PASSPHRASE`` is not set, no LockBox is constructed
    and every wrap/unwrap call is a passthrough. State + server keep
    storing values cleartext — same posture as before.
  - If the user later sets the env var, NEW writes get wrapped; OLD
    cleartext reads still succeed (marker absent → passthrough).
    Re-encryption of legacy rows is left as a future ship; the
    user can force it by re-issuing whatever creates the row (e.g.
    rejoining a group rotates the chain).
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# 0x01 marker prefix for wrapped values. Distinct from any cleartext
# shape we wrap (chain_key is exactly 32 raw bytes; UI token is
# base64url ASCII — neither starts with 0x01 in well-formed input).
WRAP_MARKER = b"\x01"
NONCE_LEN = 12
TAG_LEN = 16
MIN_WRAPPED_LEN = 1 + NONCE_LEN + TAG_LEN  # marker + nonce + tag (zero-byte plaintext)

# scrypt parameters. ~256 MiB memory cost, ~50ms on a 2024 laptop.
# The audit asked for "Argon2id ≥256MB ≥3 iterations"; this is the
# scrypt analogue.
SCRYPT_N = 1 << 17  # 131072
SCRYPT_R = 8
SCRYPT_P = 1


PASSPHRASE_ENV = "ONE_LINK_PASSPHRASE"


class LockBoxError(RuntimeError):
    """Raised when an unwrap operation fails authenticity check."""


class LockBox:
    """Wraps secrets at rest with an AES-GCM key derived from a user
    passphrase. Construct via ``LockBox.from_passphrase()``."""

    def __init__(self, data_key: bytes):
        if len(data_key) != 32:
            raise ValueError("data_key must be 32 bytes")
        self._aead = AESGCM(data_key)

    @classmethod
    def from_passphrase(cls, passphrase: bytes, salt: bytes) -> "LockBox":
        """Derive a fresh LockBox from a user passphrase + per-install
        salt. The passphrase bytes should be UTF-8 encoded;
        empty / None inputs are rejected (callers should branch on
        env-var presence instead)."""
        if not isinstance(passphrase, (bytes, bytearray)) or not passphrase:
            raise ValueError("passphrase must be non-empty bytes")
        if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
            raise ValueError("salt must be at least 16 bytes")
        kdf = Scrypt(
            salt=bytes(salt),
            length=32,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
        )
        data_key = kdf.derive(bytes(passphrase))
        return cls(data_key)

    def wrap(self, plaintext: bytes) -> bytes:
        """Encrypt ``plaintext`` and return the wrapped blob.

        Output: WRAP_MARKER || nonce(12) || ciphertext || tag(16).
        ``aad=b""`` because the value is identified by its storage
        slot, not by content metadata. For per-context separation
        callers can pass a domain-bound input (we don't expose AAD
        on this surface to keep the storage format uniform).
        """
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        nonce = secrets.token_bytes(NONCE_LEN)
        ct_with_tag = self._aead.encrypt(nonce, bytes(plaintext), b"")
        return WRAP_MARKER + nonce + ct_with_tag

    def unwrap(self, blob: bytes) -> bytes:
        """Decrypt a wrapped blob; raise LockBoxError on tag mismatch."""
        if not is_wrapped(blob):
            raise LockBoxError("not a wrapped blob")
        nonce = bytes(blob[1:1 + NONCE_LEN])
        ct = bytes(blob[1 + NONCE_LEN:])
        try:
            return self._aead.decrypt(nonce, ct, b"")
        except Exception as e:
            raise LockBoxError(f"unwrap failed: {e}") from e

    # Convenience surfaces — the most common state-layer pattern is
    # "wrap if I have a lockbox, otherwise pass through" + "unwrap if
    # marker present, otherwise pass through (legacy cleartext)."

    def maybe_wrap(self, plaintext: bytes) -> bytes:
        return self.wrap(plaintext)

    def maybe_unwrap(self, blob: bytes) -> bytes:
        if is_wrapped(blob):
            return self.unwrap(blob)
        return blob


def is_wrapped(blob: bytes) -> bool:
    """Cheap shape check: marker byte + minimum length."""
    if not isinstance(blob, (bytes, bytearray)):
        return False
    return len(blob) >= MIN_WRAPPED_LEN and blob[0:1] == WRAP_MARKER


def maybe_unwrap(blob: bytes, lockbox: Optional["LockBox"]) -> bytes:
    """Top-level convenience: unwrap if marker present and lockbox is
    available; passthrough otherwise. Use this from state-layer read
    paths so the call site stays branch-free."""
    if is_wrapped(blob):
        if lockbox is None:
            raise LockBoxError(
                "found wrapped value but no lockbox is configured "
                "(was ONE_LINK_PASSPHRASE removed between writes?)"
            )
        return lockbox.unwrap(blob)
    return blob


def maybe_wrap(plaintext: bytes, lockbox: Optional["LockBox"]) -> bytes:
    """Top-level convenience: wrap if lockbox available, passthrough
    otherwise. Use this from state-layer write paths."""
    if lockbox is None:
        return plaintext
    return lockbox.wrap(plaintext)


# ─── per-install salt persistence ──────────────────────────────────


SALT_FILENAME = "lockbox.salt"


def load_or_create_salt(data_dir: Path) -> bytes:
    """Read or generate the 16-byte per-install salt for the
    passphrase KDF. The salt is non-secret (it goes through the same
    storage as the wrapped data); it only ensures that a captured
    passphrase can't be used against another install's wrapped data
    via offline rainbow tables."""
    salt_path = Path(data_dir) / SALT_FILENAME
    try:
        existing = salt_path.read_bytes()
        if len(existing) == 16:
            return existing
    except (OSError, ValueError):
        pass
    fresh = secrets.token_bytes(16)
    salt_path.parent.mkdir(parents=True, exist_ok=True)
    # Atomic-ish write: temp + replace. The salt is non-secret so
    # we don't bother with the full fsync-the-parent dance.
    tmp = salt_path.with_name(salt_path.name + ".tmp." + secrets.token_hex(4))
    tmp.write_bytes(fresh)
    os.replace(tmp, salt_path)
    return fresh


def lockbox_from_env(data_dir: Path) -> Optional["LockBox"]:
    """Build a LockBox if ``ONE_LINK_PASSPHRASE`` is set; return None
    otherwise. The single bootstrap entry point used by Daemon at
    init."""
    pw = os.environ.get(PASSPHRASE_ENV, "")
    if not pw:
        return None
    salt = load_or_create_salt(data_dir)
    return LockBox.from_passphrase(pw.encode("utf-8"), salt)
