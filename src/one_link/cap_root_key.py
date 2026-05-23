"""Per-daemon capability root key — separate from the identity seed.

Audit M14 May 2026 — closes the "macaroon HMAC root key derives from
the identity Ed25519 seed" finding. Previously
:func:`one_link.cap_migration.derive_root_key` BLAKE3-keyed-hashed the
granter's Ed25519 private seed to produce the macaroon HMAC root
key. While domain separation prevents direct key reuse, the two
systems shared entropy: a side-channel on the macaroon HMAC could
leak bits of the identity-signing seed.

This module mints + persists a SEPARATE 32-byte ``cap_root_key`` at
first boot, alongside ``master.seed``. The macaroon path consumes
this key via
:func:`one_link.cap_migration.derive_root_key_from_cap_root`; the
identity-signing path keeps using the Ed25519 seed. A leak of one
reveals nothing about the other.

Persistence
-----------
The cap_root_key file lives at ``<data_dir>/cap_root.key``. On
Windows it's DPAPI-wrapped (same scheme as ``master.seed`` and the
lockbox data-root key); on POSIX it's raw 32 bytes with mode 0600.
Atomic via temp + rename.

Recovery
--------
The cap_root_key is **not** part of the BIP-39 24-word mnemonic
backup. If the user restores from paper, a fresh cap_root_key gets
minted on first run and any previously-issued macaroons are
invalid under the new key. Legacy Ed25519 grants survive because
they verify under the identity pubkey (recoverable from the
mnemonic). This is the right trade-off: macaroons are short-lived
delegated caps; identity grants are long-term authority.
"""
from __future__ import annotations

import os
import secrets
import tempfile
from pathlib import Path
from typing import Optional


CAP_ROOT_KEY_FILENAME = "cap_root.key"
CAP_ROOT_KEY_LEN_BYTES = 32


def _cap_root_key_path(data_dir: Path) -> Path:
    return Path(data_dir) / CAP_ROOT_KEY_FILENAME


def has_cap_root_key(data_dir: Path) -> bool:
    """True iff a cap_root_key file exists on disk."""
    return _cap_root_key_path(data_dir).is_file()


def load_cap_root_key(data_dir: Path) -> Optional[bytes]:
    """Read the cap_root_key off disk + DPAPI-unwrap on Windows.
    Returns None if no cap_root_key file exists or unwrap fails.
    """
    p = _cap_root_key_path(data_dir)
    if not p.is_file():
        return None
    try:
        blob = p.read_bytes()
    except OSError:
        return None
    if not blob:
        return None
    if os.name == "nt":
        # Same DPAPI scheme as master.seed.
        from one_link.lockbox import _dpapi_unprotect
        unwrapped = _dpapi_unprotect(blob)
        if unwrapped is None or len(unwrapped) != CAP_ROOT_KEY_LEN_BYTES:
            return None
        return unwrapped
    if len(blob) != CAP_ROOT_KEY_LEN_BYTES:
        return None
    return blob


def store_cap_root_key(data_dir: Path, key: bytes) -> None:
    """Persist the cap_root_key. Wraps with DPAPI on Windows; writes
    raw 32 bytes with mode 0600 on POSIX. Atomic via temp + rename."""
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("cap_root_key must be bytes")
    if len(key) != CAP_ROOT_KEY_LEN_BYTES:
        raise ValueError(
            f"cap_root_key must be {CAP_ROOT_KEY_LEN_BYTES} bytes, "
            f"got {len(key)}"
        )
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    p = _cap_root_key_path(data_dir)

    if os.name == "nt":
        from one_link.lockbox import _dpapi_protect
        wrapped = _dpapi_protect(bytes(key))
        if wrapped is None:
            raise RuntimeError("DPAPI wrap failed for cap_root_key")
        payload = wrapped
    else:
        payload = bytes(key)

    fd, tmp_path = tempfile.mkstemp(
        prefix=".cap_root_key.tmp.", dir=str(data_dir),
    )
    try:
        try:
            os.write(fd, payload)
        finally:
            os.close(fd)
        if os.name != "nt":
            os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, p)
    except Exception:
        # Best-effort cleanup of the temp file if rename failed.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def load_or_create_cap_root_key(data_dir: Path) -> tuple[bytes, bool]:
    """Return ``(key, created)`` — load the cap_root_key from disk or
    mint a fresh one if missing. ``created`` is True iff a new key
    was generated this call.
    """
    existing = load_cap_root_key(data_dir)
    if existing is not None:
        return existing, False
    key = secrets.token_bytes(CAP_ROOT_KEY_LEN_BYTES)
    store_cap_root_key(data_dir, key)
    return key, True


CAP_ROOT_KEY_OLD_FILENAME = "cap_root.old.key"


def rotate_cap_root_key(data_dir: Path) -> tuple[bytes, bytes | None]:
    """2026-05-21 audit T2-S: in-place cap_root_key rotation.

    Mints a fresh key, atomically swaps the active key file, and
    preserves the previous key at ``cap_root.old.key`` so any
    in-flight macaroons that haven't expired yet can still verify
    during a brief grace window. Operators invoke this via a
    privileged control-socket command (TBD) when a cap_root_key
    compromise is suspected.

    Returns ``(new_key, prior_key_or_None)``. The prior key is
    None on first-ever rotation (no active key was present).

    The OLD key file is best-effort persisted but not relied on:
    callers that need durable rotation history should record it
    themselves before calling.
    """
    data_dir = Path(data_dir)
    prior = load_cap_root_key(data_dir)
    if prior is not None:
        # Preserve previous key to ``cap_root.old.key`` so the
        # verifier can accept macaroons minted under it for a
        # short overlap window.
        old_path = data_dir / CAP_ROOT_KEY_OLD_FILENAME
        if os.name == "nt":
            from one_link.lockbox import _dpapi_protect
            wrapped = _dpapi_protect(prior)
            if wrapped is None:
                # 2026-05-22 audit FO-4: REFUSE to silently write the
                # prior key in plaintext when DPAPI wrap fails. The
                # active key's ``store_cap_root_key`` raises on this
                # same condition; rotation's old-key persistence must
                # match that contract, not degrade to a plaintext
                # file. Caller can retry rotation after the operator
                # investigates DPAPI availability.
                raise RuntimeError(
                    "rotate_cap_root_key: cannot persist prior key — "
                    "DPAPI wrap failed and we refuse to write key "
                    "material in plaintext. Investigate DPAPI "
                    "availability (Windows credential store) and retry."
                )
            payload = wrapped
        else:
            payload = prior
        fd, tmp_path = tempfile.mkstemp(
            prefix=".cap_root_key_old.tmp.", dir=str(data_dir),
        )
        try:
            try:
                os.write(fd, payload)
            finally:
                os.close(fd)
            if os.name != "nt":
                os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, old_path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    new_key = secrets.token_bytes(CAP_ROOT_KEY_LEN_BYTES)
    store_cap_root_key(data_dir, new_key)
    return new_key, prior


def load_prior_cap_root_key(data_dir: Path) -> Optional[bytes]:
    """Load the previously-active cap_root_key written by
    ``rotate_cap_root_key`` (if any). Verifier helpers consult this
    during the grace window so macaroons minted under the prior key
    still verify until they expire / are revoked.
    """
    p = Path(data_dir) / CAP_ROOT_KEY_OLD_FILENAME
    if not p.is_file():
        return None
    try:
        blob = p.read_bytes()
    except OSError:
        return None
    if not blob:
        return None
    if os.name == "nt":
        from one_link.lockbox import _dpapi_unprotect
        unwrapped = _dpapi_unprotect(blob)
        if unwrapped is None or len(unwrapped) != CAP_ROOT_KEY_LEN_BYTES:
            return None
        return unwrapped
    if len(blob) != CAP_ROOT_KEY_LEN_BYTES:
        return None
    return blob
