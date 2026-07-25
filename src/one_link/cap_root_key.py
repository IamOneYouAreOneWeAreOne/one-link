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
Explicit rotations use validated temp + atomic replace. First boot uses a
fsynced temp + atomic no-replace hard-link so concurrent daemons converge on
one authority and an existing corrupt/unreadable artifact is never replaced.

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
from pathlib import Path
from typing import Optional

from one_link.key_material import (
    KeyMaterialIntegrityError,
    KeyMaterialPersistenceError,
    KeyMaterialProtectionError,
    artifact_exists,
    atomic_create_bytes,
    atomic_replace_bytes,
    read_bytes_if_exists,
    sync_existing_authority,
)


CAP_ROOT_KEY_FILENAME = "cap_root.key"
CAP_ROOT_KEY_LEN_BYTES = 32


def _cap_root_key_path(data_dir: Path) -> Path:
    return Path(data_dir) / CAP_ROOT_KEY_FILENAME


def has_cap_root_key(data_dir: Path) -> bool:
    """True iff any cap-root authority artifact exists on disk."""
    return artifact_exists(
        _cap_root_key_path(data_dir), label="capability root key"
    )


def _harden_cap_root_path(path: Path) -> None:
    if os.name == "nt":
        from one_link.identity import _restrict_windows_acl

        _restrict_windows_acl(path)


def _decode_cap_root_blob(blob: bytes) -> bytes:
    if not blob:
        raise KeyMaterialIntegrityError("existing capability root key is empty")
    if os.name == "nt":
        from one_link.lockbox import _dpapi_unprotect

        unwrapped = _dpapi_unprotect(blob)
        if unwrapped is None:
            raise KeyMaterialProtectionError(
                "existing capability root key could not be DPAPI-unprotected"
            )
        if len(unwrapped) != CAP_ROOT_KEY_LEN_BYTES:
            raise KeyMaterialIntegrityError(
                "existing capability root key has an invalid unwrapped length"
            )
        return bytes(unwrapped)
    if len(blob) != CAP_ROOT_KEY_LEN_BYTES:
        raise KeyMaterialIntegrityError(
            "existing capability root key has an invalid length"
        )
    return bytes(blob)


def _encode_cap_root(key: bytes) -> bytes:
    if os.name != "nt":
        return bytes(key)
    from one_link.lockbox import _dpapi_protect

    wrapped = _dpapi_protect(bytes(key))
    if not wrapped:
        raise KeyMaterialProtectionError(
            "DPAPI protection failed; refusing to persist a raw capability root key"
        )
    return bytes(wrapped)


def load_cap_root_key(data_dir: Path) -> Optional[bytes]:
    """Load the key; return ``None`` only for a proven-absent artifact."""
    blob = read_bytes_if_exists(
        _cap_root_key_path(data_dir),
        label="capability root key",
        max_bytes=65536,
        harden_path=_harden_cap_root_path,
    )
    if blob is None:
        return None
    return _decode_cap_root_blob(blob)


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
    expected = bytes(key)
    payload = _encode_cap_root(expected)

    def _validate(blob: bytes) -> None:
        if not secrets.compare_digest(_decode_cap_root_blob(blob), expected):
            raise KeyMaterialIntegrityError(
                "persisted capability root key does not match requested authority"
            )

    atomic_replace_bytes(
        _cap_root_key_path(data_dir),
        payload,
        label="capability root key",
        validate=_validate,
        harden_path=_harden_cap_root_path,
    )


def load_or_create_cap_root_key(data_dir: Path) -> tuple[bytes, bool]:
    """Return ``(key, created)`` — load the cap_root_key from disk or
    mint a fresh one if missing. ``created`` is True iff a new key
    was generated this call.
    """
    existing = load_cap_root_key(data_dir)
    if existing is not None:
        return existing, False
    key = secrets.token_bytes(CAP_ROOT_KEY_LEN_BYTES)
    payload = _encode_cap_root(key)

    def _validate(blob: bytes) -> None:
        if not secrets.compare_digest(_decode_cap_root_blob(blob), key):
            raise KeyMaterialIntegrityError(
                "published capability root key does not match generated authority"
            )

    if atomic_create_bytes(
        _cap_root_key_path(data_dir),
        payload,
        label="capability root key",
        validate=_validate,
        harden_path=_harden_cap_root_path,
    ):
        return key, True
    sync_existing_authority(
        _cap_root_key_path(data_dir), label="capability root key"
    )
    winner = load_cap_root_key(data_dir)
    if winner is None:
        raise KeyMaterialPersistenceError(
            "concurrent capability-root publication reported a winner but none exists"
        )
    return winner, False


CAP_ROOT_KEY_OLD_FILENAME = "cap_root.old.key"


def rotate_cap_root_key(data_dir: Path) -> tuple[bytes, bytes | None]:
    """2026-05-21 audit T2-S: in-place cap_root_key rotation.

    Mints a fresh key, atomically swaps the active key file, and
    preserves the previous key at ``cap_root.old.key`` so any
    in-flight macaroons that haven't expired yet can still verify
    during a brief grace window. This low-level primitive is intended for
    authenticated recovery tooling; it is deliberately not exposed through
    the daemon's ordinary peer-facing command surface.

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
        payload = _encode_cap_root(prior)

        def _validate_prior(blob: bytes) -> None:
            if not secrets.compare_digest(_decode_cap_root_blob(blob), prior):
                raise KeyMaterialIntegrityError(
                    "persisted prior capability root does not match authority"
                )

        atomic_replace_bytes(
            old_path,
            payload,
            label="prior capability root key",
            validate=_validate_prior,
            harden_path=_harden_cap_root_path,
        )
    new_key = secrets.token_bytes(CAP_ROOT_KEY_LEN_BYTES)
    store_cap_root_key(data_dir, new_key)
    return new_key, prior


def load_prior_cap_root_key(data_dir: Path) -> Optional[bytes]:
    """Load the previously-active cap_root_key written by
    ``rotate_cap_root_key`` (if any). Verifier helpers consult this
    during the grace window so macaroons minted under the prior key
    still verify until they expire / are revoked.
    """
    blob = read_bytes_if_exists(
        Path(data_dir) / CAP_ROOT_KEY_OLD_FILENAME,
        label="prior capability root key",
        max_bytes=65536,
        harden_path=_harden_cap_root_path,
    )
    if blob is None:
        return None
    return _decode_cap_root_blob(blob)
