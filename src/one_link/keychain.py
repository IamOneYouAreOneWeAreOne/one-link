"""OS keychain integration for One Link's at-rest encryption key.

The state.db SQLCipher passphrase is auto-generated on first run + stored
in the platform-native secure credential store:

    Windows  → Credential Manager (DPAPI-protected blobs)
    macOS    → Keychain Services
    Linux    → Secret Service (libsecret / GNOME Keyring / KWallet)

All three are backed by the `keyring` library, which auto-detects the
right backend per-OS.

Read order for the passphrase, in priority:

  1. `ONE_LINK_PASSPHRASE` env var (explicit override; honored even on
     keychain-capable machines so operators can lock paranoid mode in
     CI / containers without depending on a desktop keychain).
  2. OS keychain entry under the service name `ONE_LINK_KEYCHAIN_SERVICE`,
     account `ONE_LINK_KEYCHAIN_USER`.
  3. None.  (Caller decides whether to auto-mint + store one.)

Auto-mint policy: on first daemon start when (1) and (2) are both empty,
`ensure_passphrase()` generates a fresh 32-byte url-safe-base64
passphrase, writes it to the keychain, and returns it. Subsequent
restarts pick it up via (2) and stay in paranoid mode automatically —
the user never has to remember anything.

Recovery: if the keychain entry is deleted / inaccessible (e.g. user
restored from a backup to a new machine), the daemon falls back to
generating a NEW passphrase. That new passphrase CANNOT decrypt the
existing state.db — the user needs the env-var override path to recover.
This is the right tradeoff: a keychain that auto-syncs across machines
defeats the whole point.

This module never logs the passphrase, never echoes it to stderr, never
includes it in exception messages, and exposes no method to retrieve it
in a string suitable for display. The bytes only ever leave via direct
return to a caller.
"""
from __future__ import annotations

import logging
import os
import secrets

log = logging.getLogger("one_link.keychain")

ONE_LINK_KEYCHAIN_SERVICE = "one_link"
ONE_LINK_KEYCHAIN_USER = "state_db_key"
ENV_VAR = "ONE_LINK_PASSPHRASE"


def _load_keyring():
    """Return the keyring module or None if the library isn't installed.
    Lazy-import so a stripped-down install without the keyring dep
    still boots — it just stays in plaintext-state.db mode."""
    try:
        import keyring  # type: ignore[import-not-found]
        return keyring
    except Exception:  # pragma: no cover - depends on install env
        return None


def get_passphrase() -> str | None:
    """Returns the active passphrase, or None if neither env var nor
    keychain entry exists. Caller decides whether to auto-mint."""
    env = os.environ.get(ENV_VAR, "").strip()
    if env:
        return env
    kr = _load_keyring()
    if kr is None:
        return None
    try:
        v = kr.get_password(ONE_LINK_KEYCHAIN_SERVICE, ONE_LINK_KEYCHAIN_USER)
        if v:
            return v
    except Exception as e:
        # Common on Linux without an active D-Bus session, or Windows
        # in unusual security contexts. Don't crash — fall through to
        # None so the daemon can boot in plaintext mode (legacy
        # behavior) instead of refusing to start.
        log.warning("keychain read failed: %s", type(e).__name__)
    return None


def ensure_passphrase() -> str | None:
    """Get the passphrase OR auto-mint + store one. Returns None ONLY
    if no keychain is available AND no env var is set — in which case
    the caller MUST fall back to plaintext state.db (legacy mode).

    A fresh passphrase is 32 random bytes encoded as url-safe-base64.
    256 bits of entropy comfortably exceeds AES-256's key strength."""
    existing = get_passphrase()
    if existing:
        return existing
    kr = _load_keyring()
    if kr is None:
        log.warning(
            "keyring library not available; state.db will use plaintext "
            "(legacy) at-rest mode. Install `keyring` to enable "
            "SQLCipher encryption with auto-generated key."
        )
        return None
    new_pw = secrets.token_urlsafe(32)
    try:
        kr.set_password(
            ONE_LINK_KEYCHAIN_SERVICE, ONE_LINK_KEYCHAIN_USER, new_pw,
        )
    except Exception as e:
        log.warning(
            "keychain write failed (%s); falling back to plaintext "
            "state.db this run", type(e).__name__,
        )
        return None
    log.info(
        "keychain: minted fresh state.db encryption key; stored in "
        "the OS credential store. Future restarts pick it up "
        "automatically."
    )
    return new_pw


def rotate_passphrase() -> str | None:
    """Generate a brand-new passphrase + write it to the keychain.
    Used by the 'Forget passphrase' button. Caller is responsible
    for re-encrypting state.db with the new key in the SAME write
    transaction; otherwise the old DB becomes unreadable.

    Returns the new passphrase, or None if the keychain refused
    the write."""
    kr = _load_keyring()
    if kr is None:
        return None
    new_pw = secrets.token_urlsafe(32)
    try:
        kr.set_password(
            ONE_LINK_KEYCHAIN_SERVICE, ONE_LINK_KEYCHAIN_USER, new_pw,
        )
    except Exception as e:
        log.warning("keychain rotate failed: %s", type(e).__name__)
        return None
    return new_pw


def forget_passphrase() -> bool:
    """Delete the keychain entry. Caller should have already
    decrypted-then-deleted state.db, or the user is permanently
    locked out of the existing DB. Returns True iff a row was
    actually deleted."""
    kr = _load_keyring()
    if kr is None:
        return False
    try:
        kr.delete_password(
            ONE_LINK_KEYCHAIN_SERVICE, ONE_LINK_KEYCHAIN_USER,
        )
        return True
    except Exception as e:
        # Most backends raise PasswordDeleteError on "not found";
        # treat that as "nothing to do" rather than failure.
        if type(e).__name__ in (
            "PasswordDeleteError", "PasswordError",
            "KeyringError", "NoKeyringError",
        ):
            return False
        log.warning("keychain delete failed: %s", type(e).__name__)
        return False


def backend_label() -> str:
    """Human-readable identifier for the active keychain backend,
    used in Settings + the boot log so the user can see WHERE their
    key lives ('Windows Credential Manager', 'macOS Keychain', etc).
    Returns 'unavailable' if the keyring library isn't loaded."""
    kr = _load_keyring()
    if kr is None:
        return "unavailable (keyring library not installed)"
    try:
        cls = type(kr.get_keyring()).__name__
    except Exception:
        return "unavailable (no usable backend)"
    return {
        "WinVaultKeyring": "Windows Credential Manager",
        "Keyring": "macOS Keychain",
        "SecretServiceKeyring": "Linux Secret Service",
        "KWallet5Keyring": "KDE KWallet",
        "GnomeKeyring": "GNOME Keyring",
        "Fail": "unavailable",
        "Null": "disabled",
    }.get(cls, cls)
