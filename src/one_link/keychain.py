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
import stat

log = logging.getLogger("one_link.keychain")

ONE_LINK_KEYCHAIN_SERVICE = "one_link"
ONE_LINK_KEYCHAIN_USER = "state_db_key"
ENV_VAR = "ONE_LINK_PASSPHRASE"
# Filename of the local key-file fallback (see _local_key_path).
LOCAL_KEY_FILENAME = "state.key"


def _load_keyring():
    """Return the keyring module or None if the library isn't installed.
    Lazy-import so a stripped-down install without the keyring dep
    still boots — it falls back to the local key file (see
    _ensure_local_key) rather than to plaintext."""
    try:
        import keyring  # type: ignore[import-not-found]
        return keyring
    except Exception:  # pragma: no cover - depends on install env
        return None


# ── Local key-file fallback ───────────────────────────────────────────
# 2026-06-16 (external-audit remediation): the OS keychain is the
# PREFERRED home for the state.db key, but on headless Linux (no Secret
# Service / D-Bus), locked-down service accounts, or when keyring's
# backend write simply fails, it isn't available. Previously the daemon
# silently fell back to a PLAINTEXT state.db in that case — a direct
# breach of One Link's "your data is yours and protected" promise.
#
# Now, when the OS keychain can't hold the key, we mint one and store it
# in a 0600 key file inside the data dir so at-rest encryption STAYS ON
# by default. Honest about the trade-off: a key file next to the DB is
# weaker than the OS keychain against an attacker who already has read
# access to the data dir — but it is strictly stronger than plaintext
# (opaque DB to backup/cloud-sync scrapes, misconfigured shares,
# forensic free-page recovery, casual inspection) and, combined with
# OS full-disk encryption (FileVault/BitLocker), gives real protection
# on a lost/stolen device. Plaintext now requires an explicit opt-in
# (see state.py ONE_LINK_ALLOW_PLAINTEXT) instead of happening silently.

def _local_key_path():
    from one_link.paths import data_dir
    return data_dir() / LOCAL_KEY_FILENAME


def _read_local_key() -> str | None:
    try:
        p = _local_key_path()
        if not p.exists():
            return None
        v = p.read_text(encoding="utf-8").strip()
        return v or None
    except Exception as e:  # pragma: no cover - fs edge
        log.warning("local key-file read failed: %s", type(e).__name__)
        return None


def _write_local_key(pw: str) -> bool:
    """Persist the key to a 0600 file in the data dir. Returns True on
    success. Best-effort restrictive perms (POSIX chmod; on Windows the
    file lives under the per-user profile dir whose ACLs already deny
    other standard users)."""
    try:
        p = _local_key_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        # Create with 0600 from the start where supported, so there's
        # no window where the key is world-readable.
        fd = os.open(
            str(p),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            stat.S_IRUSR | stat.S_IWUSR,
        )
        try:
            os.write(fd, pw.encode("utf-8"))
        finally:
            os.close(fd)
        with contextlib_suppress():
            os.chmod(str(p), stat.S_IRUSR | stat.S_IWUSR)
        return True
    except Exception as e:
        log.warning("local key-file write failed: %s", type(e).__name__)
        return False


class contextlib_suppress:
    def __enter__(self): return self
    def __exit__(self, *a): return True


DISABLE_ENV = "ONE_LINK_DISABLE_AT_REST_ENCRYPTION"


def _disabled() -> bool:
    """At-rest encryption is explicitly disabled. Used by the test
    suite (conftest sets the flag) so thousands of throwaway State()
    objects don't each hit the global OS keychain — which would both
    pollute the user's real credential store AND exhaust keychain /
    file handles at scale. An explicit ONE_LINK_PASSPHRASE always
    wins over this flag (the dedicated at-rest-encryption test opts
    back in that way)."""
    return os.environ.get(DISABLE_ENV) == "1"


def get_passphrase() -> str | None:
    """Returns the active passphrase, or None if neither env var nor
    keychain entry exists. Caller decides whether to auto-mint."""
    env = os.environ.get(ENV_VAR, "").strip()
    if env:
        return env
    if _disabled():
        # Don't even read the keychain — keep tests fully isolated
        # from the user's real credential store.
        return None
    kr = _load_keyring()
    if kr is not None:
        try:
            v = kr.get_password(ONE_LINK_KEYCHAIN_SERVICE, ONE_LINK_KEYCHAIN_USER)
            if v:
                return v
        except Exception as e:
            # Common on Linux without an active D-Bus session, or Windows
            # in unusual security contexts. Fall through to the local
            # key file rather than to plaintext.
            log.warning("keychain read failed: %s", type(e).__name__)
    # Local key-file fallback (minted by ensure_passphrase when the OS
    # keychain is unavailable). Keeps at-rest encryption on across
    # restarts even where no OS keychain exists.
    return _read_local_key()


def ensure_passphrase() -> str | None:
    """Get the passphrase OR auto-mint + store one. Returns None ONLY
    if no keychain is available AND no env var is set — in which case
    the caller MUST fall back to plaintext state.db (legacy mode).

    A fresh passphrase is 32 random bytes encoded as url-safe-base64.
    256 bits of entropy comfortably exceeds AES-256's key strength."""
    existing = get_passphrase()
    if existing:
        return existing
    if _disabled():
        # Explicitly disabled (tests / opt-out): stay plaintext, never
        # mint a keychain entry.
        return None
    new_pw = secrets.token_urlsafe(32)
    kr = _load_keyring()
    if kr is not None:
        try:
            kr.set_password(
                ONE_LINK_KEYCHAIN_SERVICE, ONE_LINK_KEYCHAIN_USER, new_pw,
            )
            log.info(
                "keychain: minted fresh state.db encryption key; stored "
                "in the OS credential store. Future restarts pick it up "
                "automatically."
            )
            return new_pw
        except Exception as e:
            log.warning(
                "keychain write failed (%s); falling back to the local "
                "0600 key file so at-rest encryption stays ON",
                type(e).__name__,
            )
    else:
        log.warning(
            "keyring library/back end unavailable; using the local 0600 "
            "key file so at-rest encryption stays ON (the OS keychain is "
            "preferred — install/enable it for stronger key isolation)"
        )
    # OS keychain unavailable → local key-file fallback (still encrypted).
    if _write_local_key(new_pw):
        log.info(
            "keychain: minted fresh state.db encryption key; stored in a "
            "0600 local key file (%s). at-rest encryption ACTIVE.",
            LOCAL_KEY_FILENAME,
        )
        return new_pw
    # Could not obtain or persist a key anywhere. Returning None signals
    # the caller; state.py refuses to silently run plaintext unless the
    # operator explicitly sets ONE_LINK_ALLOW_PLAINTEXT=1.
    log.error(
        "could not store a state.db encryption key in the OS keychain "
        "OR a local key file — at-rest encryption cannot be enabled"
    )
    return None


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
    """Delete the key from BOTH the OS keychain AND the local key file.
    Caller should have already decrypted-then-deleted state.db, or the
    user is permanently locked out of the existing DB. Returns True iff
    a key was actually removed from either store."""
    removed = False
    # Local key file (secure-overwrite before unlink so the key bytes
    # don't linger in free space).
    try:
        p = _local_key_path()
        if p.exists():
            try:
                size = p.stat().st_size
                with open(p, "r+b") as fh:
                    fh.write(secrets.token_bytes(max(32, size)))
                    fh.flush()
                    os.fsync(fh.fileno())
            except Exception:
                pass
            p.unlink()
            removed = True
    except Exception as e:
        log.warning("local key-file delete failed: %s", type(e).__name__)
    kr = _load_keyring()
    if kr is None:
        return removed
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
            return removed
        log.warning("keychain delete failed: %s", type(e).__name__)
        return removed


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
