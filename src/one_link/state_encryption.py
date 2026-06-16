"""state.db at-rest encryption helpers (SQLCipher).

Two responsibilities:

  1. Open a SQLCipher connection with the right PRAGMA key + hardening
     pragmas (secure_delete, foreign_keys, etc).

  2. Detect a legacy plaintext state.db at the same path and migrate
     it in place to encrypted form, preserving every row of every
     table. A backup copy is written to ``<path>.pre-encryption-backup``
     and kept until the user has confirmed the encrypted DB boots,
     after which they can delete it (the daemon never auto-deletes
     the backup; rolling back is a manual + deliberate decision).

A note on the failure ladder:
  - sqlcipher3 not installed       → fall back to plaintext stdlib
                                     sqlite3 (legacy mode); logged WARN.
  - keychain unavailable           → same fallback; logged WARN.
  - encrypted-open on plaintext DB → SQLCipher raises DatabaseError;
                                     we detect + migrate.
  - migration fails mid-flight     → backup is intact; original is
                                     untouched; raise so the daemon
                                     refuses to start (better than
                                     silent data loss).
"""
from __future__ import annotations

import contextlib
import logging
import os
import shutil
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("one_link.state_encryption")

# SQLCipher-version of these pragmas is a no-op on stdlib sqlite3, so
# they're safe to apply in both modes. The pragmas:
#   secure_delete = ON    overwrites freed pages with zeros so deleted
#                         rows can't be undeleted from raw disk
#   foreign_keys  = ON    matches schema-level intent
#   journal_mode  = WAL   matches the existing State() defaults
#   synchronous   = NORMAL safe in WAL + faster than FULL
#   auto_vacuum   = INCREMENTAL  enables PRAGMA incremental_vacuum on
#                         shutdown to compact freed pages
HARDENING_PRAGMAS = (
    ("secure_delete", "ON"),
    ("foreign_keys", "ON"),
    ("journal_mode", "WAL"),
    ("synchronous", "NORMAL"),
)

# SQLCipher KDF iterations. 256000 is the modern SQLCipher 4.x
# default; pin it explicitly so a future SQLCipher upgrade can't
# silently weaken the parameter on existing files.
SQLCIPHER_KDF_ITER = 256_000
SQLCIPHER_PAGE_SIZE = 4096


def _have_sqlcipher() -> bool:
    try:
        import sqlcipher3  # noqa: F401
        return True
    except Exception:
        return False


def open_encrypted_connection(
    db_path: Path,
    passphrase: str,
) -> Any:
    """Open a SQLCipher connection at db_path with the given key + the
    standard hardening pragmas applied. Returns a Connection that
    behaves identically to stdlib sqlite3.Connection (same DB-API 2.0
    surface)."""
    import sqlcipher3
    conn = sqlcipher3.connect(
        str(db_path), check_same_thread=False, isolation_level=None,
    )
    # KEY first — must precede ANY other SQL, including pragmas.
    # SQLite PRAGMAs do NOT accept bind parameters, so we have to
    # interpolate. We use SQLCipher's hex-blob form `x'<hex>'`
    # which:
    #   1. Eliminates SQL injection entirely (only hex chars).
    #   2. Treats the value as raw bytes (no UTF-8 collation
    #      ambiguity across platforms).
    #   3. Is the SQLCipher-recommended way to supply a passphrase
    #      programmatically.
    key_hex = passphrase.encode("utf-8").hex()
    conn.execute(f"PRAGMA key = \"x'{key_hex}'\"")
    conn.execute(f"PRAGMA cipher_page_size = {SQLCIPHER_PAGE_SIZE}")
    conn.execute(f"PRAGMA kdf_iter = {SQLCIPHER_KDF_ITER}")
    # Probe: a trivial SELECT will raise DatabaseError if the key
    # didn't decrypt the header — gives us a clean error path
    # BEFORE the application starts issuing real queries.
    conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
    # Hardening pragmas.
    for name, value in HARDENING_PRAGMAS:
        conn.execute(f"PRAGMA {name} = {value}")
    return conn


def detect_db_state(db_path: Path) -> str:
    """Inspect db_path and return one of:
      - "missing"     no file (fresh install)
      - "plaintext"   exists and opens with stdlib sqlite3
      - "encrypted"   exists and rejects stdlib sqlite3 (likely
                      SQLCipher OR corrupted)
      - "empty"       file exists but is zero bytes
    """
    if not db_path.exists():
        return "missing"
    if db_path.stat().st_size == 0:
        return "empty"
    import sqlite3 as _stdsq
    try:
        with _stdsq.connect(str(db_path)) as c:
            c.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return "plaintext"
    except _stdsq.DatabaseError:
        return "encrypted"


def migrate_plaintext_to_encrypted(
    db_path: Path,
    passphrase: str,
) -> Path:
    """One-shot migration: take the existing plaintext SQLite file at
    ``db_path`` and replace it with an SQLCipher-encrypted file at
    the same path containing the SAME data.

    Steps (atomic with crash safety at each):
      1. Verify SQLCipher import is available — refuse if not.
      2. Copy the existing file to ``<path>.pre-encryption-backup`` as a
         crash-safety net DURING the migration only.
      3. Open the plaintext source with stdlib sqlite3.
      4. ATTACH a new encrypted DB at ``<path>.encrypted`` using
         the passphrase, ``sqlcipher_export()`` everything over.
      5. Sanity-open the encrypted file with the passphrase to confirm
         it works; raise if it doesn't.
      6. Rename ``<path>.encrypted`` → ``<path>`` (the backup makes
         this safe even mid-rename).
      7. SECURELY DELETE the plaintext backup — once the encrypted DB
         is verified + live, a lingering plaintext copy is a data-leak
         liability (external-audit finding), not a safety net.

    Returns the backup path ONLY if it could not be removed (so the
    caller can warn the user to delete it manually); returns None in
    the normal case where the plaintext backup was securely deleted."""
    if not _have_sqlcipher():
        raise RuntimeError(
            "sqlcipher3 not installed; cannot migrate to encrypted DB"
        )
    if not db_path.exists():
        raise FileNotFoundError(f"no plaintext DB at {db_path}")
    backup_path = db_path.with_suffix(db_path.suffix + ".pre-encryption-backup")
    enc_path = db_path.with_suffix(db_path.suffix + ".encrypted")

    # 1. Backup. shutil.copy2 preserves timestamps + mode bits.
    shutil.copy2(db_path, backup_path)
    log.info(
        "state.db migration: plaintext backup written to %s "
        "(keep this until you've confirmed the encrypted DB boots)",
        backup_path,
    )

    # If a previous attempt left an .encrypted file around, kill it.
    if enc_path.exists():
        enc_path.unlink()

    # 2. Export plaintext → encrypted via SQLCipher's ATTACH +
    # sqlcipher_export pattern. This streams every page through
    # the encryption cipher, much faster than dump-and-replay.
    import gc
    import sqlcipher3
    src = sqlcipher3.connect(str(db_path))
    try:
        # ATTACH supports parameterized path BUT not parameterized
        # KEY when given as plain string in modern SQLCipher; use
        # the hex-blob form for the key. Path goes through bind to
        # avoid SQL injection on the filename.
        key_hex = passphrase.encode("utf-8").hex()
        src.execute(
            "ATTACH DATABASE ? AS encrypted KEY \""
            f"x'{key_hex}'\"",
            (str(enc_path),),
        )
        src.execute(f"PRAGMA encrypted.cipher_page_size = {SQLCIPHER_PAGE_SIZE}")
        src.execute(f"PRAGMA encrypted.kdf_iter = {SQLCIPHER_KDF_ITER}")
        src.execute("SELECT sqlcipher_export('encrypted')")
        src.execute("DETACH DATABASE encrypted")
        # Force WAL checkpoint + flip to DELETE journal so the
        # WAL/SHM siblings are dropped before we close. Windows
        # holds the WAL file open even after src.close() if WAL
        # mode is still active.
        with contextlib.suppress(Exception):
            src.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            src.execute("PRAGMA journal_mode = DELETE")
    finally:
        src.close()
    # Help Windows release the file handle. CPython's GC usually
    # collects the closed connection immediately, but on slow runs
    # the underlying SQLite handle can linger one tick.
    del src
    gc.collect()

    # 3. Sanity-open the encrypted file standalone before swapping.
    test_conn = open_encrypted_connection(enc_path, passphrase)
    try:
        # Must contain the schema_version table at minimum.
        row = test_conn.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()
        if row is None:
            raise RuntimeError(
                "encrypted DB has no schema_version table; migration "
                "produced an unusable file"
            )
    finally:
        test_conn.close()

    # 4. Atomic swap. On POSIX, rename is atomic across same FS. On
    # Windows, this requires the target file to not be open by
    # anyone (caller's responsibility — migration runs BEFORE state
    # opens its own connection). Sibling WAL/SHM files from the
    # plaintext source need to go too; we already flipped journal
    # mode to DELETE so they SHOULD be gone, but the safety belt
    # removes them explicitly if they linger.
    for sibling in (
        db_path.with_suffix(db_path.suffix + "-wal"),
        db_path.with_suffix(db_path.suffix + "-shm"),
    ):
        if sibling.exists():
            with contextlib.suppress(OSError):
                sibling.unlink()
    db_path.unlink()
    enc_path.rename(db_path)

    # 5. Securely delete the plaintext backup. 2026-06-16 (external-audit
    # remediation): the backup was previously kept FOREVER ("never
    # auto-deleted") — a full plaintext copy of every message + identity
    # key sitting on disk, which an external audit (rightly) flagged as a
    # data-at-rest leak that defeats the whole point of encrypting the
    # DB. The backup exists only as a crash-safety net DURING migration;
    # by this point the encrypted DB has been sanity-opened (step 3) AND
    # is now the live file (step 4), so the plaintext copy is pure
    # liability. Overwrite its bytes before unlinking so the plaintext
    # doesn't survive in free space / on SSDs as easily.
    with contextlib.suppress(Exception):
        if backup_path.exists():
            size = backup_path.stat().st_size
            with open(backup_path, "r+b") as fh:
                fh.write(os.urandom(max(4096, min(size, 8 * 1024 * 1024))))
                fh.flush()
                os.fsync(fh.fileno())
            backup_path.unlink()
    backup_removed = not backup_path.exists()

    log.info(
        "state.db migrated to SQLCipher AES-256 (kdf_iter=%d, "
        "page_size=%d). Plaintext backup %s.",
        SQLCIPHER_KDF_ITER, SQLCIPHER_PAGE_SIZE,
        "securely deleted" if backup_removed else (
            "could NOT be removed — delete it manually: %s" % backup_path
        ),
    )
    # Return the backup path only if it still exists (couldn't be
    # removed); None when it was securely deleted (the common path).
    return None if backup_removed else backup_path


def harden_existing_connection(conn: Any) -> None:
    """Apply the runtime hardening pragmas to an already-open
    connection. Idempotent — safe to call after every reopen. Does
    NOT touch the key pragmas (those have to happen BEFORE any
    other SQL on a fresh handle)."""
    for name, value in HARDENING_PRAGMAS:
        try:
            conn.execute(f"PRAGMA {name} = {value}")
        except Exception as e:
            log.warning(
                "hardening PRAGMA %s=%s failed: %s", name, value, e,
            )


def shutdown_compact(conn: Any) -> None:
    """Called on graceful daemon shutdown. Runs `PRAGMA
    incremental_vacuum` (cheap if auto_vacuum is enabled) so freed
    pages return to the OS instead of lingering in the file. Best-
    effort; failure is logged + swallowed (we never want a vacuum
    error to block clean shutdown)."""
    try:
        conn.execute("PRAGMA incremental_vacuum")
    except Exception as e:
        log.warning("incremental_vacuum at shutdown: %s", e)
