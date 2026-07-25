"""state.db at-rest encryption helpers (SQLCipher).

Two responsibilities:

  1. Open a SQLCipher connection with the right PRAGMA key + hardening
     pragmas (secure_delete, foreign_keys, etc).

  2. Detect a legacy plaintext state.db at the same path and migrate
     it in place to encrypted form, preserving every row of every
     table. A temporary ``<path>.pre-encryption-backup`` protects the
     migration and is securely overwritten and removed after the encrypted
     database has been verified and atomically published.

A note on the failure ladder (enforced by :class:`one_link.state.State`):
  - sqlcipher3 not installed       → fail closed unless the operator has
                                     explicitly authorized plaintext mode.
  - keychain and local key file
    both unavailable               → same fail-closed behavior.
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
import secrets
import stat
from pathlib import Path
from typing import Any

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
STATE_SCHEMA_VERSION_CURRENT = 30
PLAINTEXT_BACKUP_SUFFIX = ".pre-encryption-backup"
_BACKUP_WIPE_CHUNK_BYTES = 1024 * 1024


class PlaintextBackupCleanupError(RuntimeError):
    """A migration backup could not be erased without risking another file."""

    def __init__(self, path: Path, reason: str):
        self.path = Path(path)
        self.reason = str(reason)
        super().__init__(f"{self.path}: {self.reason}")


class EncryptedDatabaseVerificationError(RuntimeError):
    """The encrypted live DB is not yet strong enough to destroy recovery."""


def verify_encrypted_state_for_backup_cleanup(
    conn: Any,
    *,
    expected_schema_version: int = STATE_SCHEMA_VERSION_CURRENT,
) -> None:
    """Run the one-time destructive-cleanup truth gates.

    A successful key probe is not enough to destroy the only plaintext
    recovery copy: it proves only that page one decrypted. Require the exact
    application schema, a real SQLCipher engine, per-page cipher/HMAC truth,
    and SQLite's full structural integrity result first.
    """

    try:
        schema_rows = conn.execute(
            "SELECT version FROM schema_version ORDER BY version"
        ).fetchall()
        versions = [int(row[0]) for row in schema_rows]
        expected = int(expected_schema_version)
        if not versions or max(versions) != expected or any(
            version < 1 or version > expected for version in versions
        ):
            raise EncryptedDatabaseVerificationError(
                "live encrypted database is not at the exact supported "
                f"schema version {expected}"
            )

        cipher_version = conn.execute("PRAGMA cipher_version").fetchone()
        if not cipher_version or not str(cipher_version[0] or "").strip():
            raise EncryptedDatabaseVerificationError(
                "live connection did not report a SQLCipher version"
            )
        cipher_rows = conn.execute("PRAGMA cipher_integrity_check").fetchall()
        cipher_findings = [
            str(row[0] or "").strip()
            for row in cipher_rows
            if row and str(row[0] or "").strip().lower() != "ok"
        ]
        if cipher_findings:
            raise EncryptedDatabaseVerificationError(
                "SQLCipher integrity check failed: "
                + "; ".join(cipher_findings[:4])
            )

        sqlite_rows = conn.execute("PRAGMA integrity_check").fetchall()
        sqlite_findings = [str(row[0] or "").strip() for row in sqlite_rows if row]
        if sqlite_findings != ["ok"]:
            raise EncryptedDatabaseVerificationError(
                "SQLite integrity check failed: "
                + "; ".join(sqlite_findings[:4] or ["no result"])
            )
    except EncryptedDatabaseVerificationError:
        raise
    except Exception as exc:
        raise EncryptedDatabaseVerificationError(
            f"encrypted database verification raised {type(exc).__name__}: {exc}"
        ) from exc


def plaintext_backup_path(db_path: Path) -> Path:
    """Return the one exact sibling reserved for plaintext migration data."""

    path = Path(db_path)
    return path.with_name(path.name + PLAINTEXT_BACKUP_SUFFIX)


def _is_reparse_point(st: os.stat_result) -> bool:
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    attributes = getattr(st, "st_file_attributes", 0) or 0
    return bool(int(attributes) & reparse_flag)


def _file_identity(st: os.stat_result) -> tuple[int, int]:
    return (
        int(getattr(st, "st_dev", 0) or 0),
        int(getattr(st, "st_ino", 0) or 0),
    )


def _validate_cleanup_candidate(
    path: Path,
    st: os.stat_result,
    *,
    live_st: os.stat_result,
) -> None:
    if stat.S_ISLNK(st.st_mode) or _is_reparse_point(st):
        raise PlaintextBackupCleanupError(path, "refusing symlink/reparse point")
    if not stat.S_ISREG(st.st_mode):
        raise PlaintextBackupCleanupError(path, "refusing non-regular file")
    if int(getattr(st, "st_nlink", 1)) != 1:
        raise PlaintextBackupCleanupError(path, "refusing multiply-linked file")
    identity = _file_identity(st)
    if identity == (0, 0):
        raise PlaintextBackupCleanupError(path, "file identity is unavailable")
    if identity == _file_identity(live_st):
        raise PlaintextBackupCleanupError(path, "backup aliases the live database")
    size = int(st.st_size)
    if size < 0:
        raise PlaintextBackupCleanupError(path, "invalid negative file size")
    # The reserved file should be one exported state database, not an
    # attacker-created sparse device-filling workload. SQLCipher export can
    # change page packing, so allow generous drift while keeping a finite cap.
    live_size = max(0, int(live_st.st_size))
    max_expected_size = max(64 * 1024 * 1024, live_size * 4)
    if size > max_expected_size:
        raise PlaintextBackupCleanupError(
            path,
            f"backup size {size} exceeds safe bound {max_expected_size}",
        )


def _open_backup_descriptor(path: Path) -> int:
    """Open *path* read/write without following a final-component link."""

    if os.name != "nt":
        flags = os.O_RDWR | int(getattr(os, "O_CLOEXEC", 0))
        flags |= int(getattr(os, "O_NOFOLLOW", 0))
        return os.open(path, flags)

    # os.open() does not provide a dependable no-follow contract on every
    # supported Windows Python. CreateFileW with OPEN_REPARSE_POINT opens the
    # link object itself, and share-mode zero prevents rename/replacement while
    # identity is being checked, overwritten, and marked for deletion.
    import ctypes
    import msvcrt
    from ctypes import wintypes

    create_file = ctypes.windll.kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    generic_read = 0x80000000
    generic_write = 0x40000000
    delete_access = 0x00010000
    open_existing = 3
    file_attribute_normal = 0x00000080
    file_flag_open_reparse_point = 0x00200000
    file_flag_write_through = 0x80000000
    handle = create_file(
        str(path),
        generic_read | generic_write | delete_access,
        0,
        None,
        open_existing,
        (
            file_attribute_normal
            | file_flag_open_reparse_point
            | file_flag_write_through
        ),
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        raise ctypes.WinError()
    try:
        return msvcrt.open_osfhandle(
            int(handle),
            os.O_RDWR | int(getattr(os, "O_BINARY", 0)),
        )
    except Exception:
        ctypes.windll.kernel32.CloseHandle(handle)
        raise


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write while erasing plaintext backup")
        view = view[written:]


def _overwrite_backup_descriptor(fd: int, size: int) -> None:
    os.lseek(fd, 0, os.SEEK_SET)
    remaining = int(size)
    while remaining:
        take = min(_BACKUP_WIPE_CHUNK_BYTES, remaining)
        _write_all(fd, os.urandom(take))
        remaining -= take
    os.ftruncate(fd, int(size))
    os.fsync(fd)


def _delete_open_backup(path: Path, fd: int) -> None:
    """Delete the object held by *fd* without reopening its pathname."""

    if os.name != "nt":
        os.unlink(path)
        return

    import ctypes
    import msvcrt
    from ctypes import wintypes

    class _FileDispositionInfo(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BOOL)]

    disposition = _FileDispositionInfo(True)
    set_info = ctypes.windll.kernel32.SetFileInformationByHandle
    set_info.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    set_info.restype = wintypes.BOOL
    handle = wintypes.HANDLE(msvcrt.get_osfhandle(fd))
    # FILE_INFO_BY_HANDLE_CLASS::FileDispositionInfo == 4.
    if not set_info(
        handle,
        4,
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        raise ctypes.WinError()


def _fsync_parent_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0))
    fd = os.open(path.parent, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def cleanup_plaintext_migration_backup(db_path: Path) -> bool:
    """Erase a stale plaintext backup after the live DB is verified.

    Returns ``False`` when no reserved sibling exists and ``True`` after a
    complete overwrite, fsync, identity-bound unlink, and parent-directory
    fsync. Unsafe types, aliases, substitutions, and I/O failures are surfaced
    as :class:`PlaintextBackupCleanupError`; they are never followed or
    silently ignored.
    """

    live_path = Path(db_path)
    backup_path = plaintext_backup_path(live_path)
    try:
        live_st = os.lstat(live_path)
        if stat.S_ISLNK(live_st.st_mode) or _is_reparse_point(live_st):
            raise PlaintextBackupCleanupError(
                backup_path,
                "live database is not an identity-stable regular path",
            )
        if not stat.S_ISREG(live_st.st_mode):
            raise PlaintextBackupCleanupError(
                backup_path,
                "live database is not a regular file",
            )
        try:
            before = os.lstat(backup_path)
        except FileNotFoundError:
            return False
        _validate_cleanup_candidate(backup_path, before, live_st=live_st)
        expected_identity = _file_identity(before)
        expected_size = int(before.st_size)

        fd = _open_backup_descriptor(backup_path)
        try:
            opened = os.fstat(fd)
            _validate_cleanup_candidate(backup_path, opened, live_st=live_st)
            if (
                _file_identity(opened) != expected_identity
                or int(opened.st_size) != expected_size
            ):
                raise PlaintextBackupCleanupError(
                    backup_path,
                    "backup changed between path inspection and open",
                )
            _overwrite_backup_descriptor(fd, expected_size)
            wiped = os.fstat(fd)
            if (
                _file_identity(wiped) != expected_identity
                or int(wiped.st_size) != expected_size
            ):
                raise PlaintextBackupCleanupError(
                    backup_path,
                    "backup identity or size changed during overwrite",
                )
            current = os.lstat(backup_path)
            _validate_cleanup_candidate(backup_path, current, live_st=live_st)
            if (
                _file_identity(current) != expected_identity
                or int(current.st_size) != expected_size
            ):
                raise PlaintextBackupCleanupError(
                    backup_path,
                    "backup pathname was replaced before unlink",
                )
            _delete_open_backup(backup_path, fd)
        finally:
            os.close(fd)

        try:
            os.lstat(backup_path)
        except FileNotFoundError:
            pass
        else:
            raise PlaintextBackupCleanupError(
                backup_path,
                "backup still exists after deletion",
            )
        _fsync_parent_directory(backup_path)
        log.warning(
            "securely erased stale plaintext state backup: %s (%d bytes)",
            backup_path,
            expected_size,
        )
        return True
    except PlaintextBackupCleanupError:
        log.critical(
            "PLAINTEXT state backup cleanup refused or failed: %s",
            backup_path,
            exc_info=True,
        )
        raise
    except Exception as exc:
        error = PlaintextBackupCleanupError(
            backup_path,
            f"{type(exc).__name__}: {exc}",
        )
        log.critical(
            "PLAINTEXT state backup cleanup failed: %s",
            error,
            exc_info=True,
        )
        raise error from exc


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
    try:
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
    except BaseException:
        # A failed key probe still owns a native SQLite handle.  On Windows
        # that handle prevents recovery tooling from atomically replacing the
        # database, and repeated wrong-key probes leak one handle apiece.
        with contextlib.suppress(Exception):
            conn.close()
        raise


def _verify_encrypted_snapshot(conn: Any) -> None:
    """Prove that a portable snapshot is a real, coherent SQLCipher DB."""

    cipher_version = conn.execute("PRAGMA cipher_version").fetchone()
    if not cipher_version or not str(cipher_version[0] or "").strip():
        raise EncryptedDatabaseVerificationError(
            "snapshot connection did not report a SQLCipher version"
        )
    cipher_rows = conn.execute("PRAGMA cipher_integrity_check").fetchall()
    cipher_findings = [
        str(row[0] or "").strip()
        for row in cipher_rows
        if row and str(row[0] or "").strip().lower() != "ok"
    ]
    if cipher_findings:
        raise EncryptedDatabaseVerificationError(
            "snapshot SQLCipher integrity check failed: "
            + "; ".join(cipher_findings[:4])
        )
    sqlite_rows = conn.execute("PRAGMA integrity_check").fetchall()
    sqlite_findings = [str(row[0] or "").strip() for row in sqlite_rows if row]
    if sqlite_findings != ["ok"]:
        raise EncryptedDatabaseVerificationError(
            "snapshot SQLite integrity check failed: "
            + "; ".join(sqlite_findings[:4] or ["no result"])
        )


def _remove_generated_database_family(db_path: Path) -> None:
    """Remove only a caller-created temporary database family."""

    path = Path(db_path)
    for candidate in (
        path,
        path.with_name(path.name + "-wal"),
        path.with_name(path.name + "-shm"),
    ):
        with contextlib.suppress(FileNotFoundError):
            candidate.unlink()


def create_encrypted_snapshot(
    *,
    source_path: Path,
    source_passphrase: str,
    destination_path: Path,
    destination_passphrase: str | None = None,
) -> Path:
    """Create one coherent, standalone SQLCipher snapshot.

    SQLite's online-backup API reads a transactionally consistent view even
    while another connection is appending to the source WAL.  The resulting
    database is checkpointed into its main file, switched to DELETE journaling
    so no sidecars are load-bearing, closed, reopened, and fully verified
    before this function returns.  Every native connection and every partial
    destination is retired on failure.

    ``destination_passphrase`` defaults to ``source_passphrase``.  Supplying a
    different value provides the primitive used by recovery to atomically
    converge a restored database on the target machine's configured key.
    """

    source = Path(source_path).resolve()
    destination = Path(destination_path).resolve()
    if source == destination:
        raise ValueError("snapshot destination must differ from the source")
    if os.path.lexists(destination):
        raise FileExistsError(f"snapshot destination already exists: {destination}")
    if not isinstance(source_passphrase, str) or not source_passphrase:
        raise ValueError("source passphrase must be non-empty text")
    target_key = (
        source_passphrase
        if destination_passphrase is None
        else destination_passphrase
    )
    if not isinstance(target_key, str) or not target_key:
        raise ValueError("destination passphrase must be non-empty text")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    source_conn: Any | None = None
    destination_conn: Any | None = None
    try:
        source_conn = open_encrypted_connection(source, source_passphrase)
        destination_conn = open_encrypted_connection(destination, target_key)
        # A finite page batch lets SQLite yield between steps when a live
        # writer is active, without weakening the single-snapshot guarantee.
        source_conn.backup(destination_conn, pages=1024, sleep=0.01)
        destination_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        destination_conn.execute("PRAGMA journal_mode = DELETE").fetchone()
        _verify_encrypted_snapshot(destination_conn)
        destination_conn.close()
        destination_conn = None
        source_conn.close()
        source_conn = None

        # Reopen after all WAL handles are gone. This proves the main file is
        # independently recoverable and not accidentally relying on a sidecar.
        verify = open_encrypted_connection(destination, target_key)
        try:
            _verify_encrypted_snapshot(verify)
            verify.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            verify.execute("PRAGMA journal_mode = DELETE").fetchone()
        finally:
            verify.close()
        if os.name != "nt":
            os.chmod(destination, 0o600)
        with destination.open("r+b") as handle:
            os.fsync(handle.fileno())
        _fsync_parent_directory(destination)
        return destination
    except BaseException:
        if destination_conn is not None:
            with contextlib.suppress(Exception):
                destination_conn.close()
        if source_conn is not None:
            with contextlib.suppress(Exception):
                source_conn.close()
        _remove_generated_database_family(destination)
        raise


def database_accepts_passphrase(db_path: Path, passphrase: str) -> bool:
    """Return true only when *passphrase* fully opens the encrypted DB."""

    try:
        conn = open_encrypted_connection(Path(db_path), passphrase)
    except Exception:
        return False
    try:
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return True
    finally:
        conn.close()


def replace_encrypted_database_key_atomic(
    *,
    db_path: Path,
    source_passphrase: str,
    destination_passphrase: str,
) -> None:
    """Atomically re-encrypt an offline database under a new authority.

    The old database remains byte-for-byte intact until a fully fsynced and
    independently verified replacement exists.  The final ``os.replace`` is
    one-filesystem atomic.  A retained recovery-key artifact makes the
    operation replayable if power fails immediately after that boundary.
    """

    path = Path(db_path).resolve()
    if secrets.compare_digest(source_passphrase, destination_passphrase):
        conn = open_encrypted_connection(path, source_passphrase)
        try:
            _verify_encrypted_snapshot(conn)
        finally:
            conn.close()
        return
    temporary = path.with_name(
        f".{path.name}.rekey.{secrets.token_hex(16)}"
    )
    create_encrypted_snapshot(
        source_path=path,
        source_passphrase=source_passphrase,
        destination_path=temporary,
        destination_passphrase=destination_passphrase,
    )
    try:
        # This helper is an offline recovery boundary.  Make the old database
        # self-contained before replacing its main file, so a stale WAL can
        # never be replayed against the new key after a crash.
        old = open_encrypted_connection(path, source_passphrase)
        try:
            checkpoint = old.execute("PRAGMA wal_checkpoint(FULL)").fetchone()
            if checkpoint and int(checkpoint[0] or 0) != 0:
                raise RuntimeError("state database is busy; recovery rekey requires offline access")
            mode = old.execute("PRAGMA journal_mode = DELETE").fetchone()
            if not mode or str(mode[0]).lower() != "delete":
                raise RuntimeError("could not detach the old state WAL before recovery rekey")
        finally:
            old.close()
        os.replace(temporary, path)
        _fsync_parent_directory(path)
        for suffix in ("-wal", "-shm"):
            stale = path.with_name(path.name + suffix)
            with contextlib.suppress(FileNotFoundError):
                stale.unlink()
        verify = open_encrypted_connection(path, destination_passphrase)
        try:
            _verify_encrypted_snapshot(verify)
        finally:
            verify.close()
    except BaseException:
        _remove_generated_database_family(temporary)
        raise


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
) -> Path | None:
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
    backup_path = plaintext_backup_path(db_path)
    enc_path = db_path.with_suffix(db_path.suffix + ".encrypted")

    # 1. Backup. Exclusive create prevents a stale symlink or attacker-chosen
    # reserved sibling from redirecting the plaintext copy into another file.
    # The backup contains identity keys and message bodies, so force 0600 and
    # durably publish it before modifying the live path.
    with open(db_path, "rb") as source, open(backup_path, "xb") as backup:
        os.chmod(backup_path, 0o600)
        while True:
            block = source.read(_BACKUP_WIPE_CHUNK_BYTES)
            if not block:
                break
            backup.write(block)
        backup.flush()
        os.fsync(backup.fileno())
    _fsync_parent_directory(backup_path)
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

    # 5. Securely delete the plaintext backup. The helper overwrites every
    # byte, fsyncs it, binds the final path to the opened file identity, and
    # only then unlinks. A suspicious type/race is surfaced and retained for
    # operator action instead of following a link or deleting a replacement.
    cleanup_error: PlaintextBackupCleanupError | None = None
    try:
        live_verify = open_encrypted_connection(db_path, passphrase)
        try:
            verify_encrypted_state_for_backup_cleanup(live_verify)
        finally:
            live_verify.close()
        cleanup_plaintext_migration_backup(db_path)
    except (EncryptedDatabaseVerificationError, PlaintextBackupCleanupError) as exc:
        cleanup_error = PlaintextBackupCleanupError(backup_path, str(exc))
        log.critical(
            "plaintext migration backup retained until encrypted DB passes "
            "all truth gates: %s",
            cleanup_error,
        )
    backup_removed = cleanup_error is None

    log.info(
        "state.db migrated to SQLCipher AES-256 (kdf_iter=%d, "
        "page_size=%d). Plaintext backup %s.",
        SQLCIPHER_KDF_ITER, SQLCIPHER_PAGE_SIZE,
        "securely deleted" if backup_removed else (
            "could NOT be removed — delete it manually: %s" % backup_path
        ),
    )
    # Return the backup path only if it could not be safely removed; State's
    # encrypted-open path retries stale cleanup on every subsequent boot.
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
