"""v0.21.x at-rest encryption + boot-time hardening checks.

Tests pin:
  - keychain auto-mint + idempotent re-fetch + rotate + forget
  - state_encryption detection (missing/plaintext/encrypted/empty)
  - migration: plaintext → encrypted preserves data + writes backup
  - State() boots fresh-encrypted when passphrase available
  - State() refuses to silently fall back to plaintext when the
    on-disk file is encrypted and the key is wrong
  - hardening_checks: file permissions / cloud-sync / network bind /
    encryption status produce the right findings
  - /api/security/audit surfaces findings to the UI
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import hardening_checks as hc
from one_link import keychain as kc
from one_link import state_encryption as se
from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    return Identity(
        private=sk, public=sk.public_key(), public_bytes=pub,
        fingerprint=fingerprint_of(pub), short_id=fingerprint_of(pub)[:8],
        hostname="enc-host",
    )


# ── state_encryption module ──────────────────────────────────────


def test_detect_missing(tmp_path: Path):
    assert se.detect_db_state(tmp_path / "absent.db") == "missing"


def test_detect_plaintext(tmp_path: Path):
    p = tmp_path / "p.db"
    c = sqlite3.connect(str(p))
    c.execute("CREATE TABLE t(x INTEGER)")
    c.commit(); c.close()
    assert se.detect_db_state(p) == "plaintext"


def test_detect_empty(tmp_path: Path):
    p = tmp_path / "empty.db"
    p.touch()
    assert se.detect_db_state(p) == "empty"


def test_detect_never_opens_a_database_handle(tmp_path: Path, monkeypatch):
    """Detection must read the header, never open the database.

    The daemon holds the live database open through SQLCipher — a second,
    independent SQLite library inside the same process. Two SQLite copies
    that both open one WAL database keep separate shared-memory bookkeeping
    for the ``-shm`` index and corrupt each other's mappings: probing a live
    database with stdlib sqlite3 faulted the writer thread with
    SIGBUS/SIGSEGV in 19 of 25 runs. Any future refactor that reintroduces
    an open() here must fail this test rather than a user's daemon.
    """
    import sqlite3 as stdlib_sqlite3

    p = tmp_path / "live.db"
    conn = stdlib_sqlite3.connect(str(p))
    conn.execute("CREATE TABLE t(x INTEGER)")
    conn.commit()
    conn.close()

    def _forbidden(*args, **kwargs):  # pragma: no cover - assertion payload
        raise AssertionError(
            "detect_db_state opened a database handle; header inspection "
            "only (a second SQLite library must never touch a live WAL db)"
        )

    monkeypatch.setattr(stdlib_sqlite3, "connect", _forbidden)
    sqlcipher = pytest.importorskip("sqlcipher3")
    monkeypatch.setattr(sqlcipher, "connect", _forbidden, raising=False)

    assert se.detect_db_state(p) == "plaintext"


def test_stale_plaintext_backup_cleanup_overwrites_every_byte_and_unlinks(
    tmp_path: Path,
    monkeypatch,
):
    live = tmp_path / "state.db"
    live_bytes = b"encrypted-live-database-sentinel"
    live.write_bytes(live_bytes)
    backup = se.plaintext_backup_path(live)
    plaintext = (b"SQLite format 3\0" + b"PRIVATE-MESSAGE\0" * 8192)
    backup.write_bytes(plaintext)
    observed: dict[str, bytes] = {}
    real_delete = se._delete_open_backup

    def _observe_then_delete(path: Path, fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        observed["wiped"] = os.read(fd, len(plaintext))
        real_delete(path, fd)

    monkeypatch.setattr(se.os, "urandom", lambda n: b"\xa5" * n)
    monkeypatch.setattr(se, "_delete_open_backup", _observe_then_delete)

    assert se.cleanup_plaintext_migration_backup(live) is True
    assert not backup.exists()
    assert live.read_bytes() == live_bytes
    assert observed["wiped"] == b"\xa5" * len(plaintext)


def test_stale_plaintext_backup_cleanup_refuses_symlink(
    tmp_path: Path,
    monkeypatch,
):
    live = tmp_path / "state.db"
    live.write_bytes(b"encrypted-live")
    victim = tmp_path / "victim.db"
    victim_bytes = b"SQLite format 3\0DO-NOT-TOUCH"
    victim.write_bytes(victim_bytes)
    backup = se.plaintext_backup_path(live)
    try:
        backup.symlink_to(victim)
    except OSError as exc:
        # Windows may deny symlink creation outside Developer Mode. Exercise
        # the same fail-closed reparse branch with an identity-stable stand-in
        # so the security gate is never silently skipped in CI.
        backup.write_bytes(victim_bytes)
        backup_stat = os.lstat(backup)
        real_is_reparse = se._is_reparse_point
        monkeypatch.setattr(
            se,
            "_is_reparse_point",
            lambda value: value is backup_stat or real_is_reparse(value),
        )
        real_lstat = se.os.lstat
        monkeypatch.setattr(
            se.os,
            "lstat",
            lambda path: backup_stat if Path(path) == backup else real_lstat(path),
        )

    with pytest.raises(
        se.PlaintextBackupCleanupError,
        match="symlink|reparse",
    ):
        se.cleanup_plaintext_migration_backup(live)

    assert os.path.lexists(backup)
    assert victim.read_bytes() == victim_bytes
    assert live.read_bytes() == b"encrypted-live"


def test_stale_plaintext_backup_cleanup_refuses_non_regular_file(
    tmp_path: Path,
):
    live = tmp_path / "state.db"
    live.write_bytes(b"encrypted-live")
    backup = se.plaintext_backup_path(live)
    backup.mkdir()

    with pytest.raises(
        se.PlaintextBackupCleanupError,
        match="non-regular",
    ):
        se.cleanup_plaintext_migration_backup(live)

    assert backup.is_dir()
    assert live.read_bytes() == b"encrypted-live"


def test_stale_plaintext_backup_cleanup_detects_path_identity_race(
    tmp_path: Path,
    monkeypatch,
):
    live = tmp_path / "state.db"
    live_bytes = b"encrypted-live"
    live.write_bytes(live_bytes)
    backup = se.plaintext_backup_path(live)
    backup.write_bytes(b"SQLite format 3\0" + b"secret" * 4096)
    real_lstat = se.os.lstat
    backup_lstats = 0

    def _raced_lstat(path):
        nonlocal backup_lstats
        result = real_lstat(path)
        if Path(path) != backup:
            return result
        backup_lstats += 1
        if backup_lstats < 2:
            return result
        values = list(result)
        values[1] = int(result.st_ino) + 1
        return os.stat_result(values)

    monkeypatch.setattr(se.os, "lstat", _raced_lstat)

    with pytest.raises(
        se.PlaintextBackupCleanupError,
        match="replaced before unlink",
    ):
        se.cleanup_plaintext_migration_backup(live)

    assert backup.exists(), "a raced pathname must never be unlinked"
    assert live.read_bytes() == live_bytes


@pytest.mark.parametrize(
    ("cipher_rows", "sqlite_rows", "expected_error"),
    [
        ([('page 7 HMAC verification failed',)], [("ok",)], "SQLCipher"),
        ([], [("database disk image is malformed",)], "SQLite"),
    ],
)
def test_backup_cleanup_truth_gate_rejects_cipher_or_sqlite_corruption(
    cipher_rows,
    sqlite_rows,
    expected_error,
):
    class _Result:
        def __init__(self, rows):
            self.rows = rows

        def fetchall(self):
            return list(self.rows)

        def fetchone(self):
            return self.rows[0] if self.rows else None

    class _Connection:
        def execute(self, sql):
            if sql.startswith("SELECT version"):
                return _Result([(se.STATE_SCHEMA_VERSION_CURRENT,)])
            if sql == "PRAGMA cipher_version":
                return _Result([("4.6.1",)])
            if sql == "PRAGMA cipher_integrity_check":
                return _Result(cipher_rows)
            if sql == "PRAGMA integrity_check":
                return _Result(sqlite_rows)
            raise AssertionError(f"unexpected SQL: {sql}")

    with pytest.raises(
        se.EncryptedDatabaseVerificationError,
        match=expected_error,
    ):
        se.verify_encrypted_state_for_backup_cleanup(_Connection())


@pytest.mark.skipif(not se._have_sqlcipher(), reason="sqlcipher3 not installed")
def test_detect_encrypted_via_migration(tmp_path: Path):
    p = tmp_path / "x.db"
    c = sqlite3.connect(str(p))
    c.execute("CREATE TABLE schema_version(version INTEGER)")
    c.execute(
        "INSERT INTO schema_version VALUES(?)",
        (se.STATE_SCHEMA_VERSION_CURRENT,),
    )
    c.commit(); c.close()
    se.migrate_plaintext_to_encrypted(p, "test-passphrase-xyz")
    assert se.detect_db_state(p) == "encrypted"


@pytest.mark.skipif(not se._have_sqlcipher(), reason="sqlcipher3 not installed")
def test_migration_preserves_all_data(tmp_path: Path):
    """Multiple tables + multiple rows survive the encrypt round-trip."""
    p = tmp_path / "rich.db"
    c = sqlite3.connect(str(p))
    c.execute("CREATE TABLE schema_version(version INTEGER)")
    c.execute("INSERT INTO schema_version VALUES(27)")
    c.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, body TEXT)")
    for i in range(50):
        c.execute(
            "INSERT INTO messages VALUES(?, ?)",
            (i, f"message body number {i}"),
        )
    c.execute("CREATE TABLE peers(fp TEXT PRIMARY KEY, host TEXT)")
    c.execute("INSERT INTO peers VALUES('aa', 'host-a')")
    c.commit(); c.close()
    se.migrate_plaintext_to_encrypted(p, "test-passphrase-12345")
    # Verify every row survived.
    conn = se.open_encrypted_connection(p, "test-passphrase-12345")
    msgs = conn.execute("SELECT count(*) FROM messages").fetchone()
    assert msgs[0] == 50
    peer = conn.execute("SELECT host FROM peers WHERE fp='aa'").fetchone()
    assert peer[0] == "host-a"
    conn.close()


@pytest.mark.skipif(not se._have_sqlcipher(), reason="sqlcipher3 not installed")
def test_migration_securely_deletes_plaintext_backup(tmp_path: Path):
    """2026-06-16 (external-audit remediation): the migration used to
    keep a plaintext .pre-encryption-backup FOREVER — a full plaintext
    copy of every message + identity on disk, defeating the point of
    encrypting the DB. It must now be securely deleted once the
    encrypted DB is verified + live. NO plaintext may survive on disk."""
    p = tmp_path / "s.db"
    c = sqlite3.connect(str(p))
    c.execute("CREATE TABLE schema_version(version INTEGER)")
    c.execute(
        "INSERT INTO schema_version VALUES(?)",
        (se.STATE_SCHEMA_VERSION_CURRENT,),
    )
    c.execute("CREATE TABLE t(body TEXT)")
    c.execute("INSERT INTO t VALUES('plaintext must not survive')")
    c.commit(); c.close()
    backup = se.migrate_plaintext_to_encrypted(p, "test-pass")
    # Normal path: backup securely deleted, function returns None.
    assert backup is None
    backup_path = tmp_path / "s.db.pre-encryption-backup"
    assert not backup_path.exists(), "plaintext backup must be deleted"
    # The live (encrypted) file must NOT contain the plaintext.
    assert b"plaintext must not survive" not in p.read_bytes()
    # Belt-and-suspenders: NO file in the dir holds the plaintext.
    for f in tmp_path.rglob("*"):
        if f.is_file():
            assert b"plaintext must not survive" not in f.read_bytes(), (
                f"plaintext leaked into {f.name}"
            )


@pytest.mark.skipif(not se._have_sqlcipher(), reason="sqlcipher3 not installed")
def test_encrypted_state_boot_cleans_backup_left_by_older_release(
    tmp_path: Path,
    monkeypatch,
):
    db_path = tmp_path / "state.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE schema_version(version INTEGER)")
    conn.execute("INSERT INTO schema_version VALUES(27)")
    conn.execute("CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT)")
    conn.commit()
    conn.close()
    passphrase = "stale-backup-cleanup-integration-key"
    se.migrate_plaintext_to_encrypted(db_path, passphrase)
    stale = se.plaintext_backup_path(db_path)
    stale_conn = sqlite3.connect(stale)
    stale_conn.execute("CREATE TABLE leaked(body TEXT)")
    stale_conn.execute("INSERT INTO leaked VALUES('historic plaintext')")
    stale_conn.commit()
    stale_conn.close()
    assert b"historic plaintext" in stale.read_bytes()

    monkeypatch.setenv(kc.ENV_VAR, passphrase)
    state = State(db_path=db_path)
    try:
        assert state.is_encrypted is True
        assert state._encryption_backup_path is None
        assert not stale.exists()
    finally:
        state.close()


@pytest.mark.skipif(not se._have_sqlcipher(), reason="sqlcipher3 not installed")
def test_encrypted_state_retains_backup_when_full_verification_refuses(
    tmp_path: Path,
    monkeypatch,
):
    passphrase = "verification-refusal-test-key"
    monkeypatch.setenv(kc.ENV_VAR, passphrase)
    db_path = tmp_path / "state.db"
    initial = State(db_path=db_path)
    initial.close()
    stale = se.plaintext_backup_path(db_path)
    stale_bytes = b"SQLite format 3\0ONLY-RECOVERY-COPY" * 4096
    stale.write_bytes(stale_bytes)

    def _refuse(_conn, *, expected_schema_version):
        assert expected_schema_version == se.STATE_SCHEMA_VERSION_CURRENT
        raise se.EncryptedDatabaseVerificationError(
            "simulated encrypted partial-page corruption"
        )

    monkeypatch.setattr(
        se,
        "verify_encrypted_state_for_backup_cleanup",
        _refuse,
    )
    reopened = State(db_path=db_path)
    try:
        assert reopened._encryption_backup_path == stale
        assert stale.read_bytes() == stale_bytes
    finally:
        reopened.close()


@pytest.mark.skipif(not se._have_sqlcipher(), reason="sqlcipher3 not installed")
def test_encrypted_state_retains_uninspectable_backup_without_crashing(
    tmp_path: Path,
    monkeypatch,
):
    passphrase = "uninspectable-backup-test-key"
    monkeypatch.setenv(kc.ENV_VAR, passphrase)
    db_path = tmp_path / "state.db"
    initial = State(db_path=db_path)
    initial.close()
    stale = se.plaintext_backup_path(db_path)
    stale_bytes = b"SQLite format 3\0ACL-RECOVERY-COPY" * 4096
    stale.write_bytes(stale_bytes)
    real_lstat = os.lstat

    def _deny_backup_inspection(path):
        if Path(path) == stale:
            raise PermissionError("simulated backup ACL denial")
        return real_lstat(path)

    monkeypatch.setattr(os, "lstat", _deny_backup_inspection)
    reopened = State(db_path=db_path)
    try:
        assert reopened._encryption_backup_path == stale
        # Use an already-open descriptor would be overkill here; restore the
        # path inspection primitive before proving that no byte was touched.
        monkeypatch.setattr(os, "lstat", real_lstat)
        assert stale.read_bytes() == stale_bytes
    finally:
        reopened.close()


@pytest.mark.skipif(not se._have_sqlcipher(), reason="sqlcipher3 not installed")
def test_truncated_encrypted_database_never_triggers_plaintext_backup_erase(
    tmp_path: Path,
    monkeypatch,
):
    passphrase = "truncated-encrypted-database-test-key"
    monkeypatch.setenv(kc.ENV_VAR, passphrase)
    db_path = tmp_path / "state.db"
    initial = State(db_path=db_path)
    initial.set_setting("large-value", "x" * 512_000)
    initial.close()
    stale = se.plaintext_backup_path(db_path)
    stale_bytes = b"SQLite format 3\0TRUNCATION-RECOVERY" * 4096
    stale.write_bytes(stale_bytes)
    original_size = db_path.stat().st_size
    with open(db_path, "r+b") as handle:
        handle.truncate(max(4096, original_size // 2))
        handle.flush()
        os.fsync(handle.fileno())

    damaged = None
    try:
        damaged = State(db_path=db_path)
    except Exception:
        pass
    finally:
        if damaged is not None:
            assert damaged._encryption_backup_path == stale
            damaged.close()

    assert stale.read_bytes() == stale_bytes


@pytest.mark.skipif(not se._have_sqlcipher(), reason="sqlcipher3 not installed")
def test_wrong_key_rejected(tmp_path: Path):
    p = tmp_path / "k.db"
    c = sqlite3.connect(str(p))
    c.execute("CREATE TABLE schema_version(version INTEGER)")
    c.execute("INSERT INTO schema_version VALUES(1)")
    c.commit(); c.close()
    se.migrate_plaintext_to_encrypted(p, "correct-passphrase")
    with pytest.raises(Exception):
        se.open_encrypted_connection(p, "WRONG-passphrase")


# ── keychain module ──────────────────────────────────────────────


def test_keychain_round_trip_isolated(monkeypatch):
    """Use a fake keyring backend so the test doesn't touch the
    user's real OS keychain."""
    store: dict[tuple[str, str], str] = {}

    class FakeKeyring:
        @staticmethod
        def get_password(service, user):
            return store.get((service, user))

        @staticmethod
        def set_password(service, user, pw):
            store[(service, user)] = pw

        @staticmethod
        def delete_password(service, user):
            store.pop((service, user), None)

        @staticmethod
        def get_keyring():
            return type("FakeKR", (), {})()

    monkeypatch.setattr(kc, "_load_keyring", lambda: FakeKeyring)
    monkeypatch.delenv(kc.ENV_VAR, raising=False)
    # conftest disables at-rest encryption suite-wide; this test
    # exercises the real keychain logic, so opt back in.
    monkeypatch.delenv("ONE_LINK_DISABLE_AT_REST_ENCRYPTION", raising=False)
    # Initially absent.
    assert kc.get_passphrase() is None
    # Ensure mints + stores.
    pw1 = kc.ensure_passphrase()
    assert pw1 and len(pw1) >= 40
    # Subsequent ensure returns same value.
    pw2 = kc.ensure_passphrase()
    assert pw1 == pw2
    # Rotate yields a different value.
    pw3 = kc.rotate_passphrase()
    assert pw3 != pw1
    assert kc.get_passphrase() == pw3
    # Forget clears.
    assert kc.forget_passphrase() is True
    assert kc.get_passphrase() is None


def test_keychain_env_var_overrides(monkeypatch):
    monkeypatch.setenv(kc.ENV_VAR, "explicit-env-override-passphrase")
    monkeypatch.setattr(kc, "_load_keyring", lambda: None)
    assert kc.get_passphrase() == "explicit-env-override-passphrase"


def test_keychain_no_backend_no_env_returns_none(monkeypatch):
    """ensure_passphrase returns None ONLY when neither the OS keychain
    NOR the local key file can hold a key. (2026-06-16: with a working
    local key file the no-keyring path now mints a key there instead of
    returning None — see test_ensure_passphrase_falls_back_to_local_key
    _file. Here we block BOTH stores to exercise the true None path.)"""
    monkeypatch.delenv(kc.ENV_VAR, raising=False)
    monkeypatch.delenv("ONE_LINK_DISABLE_AT_REST_ENCRYPTION", raising=False)
    monkeypatch.setattr(kc, "_load_keyring", lambda: None)
    monkeypatch.setattr(kc, "_read_local_key", lambda: None)
    monkeypatch.setattr(kc, "_write_local_key", lambda pw: False)
    assert kc.ensure_passphrase() is None


# ── State() boots encrypted when key available ───────────────────


@pytest.mark.skipif(not se._have_sqlcipher(), reason="sqlcipher3 not installed")
def test_state_fresh_install_encrypts_from_scratch(
    tmp_path: Path, monkeypatch,
):
    monkeypatch.setenv(kc.ENV_VAR, "test-fresh-install-key")
    s = State(db_path=tmp_path / "fresh.db")
    assert s.is_encrypted is True
    # Use a distinctive plaintext that won't appear in random
    # ciphertext by chance (single ASCII bytes WOULD by birthday-
    # bound, so the assertion has to use a long, unlikely string).
    canary = "SQLCIPHER_PLAINTEXT_LEAK_CANARY_TOKEN_v0_21_x"
    s.set_setting("encryption_canary", canary)
    assert s.get_setting("encryption_canary") == canary
    s.close()
    raw = (tmp_path / "fresh.db").read_bytes()
    assert canary.encode() not in raw, (
        "encrypted state.db must not contain the canary token in "
        "plaintext on disk"
    )
    assert b"encryption_canary" not in raw, (
        "encrypted state.db must not contain the setting key in "
        "plaintext on disk"
    )


@pytest.mark.skipif(not se._have_sqlcipher(), reason="sqlcipher3 not installed")
def test_state_migration_on_first_open_with_passphrase(
    tmp_path: Path, monkeypatch,
):
    """Pre-existing plaintext DB gets migrated when a passphrase
    becomes available + State() is re-opened."""
    dbp = tmp_path / "mig.db"
    c = sqlite3.connect(str(dbp))
    c.execute("CREATE TABLE schema_version(version INTEGER)")
    c.execute("INSERT INTO schema_version VALUES(27)")
    c.execute("CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT)")
    c.execute(
        "INSERT INTO settings VALUES('marker', 'should survive migration')"
    )
    c.commit(); c.close()
    assert b"should survive migration" in dbp.read_bytes()
    monkeypatch.setenv(kc.ENV_VAR, "migration-test-passphrase")
    s = State(db_path=dbp)
    assert s.is_encrypted is True
    assert s.get_setting("marker") == "should survive migration"
    s.close()
    assert b"should survive migration" not in dbp.read_bytes()
    # The plaintext backup must be securely deleted after migration —
    # no plaintext copy may linger anywhere in the data dir.
    backup = dbp.with_suffix(".db.pre-encryption-backup")
    assert not backup.exists()
    for f in tmp_path.rglob("*"):
        if f.is_file():
            assert b"should survive migration" not in f.read_bytes(), (
                f"plaintext leaked into {f.name}"
            )


@pytest.mark.skipif(not se._have_sqlcipher(), reason="sqlcipher3 not installed")
def test_state_refuses_silent_fallback_on_wrong_key(
    tmp_path: Path, monkeypatch,
):
    """If state.db is encrypted but the current key is wrong, we
    MUST NOT silently fall back to plaintext sqlite3.connect —
    that would mask data corruption / let the daemon write to a
    different file than the one the user expects."""
    dbp = tmp_path / "locked.db"
    c = sqlite3.connect(str(dbp))
    c.execute("CREATE TABLE schema_version(version INTEGER)")
    c.execute("INSERT INTO schema_version VALUES(1)")
    c.commit(); c.close()
    se.migrate_plaintext_to_encrypted(dbp, "the-RIGHT-passphrase")
    monkeypatch.setenv(kc.ENV_VAR, "the-WRONG-passphrase")
    with pytest.raises(RuntimeError, match="can't decrypt"):
        State(db_path=dbp)


# ── hardening_checks module ──────────────────────────────────────


def test_cloud_sync_check_flags_onedrive_path():
    findings = hc.check_cloud_sync_colocation(
        Path("C:/Users/Bob/OneDrive/AppData/Local/Coherence/One_link"),
    )
    severities = {f.severity for f in findings}
    assert "warn" in severities
    msgs = " ".join(f.message for f in findings)
    assert "onedrive" in msgs.lower()


def test_cloud_sync_check_passes_normal_path():
    findings = hc.check_cloud_sync_colocation(
        Path("C:/Users/Alice/AppData/Local/Coherence/One_link"),
    )
    assert all(f.severity == "info" for f in findings)


def test_network_bind_loopback_is_info_with_recovery_hint():
    """Loopback-only is fine; the message should tell the user how
    to enable LAN pairing if they want it."""
    findings = hc.check_network_bind("127.0.0.1", lan_explicit=False)
    assert all(f.severity == "info" for f in findings)
    msg = " ".join(f.message for f in findings)
    assert "ONE_LINK_BIND_HOST" in msg


def test_network_bind_explicit_lan_is_info_with_recovery_hint():
    """Explicit 0.0.0.0 is auth-gated and explains loopback recovery."""
    findings = hc.check_network_bind("0.0.0.0", lan_explicit=True)
    assert all(f.severity == "info" for f in findings)
    msg = " ".join(f.message for f in findings)
    assert "127.0.0.1" in msg


def test_network_bind_custom_address_is_info():
    """A non-default custom bind is informational — operator chose
    it on purpose; surface but don't warn."""
    findings = hc.check_network_bind("192.168.1.50", lan_explicit=False)
    assert all(f.severity == "info" for f in findings)
    msg = " ".join(f.message for f in findings)
    assert "192.168.1.50" in msg


def test_encryption_active_is_info():
    findings = hc.check_at_rest_encryption(is_encrypted=True)
    assert all(f.severity == "info" for f in findings)


def test_encryption_inactive_is_warn():
    findings = hc.check_at_rest_encryption(is_encrypted=False)
    assert any(f.severity == "warn" for f in findings)


def test_run_all_checks_sorts_fails_first(tmp_path: Path):
    findings = hc.run_all_checks(
        data_dir=tmp_path,
        bind_host="0.0.0.0",
        lan_explicit=False,
        is_encrypted=False,
    )
    severities = [f.severity for f in findings]
    # Anything beyond the first warn must not be at higher severity
    # (i.e. no info before warn, no warn before fail).
    order = {"fail": 0, "warn": 1, "info": 2}
    for i in range(len(severities) - 1):
        assert order[severities[i]] <= order[severities[i + 1]], (
            f"findings not sorted by severity: {severities}"
        )


# ── /api/security/audit endpoint ─────────────────────────────────


@pytest_asyncio.fixture
async def audit_ctx(tmp_path: Path, monkeypatch):
    """Plain in-memory daemon (no encryption, no real keychain) so
    the endpoint test doesn't depend on the user's actual install."""
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    monkeypatch.delenv(kc.ENV_VAR, raising=False)
    monkeypatch.setattr(kc, "_load_keyring", lambda: None)
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = MagicMock()
    daemon.discovery.registry = MagicMock()
    daemon.discovery.registry.list = MagicMock(return_value=[])
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield {
            "client": client, "server": server,
            "token": server.token, "state": state,
        }
    finally:
        await client.close()
        state.close()


@pytest.mark.asyncio
async def test_security_audit_endpoint_returns_findings(audit_ctx):
    r = await audit_ctx["client"].get(
        "/api/security/audit",
        headers={"Authorization": f"Bearer {audit_ctx['token']}"},
    )
    assert r.status == 200
    body = await r.json()
    assert "findings" in body
    assert "summary" in body
    # Without sqlcipher + keychain (fixture wires both off), the
    # encryption check must surface a warn.
    msgs = [f["message"] for f in body["findings"]]
    assert any("encryption" in m.lower() for m in msgs)


# ── Settings → Privacy: preset cards + audit are present ─────────


def test_settings_privacy_pane_renders_preset_grid():
    """The 3 sovereignty preset cards must appear in Settings →
    Privacy (not just behind the lock icon)."""
    src = (
        Path(__file__).resolve().parents[1]
        / "src" / "one_link" / "web" / "index.html"
    ).read_text(encoding="utf-8")
    assert 'id="settings-privacy-preset-grid"' in src, (
        "Settings → Privacy pane must host the 3-card preset grid "
        "so users find it without hunting for the lock icon"
    )
    assert 'function refreshSettingsPrivacyPresets(' in src
    # Card click should POST to the sovereignty preset endpoint.
    idx = src.find("function refreshSettingsPrivacyPresets(")
    body = src[idx:idx + 4000]
    assert "/api/sovereignty/preset" in body
    assert "/api/sovereignty/status" in body


def test_settings_privacy_pane_renders_security_audit():
    """The live audit must show in Settings → Privacy so users see
    file permissions / cloud sync / encryption status at a glance."""
    src = (
        Path(__file__).resolve().parents[1]
        / "src" / "one_link" / "web" / "index.html"
    ).read_text(encoding="utf-8")
    assert 'id="settings-security-audit"' in src
    assert 'function refreshSettingsSecurityAudit(' in src
    idx = src.find("function refreshSettingsSecurityAudit(")
    body = src[idx:idx + 3000]
    assert "/api/security/audit" in body
    # Three severity classes need styling.
    assert "sev-info" in src
    assert "sev-warn" in src
    assert "sev-fail" in src


# ── local key-file fallback (2026-06-16 external-audit remediation) ──
# When the OS keychain is unavailable, the key must fall back to a 0600
# local key file so at-rest encryption STAYS ON — never silent plaintext.

def test_ensure_passphrase_falls_back_to_local_key_file(tmp_path, monkeypatch):
    """No env var + no usable OS keychain => mint a key into a 0600
    local key file (NOT return None / go plaintext)."""
    monkeypatch.delenv(kc.ENV_VAR, raising=False)
    monkeypatch.delenv(kc.DISABLE_ENV, raising=False)
    # Simulate "no OS keychain backend at all".
    monkeypatch.setattr(kc, "_load_keyring", lambda: None)
    # Point the local key file at the temp dir.
    keyfile = tmp_path / kc.LOCAL_KEY_FILENAME
    monkeypatch.setattr(kc, "_local_key_path", lambda: keyfile)

    pw = kc.ensure_passphrase()
    assert pw, "must mint a key, not fall to plaintext"
    assert keyfile.exists(), "key must be persisted to the local key file"
    assert keyfile.read_text(encoding="utf-8").strip() == pw
    # get_passphrase must read it back on the next boot.
    assert kc.get_passphrase() == pw
    # 0600 perms on POSIX (owner-only).
    if os.name != "nt":
        import stat as _stat
        mode = _stat.S_IMODE(keyfile.stat().st_mode)
        assert mode == 0o600, f"key file perms must be 0600, got {oct(mode)}"


@pytest.mark.skipif(not se._have_sqlcipher(), reason="sqlcipher3 not installed")
def test_state_db_encrypted_via_local_key_file_no_keyring(tmp_path, monkeypatch):
    """End-to-end: with NO OS keychain, State() still encrypts at rest
    using the local key file — the DB on disk must be opaque."""
    from one_link.state import State
    monkeypatch.delenv(kc.ENV_VAR, raising=False)
    monkeypatch.delenv(kc.DISABLE_ENV, raising=False)
    monkeypatch.delenv("ONE_LINK_ALLOW_PLAINTEXT", raising=False)
    monkeypatch.setattr(kc, "_load_keyring", lambda: None)
    monkeypatch.setattr(kc, "_local_key_path", lambda: tmp_path / kc.LOCAL_KEY_FILENAME)

    dbp = tmp_path / "ek.db"
    s = State(db_path=dbp)
    assert s.is_encrypted is True, "must encrypt via local key file, not plaintext"
    s.set_setting("secret_marker", "do-not-find-me-in-cleartext")
    s.close()
    # The DB file must be opaque (no plaintext marker).
    assert b"do-not-find-me-in-cleartext" not in dbp.read_bytes()


def test_plaintext_refused_without_optin(tmp_path, monkeypatch):
    """No key obtainable + no opt-in => State refuses to start plaintext."""
    from one_link.state import State
    monkeypatch.delenv(kc.ENV_VAR, raising=False)
    monkeypatch.delenv(kc.DISABLE_ENV, raising=False)
    monkeypatch.delenv("ONE_LINK_ALLOW_PLAINTEXT", raising=False)
    # No keychain AND local key file can't be written (force write fail).
    monkeypatch.setattr(kc, "_load_keyring", lambda: None)
    monkeypatch.setattr(kc, "_write_local_key", lambda pw: False)
    monkeypatch.setattr(kc, "_read_local_key", lambda: None)
    with pytest.raises(RuntimeError, match="UNENCRYPTED"):
        State(db_path=tmp_path / "refuse.db")


def test_plaintext_allowed_with_explicit_optin(tmp_path, monkeypatch):
    """ONE_LINK_ALLOW_PLAINTEXT=1 lets a no-key environment run plaintext
    (explicit operator consent, loudly logged)."""
    from one_link.state import State
    monkeypatch.delenv(kc.ENV_VAR, raising=False)
    monkeypatch.delenv(kc.DISABLE_ENV, raising=False)
    monkeypatch.setenv("ONE_LINK_ALLOW_PLAINTEXT", "1")
    monkeypatch.setattr(kc, "_load_keyring", lambda: None)
    monkeypatch.setattr(kc, "_write_local_key", lambda pw: False)
    monkeypatch.setattr(kc, "_read_local_key", lambda: None)
    s = State(db_path=tmp_path / "plain.db")
    assert s.is_encrypted is False
    s.close()
