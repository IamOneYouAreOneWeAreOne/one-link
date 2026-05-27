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
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

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


@pytest.mark.skipif(not se._have_sqlcipher(), reason="sqlcipher3 not installed")
def test_detect_encrypted_via_migration(tmp_path: Path):
    p = tmp_path / "x.db"
    c = sqlite3.connect(str(p))
    c.execute("CREATE TABLE schema_version(version INTEGER)")
    c.execute("INSERT INTO schema_version VALUES(1)")
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
def test_migration_writes_backup_with_plaintext(tmp_path: Path):
    p = tmp_path / "s.db"
    c = sqlite3.connect(str(p))
    c.execute("CREATE TABLE schema_version(version INTEGER)")
    c.execute("INSERT INTO schema_version VALUES(1)")
    c.execute("CREATE TABLE t(body TEXT)")
    c.execute("INSERT INTO t VALUES('plaintext lives in backup')")
    c.commit(); c.close()
    backup = se.migrate_plaintext_to_encrypted(p, "test-pass")
    assert backup.exists()
    assert backup.name.endswith(".pre-encryption-backup")
    assert b"plaintext lives in backup" in backup.read_bytes()
    # The live file must NOT contain the plaintext.
    assert b"plaintext lives in backup" not in p.read_bytes()


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
    monkeypatch.delenv(kc.ENV_VAR, raising=False)
    monkeypatch.setattr(kc, "_load_keyring", lambda: None)
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
    # Backup must exist with the original plaintext.
    backup = dbp.with_suffix(".db.pre-encryption-backup")
    assert backup.exists()
    assert b"should survive migration" in backup.read_bytes()


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


def test_network_bind_loopback_is_ok():
    findings = hc.check_network_bind("127.0.0.1", lan_explicit=False)
    assert all(f.severity == "info" for f in findings)


def test_network_bind_lan_explicit_is_ok():
    findings = hc.check_network_bind("0.0.0.0", lan_explicit=True)
    assert all(f.severity == "info" for f in findings)


def test_network_bind_lan_without_flag_warns():
    findings = hc.check_network_bind("0.0.0.0", lan_explicit=False)
    assert any(f.severity == "warn" for f in findings)


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
