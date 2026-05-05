"""Encrypted-on-disk identity (PASSPHRASE_ENV)."""

from __future__ import annotations

from pathlib import Path

import pytest

from one_link.identity import PASSPHRASE_ENV, load_or_create


def test_unencrypted_create_then_load(tmp_path: Path, monkeypatch):
    monkeypatch.delenv(PASSPHRASE_ENV, raising=False)
    key = tmp_path / "id.key"
    a = load_or_create(key)
    b = load_or_create(key)
    assert a.fingerprint == b.fingerprint
    # On-disk format is unencrypted PEM
    raw = key.read_text()
    assert "BEGIN PRIVATE KEY" in raw  # unencrypted PKCS8


def test_encrypted_create_then_load_with_passphrase(tmp_path: Path, monkeypatch):
    key = tmp_path / "id.key"
    monkeypatch.setenv(PASSPHRASE_ENV, "correct horse battery staple")
    a = load_or_create(key)
    b = load_or_create(key)
    assert a.fingerprint == b.fingerprint
    raw = key.read_text()
    assert "ENCRYPTED PRIVATE KEY" in raw


def test_encrypted_load_with_wrong_passphrase_raises(tmp_path: Path, monkeypatch):
    key = tmp_path / "id.key"
    monkeypatch.setenv(PASSPHRASE_ENV, "secret-1")
    load_or_create(key)
    monkeypatch.setenv(PASSPHRASE_ENV, "secret-2-WRONG")
    with pytest.raises(RuntimeError, match="encrypted"):
        load_or_create(key)


def test_encrypted_load_with_no_passphrase_raises(tmp_path: Path, monkeypatch):
    key = tmp_path / "id.key"
    monkeypatch.setenv(PASSPHRASE_ENV, "secret")
    load_or_create(key)
    monkeypatch.delenv(PASSPHRASE_ENV, raising=False)
    with pytest.raises(RuntimeError, match="encrypted"):
        load_or_create(key)


def test_transparent_migration_unencrypted_to_encrypted(tmp_path: Path, monkeypatch):
    """If the file is unencrypted but PASSPHRASE_ENV is set on next launch,
    re-save the file encrypted."""
    key = tmp_path / "id.key"
    # Phase 1: create unencrypted
    monkeypatch.delenv(PASSPHRASE_ENV, raising=False)
    a = load_or_create(key)
    assert "BEGIN PRIVATE KEY" in key.read_text()

    # Phase 2: set passphrase, load again — file should be re-saved encrypted
    monkeypatch.setenv(PASSPHRASE_ENV, "new-passphrase")
    b = load_or_create(key)
    assert b.fingerprint == a.fingerprint
    assert "ENCRYPTED PRIVATE KEY" in key.read_text()


def test_explicit_passphrase_arg_overrides_env(tmp_path: Path, monkeypatch):
    key = tmp_path / "id.key"
    monkeypatch.setenv(PASSPHRASE_ENV, "env-pass")
    a = load_or_create(key, passphrase="explicit-pass")
    # Env passphrase should NOT decrypt; explicit one must.
    monkeypatch.setenv(PASSPHRASE_ENV, "env-pass")  # still set
    with pytest.raises(RuntimeError):
        load_or_create(key)  # uses env passphrase, fails
    b = load_or_create(key, passphrase="explicit-pass")
    assert a.fingerprint == b.fingerprint
