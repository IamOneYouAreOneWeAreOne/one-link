from __future__ import annotations

import os


def _fast_scrypt(monkeypatch) -> None:
    from one_link import lockbox

    # Format v1 fixes the real production parameters.  Tests reduce the work
    # factor only inside this process so migration/recovery semantics stay fast.
    monkeypatch.setattr(lockbox, "SCRYPT_N", 1 << 10)


def test_legacy_passphrase_rows_survive_atomic_envelope_migration(
    tmp_path, monkeypatch
) -> None:
    from one_link import lockbox, master_seed

    _fast_scrypt(monkeypatch)
    passphrase = "correct horse battery staple"
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, passphrase)
    seed = os.urandom(32)
    master_seed.store_seed(tmp_path, seed)

    salt = lockbox.load_or_create_salt(tmp_path)
    legacy = lockbox.LockBox.from_passphrase(passphrase.encode(), salt)
    wrapped_before_upgrade = legacy.wrap(b"existing application secret")

    migrated = lockbox.acquire_lockbox(tmp_path)
    assert migrated.unwrap(wrapped_before_upgrade) == b"existing application secret"
    assert (tmp_path / lockbox.DEK_ENVELOPE_FILENAME).is_file()
    assert lockbox.recovery_envelope_matches_seed(tmp_path, seed) is True

    # Paper-seed recovery is now sufficient even when the environment-specific
    # passphrase is absent on the replacement machine/process.
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV)
    recovered = lockbox.acquire_lockbox(tmp_path)
    assert recovered.unwrap(wrapped_before_upgrade) == b"existing application secret"


def test_explicit_env_compatibility_entry_cannot_bypass_recovery_envelope(
    tmp_path, monkeypatch,
) -> None:
    from one_link import lockbox, master_seed

    _fast_scrypt(monkeypatch)
    seed = os.urandom(32)
    master_seed.store_seed(tmp_path, seed)
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "explicit compatibility path")
    explicit = lockbox.lockbox_from_env(tmp_path)
    assert explicit is not None
    wrapped = explicit.wrap(b"must remain seed recoverable")
    assert (tmp_path / lockbox.DEK_ENVELOPE_FILENAME).is_file()

    monkeypatch.delenv(lockbox.PASSPHRASE_ENV)
    assert lockbox.acquire_lockbox(tmp_path).unwrap(wrapped) == (
        b"must remain seed recoverable"
    )


def test_envelope_seed_rebind_preserves_dek_without_source_passphrase(
    tmp_path, monkeypatch
) -> None:
    from one_link import lockbox, master_seed

    _fast_scrypt(monkeypatch)
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "source-only passphrase")
    source_seed = os.urandom(32)
    target_seed = os.urandom(32)
    master_seed.store_seed(tmp_path, source_seed)
    wrapped = lockbox.acquire_lockbox(tmp_path).wrap(b"survives seed rotation")

    monkeypatch.delenv(lockbox.PASSPHRASE_ENV)
    assert lockbox.rebind_recovery_envelope(
        tmp_path,
        target_seed=target_seed,
        current_seed=source_seed,
    )
    master_seed.store_seed(tmp_path, target_seed)

    assert lockbox.recovery_envelope_matches_seed(tmp_path, source_seed) is False
    assert lockbox.recovery_envelope_matches_seed(tmp_path, target_seed) is True
    assert lockbox.acquire_lockbox(tmp_path).unwrap(wrapped) == b"survives seed rotation"


def test_envelope_is_in_authenticated_backup_and_recovers_application_rows(
    tmp_path, monkeypatch
) -> None:
    from one_link import backup_bundle, lockbox, master_seed

    _fast_scrypt(monkeypatch)
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    seed = os.urandom(32)
    master_seed.store_seed(source, seed)
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "portable app secret")
    wrapped = lockbox.acquire_lockbox(source).wrap(b"portable application row")

    bundle = backup_bundle.create_bundle(seed=seed, data_dir=source)
    _header, plaintext = backup_bundle.open_bundle(seed=seed, bundle_bytes=bundle)
    members = backup_bundle.inspect_bundle_archive(plaintext=plaintext)
    assert lockbox.DEK_ENVELOPE_FILENAME in members
    assert lockbox.SALT_FILENAME in members
    backup_bundle.extract_bundle_to_dir(
        plaintext=plaintext,
        target_dir=target,
        overwrite=True,
    )

    # The transaction overwrites any machine-bound seed representation with
    # the phrase-derived target authority before LockBox acquisition.
    master_seed.store_seed(target, seed)
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV)
    assert lockbox.acquire_lockbox(target).unwrap(wrapped) == b"portable application row"


def test_tampered_envelope_never_falls_back_to_a_random_or_silent_key(
    tmp_path, monkeypatch
) -> None:
    import pytest

    from one_link import lockbox, master_seed
    from one_link.key_material import KeyMaterialProtectionError

    _fast_scrypt(monkeypatch)
    seed = os.urandom(32)
    master_seed.store_seed(tmp_path, seed)
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "tamper test passphrase")
    lockbox.acquire_lockbox(tmp_path)
    path = tmp_path / lockbox.DEK_ENVELOPE_FILENAME
    payload = bytearray(path.read_bytes())
    payload[-1] ^= 0x80
    path.write_bytes(payload)
    monkeypatch.delenv(lockbox.PASSPHRASE_ENV)

    assert lockbox.recovery_envelope_matches_seed(tmp_path, seed) is False
    with pytest.raises(KeyMaterialProtectionError):
        lockbox.acquire_lockbox(tmp_path)


def test_phrase_preflight_truthfully_requires_unmigrated_legacy_passphrase(
    tmp_path, monkeypatch
) -> None:
    from one_link import lockbox, master_seed, mnemonic, paths, recovery_api

    _fast_scrypt(monkeypatch)
    identity_path = tmp_path / "identity.key"
    monkeypatch.setattr(paths, "key_path", lambda: identity_path)
    seed = os.urandom(32)
    master_seed.install_seed_derived_authority(
        tmp_path,
        identity_path=identity_path,
        seed=seed,
    )
    monkeypatch.setenv(lockbox.PASSPHRASE_ENV, "legacy direct scrypt")
    lockbox.load_or_create_salt(tmp_path)

    before = recovery_api.test_phrase_against_current_seed(
        data_dir=tmp_path,
        phrase=mnemonic.encode(seed),
    )
    assert before["matches_current_seed"] is True
    assert before["matches_current_authority"] is False
    assert before["requires_lockbox_passphrase"] is True
    assert before["additional_recovery_factors"] == ["ONE_LINK_PASSPHRASE"]
    assert before["error"] == "lockbox_passphrase_recovery_not_migrated"

    lockbox.acquire_lockbox(tmp_path)
    after = recovery_api.test_phrase_against_current_seed(
        data_dir=tmp_path,
        phrase=mnemonic.encode(seed),
    )
    assert after["matches_current_authority"] is True
    assert after["requires_lockbox_passphrase"] is False
    assert after["additional_recovery_factors"] == []


def test_backup_refuses_unmigrated_passphrase_state_without_source_factor(
    tmp_path, monkeypatch
) -> None:
    import pytest

    from one_link import backup_bundle, lockbox, master_seed
    from one_link.key_material import KeyMaterialProtectionError

    _fast_scrypt(monkeypatch)
    seed = os.urandom(32)
    master_seed.store_seed(tmp_path, seed)
    lockbox.load_or_create_salt(tmp_path)

    with pytest.raises(KeyMaterialProtectionError, match="source ONE_LINK_PASSPHRASE"):
        backup_bundle.create_bundle(seed=seed, data_dir=tmp_path)
    assert not (tmp_path / lockbox.DEK_ENVELOPE_FILENAME).exists()
