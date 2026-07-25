from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from one_link import (
    cap_root_key,
    identity,
    keychain,
    lockbox,
    master_seed,
    mnemonic,
    paths,
    recovery_api,
)
from one_link import key_material as km


def _assert_preserved(path: Path, before: bytes) -> None:
    assert path.exists()
    assert path.read_bytes() == before


def test_master_seed_corruption_is_not_absence_or_replaced(tmp_path: Path) -> None:
    path = tmp_path / master_seed.SEED_FILENAME
    corrupt = b"existing-corrupt-master-seed"
    path.write_bytes(corrupt)

    with pytest.raises(km.KeyMaterialError):
        master_seed.load_or_create_seed(tmp_path)

    _assert_preserved(path, corrupt)


def test_master_seed_transient_read_failure_is_not_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed, _ = master_seed.load_or_create_seed(tmp_path)
    path = tmp_path / master_seed.SEED_FILENAME
    stored = path.read_bytes()
    real_open = km.os.open

    def fail_target_open(candidate, flags, *args, **kwargs):
        if Path(candidate) == path:
            raise PermissionError("injected transient read failure")
        return real_open(candidate, flags, *args, **kwargs)

    monkeypatch.setattr(km.os, "open", fail_target_open)
    with pytest.raises(km.KeyMaterialAccessError):
        master_seed.load_or_create_seed(tmp_path)
    _assert_preserved(path, stored)
    assert len(seed) == 32


def test_master_seed_transient_unprotect_failure_recovers_without_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed, _ = master_seed.load_or_create_seed(tmp_path)
    path = tmp_path / master_seed.SEED_FILENAME
    stored = path.read_bytes()
    if os.name != "nt":
        pytest.skip("DPAPI failure is Windows-specific")
    real_unprotect = lockbox._dpapi_unprotect
    monkeypatch.setattr(lockbox, "_dpapi_unprotect", lambda _blob: None)
    with pytest.raises(km.KeyMaterialProtectionError):
        master_seed.load_or_create_seed(tmp_path)
    _assert_preserved(path, stored)
    monkeypatch.setattr(lockbox, "_dpapi_unprotect", real_unprotect)
    loaded, created = master_seed.load_or_create_seed(tmp_path)
    assert created is False
    assert loaded == seed


def test_master_seed_dpapi_protect_failure_never_writes_raw(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.skip("DPAPI failure is Windows-specific")
    monkeypatch.setattr(lockbox, "_dpapi_protect", lambda _raw: None)
    with pytest.raises(km.KeyMaterialProtectionError):
        master_seed.load_or_create_seed(tmp_path)
    assert not (tmp_path / master_seed.SEED_FILENAME).exists()


def test_master_seed_failed_rotation_preserves_old_wrapped_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.skip("DPAPI failure is Windows-specific")
    old, _ = master_seed.load_or_create_seed(tmp_path)
    path = tmp_path / master_seed.SEED_FILENAME
    stored = path.read_bytes()
    monkeypatch.setattr(lockbox, "_dpapi_protect", lambda _raw: None)
    with pytest.raises(km.KeyMaterialProtectionError):
        master_seed.store_seed(tmp_path, os.urandom(32))
    _assert_preserved(path, stored)
    assert master_seed.load_seed(tmp_path) == old


def test_fsync_failure_returns_no_ephemeral_master_seed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(km.os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError("fault")))
    with pytest.raises(km.KeyMaterialPersistenceError):
        master_seed.load_or_create_seed(tmp_path)
    assert not (tmp_path / master_seed.SEED_FILENAME).exists()


def test_concurrent_master_seed_first_boot_converges(tmp_path: Path) -> None:
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _n: master_seed.load_or_create_seed(tmp_path), range(24)))
    assert sum(created for _seed, created in results) == 1
    assert len({seed for seed, _created in results}) == 1
    assert master_seed.load_seed(tmp_path) == results[0][0]


def test_corrupt_drk_is_preserved_and_never_reminted(tmp_path: Path) -> None:
    path = tmp_path / lockbox.DRK_FILENAME
    corrupt = b"existing-corrupt-drk"
    path.write_bytes(corrupt)
    with pytest.raises(km.KeyMaterialError):
        lockbox.acquire_or_create_silent_drk(tmp_path)
    _assert_preserved(path, corrupt)


def test_drk_dpapi_protect_failure_returns_no_ephemeral_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.skip("DPAPI failure is Windows-specific")
    monkeypatch.setattr(lockbox, "_dpapi_protect", lambda _raw: None)
    with pytest.raises(km.KeyMaterialProtectionError):
        lockbox.acquire_or_create_silent_drk(tmp_path)
    assert not (tmp_path / lockbox.DRK_FILENAME).exists()


def test_concurrent_drk_first_boot_converges(tmp_path: Path) -> None:
    with ThreadPoolExecutor(max_workers=12) as pool:
        values = list(
            pool.map(lambda _n: lockbox.acquire_or_create_silent_drk(tmp_path), range(24))
        )
    assert len(set(values)) == 1
    assert lockbox.acquire_or_create_silent_drk(tmp_path) == values[0]


def test_cap_root_corruption_is_preserved_and_never_reminted(tmp_path: Path) -> None:
    path = tmp_path / cap_root_key.CAP_ROOT_KEY_FILENAME
    corrupt = b"existing-corrupt-capability-root"
    path.write_bytes(corrupt)
    with pytest.raises(km.KeyMaterialError):
        cap_root_key.load_or_create_cap_root_key(tmp_path)
    _assert_preserved(path, corrupt)


def test_cap_root_dpapi_protect_failure_publishes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.skip("DPAPI failure is Windows-specific")
    monkeypatch.setattr(lockbox, "_dpapi_protect", lambda _raw: None)
    with pytest.raises(km.KeyMaterialProtectionError):
        cap_root_key.load_or_create_cap_root_key(tmp_path)
    assert not (tmp_path / cap_root_key.CAP_ROOT_KEY_FILENAME).exists()


def test_concurrent_cap_root_first_boot_converges(tmp_path: Path) -> None:
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(
            pool.map(lambda _n: cap_root_key.load_or_create_cap_root_key(tmp_path), range(24))
        )
    assert sum(created for _key, created in results) == 1
    assert len({key for key, _created in results}) == 1


def test_invalid_master_seed_cannot_generate_new_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    master_path = tmp_path / master_seed.SEED_FILENAME
    corrupt = b"invalid-existing-master"
    master_path.write_bytes(corrupt)
    identity_path = tmp_path / "identity.key"

    with pytest.raises(km.KeyMaterialError):
        identity.load_or_create(path=identity_path)

    _assert_preserved(master_path, corrupt)
    assert not identity_path.exists()


def test_concurrent_identity_first_boot_converges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    identity_path = tmp_path / "identity.key"
    with ThreadPoolExecutor(max_workers=12) as pool:
        identities = list(
            pool.map(
                lambda _n: identity.load_or_create(path=identity_path),
                range(24),
            )
        )
    assert len({item.public_bytes for item in identities}) == 1
    assert identity.load_or_create(path=identity_path).public_bytes == identities[0].public_bytes


def test_identity_encryption_migration_failure_preserves_only_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    identity_path = tmp_path / "identity.key"
    original = identity.load_or_create(path=identity_path)
    before = identity_path.read_bytes()
    real_replace = km.os.replace

    def fail_identity_replace(source, target):
        if Path(target) == identity_path:
            raise OSError("injected replace failure")
        return real_replace(source, target)

    monkeypatch.setattr(km.os, "replace", fail_identity_replace)
    with pytest.raises(km.KeyMaterialPersistenceError):
        identity.load_or_create(path=identity_path, passphrase=b"migration-secret")
    _assert_preserved(identity_path, before)
    assert identity.load_or_create(path=identity_path).public_bytes == original.public_bytes


def test_identity_encryption_migration_fsync_failure_preserves_only_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    identity_path = tmp_path / "identity.key"
    original = identity.load_or_create(path=identity_path)
    before = identity_path.read_bytes()
    monkeypatch.setattr(
        km.os,
        "fsync",
        lambda _fd: (_ for _ in ()).throw(OSError("injected fsync failure")),
    )
    with pytest.raises(km.KeyMaterialPersistenceError):
        identity.load_or_create(path=identity_path, passphrase=b"migration-secret")
    _assert_preserved(identity_path, before)
    assert original.public_bytes


def test_identity_acl_failure_never_returns_or_publishes_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.skip("strict DACL publication is Windows-specific")
    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    identity_path = tmp_path / "identity.key"

    def fail_acl(_path: Path) -> None:
        raise km.KeyMaterialProtectionError("injected ACL failure")

    monkeypatch.setattr(identity, "_restrict_windows_acl", fail_acl)
    with pytest.raises(km.KeyMaterialProtectionError):
        identity.load_or_create(path=identity_path)
    assert not identity_path.exists()


def test_windows_acl_round_trip_is_verified(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("Windows DACL verification is platform-specific")
    path = tmp_path / "secret.bin"
    path.write_bytes(b"secret")
    identity._restrict_windows_acl(path)
    # The helper's success contract includes a Win32 read-back of protected
    # state, exact ACE count/mask, and current-user SID equality.
    identity._restrict_windows_acl(path)


def test_empty_existing_local_sqlcipher_key_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / keychain.LOCAL_KEY_FILENAME
    path.write_bytes(b"")
    monkeypatch.delenv(keychain.ENV_VAR, raising=False)
    monkeypatch.delenv(keychain.DISABLE_ENV, raising=False)
    monkeypatch.setattr(keychain, "_load_keyring", lambda: None)
    monkeypatch.setattr(keychain, "_local_key_path", lambda: path)
    with pytest.raises(km.KeyMaterialIntegrityError):
        keychain.ensure_passphrase()
    _assert_preserved(path, b"")


def test_recovery_reports_existing_unavailable_seed_distinct_from_absence(
    tmp_path: Path,
) -> None:
    (tmp_path / master_seed.SEED_FILENAME).write_bytes(b"corrupt-existing-seed")
    phrase = mnemonic.encode(os.urandom(32))
    result = recovery_api.test_phrase_against_current_seed(
        data_dir=tmp_path,
        phrase=phrase,
    )
    assert result["valid_checksum"] is True
    assert result["has_current_identity"] is True
    assert result["matches_current_identity"] is False
    assert result["error"] == "current_master_seed_unavailable"


def test_recovery_persistence_failure_retires_no_derived_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.skip("DPAPI failure is Windows-specific")
    master_seed.load_or_create_seed(tmp_path)
    master_path = tmp_path / master_seed.SEED_FILENAME
    identity_path = tmp_path / "identity.key"
    drk_path = tmp_path / lockbox.DRK_FILENAME
    identity_path.write_bytes(b"existing-identity-authority")
    drk_path.write_bytes(b"existing-drk-authority")
    originals = {
        master_path: master_path.read_bytes(),
        identity_path: identity_path.read_bytes(),
        drk_path: drk_path.read_bytes(),
    }
    monkeypatch.setattr(paths, "key_path", lambda: identity_path)
    monkeypatch.setattr(lockbox, "_dpapi_protect", lambda _raw: None)
    with pytest.raises(km.KeyMaterialProtectionError):
        recovery_api.restore_seed_from_phrase(
            data_dir=tmp_path,
            phrase=mnemonic.encode(os.urandom(32)),
            delete_identity_files=True,
        )
    for path, before in originals.items():
        _assert_preserved(path, before)


def test_keyring_lookup_error_never_creates_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class BrokenKeyring:
        @staticmethod
        def get_password(_service, _user):
            raise OSError("transient backend outage")

    path = tmp_path / keychain.LOCAL_KEY_FILENAME
    monkeypatch.delenv(keychain.ENV_VAR, raising=False)
    monkeypatch.delenv(keychain.DISABLE_ENV, raising=False)
    monkeypatch.setattr(keychain, "_load_keyring", lambda: BrokenKeyring)
    monkeypatch.setattr(keychain, "_local_key_path", lambda: path)
    with pytest.raises(keychain.KeychainBackendError):
        keychain.ensure_passphrase()
    assert not path.exists()


def test_keyring_ambiguous_write_read_failure_never_creates_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class AmbiguousKeyring:
        reads = 0

        @classmethod
        def get_password(cls, _service, _user):
            cls.reads += 1
            if cls.reads <= 2:
                return None
            raise OSError("read failed after ambiguous write")

        @staticmethod
        def set_password(_service, _user, _pw):
            raise OSError("backend may have committed")

    path = tmp_path / keychain.LOCAL_KEY_FILENAME
    monkeypatch.delenv(keychain.ENV_VAR, raising=False)
    monkeypatch.delenv(keychain.DISABLE_ENV, raising=False)
    monkeypatch.setattr(keychain, "_load_keyring", lambda: AmbiguousKeyring)
    monkeypatch.setattr(keychain, "_local_key_path", lambda: path)
    with pytest.raises(keychain.KeychainBackendError):
        keychain.ensure_passphrase()
    assert not path.exists()


def test_keyring_commit_then_error_returns_only_read_back_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class CommitThenErrorKeyring:
        stored = None

        @classmethod
        def get_password(cls, _service, _user):
            return cls.stored

        @classmethod
        def set_password(cls, _service, _user, pw):
            cls.stored = pw
            raise OSError("reported failure after commit")

    path = tmp_path / keychain.LOCAL_KEY_FILENAME
    monkeypatch.delenv(keychain.ENV_VAR, raising=False)
    monkeypatch.delenv(keychain.DISABLE_ENV, raising=False)
    monkeypatch.setattr(keychain, "_load_keyring", lambda: CommitThenErrorKeyring)
    monkeypatch.setattr(keychain, "_local_key_path", lambda: path)
    returned = keychain.ensure_passphrase()
    assert returned == CommitThenErrorKeyring.stored
    assert returned is not None
    assert not path.exists()


def test_local_key_fsync_failure_returns_no_ephemeral_passphrase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / keychain.LOCAL_KEY_FILENAME
    monkeypatch.delenv(keychain.ENV_VAR, raising=False)
    monkeypatch.delenv(keychain.DISABLE_ENV, raising=False)
    monkeypatch.setattr(keychain, "_load_keyring", lambda: None)
    monkeypatch.setattr(keychain, "_local_key_path", lambda: path)
    real_fsync = km.os.fsync

    def fail_key_fsync(fd: int) -> None:
        # The provision-lock fsync happens first.  Fail only a secret temp.
        try:
            opened = Path(os.readlink(f"/proc/self/fd/{fd}"))
        except OSError:
            opened = Path("")
        if "state.key.tmp" in opened.name:
            raise OSError("injected key fsync failure")
        real_fsync(fd)

    if os.name == "nt":
        # Windows has no /proc descriptor names; count the non-lock flush.
        calls = 0

        def fail_second_fsync(fd: int) -> None:
            nonlocal calls
            calls += 1
            if calls >= 2:
                raise OSError("injected key fsync failure")
            real_fsync(fd)

        monkeypatch.setattr(km.os, "fsync", fail_second_fsync)
    else:
        monkeypatch.setattr(km.os, "fsync", fail_key_fsync)
    assert keychain.ensure_passphrase() is None
    assert not path.exists()


def test_concurrent_local_key_first_boot_converges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / keychain.LOCAL_KEY_FILENAME
    monkeypatch.delenv(keychain.ENV_VAR, raising=False)
    monkeypatch.delenv(keychain.DISABLE_ENV, raising=False)
    monkeypatch.setattr(keychain, "_load_keyring", lambda: None)
    monkeypatch.setattr(keychain, "_local_key_path", lambda: path)
    with ThreadPoolExecutor(max_workers=12) as pool:
        values = list(pool.map(lambda _n: keychain.ensure_passphrase(), range(24)))
    assert None not in values
    assert len(set(values)) == 1
    assert keychain.get_passphrase() == values[0]
