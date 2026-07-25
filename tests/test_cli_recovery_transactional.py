from __future__ import annotations

import os

from click.testing import CliRunner


def _isolate_paths(monkeypatch, root):
    from one_link import paths

    identity_path = root / "identity.key"
    monkeypatch.setattr(paths, "data_dir", lambda: root)
    monkeypatch.setattr(paths, "key_path", lambda: identity_path)
    return identity_path


def _bundle_with_state(root, *, seed: bytes, state_bytes: bytes):
    from one_link import backup_bundle, master_seed

    source = root / "bundle-source"
    source.mkdir()
    master_seed.store_seed(source, seed)
    (source / "state.db").write_bytes(state_bytes)
    payload = backup_bundle.create_bundle(seed=seed, data_dir=source)
    path = root / "backup.olbak"
    path.write_bytes(payload)
    return path


def test_forced_phrase_restore_never_predeletes_live_authority(
    tmp_path, monkeypatch
) -> None:
    from one_link import master_seed, mnemonic, recovery_api
    from one_link.cli import cli

    identity_path = _isolate_paths(monkeypatch, tmp_path)
    old_seed = os.urandom(32)
    new_seed = os.urandom(32)
    master_seed.install_seed_derived_authority(
        tmp_path,
        identity_path=identity_path,
        seed=old_seed,
    )
    seed_before = (tmp_path / master_seed.SEED_FILENAME).read_bytes()
    identity_before = identity_path.read_bytes()
    drk_before = (tmp_path / "data-root-key.bin").read_bytes()

    result = CliRunner().invoke(
        cli,
        ["backup", "restore", *mnemonic.encode(new_seed).split(), "--force"],
    )
    assert result.exit_code == 0, result.output
    assert "staged durably" in result.output
    assert (tmp_path / master_seed.SEED_FILENAME).read_bytes() == seed_before
    assert identity_path.read_bytes() == identity_before
    assert (tmp_path / "data-root-key.bin").read_bytes() == drk_before
    assert recovery_api.has_pending_recovery(tmp_path)

    recovery_api.complete_pending_recovery(
        data_dir=tmp_path,
        identity_path=identity_path,
    )
    assert master_seed.load_seed(tmp_path) == new_seed
    assert master_seed.inspect_derived_authority(
        tmp_path,
        identity_path=identity_path,
        seed=new_seed,
    ) == {"identity": True, "data_root": True}


def test_forced_backup_init_preserves_legacy_keys_until_replay(
    tmp_path, monkeypatch
) -> None:
    from one_link import identity, lockbox, master_seed, recovery_api
    from one_link.cli import cli

    identity_path = _isolate_paths(monkeypatch, tmp_path)
    identity.load_or_create(identity_path)
    lockbox.acquire_or_create_silent_drk(tmp_path)
    identity_before = identity_path.read_bytes()
    drk_before = (tmp_path / lockbox.DRK_FILENAME).read_bytes()

    result = CliRunner().invoke(cli, ["backup", "init", "--force"])
    assert result.exit_code == 0, result.output
    assert "Existing keys were not" in result.output
    assert identity_path.read_bytes() == identity_before
    assert (tmp_path / lockbox.DRK_FILENAME).read_bytes() == drk_before
    assert not (tmp_path / master_seed.SEED_FILENAME).exists()
    assert recovery_api.has_pending_recovery(tmp_path)

    recovery_api.complete_pending_recovery(
        data_dir=tmp_path,
        identity_path=identity_path,
    )
    recovered = master_seed.load_seed(tmp_path)
    assert recovered is not None
    assert master_seed.inspect_derived_authority(
        tmp_path,
        identity_path=identity_path,
        seed=recovered,
    ) == {"identity": True, "data_root": True}


def test_live_backup_import_stages_without_replacing_open_state(
    tmp_path, monkeypatch
) -> None:
    from one_link import master_seed, recovery_api
    from one_link.cli import cli

    home = tmp_path / "active"
    identity_path = _isolate_paths(monkeypatch, home)
    seed = os.urandom(32)
    master_seed.install_seed_derived_authority(
        home,
        identity_path=identity_path,
        seed=seed,
    )
    state_path = home / "state.db"
    state_path.write_bytes(b"live-open-state")
    bundle_path = _bundle_with_state(
        tmp_path,
        seed=seed,
        state_bytes=b"restored-state",
    )
    identity_before = identity_path.read_bytes()
    drk_before = (home / "data-root-key.bin").read_bytes()

    result = CliRunner().invoke(
        cli,
        ["backup", "import", str(bundle_path), "--overwrite"],
    )
    assert result.exit_code == 0, result.output
    assert "staged" in result.output
    assert state_path.read_bytes() == b"live-open-state"
    assert identity_path.read_bytes() == identity_before
    assert (home / "data-root-key.bin").read_bytes() == drk_before
    assert recovery_api.has_pending_recovery(home)

    recovery_api.complete_pending_recovery(
        data_dir=home,
        identity_path=identity_path,
    )
    assert state_path.read_bytes() == b"restored-state"


def test_corrupt_live_backup_import_writes_no_intent_or_authority(
    tmp_path, monkeypatch
) -> None:
    from one_link import master_seed, recovery_api
    from one_link.cli import cli

    home = tmp_path / "active"
    identity_path = _isolate_paths(monkeypatch, home)
    seed = os.urandom(32)
    master_seed.install_seed_derived_authority(
        home,
        identity_path=identity_path,
        seed=seed,
    )
    state_path = home / "state.db"
    state_path.write_bytes(b"live-state")
    corrupt = tmp_path / "corrupt.olbak"
    corrupt.write_bytes(b"not a backup")
    identity_before = identity_path.read_bytes()

    result = CliRunner().invoke(
        cli,
        ["backup", "import", str(corrupt), "--overwrite"],
    )
    assert result.exit_code != 0
    assert state_path.read_bytes() == b"live-state"
    assert identity_path.read_bytes() == identity_before
    assert recovery_api.has_pending_recovery(home) is False


def test_custom_backup_import_requires_and_uses_clean_offline_target(
    tmp_path, monkeypatch
) -> None:
    from one_link import master_seed
    from one_link.cli import cli

    home = tmp_path / "active"
    active_identity = _isolate_paths(monkeypatch, home)
    seed = os.urandom(32)
    master_seed.install_seed_derived_authority(
        home,
        identity_path=active_identity,
        seed=seed,
    )
    bundle_path = _bundle_with_state(
        tmp_path,
        seed=seed,
        state_bytes=b"offline-restored-state",
    )
    active_identity_before = active_identity.read_bytes()
    target = tmp_path / "offline-target"

    result = CliRunner().invoke(
        cli,
        ["backup", "import", str(bundle_path), "--target-dir", str(target)],
    )
    assert result.exit_code == 0, result.output
    assert "restored and verified" in result.output
    assert (target / "state.db").read_bytes() == b"offline-restored-state"
    assert master_seed.load_seed(target) == seed
    assert (target / "identity.key").is_file()
    assert active_identity.read_bytes() == active_identity_before

    dirty = tmp_path / "dirty-target"
    dirty.mkdir()
    marker = dirty / "keep.txt"
    marker.write_text("preserve me")
    rejected = CliRunner().invoke(
        cli,
        ["backup", "import", str(bundle_path), "--target-dir", str(dirty)],
    )
    assert rejected.exit_code != 0
    assert "not empty" in rejected.output
    assert marker.read_text() == "preserve me"


def test_live_backup_import_fails_fast_when_recovery_lock_is_owned(
    tmp_path, monkeypatch
) -> None:
    from one_link import master_seed, recovery_api
    from one_link.cli import cli

    home = tmp_path / "active"
    identity_path = _isolate_paths(monkeypatch, home)
    seed = os.urandom(32)
    master_seed.install_seed_derived_authority(
        home,
        identity_path=identity_path,
        seed=seed,
    )
    (home / "state.db").write_bytes(b"live-state")
    bundle_path = _bundle_with_state(
        tmp_path,
        seed=seed,
        state_bytes=b"other-state",
    )

    with recovery_api._recovery_transaction_lock(home):
        result = CliRunner().invoke(
            cli,
            ["backup", "import", str(bundle_path), "--overwrite"],
        )
    assert result.exit_code != 0
    assert "already in progress" in result.output
    assert (home / "state.db").read_bytes() == b"live-state"
    assert recovery_api.has_pending_recovery(home) is False
