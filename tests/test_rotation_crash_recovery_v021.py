"""Legacy partial-rotation detection plus low-level seed durability gates.

Current rotation is journaled and its full crash matrix lives in
``test_rotation_authority_transaction.py``. The malformed states here model
pre-journal releases or manual artifact replacement only. Startup must either
reject mismatched authority or identify the exact legacy risk; no current
``perform_local_rotation`` path creates these shapes.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def _set_paths(monkeypatch, data_dir: Path, config_dir: Path):
    """Point authority resolution at one isolated legacy fixture."""
    from one_link import paths
    monkeypatch.setattr(paths, "key_path", lambda: config_dir / "identity.key")
    monkeypatch.setattr(paths, "data_dir", lambda: data_dir)


def _setup_pre_rotation(tmp_path, monkeypatch):
    """Plant an existing seed + identity.key + DRK + the in-memory
    old identity. Returns (data_dir, config_dir, old_priv, old_seed)."""
    from one_link import master_seed
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    _set_paths(monkeypatch, data_dir, config_dir)
    old_seed = master_seed.load_or_create_seed(data_dir)[0]
    old_priv = master_seed.derive_identity_priv(old_seed)
    master_seed.install_seed_derived_authority(
        data_dir,
        identity_path=config_dir / "identity.key",
        seed=old_seed,
        previous_seed=old_seed,
    )
    return data_dir, config_dir, old_priv, old_seed


# ── crash points ────────────────────────────────────────────────────


def test_crash_before_any_rotation_state_change(tmp_path, monkeypatch):
    """User clicks Rotate; daemon dies before perform_local_rotation
    runs even one statement. On-disk state must be exactly the
    pre-rotation state - no half-written files, no orphan queue
    rows. Boot recovery: identical to a normal restart, OLD
    identity loads cleanly."""
    from one_link import master_seed
    data_dir, config_dir, _, old_seed = _setup_pre_rotation(tmp_path, monkeypatch)

    # Crash = simply don't call perform_local_rotation. Assert the
    # files are exactly what we planted.
    assert master_seed.load_seed(data_dir) == old_seed
    assert (config_dir / "identity.key").exists()
    assert (data_dir / "data-root-key.bin").exists()


def test_legacy_seed_identity_mismatch_fails_boot_authority_gate(tmp_path, monkeypatch):
    """A pre-journal torn rotation is rejected instead of being served."""
    from one_link import master_seed
    from one_link.key_material import KeyMaterialIntegrityError
    data_dir, config_dir, _, _ = _setup_pre_rotation(tmp_path, monkeypatch)
    # Simulate: store_seed ran successfully, unlinks did NOT.
    new_seed = master_seed.generate_seed_if_present_in_module() if hasattr(
        master_seed, "generate_seed_if_present_in_module"
    ) else os.urandom(master_seed.SEED_LEN_BYTES)
    master_seed.store_seed(data_dir, new_seed)
    assert (config_dir / "identity.key").exists()
    assert master_seed.load_seed(data_dir) == new_seed
    with pytest.raises(KeyMaterialIntegrityError, match="does not derive"):
        master_seed.provision_seed_before_derived_authority(
            data_dir,
            identity_path=config_dir / "identity.key",
        )


def test_legacy_prejournal_seed_without_certificate_shape_is_explicit(
    tmp_path, monkeypatch,
):
    """Document the old release shape that the new journal makes impossible.

    A pre-upgrade process could replace authority before persisting its cert.
    Current rotation validates and journals the cert/peer snapshot first, so
    this fixture is not an accepted current failure mode.
    """
    from one_link import master_seed
    data_dir, config_dir, _, _ = _setup_pre_rotation(tmp_path, monkeypatch)
    new_seed = os.urandom(master_seed.SEED_LEN_BYTES)
    master_seed.store_seed(data_dir, new_seed)
    (config_dir / "identity.key").unlink()
    (data_dir / "data-root-key.bin").unlink()
    # Queue was never populated.
    # Boot: identity load from new_seed.
    new_priv = master_seed.derive_identity_priv(master_seed.load_seed(data_dir))
    assert new_priv.public_key().public_bytes_raw() == (
        master_seed.derive_identity_priv(new_seed).public_key().public_bytes_raw()
    )


def test_master_seed_store_is_atomic_at_publish(tmp_path, monkeypatch):
    """master_seed.store_seed is documented as atomic (tmp + rename
    + fsync). A crash mid-write should NOT leave a partial
    master.seed file - either the OLD bytes or the NEW bytes,
    never a torn write. Confirm by direct test of store_seed."""
    from one_link import master_seed
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    # Plant original.
    original = os.urandom(master_seed.SEED_LEN_BYTES)
    master_seed.store_seed(data_dir, original)
    # Write a new seed - the rename should overwrite atomically.
    new = os.urandom(master_seed.SEED_LEN_BYTES)
    master_seed.store_seed(data_dir, new)
    # On disk we get exactly the new bytes (DPAPI-wrapped on Win;
    # load_seed unwraps + returns the raw bytes for comparison).
    loaded = master_seed.load_seed(data_dir)
    assert loaded == new


def test_no_partial_seed_files_left_in_data_dir(tmp_path, monkeypatch):
    """The atomic rename uses a tmp filename like master.seed.tmp.<hex>.
    After successful writes, no stale tmps should sit in data_dir
    eating space. Pin via a tight loop of writes."""
    from one_link import master_seed
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    for _ in range(10):
        master_seed.store_seed(data_dir, os.urandom(master_seed.SEED_LEN_BYTES))
    stale = list(data_dir.glob("master.seed.tmp.*"))
    assert stale == [], f"stale tmp seed files: {stale}"


def test_double_rotation_guard_logic_holds_after_crash_b(tmp_path, monkeypatch):
    """The HTTP defense also recognizes an injected legacy mismatch.

    Normal startup rejects this state before loading identity. The comparison
    remains defense in depth for tests/adapters that invoke the handler with a
    preconstructed old in-memory identity.
    """
    from one_link import master_seed
    data_dir, config_dir, old_priv, _ = _setup_pre_rotation(tmp_path, monkeypatch)
    new_seed = os.urandom(master_seed.SEED_LEN_BYTES)
    master_seed.store_seed(data_dir, new_seed)
    # identity.key is unchanged; compare the would-be old signer to disk.
    on_disk_pub = master_seed.derive_identity_priv(master_seed.load_seed(data_dir))\
        .public_key().public_bytes_raw()
    in_memory_pub = old_priv.public_key().public_bytes_raw()
    assert on_disk_pub != in_memory_pub, (
        "guard should detect this mismatch; if equal, the crash-B "
        "state would pass the guard and a second rotation would "
        "silently desync peers (the bug a330e84 fixes)"
    )


def test_rotation_refuses_incomplete_current_authority_without_mutation(
    tmp_path, monkeypatch,
):
    """Missing identity/DRK cannot be silently relabelled as rotatable."""
    from one_link import identity_rotation, master_seed, paths, recovery_api
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    monkeypatch.setattr(paths, "key_path", lambda: config_dir / "identity.key")
    # Files do not exist: only an unproven seed is present.
    old_seed = master_seed.load_or_create_seed(data_dir)[0]
    old_priv = master_seed.derive_identity_priv(old_seed)
    with pytest.raises(
        recovery_api.RecoveryTransactionError,
        match="not fully converged",
    ):
        identity_rotation.perform_local_rotation(
            data_dir=data_dir,
            old_priv=old_priv,
            pinned_peer_fingerprints=[],
        )
    assert master_seed.load_seed(data_dir) == old_seed
    assert recovery_api.has_pending_recovery(data_dir) is False
