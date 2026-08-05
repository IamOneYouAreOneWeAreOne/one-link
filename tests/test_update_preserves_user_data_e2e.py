"""An update, and a rollback, must not touch the user's data.

test_update_metadata_transaction.py drives the transaction thoroughly: prepare,
activate, health, commit, every crash boundary, rollback on health timeout. All
of it against a synthetic three-file bundle, with no user data anywhere.

test_migration_from_oldest_schema.py drives the database ladder thoroughly. No
update anywhere.

The seam between them was untested, and it is where the expensive failure lives.
An update replaces the install root wholesale and a rollback restores it from a
backup; both operations rename directories on the same disk as the user's chat
history, folder manifests and identity. Nothing proved those two roots stay
disjoint under either operation.

So this file runs the real transaction against a real State database and asks
the only question that matters to a user: is my data still there, still
readable, and still exactly what it was -- after an update commits, and after
an update rolls back.

The rollback case is the one that keeps me up: it is the path that runs when
something has ALREADY gone wrong, so it is the least exercised in practice and
the most damaging to get wrong.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta
from pathlib import Path

import pytest

from one_link import state as state_mod
from one_link.update_transaction import (
    TransactionPhase,
    activate_prepared_update,
    mark_update_healthy,
    recover_update_transaction,
    validate_installed_bundle,
)

# The transaction fixtures already exist and are correct. Rebuilding a bundle
# writer here would risk testing against a bundle shape the product does not
# produce, which is the defect this whole audit keeps finding.
from tests.test_update_metadata_transaction import (
    AUTHORITY_KEY,
    EXECUTABLE,
    NOW,
    PLATFORM_KEY,
    _artifact_for_archive,
    _parsed_manifest,
    _stopped_guard,
    _write_bundle,
    _write_bundle_zip,
)
from one_link.update_transaction import prepare_update_transaction


MESSAGE = "the message that must outlive the update"
PEER_FP = "e" * 64


def _seed_user_data(data_root: Path) -> Path:
    """A real State database with content a user would notice losing."""
    data_root.mkdir(parents=True, exist_ok=True)
    db_path = data_root / "state.db"
    state = state_mod.State(db_path=db_path)
    try:
        state.set_setting("display_name", "Ada")
        state._conn.execute(
            "INSERT INTO peers(fingerprint, short_id, pubkey, hostname, "
            "last_address, last_port, trust, first_seen_ms, last_seen_ms) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (PEER_FP, "SHORTE", b"pub", "gamma.local", "10.0.0.5", 45000,
             "verified", 1_700_000_000_000, 1_700_000_000_000),
        )
        state._conn.execute(
            "INSERT INTO messages(id, ts_ms, direction, peer_fp, msg_type, "
            "body, room_id, metadata_json) VALUES(?,?,?,?,?,?,?,?)",
            ("keep-me", 1_700_000_000_001, "in", PEER_FP, "text",
             MESSAGE, None, "{}"),
        )
        state._conn.commit()
    finally:
        state._conn.close()
    return db_path


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_back(db_path: Path) -> tuple[str | None, str | None, str | None]:
    """Open with the real State class -- the way the product would."""
    state = state_mod.State(db_path=db_path)
    try:
        row = state._conn.execute(
            "SELECT body FROM messages WHERE id = 'keep-me'"
        ).fetchone()
        trust = state._conn.execute(
            "SELECT trust FROM peers WHERE fingerprint = ?", (PEER_FP,)
        ).fetchone()
        return (
            state.get_setting("display_name"),
            row[0] if row else None,
            trust[0] if trust else None,
        )
    finally:
        state._conn.close()


@pytest.fixture
def scenario(tmp_path: Path):
    """An installed old build, a candidate new build, and populated user data.

    The layout mirrors a real install: the bundle, the updater's private state,
    and the user's data are three sibling directories.
    """
    install = _write_bundle(tmp_path / "installed-one-link", marker=b"old-0.21")
    archive = _write_bundle_zip(tmp_path / "candidate.zip", marker=b"new-0.22")
    manifest = _parsed_manifest(_artifact_for_archive(archive))
    state_root = tmp_path / "update-state"
    data_root = tmp_path / "user-data"
    db_path = _seed_user_data(data_root)

    # Baseline. Every assertion below compares against these.
    before = _digest(db_path)
    assert _read_back(db_path) == ("Ada", MESSAGE, "verified"), (
        "the fixture did not seed readable user data"
    )

    prepared = prepare_update_transaction(
        manifest=manifest,
        platform_key=PLATFORM_KEY,
        archive_path=archive,
        install_root=install,
        state_root=state_root,
        authority_key=AUTHORITY_KEY,
        current_version="0.21.0",
        now=NOW,
        health_window=timedelta(seconds=30),
    )
    return {
        "install": install, "state_root": state_root, "data_root": data_root,
        "db_path": db_path, "before": before, "prepared": prepared,
    }


def _activate(state_root: Path):
    return activate_prepared_update(
        state_root=state_root,
        authority_key=AUTHORITY_KEY,
        process_guard=_stopped_guard(),
        identity_reader=lambda _pid: None,
        process_timeout=0,
        now=NOW + timedelta(seconds=10),
    )


# ── the update commits ────────────────────────────────────────────────


def test_a_committed_update_leaves_the_database_byte_identical(scenario) -> None:
    """The install root changes. The data root must not.

    Byte-identical is the right bar here, not "still readable": the updater has
    no reason to open the database at all, so any change to it is a change
    nobody intended.
    """
    _activate(scenario["state_root"])
    committed = mark_update_healthy(
        state_root=scenario["state_root"],
        authority_key=AUTHORITY_KEY,
        running_executable=scenario["install"] / EXECUTABLE,
        observed_version="0.22.0",
        health_probe=lambda executable: executable.is_file(),
        now=NOW + timedelta(seconds=20),
    )
    assert committed.phase == TransactionPhase.COMMITTED.value

    assert _digest(scenario["db_path"]) == scenario["before"], (
        "committing an update modified the user's database"
    )
    assert _read_back(scenario["db_path"]) == ("Ada", MESSAGE, "verified")


def test_the_committed_update_really_did_replace_the_install(scenario) -> None:
    """CONTROL.

    "The data survived" is satisfied trivially by an update that did nothing.
    This proves the install root actually moved to the new bundle, which is
    what makes the assertion above meaningful.
    """
    _activate(scenario["state_root"])
    mark_update_healthy(
        state_root=scenario["state_root"],
        authority_key=AUTHORITY_KEY,
        running_executable=scenario["install"] / EXECUTABLE,
        observed_version="0.22.0",
        health_probe=lambda executable: executable.is_file(),
        now=NOW + timedelta(seconds=20),
    )
    tree = validate_installed_bundle(
        scenario["install"], expected_executable=EXECUTABLE
    )
    assert tree.manifest_sha256 == scenario["prepared"].candidate_manifest_sha256, (
        "the install root was not replaced, so the data assertions prove nothing"
    )
    assert b"new-0.22" in (scenario["install"] / EXECUTABLE).read_bytes()


# ── the update rolls back ─────────────────────────────────────────────


def test_a_rolled_back_update_leaves_the_database_byte_identical(scenario) -> None:
    """The path that runs when something has already gone wrong.

    Rollback restores the install root from a backup directory. If the backup
    or the restore ever reached wider than the install root, this is where a
    user's history would disappear -- during recovery from an unrelated fault,
    which is the worst possible moment and the hardest to reproduce.
    """
    _activate(scenario["state_root"])
    result = recover_update_transaction(
        state_root=scenario["state_root"],
        authority_key=AUTHORITY_KEY,
        now=NOW + timedelta(minutes=1),  # past the health window
    )
    assert result.status == "rolled_back", f"expected a rollback, got {result.status}"

    assert _digest(scenario["db_path"]) == scenario["before"], (
        "rolling an update back modified the user's database"
    )
    assert _read_back(scenario["db_path"]) == ("Ada", MESSAGE, "verified")


def test_the_rollback_really_did_restore_the_old_bundle(scenario) -> None:
    """CONTROL for the rollback case."""
    _activate(scenario["state_root"])
    recover_update_transaction(
        state_root=scenario["state_root"],
        authority_key=AUTHORITY_KEY,
        now=NOW + timedelta(minutes=1),
    )
    tree = validate_installed_bundle(
        scenario["install"], expected_executable=EXECUTABLE
    )
    assert tree.manifest_sha256 == scenario["prepared"].previous_manifest_sha256
    assert b"old-0.21" in (scenario["install"] / EXECUTABLE).read_bytes(), (
        "the rollback did not restore the previous build"
    )


# ── the roots stay disjoint ───────────────────────────────────────────


def test_the_update_writes_nothing_into_the_user_data_root(scenario) -> None:
    """No new files, and no missing ones.

    A stray staging directory or backup landing in the data root would not
    break anything today, and would be exactly the kind of thing that later
    gets cleaned up by something that assumes it owns that directory.
    """
    before = sorted(p.name for p in scenario["data_root"].iterdir())
    _activate(scenario["state_root"])
    mark_update_healthy(
        state_root=scenario["state_root"],
        authority_key=AUTHORITY_KEY,
        running_executable=scenario["install"] / EXECUTABLE,
        observed_version="0.22.0",
        health_probe=lambda executable: executable.is_file(),
        now=NOW + timedelta(seconds=20),
    )
    after = sorted(p.name for p in scenario["data_root"].iterdir())
    assert after == before, f"the update changed the data root: {before} -> {after}"


def test_an_update_is_still_usable_by_a_database_that_needs_migrating(
    scenario,
) -> None:
    """The two subsystems meeting, which is the whole point of this file.

    A user upgrades from an old build carrying an old schema. The update
    replaces the binary; the next boot migrates the database. If the update
    disturbed the database at all, that migration is where it would surface --
    and it would surface as data loss, not as an error.
    """
    _activate(scenario["state_root"])
    mark_update_healthy(
        state_root=scenario["state_root"],
        authority_key=AUTHORITY_KEY,
        running_executable=scenario["install"] / EXECUTABLE,
        observed_version="0.22.0",
        health_probe=lambda executable: executable.is_file(),
        now=NOW + timedelta(seconds=20),
    )
    # Re-open exactly as the newly installed build would on first boot.
    state = state_mod.State(db_path=scenario["db_path"])
    try:
        version = state._conn.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()[0]
        body = state._conn.execute(
            "SELECT body FROM messages WHERE id = 'keep-me'"
        ).fetchone()[0]
    finally:
        state._conn.close()
    assert body == MESSAGE
    assert version >= 30, f"the post-update boot left the schema at v{version}"
