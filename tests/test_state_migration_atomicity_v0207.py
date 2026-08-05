"""v0.20.7 (audit H20) — schema migrations are atomic per step.

Pre-v0.20.7 each ``_migrate_vN_*`` ran in autocommit, so a SIGKILL
between an ALTER TABLE and the version-stamp INSERT could leave the
DB with the new column AND a stale version stamp. The next boot
either errored on ``ALTER TABLE ADD COLUMN`` (duplicate column) or
silently mis-stamped to a higher version while skipping the
backfill.

These tests pin two atomicity properties:

  1. **Idempotent re-run**: running ``State()`` against an existing,
     fully-migrated database is a no-op (no duplicate stamps, no
     ALTER errors).

  2. **All-or-nothing per step**: if a migration step raises mid-
     apply, the version stamp is NOT advanced — so the next boot
     re-runs the same step instead of skipping it.

  3. **Crash-replay safety on freshly-created DBs**: a freshly-
     created v16 schema, fully stamped, opens cleanly twice in a row.
"""
from __future__ import annotations

import sqlite3

import pytest

from one_link import state as state_mod


def test_idempotent_reopen(tmp_path):
    db_path = tmp_path / "state.db"
    s1 = state_mod.State(db_path=db_path)
    first_version = s1._conn.execute("PRAGMA user_version").fetchone()[0]
    s1.set_setting("survives", "yes")
    s1._conn.close()

    # Second open against the already-migrated db must succeed.
    s2 = state_mod.State(db_path=db_path)
    second_version = s2._conn.execute("PRAGMA user_version").fetchone()[0]
    carried = s2.get_setting("survives")
    s2._conn.close()

    # And a third for good measure.
    s3 = state_mod.State(db_path=db_path)
    third_version = s3._conn.execute("PRAGMA user_version").fetchone()[0]
    s3._conn.close()

    # Reopening must not RE-MIGRATE. A migration that ran again would not
    # raise -- it would quietly rewrite or drop tables -- so "opened without an
    # exception" is exactly the wrong thing to assert here.
    assert first_version == second_version == third_version, (
        f"schema version moved on reopen: {first_version} -> {second_version} "
        f"-> {third_version}"
    )
    assert carried == "yes", "reopening the migrated db lost existing rows"


def test_schema_version_unique_after_migration(tmp_path):
    """Each successful step should leave exactly one row at the
    target version. Re-opens shouldn't add duplicates."""
    db_path = tmp_path / "state.db"
    s = state_mod.State(db_path=db_path)
    rows_before = s._conn.execute(
        "SELECT version, COUNT(*) FROM schema_version GROUP BY version"
    ).fetchall()
    s._conn.close()
    s2 = state_mod.State(db_path=db_path)
    rows_after = s2._conn.execute(
        "SELECT version, COUNT(*) FROM schema_version GROUP BY version"
    ).fetchall()
    s2._conn.close()
    assert rows_before == rows_after, (
        "re-opening migrated DB should not change version-stamp counts"
    )


def test_failing_migration_does_not_advance_stamp(tmp_path, monkeypatch):
    """If a migration step raises mid-apply the BEGIN IMMEDIATE / ROLLBACK
    contract guarantees the schema_version stamp does NOT advance.
    The next boot will retry the same migration."""
    db_path = tmp_path / "state.db"
    # First boot: fully migrate to current head.
    s = state_mod.State(db_path=db_path)
    head_version = s._conn.execute(
        "SELECT MAX(version) FROM schema_version"
    ).fetchone()[0]
    s._conn.close()

    # Synthetically roll back schema_version to head-1 so the next
    # boot sees a single pending step. Then patch that step to raise.
    conn = sqlite3.connect(str(db_path), isolation_level=None)
    conn.execute(
        "DELETE FROM schema_version WHERE version=?", (head_version,)
    )
    conn.close()

    # Patch the head migration to raise. The pre-fix behavior would
    # leave any DDL applied + no stamp — a half state. The fixed
    # behavior rolls back the entire transaction. We resolve the head
    # method by walking the State class for the matching prefix so the
    # test stays accurate as new migrations land.
    head_attr = next(
        n for n in dir(state_mod.State)
        if n.startswith(f"_migrate_v{head_version}_")
    )
    original = getattr(state_mod.State, head_attr)
    boom = RuntimeError("synthetic boom")

    def _raise(self, c):
        raise boom

    monkeypatch.setattr(state_mod.State, head_attr, _raise)

    with pytest.raises(RuntimeError, match="synthetic boom"):
        state_mod.State(db_path=db_path)

    # Verify: the stamp is NOT at head_version (rollback worked).
    conn = sqlite3.connect(str(db_path), isolation_level=None)
    max_v = conn.execute(
        "SELECT MAX(version) FROM schema_version"
    ).fetchone()[0]
    conn.close()
    assert max_v == head_version - 1, (
        f"failed migration must not advance stamp; got {max_v}, "
        f"expected {head_version - 1}"
    )

    # Restore + re-boot: the migration retries and now succeeds.
    monkeypatch.setattr(state_mod.State, head_attr, original)
    s2 = state_mod.State(db_path=db_path)
    final_v = s2._conn.execute(
        "SELECT MAX(version) FROM schema_version"
    ).fetchone()[0]
    s2._conn.close()
    assert final_v == head_version


def test_no_active_transaction_after_migrate(tmp_path):
    """The migration helper must commit/rollback every transaction it
    opens. After construction the connection should be back in
    autocommit (in_transaction == False) so callers don't accidentally
    inherit a half-open tx from boot."""
    db_path = tmp_path / "state.db"
    s = state_mod.State(db_path=db_path)
    assert s._conn.in_transaction is False
    s._conn.close()
