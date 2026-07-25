"""Adversarial durability contracts for multi-control settings saves."""

from __future__ import annotations

from pathlib import Path

import pytest

from one_link.state import State


def test_settings_batch_rolls_back_every_row_on_mid_batch_failure(
    tmp_path: Path,
) -> None:
    state = State(db_path=tmp_path / "state.db")
    try:
        state.set_setting("alpha", "old")
        state._conn.execute(
            "CREATE TRIGGER reject_test_setting "
            "BEFORE INSERT ON settings "
            "WHEN NEW.key = 'zz_forced_failure' "
            "BEGIN SELECT RAISE(ABORT, 'forced settings failure'); END"
        )

        with pytest.raises(Exception, match="forced settings failure"):
            state.apply_settings_batch(
                upserts={
                    "alpha": "new",
                    "zz_forced_failure": "never-committed",
                }
            )

        assert state.get_setting("alpha") == "old"
        assert state.get_setting("zz_forced_failure") is None
        assert state._conn.in_transaction is False
    finally:
        state.close()


def test_settings_batch_rejects_delete_upsert_overlap_without_writes(
    tmp_path: Path,
) -> None:
    state = State(db_path=tmp_path / "state.db")
    try:
        state.set_setting("theme", "dark")
        with pytest.raises(ValueError, match="same key"):
            state.apply_settings_batch(
                upserts={"theme": "light"},
                deletes={"theme"},
            )
        assert state.get_setting("theme") == "dark"
    finally:
        state.close()


def test_settings_batch_commits_upserts_and_deletes_together(tmp_path: Path) -> None:
    state = State(db_path=tmp_path / "state.db")
    try:
        state.set_setting("obsolete", "yes")
        state.apply_settings_batch(
            upserts={"theme": "light", "dnd_enabled": "true"},
            deletes={"obsolete"},
        )
        assert state.get_setting("theme") == "light"
        assert state.get_setting("dnd_enabled") == "true"
        assert state.get_setting("obsolete") is None
    finally:
        state.close()
