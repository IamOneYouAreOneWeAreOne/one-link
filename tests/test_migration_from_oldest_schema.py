"""A database created by the OLDEST shipped schema must migrate without loss.

The migration ladder is 30 steps, v1 -> v30. What existed before this file:
test_state_migration_atomicity_v0207.py, which proves each step is atomic and
that re-opening an already-migrated database is a no-op. Both are properties of
the MECHANISM. Neither says anything about the DATA.

So the ladder had never been run end to end against a populated v1 database.
Every step was individually atomic, and nobody had checked that a message
written by the first release is still readable by the current one.

That is the single worst failure this product can have. A user's chat history,
their folder manifests and their peer trust decisions are not reproducible from
anywhere else. A sync bug loses a file that still exists on the other machine;
a migration bug loses the only copy.

The test builds a v1 database from the real SCHEMA_V1 constant, fills every v1
table with recognisable values, opens it with the current State class, and
requires each value back -- through the public API wherever one exists, because
data that survives in SQLite but is unreachable through the application has
been lost from the user's point of view.
"""

from __future__ import annotations

import sqlite3

import pytest

from one_link import state as state_mod
from one_link.state import SCHEMA_V1
from one_link.state_encryption import STATE_SCHEMA_VERSION_CURRENT


# Values chosen to be unmistakable in a failure message, and to include the
# things that break naively-written migrations: unicode, an emoji outside the
# BMP, an embedded quote, and a long body.
PEER_FP = "a" * 64
PEER2_FP = "b" * 64
MESSAGE_BODY = "hello from v1 — o'brien's \"quoted\" 🛰️ payload"
LONG_BODY = "x" * 8000
FOLDER = "shared-docs"


def _make_v1_database(path) -> None:
    """A database exactly as the first release would have left it."""
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA_V1)
    conn.execute("INSERT INTO schema_version(version) VALUES(1)")

    conn.execute(
        "INSERT INTO peers(fingerprint, short_id, pubkey, hostname, "
        "last_address, last_port, trust, first_seen_ms, last_seen_ms) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (PEER_FP, "SHORT1", b"\x01\x02pub", "alpha.local",
         "192.168.1.20", 45123, "verified", 1_600_000_000_000, 1_600_000_100_000),
    )
    conn.execute(
        "INSERT INTO peers(fingerprint, short_id, pubkey, hostname, "
        "last_address, last_port, trust, first_seen_ms, last_seen_ms) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (PEER2_FP, "SHORT2", b"\x03\x04pub", "beta.local",
         "192.168.1.21", 45124, "blocked", 1_600_000_000_000, 1_600_000_200_000),
    )
    for index, body in enumerate((MESSAGE_BODY, LONG_BODY), start=1):
        conn.execute(
            "INSERT INTO messages(id, ts_ms, direction, peer_fp, msg_type, "
            "body, room_id, metadata_json) VALUES(?,?,?,?,?,?,?,?)",
            (f"msg-v1-{index}", 1_600_000_000_000 + index, "in", PEER_FP,
             "text", body, None, '{"origin":"v1"}'),
        )
    conn.execute(
        "INSERT INTO folders(name, local_path, shared_with_json, created_ms) "
        "VALUES(?,?,?,?)",
        (FOLDER, "/home/user/docs", f'["{PEER_FP}"]', 1_600_000_000_000),
    )
    conn.execute(
        "INSERT INTO folder_manifest(folder_name, file_path, blob_hash, size, "
        "mtime_ms, vclock_json, updated_ms) VALUES(?,?,?,?,?,?,?)",
        (FOLDER, "notes/plan.md", "c" * 64, 4096,
         1_600_000_000_000, '{"a":1}', 1_600_000_000_000),
    )
    conn.execute(
        "INSERT INTO settings(key, value) VALUES(?,?)",
        ("display_name", "Ada from v1"),
    )
    conn.execute(
        "INSERT INTO blobs(hash, size, received_ms) VALUES(?,?,?)",
        ("c" * 64, 4096, 1_600_000_000_000),
    )
    conn.execute(
        "INSERT INTO transfers(id, direction, peer_fp, kind, name, size, "
        "blob_hash, status, progress_bytes, total_bytes, chunks_done, "
        "chunks_total, raw_bytes, wire_bytes, updated_ms, metadata_json) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("xfer-v1-1", "out", PEER_FP, "file", "plan.md", 4096, "c" * 64,
         "complete", 4096, 4096, 4, 4, 4096, 4400, 1_600_000_000_000, "{}"),
    )
    conn.execute(
        "INSERT INTO groups(group_id, name, created_ms, state_hash, updated_ms) "
        "VALUES(?,?,?,?,?)",
        ("grp-v1", "Team from v1", 1_600_000_000_000, "d" * 64, 1_600_000_000_000),
    )
    conn.execute(
        "INSERT INTO group_messages(group_id, sender_pub, epoch, counter, "
        "direction, body, ts_ms) VALUES(?,?,?,?,?,?,?)",
        ("grp-v1", "senderpub", 0, 1, "in", "group hello from v1",
         1_600_000_000_000),
    )
    conn.execute(
        "INSERT INTO outbox(id, peer_fp, msg_id, msg_kind, msg_body_json, "
        "enqueued_ms, attempts, last_attempt_ms, last_error, delivered_ms) "
        "VALUES(?,?,?,?,?,?,?,?,?,?)",
        # id is INTEGER PRIMARY KEY (a rowid alias), so it must be an int --
        # SQLite's dynamic typing does not apply to that one column.
        (1, PEER_FP, "msg-v1-1", "text", '{"body":"queued in v1"}',
         1_600_000_000_000, 0, None, None, None),
    )
    conn.execute(
        "INSERT INTO capability_audit(ts_ms, fingerprint, kind, before_json, "
        "after_json, actor, note) VALUES(?,?,?,?,?,?,?)",
        (1_600_000_000_000, PEER_FP, "grant", "{}", '{"files":true}',
         "user", "granted in v1"),
    )
    conn.commit()
    conn.close()


@pytest.fixture
def migrated(tmp_path):
    """A v1 database, opened once by the current State so it migrates."""
    db_path = tmp_path / "state.db"
    _make_v1_database(db_path)

    before = sqlite3.connect(db_path)
    start_version = before.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
    before.close()
    assert start_version == 1, f"fixture did not build a v1 database ({start_version})"

    state = state_mod.State(db_path=db_path)
    yield state, db_path
    try:
        state._conn.close()
    except Exception:
        pass


def test_the_ladder_actually_ran(migrated) -> None:
    """CONTROL, and the most important assertion in the file.

    Every "the data survived" check below would also pass against a database
    that was never migrated at all. This is what proves the other tests are
    measuring a migration rather than an untouched v1 file.
    """
    state, _ = migrated
    final = state._conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
    assert final == STATE_SCHEMA_VERSION_CURRENT, (
        f"migration stopped at v{final}, expected v{STATE_SCHEMA_VERSION_CURRENT}"
    )
    assert final >= 30, "the ladder is shorter than the 30 steps this test covers"


def test_a_v1_message_is_still_readable(migrated) -> None:
    """Chat history is the data with no other copy."""
    state, _ = migrated
    rows = state._conn.execute(
        "SELECT id, body, peer_fp, metadata_json FROM messages ORDER BY ts_ms"
    ).fetchall()
    bodies = [r[1] for r in rows]
    assert MESSAGE_BODY in bodies, f"the v1 message body was lost: {bodies!r}"
    assert LONG_BODY in bodies, "the long v1 message body was lost or truncated"
    assert rows[0][2] == PEER_FP, "the message lost its peer association"
    assert rows[0][3] == '{"origin":"v1"}', "message metadata was dropped"


def test_unicode_and_quoting_survive_thirty_migrations(migrated) -> None:
    """Naive migrations that rebuild a table via string-formatted SQL lose these.

    The body carries an apostrophe, embedded double quotes, an em dash and an
    astral-plane emoji. Any step that round-trips content through hand-built
    SQL or a narrower text encoding damages at least one of them.
    """
    state, _ = migrated
    body = state._conn.execute(
        "SELECT body FROM messages WHERE id = 'msg-v1-1'"
    ).fetchone()[0]
    assert body == MESSAGE_BODY, f"content was altered in transit: {body!r}"


def test_peer_trust_decisions_survive(migrated) -> None:
    """Trust is a decision a human made. Losing it silently re-trusts a peer.

    The blocked peer matters more than the verified one: a lost `verified`
    prompts the user again, a lost `blocked` lets someone back in.
    """
    state, _ = migrated
    trust = dict(
        state._conn.execute("SELECT fingerprint, trust FROM peers").fetchall()
    )
    assert trust.get(PEER_FP) == "verified", "a verified peer lost its trust mark"
    assert trust.get(PEER2_FP) == "blocked", "a BLOCKED peer lost its block"


def test_settings_survive_through_the_public_api(migrated) -> None:
    """Read back through get_setting, not raw SQL.

    A row that exists in the file but that the application cannot reach has
    been lost from the user's point of view, and raw SQL would not notice.
    """
    state, _ = migrated
    assert state.get_setting("display_name") == "Ada from v1"


@pytest.mark.parametrize(
    "table,where,label",
    [
        ("folders", "name = 'shared-docs'", "a shared folder"),
        ("folder_manifest", "file_path = 'notes/plan.md'", "a folder manifest entry"),
        ("blobs", f"hash = '{'c' * 64}'", "a stored blob record"),
        ("transfers", "id = 'xfer-v1-1'", "a completed transfer"),
        ("groups", "group_id = 'grp-v1'", "a group"),
        ("group_messages", "group_id = 'grp-v1'", "a group message"),
        ("outbox", "id = 1", "an undelivered queued message"),
        ("capability_audit", "fingerprint = ?", "a capability audit record"),
    ],
)
def test_every_populated_v1_table_still_holds_its_row(
    migrated, table: str, where: str, label: str
) -> None:
    state, _ = migrated
    params = (PEER_FP,) if "?" in where else ()
    count = state._conn.execute(
        f"SELECT COUNT(*) FROM {table} WHERE {where}", params
    ).fetchone()[0]
    assert count == 1, f"{label} did not survive migration ({table}: {count} rows)"


def test_full_text_search_still_finds_a_v1_message(migrated) -> None:
    """The FTS index is DERIVED, so it can be silently left behind.

    A migration that rebuilds `messages` without repopulating `messages_fts`
    leaves every row present and every search broken -- history that exists but
    cannot be found, which a row-count check would call a pass.
    """
    state, _ = migrated
    hits = state._conn.execute(
        "SELECT rowid FROM messages_fts WHERE messages_fts MATCH 'payload'"
    ).fetchall()
    assert hits, "a v1 message is no longer discoverable by full-text search"


def test_reopening_the_migrated_database_changes_nothing(migrated) -> None:
    """The second boot after an upgrade must be a no-op.

    A step that is not guarded on the version stamp would re-run here and could
    rewrite or truncate the data the first boot preserved.
    """
    state, db_path = migrated
    first = state._conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
    body_before = state._conn.execute(
        "SELECT body FROM messages WHERE id = 'msg-v1-1'"
    ).fetchone()[0]
    state._conn.close()

    reopened = state_mod.State(db_path=db_path)
    try:
        second = reopened._conn.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()[0]
        body_after = reopened._conn.execute(
            "SELECT body FROM messages WHERE id = 'msg-v1-1'"
        ).fetchone()[0]
        duplicate_stamps = reopened._conn.execute(
            "SELECT version, COUNT(*) c FROM schema_version "
            "GROUP BY version HAVING c > 1"
        ).fetchall()
    finally:
        reopened._conn.close()

    assert first == second, f"the version moved on reopen: {first} -> {second}"
    assert body_after == body_before, "reopening altered existing message content"
    assert not duplicate_stamps, f"duplicate version stamps: {duplicate_stamps}"


def test_the_migrated_database_accepts_new_writes(migrated) -> None:
    """Surviving the ladder is not enough; the result has to be usable.

    A migration can leave a schema that reads fine and rejects every insert --
    a missing NOT NULL default, a constraint added without a backfill. Nothing
    above would catch it, because everything above only reads.
    """
    state, _ = migrated
    state.set_setting("written_after_migration", "yes")
    assert state.get_setting("written_after_migration") == "yes"
    assert state.get_setting("display_name") == "Ada from v1", (
        "writing after migration disturbed pre-existing data"
    )
