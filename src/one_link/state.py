"""Persistent state layer.

A single sqlite database under ONE_LINK_HOME/data/state.db backs:

- peers (fingerprint, trust state, last seen)
- messages (full chat history with FTS5 full-text search)
- rooms (multi-party named conversations)
- folders (designated sync folders)
- folder_manifest (CRDT — file_path → blob_hash with vector clocks)
- blobs (content-addressed blob index)

Concurrency model: a single shared `sqlite3.Connection` with
`check_same_thread=False` and `journal_mode=WAL`, guarded by a re-entrant
threading lock for writes. Reads can race; writes serialize.

Schema migrations are versioned in a `schema_version` table; applying one
migration at a time is idempotent.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from one_link.paths import data_dir

DB_FILE = "state.db"

SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS peers (
    fingerprint   TEXT    PRIMARY KEY,   -- BLAKE3 hex of pubkey
    short_id      TEXT    NOT NULL,
    pubkey        BLOB    NOT NULL,
    hostname      TEXT,
    last_address  TEXT,
    last_port     INTEGER,
    trust         TEXT    NOT NULL,      -- 'pinned' | 'pending' | 'rejected'
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id              TEXT    PRIMARY KEY,
    ts_ms           INTEGER NOT NULL,
    direction       TEXT    NOT NULL,    -- 'in' | 'out'
    peer_fp         TEXT    NOT NULL,
    msg_type        TEXT    NOT NULL,    -- 'TEXT' | 'FILE_OFFER' | 'FILE_DONE' ...
    body            TEXT,
    room_id         TEXT,
    metadata_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_messages_ts   ON messages(ts_ms);
CREATE INDEX IF NOT EXISTS idx_messages_peer ON messages(peer_fp);
CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id);

-- Full-text search across message bodies.
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    body,
    content='messages',
    content_rowid='rowid'
);
CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, body) VALUES (new.rowid, new.body);
END;
CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, body) VALUES('delete', old.rowid, old.body);
END;
CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, body) VALUES('delete', old.rowid, old.body);
    INSERT INTO messages_fts(rowid, body) VALUES (new.rowid, new.body);
END;

CREATE TABLE IF NOT EXISTS rooms (
    id            TEXT    PRIMARY KEY,
    name          TEXT    NOT NULL UNIQUE,
    created_ms    INTEGER NOT NULL,
    members_json  TEXT    NOT NULL          -- JSON array of fingerprints
);

CREATE TABLE IF NOT EXISTS folders (
    name             TEXT    PRIMARY KEY,
    local_path       TEXT    NOT NULL,
    shared_with_json TEXT    NOT NULL,
    created_ms       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS folder_manifest (
    folder_name  TEXT NOT NULL,
    file_path    TEXT NOT NULL,
    blob_hash    TEXT,                      -- NULL = tombstone (deleted)
    size         INTEGER,
    mtime_ms     INTEGER,
    vclock_json  TEXT NOT NULL,             -- {peer_fp: counter}
    updated_ms   INTEGER NOT NULL,
    PRIMARY KEY (folder_name, file_path)
);
CREATE INDEX IF NOT EXISTS idx_manifest_folder ON folder_manifest(folder_name);

CREATE TABLE IF NOT EXISTS blobs (
    hash          TEXT    PRIMARY KEY,
    size          INTEGER NOT NULL,
    received_ms   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS peer_capabilities (
    fingerprint TEXT PRIMARY KEY,
    caps_json   TEXT NOT NULL,
    updated_ms  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS peer_capability_policy (
    fingerprint TEXT PRIMARY KEY,
    allowed_json TEXT NOT NULL,
    updated_ms INTEGER NOT NULL
);

-- H1: capability-policy + trust audit log. Append-only.
-- `kind` is one of: cap_policy_set, cap_policy_clear, trust_set
-- `before_json` / `after_json` capture the previous and new value for diff.
CREATE TABLE IF NOT EXISTS capability_audit (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms       INTEGER NOT NULL,
    fingerprint TEXT    NOT NULL,
    kind        TEXT    NOT NULL,
    before_json TEXT,
    after_json  TEXT,
    actor       TEXT,
    note        TEXT
);
CREATE INDEX IF NOT EXISTS idx_cap_audit_ts ON capability_audit(ts_ms);
CREATE INDEX IF NOT EXISTS idx_cap_audit_fp ON capability_audit(fingerprint);

-- v0.6.2: groups + group events + per-(group, sender, epoch) sender keys.
-- The event log is the source of truth for group state; reduce_events
-- materializes the membership/role/name lazily. Sender chains are
-- stored separately because they advance per message and need fast
-- per-row update.
CREATE TABLE IF NOT EXISTS groups (
    group_id    BLOB    PRIMARY KEY,        -- 16-byte stable id
    name        TEXT    NOT NULL DEFAULT '',-- cached from latest reduce
    created_ms  INTEGER NOT NULL DEFAULT 0,
    state_hash  TEXT    NOT NULL DEFAULT '',-- last computed Merkle of events
    updated_ms  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_events (
    group_id    BLOB    NOT NULL,
    event_id    TEXT    NOT NULL,           -- content-addressed hash
    timestamp_ms INTEGER NOT NULL,
    wire_json   TEXT    NOT NULL,           -- full serialized event
    PRIMARY KEY (group_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_group_events_ts
    ON group_events(group_id, timestamp_ms);

-- Sender chains: my own outbound chain per group AND every peer's
-- chain that they shared with me via GROUP_KEY_OFFER. Direction
-- ('out' / 'in') tells us which we're tracking. Counter is
-- materialized per row and bumped after every encrypt/decrypt.
CREATE TABLE IF NOT EXISTS group_sender_chains (
    group_id    BLOB NOT NULL,
    sender_pub  BLOB NOT NULL,              -- 32-byte Ed25519 pubkey
    direction   TEXT NOT NULL,              -- 'out' | 'in'
    epoch       INTEGER NOT NULL,
    chain_key   BLOB NOT NULL,              -- 32 bytes
    counter     INTEGER NOT NULL DEFAULT 0,
    updated_ms  INTEGER NOT NULL,
    PRIMARY KEY (group_id, sender_pub, direction, epoch)
);
CREATE INDEX IF NOT EXISTS idx_group_chains_lookup
    ON group_sender_chains(group_id, sender_pub, direction);

-- Per-group inbox of decrypted-and-verified plaintext messages.
-- Persisted so the UI can render history; encryption-side info kept
-- so the audit endpoint can show provenance.
CREATE TABLE IF NOT EXISTS group_messages (
    id           TEXT PRIMARY KEY,
    group_id     BLOB NOT NULL,
    sender_pub   BLOB NOT NULL,
    epoch        INTEGER NOT NULL,
    counter      INTEGER NOT NULL,
    direction    TEXT NOT NULL,             -- 'in' | 'out'
    body         TEXT NOT NULL,
    ts_ms        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_group_messages_group_ts
    ON group_messages(group_id, ts_ms);

CREATE TABLE IF NOT EXISTS transfers (
    id             TEXT PRIMARY KEY,
    direction      TEXT NOT NULL,
    peer_fp        TEXT NOT NULL,
    kind           TEXT NOT NULL,
    name           TEXT NOT NULL,
    size           INTEGER NOT NULL,
    blob_hash      TEXT,
    status         TEXT NOT NULL,
    progress_bytes INTEGER NOT NULL,
    total_bytes    INTEGER NOT NULL,
    chunks_done    INTEGER NOT NULL,
    chunks_total   INTEGER NOT NULL,
    raw_bytes      INTEGER NOT NULL,
    wire_bytes     INTEGER NOT NULL,
    updated_ms     INTEGER NOT NULL,
    metadata_json  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transfers_updated ON transfers(updated_ms);
CREATE INDEX IF NOT EXISTS idx_transfers_peer ON transfers(peer_fp);

-- v0.7.1: store-and-forward outbox. Holds chat messages addressed to
-- a paired peer that's offline at send time. The daemon re-tries
-- delivery on every fresh outbound session for that peer; rows are
-- marked `delivered_ms` non-null on the first successful ACK.
-- (peer_fp, msg_id) is unique so the same message can't be enqueued
-- twice. attempts/last_error let the UI explain stuck deliveries.
CREATE TABLE IF NOT EXISTS outbox (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_fp         TEXT    NOT NULL,
    msg_id          TEXT    NOT NULL,
    msg_kind        TEXT    NOT NULL DEFAULT 'TEXT',
    msg_body_json   TEXT    NOT NULL,
    enqueued_ms     INTEGER NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_attempt_ms INTEGER,
    last_error      TEXT,
    delivered_ms    INTEGER,
    UNIQUE(peer_fp, msg_id)
);
CREATE INDEX IF NOT EXISTS idx_outbox_peer ON outbox(peer_fp);
CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox(peer_fp, delivered_ms);

-- v0.7.2: folder sandbox capability audit. Append-only log of
-- accepted and rejected remote writes against a sync root, so the
-- user can answer "what did this peer do to my folder last week".
-- root_id binds the audit event to a stable identifier even if the
-- folder is renamed or recreated.
CREATE TABLE IF NOT EXISTS folder_audit (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms         INTEGER NOT NULL,
    folder_name   TEXT    NOT NULL,
    root_id       TEXT    NOT NULL,
    peer_fp       TEXT    NOT NULL,
    action        TEXT    NOT NULL,
    file_path     TEXT    NOT NULL,
    blob_hash     TEXT,
    size          INTEGER,
    note          TEXT
);
CREATE INDEX IF NOT EXISTS idx_folder_audit_ts ON folder_audit(ts_ms);
CREATE INDEX IF NOT EXISTS idx_folder_audit_folder ON folder_audit(folder_name);
CREATE INDEX IF NOT EXISTS idx_folder_audit_peer ON folder_audit(peer_fp);
"""


def _now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class PeerRecord:
    fingerprint: str
    short_id: str
    pubkey: bytes
    hostname: Optional[str]
    last_address: Optional[str]
    last_port: Optional[int]
    trust: str
    first_seen_ms: int
    last_seen_ms: int


@dataclass
class MessageRecord:
    id: str
    ts_ms: int
    direction: str
    peer_fp: str
    msg_type: str
    body: Optional[str]
    room_id: Optional[str]
    metadata: dict


@dataclass
class TransferRecord:
    id: str
    direction: str
    peer_fp: str
    kind: str
    name: str
    size: int
    blob_hash: Optional[str]
    status: str
    progress_bytes: int
    total_bytes: int
    chunks_done: int
    chunks_total: int
    raw_bytes: int
    wire_bytes: int
    updated_ms: int
    metadata: dict


@dataclass
class OutboxEntry:
    """v0.7.1: pending or delivered store-and-forward message row."""
    id: int
    peer_fp: str
    msg_id: str
    msg_kind: str
    msg_body: dict
    enqueued_ms: int
    attempts: int
    last_attempt_ms: Optional[int]
    last_error: Optional[str]
    delivered_ms: Optional[int]

    @property
    def delivered(self) -> bool:
        return self.delivered_ms is not None


class State:
    """Singleton-style state handle. Construct once per daemon."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or (data_dir() / DB_FILE)
        self._conn: sqlite3.Connection = sqlite3.connect(
            self.db_path, check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._write_lock = threading.RLock()
        self._init_pragmas()
        self._migrate()

    def _init_pragmas(self) -> None:
        c = self._conn.cursor()
        c.execute("PRAGMA journal_mode = WAL")
        c.execute("PRAGMA synchronous = NORMAL")
        c.execute("PRAGMA foreign_keys = ON")
        c.execute("PRAGMA temp_store = MEMORY")
        c.execute("PRAGMA cache_size = -8000")  # 8 MB
        c.close()

    def _migrate(self) -> None:
        with self._write_lock:
            c = self._conn.cursor()
            try:
                c.executescript(SCHEMA_V1)
                # Stamp version
                cur = c.execute("SELECT MAX(version) FROM schema_version")
                row = cur.fetchone()
                current = row[0] if row and row[0] is not None else 0
                if current < 1:
                    c.execute("INSERT INTO schema_version(version) VALUES(1)")
                # v0.7.2: folder sandbox columns. Add only if not
                # present so existing dbs upgrade cleanly. SQLite
                # has no `ADD COLUMN IF NOT EXISTS`, so we PRAGMA-
                # introspect first.
                self._migrate_v2_folder_sandboxes(c)
                if current < 2:
                    c.execute("INSERT INTO schema_version(version) VALUES(2)")
            finally:
                c.close()

    def _migrate_v2_folder_sandboxes(self, c: sqlite3.Cursor) -> None:
        """Add per-folder sandbox columns: root_id (stable id),
        max_file_bytes (size cap), ignored_patterns_json (deny-list
        globs), conflict_policy (latest-wins | local-priority |
        peer-priority). Idempotent — safe to re-run."""
        rows = c.execute("PRAGMA table_info(folders)").fetchall()
        existing = {row[1] for row in rows}  # column name index
        if "root_id" not in existing:
            c.execute("ALTER TABLE folders ADD COLUMN root_id TEXT")
        if "max_file_bytes" not in existing:
            c.execute("ALTER TABLE folders ADD COLUMN max_file_bytes INTEGER")
        if "ignored_patterns_json" not in existing:
            c.execute(
                "ALTER TABLE folders ADD COLUMN ignored_patterns_json"
                " TEXT NOT NULL DEFAULT '[]'"
            )
        if "conflict_policy" not in existing:
            c.execute(
                "ALTER TABLE folders ADD COLUMN conflict_policy"
                " TEXT NOT NULL DEFAULT 'latest-wins'"
            )
        # Backfill root_id for any folder still missing one — needed
        # the moment we start writing it into folder_audit rows.
        rows = c.execute(
            "SELECT name FROM folders WHERE root_id IS NULL OR root_id = ''"
        ).fetchall()
        for row in rows:
            new_id = uuid.uuid4().hex
            c.execute(
                "UPDATE folders SET root_id = ? WHERE name = ?",
                (new_id, row["name"]),
            )

    # ─── peers ────────────────────────────────────────────────────────

    def upsert_peer(
        self,
        *,
        fingerprint: str,
        short_id: str,
        pubkey: bytes,
        hostname: Optional[str] = None,
        address: Optional[str] = None,
        port: Optional[int] = None,
        trust_default: str = "pending",
    ) -> PeerRecord:
        now = _now_ms()
        with self._write_lock:
            c = self._conn.cursor()
            try:
                c.execute(
                    """
                    INSERT INTO peers(fingerprint, short_id, pubkey, hostname,
                        last_address, last_port, trust, first_seen_ms, last_seen_ms)
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(fingerprint) DO UPDATE SET
                        short_id     = excluded.short_id,
                        pubkey       = excluded.pubkey,
                        hostname     = COALESCE(excluded.hostname, peers.hostname),
                        last_address = COALESCE(excluded.last_address, peers.last_address),
                        last_port    = COALESCE(excluded.last_port, peers.last_port),
                        last_seen_ms = excluded.last_seen_ms
                    """,
                    (
                        fingerprint, short_id, pubkey, hostname,
                        address, port, trust_default, now, now,
                    ),
                )
                row = c.execute(
                    "SELECT * FROM peers WHERE fingerprint = ?", (fingerprint,)
                ).fetchone()
                return self._row_to_peer(row)
            finally:
                c.close()

    def set_peer_trust(
        self,
        fingerprint: str,
        trust: str,
        *,
        actor: Optional[str] = None,
        note: Optional[str] = None,
    ) -> None:
        if trust not in ("pinned", "pending", "rejected"):
            raise ValueError(f"invalid trust state: {trust!r}")
        with self._write_lock:
            row = self._conn.execute(
                "SELECT trust FROM peers WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            before = row["trust"] if row else None
            self._conn.execute(
                "UPDATE peers SET trust = ? WHERE fingerprint = ?",
                (trust, fingerprint),
            )
            if before != trust:
                self._record_capability_audit(
                    fingerprint=fingerprint,
                    kind="trust_set",
                    before=before,
                    after=trust,
                    actor=actor,
                    note=note,
                )

    def get_peer(self, fingerprint: str) -> Optional[PeerRecord]:
        row = self._conn.execute(
            "SELECT * FROM peers WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return self._row_to_peer(row) if row else None

    def get_peer_by_short_id(self, short_id: str) -> Optional[PeerRecord]:
        row = self._conn.execute(
            "SELECT * FROM peers WHERE short_id = ?", (short_id,)
        ).fetchone()
        return self._row_to_peer(row) if row else None

    def list_peers(self) -> list[PeerRecord]:
        rows = self._conn.execute(
            "SELECT * FROM peers ORDER BY last_seen_ms DESC"
        ).fetchall()
        return [self._row_to_peer(r) for r in rows]

    def set_peer_capabilities(self, fingerprint: str, caps: Iterable[str]) -> None:
        values = sorted({str(c) for c in caps if str(c)})
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO peer_capabilities(fingerprint, caps_json, updated_ms)
                VALUES(?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    caps_json = excluded.caps_json,
                    updated_ms = excluded.updated_ms
                """,
                (fingerprint, json.dumps(values), _now_ms()),
            )

    def get_peer_capabilities(self, fingerprint: str) -> list[str]:
        row = self._conn.execute(
            "SELECT caps_json FROM peer_capabilities WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if not row:
            return []
        try:
            return list(json.loads(row["caps_json"]))
        except Exception:
            return []

    def set_peer_capability_policy(
        self,
        fingerprint: str,
        allowed: Iterable[str],
        *,
        actor: Optional[str] = None,
        note: Optional[str] = None,
    ) -> None:
        values = sorted({str(c) for c in allowed if str(c)})
        with self._write_lock:
            before = self.get_peer_capability_policy(fingerprint)
            self._conn.execute(
                """
                INSERT INTO peer_capability_policy(fingerprint, allowed_json, updated_ms)
                VALUES(?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    allowed_json = excluded.allowed_json,
                    updated_ms = excluded.updated_ms
                """,
                (fingerprint, json.dumps(values), _now_ms()),
            )
            if before != values:
                self._record_capability_audit(
                    fingerprint=fingerprint,
                    kind="cap_policy_set",
                    before=before,
                    after=values,
                    actor=actor,
                    note=note,
                )

    def clear_peer_capability_policy(
        self,
        fingerprint: str,
        *,
        actor: Optional[str] = None,
        note: Optional[str] = None,
    ) -> None:
        with self._write_lock:
            before = self.get_peer_capability_policy(fingerprint)
            self._conn.execute(
                "DELETE FROM peer_capability_policy WHERE fingerprint = ?",
                (fingerprint,),
            )
            if before is not None:
                self._record_capability_audit(
                    fingerprint=fingerprint,
                    kind="cap_policy_clear",
                    before=before,
                    after=None,
                    actor=actor,
                    note=note,
                )

    def get_peer_capability_policy(self, fingerprint: str) -> Optional[list[str]]:
        row = self._conn.execute(
            "SELECT allowed_json FROM peer_capability_policy WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if not row:
            return None
        try:
            return list(json.loads(row["allowed_json"]))
        except Exception:
            return []

    # ─── capability / trust audit log (H1) ────────────────────────────
    def _record_capability_audit(
        self,
        *,
        fingerprint: str,
        kind: str,
        before: Any,
        after: Any,
        actor: Optional[str] = None,
        note: Optional[str] = None,
    ) -> None:
        # Caller already holds _write_lock.
        self._conn.execute(
            """
            INSERT INTO capability_audit(
                ts_ms, fingerprint, kind, before_json, after_json, actor, note
            ) VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _now_ms(),
                fingerprint,
                kind,
                None if before is None else json.dumps(before),
                None if after is None else json.dumps(after),
                actor,
                note,
            ),
        )

    def recent_capability_audit(
        self,
        *,
        fingerprint: Optional[str] = None,
        limit: int = 200,
    ) -> list[dict]:
        sql = (
            "SELECT id, ts_ms, fingerprint, kind, before_json, after_json,"
            " actor, note FROM capability_audit"
        )
        params: list[Any] = []
        if fingerprint is not None:
            sql += " WHERE fingerprint = ?"
            params.append(fingerprint)
        sql += " ORDER BY ts_ms DESC, id DESC LIMIT ?"
        params.append(int(limit))
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        out: list[dict] = []
        for r in rows:
            def _parse(s: Optional[str]) -> Any:
                if s is None:
                    return None
                try:
                    return json.loads(s)
                except Exception:
                    return s
            out.append({
                "id": r["id"],
                "ts_ms": r["ts_ms"],
                "fingerprint": r["fingerprint"],
                "kind": r["kind"],
                "before": _parse(r["before_json"]),
                "after": _parse(r["after_json"]),
                "actor": r["actor"],
                "note": r["note"],
            })
        return out

    # ─── groups (v0.6.2) ──────────────────────────────────────────────
    # `event` is a one_link.groups.GroupEvent — we serialize via to_wire().
    # This module avoids importing groups directly to dodge a cycle; the
    # daemon does that work and passes `wire_dict`.

    def upsert_group_event(
        self,
        *,
        group_id: bytes,
        event_id: str,
        timestamp_ms: int,
        wire_dict: dict,
    ) -> bool:
        """Persist a group event. Returns True if newly inserted,
        False if already present (content-addressed, idempotent)."""
        with self._write_lock:
            cur = self._conn.execute(
                """
                INSERT OR IGNORE INTO group_events(
                    group_id, event_id, timestamp_ms, wire_json
                ) VALUES(?, ?, ?, ?)
                """,
                (group_id, event_id, int(timestamp_ms), json.dumps(wire_dict)),
            )
            return cur.rowcount > 0

    def list_group_events(self, group_id: bytes) -> list[dict]:
        """All events for a group, returned as wire dicts ready to feed
        through GroupEvent.from_wire()."""
        rows = self._conn.execute(
            "SELECT wire_json FROM group_events WHERE group_id = ? "
            "ORDER BY timestamp_ms ASC, event_id ASC",
            (group_id,),
        ).fetchall()
        out: list[dict] = []
        for r in rows:
            try:
                out.append(json.loads(r["wire_json"]))
            except Exception:
                continue
        return out

    def list_group_ids(self) -> list[bytes]:
        rows = self._conn.execute(
            "SELECT group_id FROM groups ORDER BY updated_ms DESC"
        ).fetchall()
        return [r["group_id"] for r in rows]

    def upsert_group_meta(
        self,
        *,
        group_id: bytes,
        name: str,
        created_ms: int,
        state_hash: str,
    ) -> None:
        """Cache the materialized state of a group (name, hash) so the
        UI can render the list without re-reducing every event log."""
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO groups(group_id, name, created_ms, state_hash, updated_ms)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(group_id) DO UPDATE SET
                    name = excluded.name,
                    state_hash = excluded.state_hash,
                    updated_ms = excluded.updated_ms
                """,
                (group_id, name, int(created_ms), state_hash, _now_ms()),
            )

    def get_group_meta(self, group_id: bytes) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT group_id, name, created_ms, state_hash, updated_ms "
            "FROM groups WHERE group_id = ?",
            (group_id,),
        ).fetchone()
        if not row:
            return None
        return {
            "group_id": row["group_id"],
            "name": row["name"],
            "created_ms": row["created_ms"],
            "state_hash": row["state_hash"],
            "updated_ms": row["updated_ms"],
        }

    # Sender chains.
    def upsert_sender_chain(
        self,
        *,
        group_id: bytes,
        sender_pub: bytes,
        direction: str,
        epoch: int,
        chain_key: bytes,
        counter: int,
    ) -> None:
        if direction not in ("in", "out"):
            raise ValueError(f"direction must be 'in' or 'out', got {direction!r}")
        if len(chain_key) != 32:
            raise ValueError("chain_key must be 32 bytes")
        if len(sender_pub) != 32:
            raise ValueError("sender_pub must be 32 bytes")
        if len(group_id) != 16:
            raise ValueError("group_id must be 16 bytes")
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO group_sender_chains(
                    group_id, sender_pub, direction, epoch,
                    chain_key, counter, updated_ms
                )
                VALUES(?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(group_id, sender_pub, direction, epoch)
                DO UPDATE SET
                    chain_key = excluded.chain_key,
                    counter = excluded.counter,
                    updated_ms = excluded.updated_ms
                """,
                (group_id, sender_pub, direction, int(epoch),
                 chain_key, int(counter), _now_ms()),
            )

    def get_sender_chain(
        self,
        *,
        group_id: bytes,
        sender_pub: bytes,
        direction: str,
        epoch: Optional[int] = None,
    ) -> Optional[dict]:
        """Get the latest chain for (group, sender, direction). If
        `epoch` is given, returns that exact epoch; otherwise the
        highest known epoch."""
        if epoch is not None:
            row = self._conn.execute(
                "SELECT epoch, chain_key, counter FROM group_sender_chains "
                "WHERE group_id = ? AND sender_pub = ? AND direction = ? AND epoch = ?",
                (group_id, sender_pub, direction, int(epoch)),
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT epoch, chain_key, counter FROM group_sender_chains "
                "WHERE group_id = ? AND sender_pub = ? AND direction = ? "
                "ORDER BY epoch DESC LIMIT 1",
                (group_id, sender_pub, direction),
            ).fetchone()
        if not row:
            return None
        return {
            "epoch": row["epoch"],
            "chain_key": row["chain_key"],
            "counter": row["counter"],
        }

    def insert_group_message(
        self,
        *,
        id: str,
        group_id: bytes,
        sender_pub: bytes,
        epoch: int,
        counter: int,
        direction: str,
        body: str,
        ts_ms: Optional[int] = None,
    ) -> None:
        with self._write_lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO group_messages(
                    id, group_id, sender_pub, epoch, counter,
                    direction, body, ts_ms
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (id, group_id, sender_pub, int(epoch), int(counter),
                 direction, body, int(ts_ms if ts_ms is not None else _now_ms())),
            )

    def recent_group_messages(
        self,
        *,
        group_id: bytes,
        limit: int = 100,
    ) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, group_id, sender_pub, epoch, counter, direction, "
            "body, ts_ms FROM group_messages WHERE group_id = ? "
            "ORDER BY ts_ms DESC LIMIT ?",
            (group_id, int(limit)),
        ).fetchall()
        return [
            {
                "id": r["id"],
                "group_id": r["group_id"],
                "sender_pub": r["sender_pub"],
                "epoch": r["epoch"],
                "counter": r["counter"],
                "direction": r["direction"],
                "body": r["body"],
                "ts_ms": r["ts_ms"],
            }
            for r in rows
        ]

    def _row_to_peer(self, row: sqlite3.Row) -> PeerRecord:
        return PeerRecord(
            fingerprint=row["fingerprint"],
            short_id=row["short_id"],
            pubkey=row["pubkey"],
            hostname=row["hostname"],
            last_address=row["last_address"],
            last_port=row["last_port"],
            trust=row["trust"],
            first_seen_ms=row["first_seen_ms"],
            last_seen_ms=row["last_seen_ms"],
        )

    # ─── messages ─────────────────────────────────────────────────────

    def record_message(
        self,
        *,
        id: str,
        ts_ms: int,
        direction: str,
        peer_fp: str,
        msg_type: str,
        body: Optional[str],
        room_id: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> None:
        with self._write_lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO messages(
                    id, ts_ms, direction, peer_fp, msg_type, body, room_id, metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    id, ts_ms, direction, peer_fp, msg_type, body, room_id,
                    json.dumps(metadata or {}, separators=(",", ":")),
                ),
            )

    def search_messages(
        self,
        query: str,
        *,
        limit: int = 50,
        peer_fp: Optional[str] = None,
        room_id: Optional[str] = None,
    ) -> list[MessageRecord]:
        clauses = ["messages.rowid IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?)"]
        params: list[Any] = [query]
        if peer_fp:
            clauses.append("messages.peer_fp = ?")
            params.append(peer_fp)
        if room_id:
            clauses.append("messages.room_id = ?")
            params.append(room_id)
        where = " AND ".join(clauses)
        sql = (
            f"SELECT * FROM messages WHERE {where} "
            f"ORDER BY ts_ms DESC LIMIT ?"
        )
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_msg(r) for r in rows]

    def recent_messages(
        self,
        *,
        peer_fp: Optional[str] = None,
        room_id: Optional[str] = None,
        limit: int = 50,
    ) -> list[MessageRecord]:
        clauses: list[str] = []
        params: list[Any] = []
        if peer_fp:
            clauses.append("peer_fp = ?")
            params.append(peer_fp)
        if room_id:
            clauses.append("room_id = ?")
            params.append(room_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM messages{where} ORDER BY ts_ms DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_msg(r) for r in reversed(rows)]

    def _row_to_msg(self, row: sqlite3.Row) -> MessageRecord:
        try:
            md = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            md = {}
        return MessageRecord(
            id=row["id"],
            ts_ms=row["ts_ms"],
            direction=row["direction"],
            peer_fp=row["peer_fp"],
            msg_type=row["msg_type"],
            body=row["body"],
            room_id=row["room_id"],
            metadata=md,
        )

    # --- transfers ---------------------------------------------------------

    def upsert_transfer(
        self,
        *,
        id: str,
        direction: str,
        peer_fp: str,
        kind: str,
        name: str,
        size: int,
        blob_hash: Optional[str] = None,
        status: str = "queued",
        progress_bytes: int = 0,
        total_bytes: Optional[int] = None,
        chunks_done: int = 0,
        chunks_total: int = 0,
        raw_bytes: int = 0,
        wire_bytes: int = 0,
        metadata: Optional[dict] = None,
    ) -> TransferRecord:
        if direction not in ("in", "out"):
            raise ValueError(f"invalid transfer direction: {direction!r}")
        if status not in ("queued", "offered", "active", "complete", "failed"):
            raise ValueError(f"invalid transfer status: {status!r}")
        total = int(size if total_bytes is None else total_bytes)
        now = _now_ms()
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO transfers(
                    id, direction, peer_fp, kind, name, size, blob_hash, status,
                    progress_bytes, total_bytes, chunks_done, chunks_total,
                    raw_bytes, wire_bytes, updated_ms, metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    direction = excluded.direction,
                    peer_fp = excluded.peer_fp,
                    kind = excluded.kind,
                    name = excluded.name,
                    size = excluded.size,
                    blob_hash = excluded.blob_hash,
                    status = excluded.status,
                    progress_bytes = excluded.progress_bytes,
                    total_bytes = excluded.total_bytes,
                    chunks_done = excluded.chunks_done,
                    chunks_total = excluded.chunks_total,
                    raw_bytes = excluded.raw_bytes,
                    wire_bytes = excluded.wire_bytes,
                    updated_ms = excluded.updated_ms,
                    metadata_json = excluded.metadata_json
                """,
                (
                    id, direction, peer_fp, kind, name, int(size), blob_hash,
                    status, int(progress_bytes), total, int(chunks_done),
                    int(chunks_total), int(raw_bytes), int(wire_bytes), now,
                    json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True),
                ),
            )
            row = self._conn.execute(
                "SELECT * FROM transfers WHERE id = ?", (id,)
            ).fetchone()
        return self._row_to_transfer(row)

    def update_transfer(self, id: str, **fields: Any) -> Optional[TransferRecord]:
        allowed = {
            "status", "progress_bytes", "total_bytes", "chunks_done",
            "chunks_total", "raw_bytes", "wire_bytes", "metadata",
        }
        bad = set(fields) - allowed
        if bad:
            raise ValueError(f"unknown transfer fields: {sorted(bad)!r}")
        current = self.get_transfer(id)
        if current is None:
            return None
        metadata = fields.pop("metadata", current.metadata)
        data = {
            "id": current.id,
            "direction": current.direction,
            "peer_fp": current.peer_fp,
            "kind": current.kind,
            "name": current.name,
            "size": current.size,
            "blob_hash": current.blob_hash,
            "status": current.status,
            "progress_bytes": current.progress_bytes,
            "total_bytes": current.total_bytes,
            "chunks_done": current.chunks_done,
            "chunks_total": current.chunks_total,
            "raw_bytes": current.raw_bytes,
            "wire_bytes": current.wire_bytes,
            "metadata": metadata,
        }
        data.update(fields)
        return self.upsert_transfer(**data)

    def get_transfer(self, id: str) -> Optional[TransferRecord]:
        row = self._conn.execute(
            "SELECT * FROM transfers WHERE id = ?", (id,)
        ).fetchone()
        return self._row_to_transfer(row) if row else None

    def list_transfers(
        self,
        *,
        peer_fp: Optional[str] = None,
        limit: int = 100,
    ) -> list[TransferRecord]:
        limit = max(1, min(int(limit), 500))
        if peer_fp:
            rows = self._conn.execute(
                "SELECT * FROM transfers WHERE peer_fp = ? ORDER BY updated_ms DESC LIMIT ?",
                (peer_fp, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM transfers ORDER BY updated_ms DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_transfer(r) for r in rows]

    def delete_transfer(self, id: str) -> bool:
        with self._write_lock:
            cur = self._conn.execute("DELETE FROM transfers WHERE id = ?", (id,))
            return cur.rowcount > 0

    def prune_transfers(
        self,
        *,
        statuses: Iterable[str] = ("complete", "failed"),
        older_than_ms: Optional[int] = None,
        keep_latest: int = 200,
    ) -> int:
        clean_statuses = [str(s) for s in statuses if str(s)]
        if not clean_statuses:
            return 0
        keep_latest = max(0, int(keep_latest))
        params: list[Any] = clean_statuses
        where = f"status IN ({','.join('?' for _ in clean_statuses)})"
        if older_than_ms is not None:
            where += " AND updated_ms < ?"
            params.append(int(older_than_ms))
        keep_clause = ""
        if keep_latest:
            keep_clause = (
                " AND id NOT IN ("
                "SELECT id FROM transfers ORDER BY updated_ms DESC LIMIT ?"
                ")"
            )
            params.append(keep_latest)
        with self._write_lock:
            cur = self._conn.execute(
                f"DELETE FROM transfers WHERE {where}{keep_clause}",
                params,
            )
            return int(cur.rowcount)

    # ─── outbox (v0.7.1: store-and-forward) ──────────────────────────

    def enqueue_outbox(
        self,
        *,
        peer_fp: str,
        msg_id: str,
        msg_body: dict,
        msg_kind: str = "TEXT",
    ) -> int:
        """Queue a chat message for delivery to peer when next online.
        Returns the row id. If (peer_fp, msg_id) is already enqueued
        (delivered or not), returns the existing row id — idempotent."""
        if not peer_fp or not msg_id:
            raise ValueError("peer_fp and msg_id required")
        body_json = json.dumps(msg_body, separators=(",", ":"))
        now = _now_ms()
        with self._write_lock:
            cur = self._conn.execute(
                """
                INSERT INTO outbox(
                    peer_fp, msg_id, msg_kind, msg_body_json, enqueued_ms
                ) VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(peer_fp, msg_id) DO NOTHING
                """,
                (peer_fp, msg_id, msg_kind, body_json, now),
            )
            if cur.rowcount > 0:
                return int(cur.lastrowid)
            row = self._conn.execute(
                "SELECT id FROM outbox WHERE peer_fp = ? AND msg_id = ?",
                (peer_fp, msg_id),
            ).fetchone()
            return int(row["id"]) if row else -1

    def list_outbox(
        self,
        *,
        peer_fp: Optional[str] = None,
        pending_only: bool = True,
        limit: int = 200,
    ) -> list[OutboxEntry]:
        sql = (
            "SELECT id, peer_fp, msg_id, msg_kind, msg_body_json, enqueued_ms,"
            " attempts, last_attempt_ms, last_error, delivered_ms"
            " FROM outbox"
        )
        clauses: list[str] = []
        params: list[Any] = []
        if peer_fp is not None:
            clauses.append("peer_fp = ?")
            params.append(peer_fp)
        if pending_only:
            clauses.append("delivered_ms IS NULL")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY enqueued_ms ASC, id ASC LIMIT ?"
        params.append(int(limit))
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [self._row_to_outbox(r) for r in rows]

    def get_outbox_entry(self, entry_id: int) -> Optional[OutboxEntry]:
        row = self._conn.execute(
            "SELECT id, peer_fp, msg_id, msg_kind, msg_body_json, enqueued_ms,"
            " attempts, last_attempt_ms, last_error, delivered_ms"
            " FROM outbox WHERE id = ?",
            (int(entry_id),),
        ).fetchone()
        return self._row_to_outbox(row) if row else None

    def mark_outbox_delivered(self, entry_id: int) -> bool:
        with self._write_lock:
            cur = self._conn.execute(
                "UPDATE outbox SET delivered_ms = ?, last_error = NULL"
                " WHERE id = ? AND delivered_ms IS NULL",
                (_now_ms(), int(entry_id)),
            )
            return cur.rowcount > 0

    def record_outbox_attempt(
        self, entry_id: int, *, error: Optional[str] = None,
    ) -> None:
        with self._write_lock:
            self._conn.execute(
                "UPDATE outbox SET attempts = attempts + 1,"
                " last_attempt_ms = ?, last_error = ? WHERE id = ?",
                (_now_ms(), error[:500] if error else None, int(entry_id)),
            )

    def cancel_outbox(self, entry_id: int) -> bool:
        """Drop a pending entry without delivery. Idempotent."""
        with self._write_lock:
            cur = self._conn.execute(
                "DELETE FROM outbox WHERE id = ? AND delivered_ms IS NULL",
                (int(entry_id),),
            )
            return cur.rowcount > 0

    def clear_outbox_for_peer(self, peer_fp: str) -> int:
        """Drop every (delivered or not) outbox row for a peer.
        Hooked from revoke_peer so we don't keep messages addressed
        to a peer the user no longer trusts."""
        with self._write_lock:
            cur = self._conn.execute(
                "DELETE FROM outbox WHERE peer_fp = ?", (peer_fp,),
            )
            return int(cur.rowcount)

    def prune_outbox(
        self,
        *,
        older_than_ms: Optional[int] = None,
        delivered_only: bool = True,
    ) -> int:
        """Cleanup. Default: drop delivered rows. Pass
        `delivered_only=False, older_than_ms=...` to also drop
        ancient undelivered rows (e.g. peer never came back)."""
        clauses: list[str] = []
        params: list[Any] = []
        if delivered_only:
            clauses.append("delivered_ms IS NOT NULL")
        if older_than_ms is not None:
            clauses.append("enqueued_ms < ?")
            params.append(int(older_than_ms))
        if not clauses:
            return 0
        sql = "DELETE FROM outbox WHERE " + " AND ".join(clauses)
        with self._write_lock:
            cur = self._conn.execute(sql, tuple(params))
            return int(cur.rowcount)

    def _row_to_outbox(self, row: sqlite3.Row) -> OutboxEntry:
        try:
            body = json.loads(row["msg_body_json"]) if row["msg_body_json"] else {}
        except Exception:
            body = {}
        return OutboxEntry(
            id=int(row["id"]),
            peer_fp=row["peer_fp"],
            msg_id=row["msg_id"],
            msg_kind=row["msg_kind"],
            msg_body=body,
            enqueued_ms=int(row["enqueued_ms"]),
            attempts=int(row["attempts"]),
            last_attempt_ms=row["last_attempt_ms"],
            last_error=row["last_error"],
            delivered_ms=row["delivered_ms"],
        )

    def _row_to_transfer(self, row: sqlite3.Row) -> TransferRecord:
        try:
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            metadata = {}
        return TransferRecord(
            id=row["id"],
            direction=row["direction"],
            peer_fp=row["peer_fp"],
            kind=row["kind"],
            name=row["name"],
            size=row["size"],
            blob_hash=row["blob_hash"],
            status=row["status"],
            progress_bytes=row["progress_bytes"],
            total_bytes=row["total_bytes"],
            chunks_done=row["chunks_done"],
            chunks_total=row["chunks_total"],
            raw_bytes=row["raw_bytes"],
            wire_bytes=row["wire_bytes"],
            updated_ms=row["updated_ms"],
            metadata=metadata,
        )

    # ─── rooms ────────────────────────────────────────────────────────

    def create_room(self, *, room_id: str, name: str, members: list[str]) -> None:
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO rooms(id, name, created_ms, members_json)
                VALUES(?, ?, ?, ?)
                """,
                (room_id, name, _now_ms(), json.dumps(members)),
            )

    def get_room(self, room_id: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM rooms WHERE id = ?", (room_id,)
        ).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "name": row["name"],
            "created_ms": row["created_ms"],
            "members": json.loads(row["members_json"]),
        }

    def get_room_by_name(self, name: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM rooms WHERE name = ?", (name,)
        ).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "name": row["name"],
            "created_ms": row["created_ms"],
            "members": json.loads(row["members_json"]),
        }

    def list_rooms(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM rooms ORDER BY created_ms"
        ).fetchall()
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "created_ms": r["created_ms"],
                "members": json.loads(r["members_json"]),
            }
            for r in rows
        ]

    def update_room_members(self, room_id: str, members: list[str]) -> None:
        with self._write_lock:
            self._conn.execute(
                "UPDATE rooms SET members_json = ? WHERE id = ?",
                (json.dumps(members), room_id),
            )

    # ─── folders ──────────────────────────────────────────────────────

    def add_folder(
        self, *, name: str, local_path: str, shared_with: list[str],
        max_file_bytes: Optional[int] = None,
        ignored_patterns: Optional[list[str]] = None,
        conflict_policy: str = "latest-wins",
    ) -> None:
        if conflict_policy not in ("latest-wins", "local-priority", "peer-priority"):
            raise ValueError(f"invalid conflict_policy: {conflict_policy!r}")
        ip_json = json.dumps(list(ignored_patterns or []))
        root_id = uuid.uuid4().hex
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO folders(
                    name, local_path, shared_with_json, created_ms,
                    root_id, max_file_bytes, ignored_patterns_json,
                    conflict_policy
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name, local_path, json.dumps(shared_with), _now_ms(),
                    root_id,
                    int(max_file_bytes) if max_file_bytes is not None else None,
                    ip_json,
                    conflict_policy,
                ),
            )
            for peer_fp in shared_with:
                self._set_folder_peer_permission_locked(name, peer_fp, "rw")

    def remove_folder(self, name: str) -> None:
        with self._write_lock:
            self._conn.execute("DELETE FROM folders WHERE name = ?", (name,))
            self._conn.execute(
                "DELETE FROM folder_manifest WHERE folder_name = ?", (name,)
            )

    def get_folder(self, name: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM folders WHERE name = ?", (name,)
        ).fetchone()
        if not row:
            return None
        return self._row_to_folder(row)

    def list_folders(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM folders ORDER BY name"
        ).fetchall()
        return [self._row_to_folder(r) for r in rows]

    def _row_to_folder(self, r: sqlite3.Row) -> dict:
        cols = r.keys()
        try:
            ignored = json.loads(r["ignored_patterns_json"]) if (
                "ignored_patterns_json" in cols
                and r["ignored_patterns_json"]
            ) else []
        except Exception:
            ignored = []
        return {
            "name": r["name"],
            "local_path": r["local_path"],
            "shared_with": json.loads(r["shared_with_json"]),
            "created_ms": r["created_ms"],
            "root_id": r["root_id"] if "root_id" in cols else None,
            "max_file_bytes": (
                r["max_file_bytes"] if "max_file_bytes" in cols else None
            ),
            "ignored_patterns": ignored,
            "conflict_policy": (
                r["conflict_policy"] if "conflict_policy" in cols else "latest-wins"
            ),
        }

    def share_folder_with(self, folder_name: str, peer_fp: str) -> None:
        f = self.get_folder(folder_name)
        if not f:
            raise KeyError(f"no such folder: {folder_name!r}")
        if peer_fp in f["shared_with"]:
            return
        new = f["shared_with"] + [peer_fp]
        with self._write_lock:
            self._conn.execute(
                "UPDATE folders SET shared_with_json = ? WHERE name = ?",
                (json.dumps(new), folder_name),
            )
            self._set_folder_peer_permission_locked(folder_name, peer_fp, "rw")

    def unshare_folder_with(self, folder_name: str, peer_fp: str) -> None:
        f = self.get_folder(folder_name)
        if not f:
            raise KeyError(f"no such folder: {folder_name!r}")
        if peer_fp not in f["shared_with"]:
            return
        new = [fp for fp in f["shared_with"] if fp != peer_fp]
        with self._write_lock:
            self._conn.execute(
                "UPDATE folders SET shared_with_json = ? WHERE name = ?",
                (json.dumps(new), folder_name),
            )
            self._delete_folder_peer_permission_locked(folder_name, peer_fp)

    def _folder_perm_key(self, folder_name: str, peer_fp: str) -> str:
        return f"folder_permission:{folder_name}:{peer_fp}"

    def _set_folder_peer_permission_locked(
        self, folder_name: str, peer_fp: str, mode: str
    ) -> None:
        if mode not in ("push", "pull", "rw"):
            raise ValueError("folder permission must be push, pull, or rw")
        self._conn.execute(
            """
            INSERT INTO settings(key, value) VALUES(?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (self._folder_perm_key(folder_name, peer_fp), mode),
        )

    def _delete_folder_peer_permission_locked(
        self, folder_name: str, peer_fp: str
    ) -> None:
        self._conn.execute(
            "DELETE FROM settings WHERE key = ?",
            (self._folder_perm_key(folder_name, peer_fp),),
        )

    def set_folder_peer_permission(
        self, folder_name: str, peer_fp: str, mode: str
    ) -> None:
        f = self.get_folder(folder_name)
        if not f:
            raise KeyError(f"no such folder: {folder_name!r}")
        if peer_fp not in f["shared_with"]:
            raise KeyError(f"folder {folder_name!r} is not shared with {peer_fp!r}")
        with self._write_lock:
            self._set_folder_peer_permission_locked(folder_name, peer_fp, mode)

    def get_folder_peer_permission(self, folder_name: str, peer_fp: str) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM settings WHERE key = ?",
            (self._folder_perm_key(folder_name, peer_fp),),
        ).fetchone()
        if not row:
            return "rw" if peer_fp in (self.get_folder(folder_name) or {}).get("shared_with", []) else None
        mode = str(row["value"])
        return mode if mode in ("push", "pull", "rw") else None

    # ─── v0.7.2 sandbox policy setters + audit ──────────────────────

    def set_folder_max_file_bytes(
        self, folder_name: str, max_file_bytes: Optional[int],
    ) -> None:
        if not self.get_folder(folder_name):
            raise KeyError(f"no such folder: {folder_name!r}")
        with self._write_lock:
            self._conn.execute(
                "UPDATE folders SET max_file_bytes = ? WHERE name = ?",
                (
                    int(max_file_bytes) if max_file_bytes is not None else None,
                    folder_name,
                ),
            )

    def set_folder_ignored_patterns(
        self, folder_name: str, patterns: list[str],
    ) -> None:
        if not self.get_folder(folder_name):
            raise KeyError(f"no such folder: {folder_name!r}")
        clean = [str(p) for p in patterns if str(p).strip()]
        with self._write_lock:
            self._conn.execute(
                "UPDATE folders SET ignored_patterns_json = ? WHERE name = ?",
                (json.dumps(clean), folder_name),
            )

    def set_folder_conflict_policy(
        self, folder_name: str, policy: str,
    ) -> None:
        if policy not in ("latest-wins", "local-priority", "peer-priority"):
            raise ValueError(f"invalid conflict_policy: {policy!r}")
        if not self.get_folder(folder_name):
            raise KeyError(f"no such folder: {folder_name!r}")
        with self._write_lock:
            self._conn.execute(
                "UPDATE folders SET conflict_policy = ? WHERE name = ?",
                (policy, folder_name),
            )

    def record_folder_audit_event(
        self,
        *,
        folder_name: str,
        peer_fp: str,
        action: str,
        file_path: str,
        blob_hash: Optional[str] = None,
        size: Optional[int] = None,
        note: Optional[str] = None,
    ) -> int:
        """v0.7.2: append an immutable audit row for any peer write
        attempt against a sandbox root. Action values:
          - 'write'           — accepted manifest entry update
          - 'delete'          — accepted tombstone
          - 'reject_size'     — declined: exceeds max_file_bytes
          - 'reject_pattern'  — declined: matches ignored pattern
          - 'reject_unshared' — declined: peer not on shared_with
          - 'reject_perm'     — declined: peer mode forbids write
        """
        f = self.get_folder(folder_name)
        if not f:
            raise KeyError(f"no such folder: {folder_name!r}")
        root_id = f.get("root_id") or ""
        with self._write_lock:
            cur = self._conn.execute(
                """
                INSERT INTO folder_audit(
                    ts_ms, folder_name, root_id, peer_fp, action,
                    file_path, blob_hash, size, note
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _now_ms(), folder_name, root_id, peer_fp, action,
                    file_path,
                    blob_hash,
                    int(size) if size is not None else None,
                    note,
                ),
            )
            return int(cur.lastrowid)

    def list_folder_audit(
        self,
        *,
        folder_name: Optional[str] = None,
        peer_fp: Optional[str] = None,
        actions: Optional[Iterable[str]] = None,
        limit: int = 200,
    ) -> list[dict]:
        sql = (
            "SELECT id, ts_ms, folder_name, root_id, peer_fp, action,"
            " file_path, blob_hash, size, note FROM folder_audit"
        )
        clauses: list[str] = []
        params: list[Any] = []
        if folder_name is not None:
            clauses.append("folder_name = ?")
            params.append(folder_name)
        if peer_fp is not None:
            clauses.append("peer_fp = ?")
            params.append(peer_fp)
        action_list = list(actions or [])
        if action_list:
            clauses.append("action IN (" + ",".join("?" for _ in action_list) + ")")
            params.extend(action_list)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY ts_ms DESC, id DESC LIMIT ?"
        params.append(int(limit))
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [
            {
                "id": int(r["id"]),
                "ts_ms": int(r["ts_ms"]),
                "folder_name": r["folder_name"],
                "root_id": r["root_id"],
                "peer_fp": r["peer_fp"],
                "action": r["action"],
                "file_path": r["file_path"],
                "blob_hash": r["blob_hash"],
                "size": r["size"],
                "note": r["note"],
            }
            for r in rows
        ]

    @staticmethod
    def folder_path_matches_ignored(
        file_path: str, patterns: Iterable[str],
    ) -> bool:
        """Does the given relative path match any of the glob patterns?
        Uses fnmatch over both the full path and the basename — same
        semantics as gitignore-style ignores for typical use."""
        from fnmatch import fnmatch
        norm = (file_path or "").replace("\\", "/").lstrip("/")
        base = norm.split("/")[-1] if norm else ""
        for raw in patterns or []:
            p = str(raw).strip()
            if not p:
                continue
            if fnmatch(norm, p) or fnmatch(base, p):
                return True
        return False

    def folder_peer_allows(self, folder_name: str, peer_fp: str, action: str) -> bool:
        mode = self.get_folder_peer_permission(folder_name, peer_fp)
        if action == "push":
            return mode in ("push", "rw")
        if action == "pull":
            return mode in ("pull", "rw")
        raise ValueError("folder action must be push or pull")

    # ─── manifest (CRDT entries per file) ─────────────────────────────

    def upsert_manifest_entry(
        self,
        *,
        folder_name: str,
        file_path: str,
        blob_hash: Optional[str],
        size: Optional[int],
        mtime_ms: Optional[int],
        vclock: dict[str, int],
    ) -> None:
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO folder_manifest(
                    folder_name, file_path, blob_hash, size, mtime_ms,
                    vclock_json, updated_ms
                ) VALUES(?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(folder_name, file_path) DO UPDATE SET
                    blob_hash    = excluded.blob_hash,
                    size         = excluded.size,
                    mtime_ms     = excluded.mtime_ms,
                    vclock_json  = excluded.vclock_json,
                    updated_ms   = excluded.updated_ms
                """,
                (
                    folder_name, file_path, blob_hash, size, mtime_ms,
                    json.dumps(vclock, sort_keys=True), _now_ms(),
                ),
            )

    def get_manifest_entry(
        self, folder_name: str, file_path: str
    ) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM folder_manifest WHERE folder_name = ? AND file_path = ?",
            (folder_name, file_path),
        ).fetchone()
        return self._row_to_manifest(row) if row else None

    def list_manifest(self, folder_name: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM folder_manifest WHERE folder_name = ? ORDER BY file_path",
            (folder_name,),
        ).fetchall()
        return [self._row_to_manifest(r) for r in rows]

    def _row_to_manifest(self, row: sqlite3.Row) -> dict:
        return {
            "folder_name": row["folder_name"],
            "file_path":   row["file_path"],
            "blob_hash":   row["blob_hash"],
            "size":        row["size"],
            "mtime_ms":    row["mtime_ms"],
            "vclock":      json.loads(row["vclock_json"]),
            "updated_ms":  row["updated_ms"],
        }

    # ─── blobs index ──────────────────────────────────────────────────

    def record_blob(self, hash_hex: str, size: int) -> None:
        with self._write_lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO blobs(hash, size, received_ms)
                VALUES(?, ?, ?)
                """,
                (hash_hex, size, _now_ms()),
            )

    def has_blob(self, hash_hex: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM blobs WHERE hash = ?", (hash_hex,)
        ).fetchone()
        return bool(row)

    def list_blobs(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT hash, size, received_ms FROM blobs ORDER BY received_ms DESC"
        ).fetchall()
        return [{"hash": r["hash"], "size": r["size"], "received_ms": r["received_ms"]} for r in rows]

    # ─── settings (kv) ────────────────────────────────────────────────

    def set_setting(self, key: str, value: str) -> None:
        with self._write_lock:
            self._conn.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self._conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def all_settings(self) -> dict[str, str]:
        rows = self._conn.execute("SELECT key, value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}

    def delete_setting(self, key: str) -> None:
        with self._write_lock:
            self._conn.execute("DELETE FROM settings WHERE key = ?", (key,))

    # ─── rendezvous (v0.5.1) ──────────────────────────────────────────
    # Stored as a JSON list under the `rendezvous_urls` setting key.
    # The daemon registers its presence with each on startup and uses
    # them for cross-internet peer lookup when mDNS doesn't have the
    # peer.

    def get_rendezvous_urls(self) -> list[str]:
        raw = self.get_setting("rendezvous_urls")
        if not raw:
            return []
        try:
            v = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if not isinstance(v, list):
            return []
        return [str(u) for u in v if isinstance(u, str) and u]

    def set_rendezvous_urls(self, urls: Iterable[str]) -> None:
        clean = sorted({u.strip().rstrip("/") for u in urls if u and u.strip()})
        # Light validation — protocol prefix only.
        for u in clean:
            if not (u.startswith("http://") or u.startswith("https://")):
                raise ValueError(f"rendezvous URL must be http(s): {u!r}")
        self.set_setting("rendezvous_urls", json.dumps(clean))

    # ─── lifecycle ────────────────────────────────────────────────────

    def close(self) -> None:
        with self._write_lock:
            self._conn.close()
