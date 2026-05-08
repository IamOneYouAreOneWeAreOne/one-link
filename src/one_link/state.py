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

-- v0.7.5: per-message emoji reactions. (target_msg_id, peer_fp, emoji)
-- is the natural primary key — each peer can hold at most one of each
-- emoji on a given message (toggle on/off semantics).
CREATE TABLE IF NOT EXISTS message_reactions (
    target_msg_id  TEXT    NOT NULL,
    peer_fp        TEXT    NOT NULL,
    emoji          TEXT    NOT NULL,
    ts_ms          INTEGER NOT NULL,
    PRIMARY KEY (target_msg_id, peer_fp, emoji)
);
CREATE INDEX IF NOT EXISTS idx_reactions_target ON message_reactions(target_msg_id);
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
    # v0.7.3 per-device profile.
    local_alias: Optional[str] = None
    muted: bool = False
    # v0.7.7 verified-in-person trust state. `verified_at_ms` is set
    # the moment the user confirms a side-channel SAS match (face-to-
    # face, QR scan, audio readback). `verified_method` is one of
    # 'sas-digits', 'sas-qr', 'sas-audio', 'manual'. `verified_note`
    # is an optional free-text reminder ("met at office Tue").
    verified_at_ms: Optional[int] = None
    verified_method: Optional[str] = None
    verified_note: Optional[str] = None
    # v0.10.2 disappearing-message TTL. None = off; otherwise every
    # TEXT message sent to / received from this peer carries an
    # expires_at_ms = ts_ms + dm_ttl_ms. The daemon's reaper sweeps
    # expired rows + broadcasts msg_delete WS events.
    dm_ttl_ms: Optional[int] = None
    # v0.11.2 per-chat mute with duration. None = not muted; 0 = muted
    # forever (no auto-expire); N > 0 = muted until wall-clock ms N.
    # is_muted derives this with the current time so an expired mute
    # automatically un-mutes itself.
    muted_until_ms: Optional[int] = None

    @property
    def display_name(self) -> str:
        """Resolves to local_alias if set, else hostname, else short_id."""
        return self.local_alias or self.hostname or self.short_id

    @property
    def is_verified(self) -> bool:
        """v0.7.7: True iff the peer has been verified in person via
        a side-channel SAS confirm. Independent of `trust` — trust
        gates wire access; verification gates UI affordance."""
        return self.verified_at_ms is not None

    def is_muted_at(self, now_ms: int) -> bool:
        """v0.11.2: True iff the per-chat mute is active at `now_ms`.
        muted_until_ms = 0 means muted forever; >0 means muted until
        that timestamp. Falls back to the legacy `muted` boolean for
        rows persisted under v0.7.3 schema before muted_until_ms
        existed."""
        if self.muted_until_ms is not None:
            if self.muted_until_ms == 0:
                return True
            return self.muted_until_ms > now_ms
        return self.muted


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
    # v0.7.5: optional parent message id for reply/quote rendering.
    reply_to: Optional[str] = None
    # v0.7.6: edit / delete state.
    edited_at_ms: Optional[int] = None
    original_body: Optional[str] = None
    deleted_at_ms: Optional[int] = None
    # v0.10.2: disappearing-message expiry (ms epoch). NULL = never.
    expires_at_ms: Optional[int] = None

    @property
    def is_edited(self) -> bool:
        return self.edited_at_ms is not None

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at_ms is not None

    @property
    def is_expiring(self) -> bool:
        return self.expires_at_ms is not None


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
                # v0.7.3: per-device profile fields (local alias + mute).
                self._migrate_v3_peer_profile(c)
                if current < 3:
                    c.execute("INSERT INTO schema_version(version) VALUES(3)")
                # v0.7.5: messages gain reply_to column.
                self._migrate_v4_messages_reply_to(c)
                if current < 4:
                    c.execute("INSERT INTO schema_version(version) VALUES(4)")
                # v0.7.6: messages gain edit/delete columns +
                # per-peer read marker table.
                self._migrate_v5_edit_delete_read(c)
                if current < 5:
                    c.execute("INSERT INTO schema_version(version) VALUES(5)")
                self._migrate_v6_group_reply(c)
                if current < 6:
                    c.execute("INSERT INTO schema_version(version) VALUES(6)")
                self._migrate_v7_group_edit_delete(c)
                if current < 7:
                    c.execute("INSERT INTO schema_version(version) VALUES(7)")
                # v0.7.7: peer verified-in-person trust state.
                self._migrate_v8_peer_verification(c)
                if current < 8:
                    c.execute("INSERT INTO schema_version(version) VALUES(8)")
                # v0.7.8: hostname-pubkey history + key-change events.
                self._migrate_v9_key_change_tracking(c)
                if current < 9:
                    c.execute("INSERT INTO schema_version(version) VALUES(9)")
                # v0.8.9: folder-sync concurrent-edit conflicts.
                self._migrate_v10_folder_conflicts(c)
                if current < 10:
                    c.execute("INSERT INTO schema_version(version) VALUES(10)")
                self._migrate_v11_chunk_availability(c)
                if current < 11:
                    c.execute("INSERT INTO schema_version(version) VALUES(11)")
                # v0.10.2: disappearing messages (per-peer TTL).
                self._migrate_v12_disappearing_messages(c)
                if current < 12:
                    c.execute("INSERT INTO schema_version(version) VALUES(12)")
                self._migrate_v13_prior_chunk_sources(c)
                if current < 13:
                    c.execute("INSERT INTO schema_version(version) VALUES(13)")
                self._migrate_v14_mute_until(c)
                if current < 14:
                    c.execute("INSERT INTO schema_version(version) VALUES(14)")
                self._migrate_v15_file_index_cache(c)
                if current < 15:
                    c.execute("INSERT INTO schema_version(version) VALUES(15)")
            finally:
                c.close()

    def _migrate_v15_file_index_cache(self, c: sqlite3.Cursor) -> None:
        """v0.12.4: durable file fingerprint/manifest cache.

        Large-file sends should not re-hash and re-index an unchanged file
        every time the user sends it. The cache is keyed by canonical path and
        guarded by file size + nanosecond mtimes/ctimes, so a stale row is
        ignored automatically when the file changes.
        """
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS file_index_cache (
                path        TEXT PRIMARY KEY,
                size        INTEGER NOT NULL,
                mtime_ns    INTEGER NOT NULL,
                ctime_ns    INTEGER NOT NULL,
                blob_hash   TEXT    NOT NULL,
                index_kind  TEXT    NOT NULL,
                chunks_json TEXT    NOT NULL,
                updated_ms  INTEGER NOT NULL
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_file_index_cache_updated "
            "ON file_index_cache(updated_ms)"
        )

    def _migrate_v14_mute_until(self, c: sqlite3.Cursor) -> None:
        """v0.11.2: per-chat mute with duration.

        peers.muted_until_ms — wall-clock ms after which the mute
        auto-expires. NULL = not muted. 0 = muted forever (no auto-
        expire). N > 0 = muted until ts N. The legacy `muted` boolean
        column from v0.7.3 stays in place for back-compat but is now
        a derived value (muted_until_ms IS NOT NULL AND
        (muted_until_ms = 0 OR muted_until_ms > now)).

        Group mutes use the existing settings table keyed as
        `group_mute:<group_id_hex>` = until_ms — no schema change
        needed for the group case."""
        rows = c.execute("PRAGMA table_info(peers)").fetchall()
        existing = {row[1] for row in rows}
        if "muted_until_ms" not in existing:
            c.execute("ALTER TABLE peers ADD COLUMN muted_until_ms INTEGER")

    def _migrate_v13_prior_chunk_sources(self, c: sqlite3.Cursor) -> None:
        """v0.10.3: path-backed chunk sources for prior knowledge transfer.

        The chunk cache stores bytes only after a chunk is actually needed.
        This table lets the daemon remember that a verified chunk exists in a
        local inbox/sync-folder file at a byte range, then hydrate it lazily.
        """
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS chunk_sources (
                chunk_hash TEXT NOT NULL,
                path       TEXT NOT NULL,
                start      INTEGER NOT NULL,
                size       INTEGER NOT NULL,
                mtime_ms   INTEGER NOT NULL,
                file_size  INTEGER NOT NULL,
                source     TEXT NOT NULL DEFAULT 'prior',
                updated_ms INTEGER NOT NULL,
                PRIMARY KEY(chunk_hash, path, start)
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_chunk_sources_hash "
            "ON chunk_sources(chunk_hash)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_chunk_sources_updated "
            "ON chunk_sources(updated_ms)"
        )

    def _migrate_v12_disappearing_messages(self, c: sqlite3.Cursor) -> None:
        """v0.10.2: per-peer disappearing-message TTL.

        peers.dm_ttl_ms — when set, every TEXT message exchanged with
        this peer carries an expires_at_ms = ts_ms + dm_ttl_ms. None
        = TTL off (default). Both ends must support v12 for end-to-end
        expiry — receivers running older builds keep the message
        forever; sender's local copy still expires.

        messages.expires_at_ms — wall-clock ms when this row should
        be tombstoned. NULL = never expires (legacy + non-TTL chats).
        Indexed for fast reaper sweeps."""
        rows = c.execute("PRAGMA table_info(peers)").fetchall()
        existing = {row[1] for row in rows}
        if "dm_ttl_ms" not in existing:
            c.execute("ALTER TABLE peers ADD COLUMN dm_ttl_ms INTEGER")
        rows = c.execute("PRAGMA table_info(messages)").fetchall()
        existing = {row[1] for row in rows}
        if "expires_at_ms" not in existing:
            c.execute("ALTER TABLE messages ADD COLUMN expires_at_ms INTEGER")
        # Partial index — only rows with non-NULL expires_at_ms are
        # candidates for the reaper sweep, so a partial index keeps
        # the index page footprint tiny on chats that never use TTL.
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_expiry "
            "ON messages(expires_at_ms) "
            "WHERE expires_at_ms IS NOT NULL"
        )

    def _migrate_v11_chunk_availability(self, c: sqlite3.Cursor) -> None:
        """v0.9.x: local chunk availability index for swarm transfer."""
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS chunk_availability (
                chunk_hash  TEXT PRIMARY KEY,
                size        INTEGER NOT NULL,
                blob_hash   TEXT,
                chunk_index INTEGER,
                source      TEXT NOT NULL DEFAULT 'local',
                updated_ms  INTEGER NOT NULL
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_chunk_availability_blob "
            "ON chunk_availability(blob_hash)"
        )

    def _migrate_v10_folder_conflicts(self, c: sqlite3.Cursor) -> None:
        """v0.8.9: track CRDT-detected concurrent edits to the same
        file path. Today merge_manifest_entries silently latest-wins
        on the concurrent case; v0.8.9 records both sides so the user
        can override via the Folders → Conflicts UI. Idempotent."""
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS manifest_conflicts (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                folder_name         TEXT    NOT NULL,
                file_path           TEXT    NOT NULL,
                detected_ms         INTEGER NOT NULL,
                peer_fp             TEXT,
                -- local snapshot at detection time
                local_blob_hash     TEXT,
                local_size          INTEGER,
                local_mtime_ms      INTEGER,
                local_vclock_json   TEXT    NOT NULL,
                -- remote snapshot
                remote_blob_hash    TEXT,
                remote_size         INTEGER,
                remote_mtime_ms     INTEGER,
                remote_vclock_json  TEXT    NOT NULL,
                -- which side was applied as the auto-merge winner
                applied_choice      TEXT    NOT NULL,
                -- user resolution
                resolved_ms         INTEGER,
                resolution          TEXT,
                resolved_by         TEXT
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_mc_folder"
            " ON manifest_conflicts(folder_name)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_mc_unresolved"
            " ON manifest_conflicts(resolved_ms)"
        )

    def _migrate_v9_key_change_tracking(self, c: sqlite3.Cursor) -> None:
        """v0.7.8: track every (hostname, ed_pub_hex) ever observed
        + log conflict events when a hostname rotates pubkeys (the
        re-install / MITM scenario). Idempotent."""
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS hostname_keys (
                hostname      TEXT    NOT NULL,
                ed_pub_hex    TEXT    NOT NULL,
                fingerprint   TEXT    NOT NULL,
                first_seen_ms INTEGER NOT NULL,
                last_seen_ms  INTEGER NOT NULL,
                PRIMARY KEY (hostname, ed_pub_hex)
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_hostname_keys_host"
            " ON hostname_keys(hostname)"
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS key_change_events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ms           INTEGER NOT NULL,
                hostname        TEXT    NOT NULL,
                old_fingerprint TEXT    NOT NULL,
                new_fingerprint TEXT    NOT NULL,
                old_pub_hex     TEXT    NOT NULL,
                new_pub_hex     TEXT    NOT NULL,
                severity        TEXT    NOT NULL,
                acked_ms        INTEGER
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_kce_acked"
            " ON key_change_events(acked_ms)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_kce_new_fp"
            " ON key_change_events(new_fingerprint)"
        )

    def _migrate_v8_peer_verification(self, c: sqlite3.Cursor) -> None:
        """v0.7.7: peers gain side-channel verification state.
        Idempotent — safe to re-run."""
        rows = c.execute("PRAGMA table_info(peers)").fetchall()
        existing = {row[1] for row in rows}
        if "verified_at_ms" not in existing:
            c.execute("ALTER TABLE peers ADD COLUMN verified_at_ms INTEGER")
        if "verified_method" not in existing:
            c.execute("ALTER TABLE peers ADD COLUMN verified_method TEXT")
        if "verified_note" not in existing:
            c.execute("ALTER TABLE peers ADD COLUMN verified_note TEXT")

    def _migrate_v6_group_reply(self, c: sqlite3.Cursor) -> None:
        """v0.8.2: group messages gain reply_to for threaded context."""
        rows = c.execute("PRAGMA table_info(group_messages)").fetchall()
        existing = {row[1] for row in rows}
        if "reply_to" not in existing:
            c.execute("ALTER TABLE group_messages ADD COLUMN reply_to TEXT")

    def _migrate_v7_group_edit_delete(self, c: sqlite3.Cursor) -> None:
        """v0.8.2: group messages gain edit/delete state."""
        rows = c.execute("PRAGMA table_info(group_messages)").fetchall()
        existing = {row[1] for row in rows}
        if "edited_at_ms" not in existing:
            c.execute("ALTER TABLE group_messages ADD COLUMN edited_at_ms INTEGER")
        if "original_body" not in existing:
            c.execute("ALTER TABLE group_messages ADD COLUMN original_body TEXT")
        if "deleted_at_ms" not in existing:
            c.execute("ALTER TABLE group_messages ADD COLUMN deleted_at_ms INTEGER")

    def _migrate_v5_edit_delete_read(self, c: sqlite3.Cursor) -> None:
        """v0.7.6: add edit_at_ms / original_body / deleted_at_ms
        columns to messages, plus a peer_read_markers table for
        receipt tracking. Idempotent — safe to re-run."""
        rows = c.execute("PRAGMA table_info(messages)").fetchall()
        existing = {row[1] for row in rows}
        if "edited_at_ms" not in existing:
            c.execute("ALTER TABLE messages ADD COLUMN edited_at_ms INTEGER")
        if "original_body" not in existing:
            c.execute("ALTER TABLE messages ADD COLUMN original_body TEXT")
        if "deleted_at_ms" not in existing:
            c.execute("ALTER TABLE messages ADD COLUMN deleted_at_ms INTEGER")
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS peer_read_markers (
                peer_fp        TEXT    PRIMARY KEY,
                up_to_ts_ms    INTEGER NOT NULL,
                updated_ms     INTEGER NOT NULL
            )
            """
        )

    def schema_version(self) -> int:
        """Return the latest applied schema version.

        Exposed through daemon status so launchers and UIs can detect a
        stale backend before the user hits a broken feature path.
        """
        try:
            row = self._conn.execute(
                "SELECT MAX(version) AS version FROM schema_version"
            ).fetchone()
            return int(row["version"] or 0) if row else 0
        except Exception:
            return 0

    def _migrate_v4_messages_reply_to(self, c: sqlite3.Cursor) -> None:
        """v0.7.5: messages.reply_to is the parent msg_id when a row
        is a reply/quote. Idempotent."""
        rows = c.execute("PRAGMA table_info(messages)").fetchall()
        existing = {row[1] for row in rows}
        if "reply_to" not in existing:
            c.execute("ALTER TABLE messages ADD COLUMN reply_to TEXT")

    def _migrate_v3_peer_profile(self, c: sqlite3.Cursor) -> None:
        """v0.7.3: add per-peer profile columns. local_alias is a
        user-set name override that wins over remote-advertised
        hostname in the UI. muted suppresses desktop notifications
        for messages from this peer (no protocol effect).
        Idempotent."""
        rows = c.execute("PRAGMA table_info(peers)").fetchall()
        existing = {row[1] for row in rows}
        if "local_alias" not in existing:
            c.execute("ALTER TABLE peers ADD COLUMN local_alias TEXT")
        if "muted" not in existing:
            c.execute(
                "ALTER TABLE peers ADD COLUMN muted INTEGER NOT NULL DEFAULT 0"
            )

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
                # v0.7.8: track hostname↔key history + raise a key-change
                # event whenever a hostname rotates fingerprints. The
                # detection happens here (post-INSERT) so it covers every
                # code path that upserts a peer (handshake, discovery,
                # snapshot rehydration). pubkey is bytes — convert once.
                # The new-event id (if any) is stashed on the returned
                # PeerRecord via `_pending_key_change_event_id` so the
                # daemon can broadcast it without a second query.
                new_event_id: Optional[int] = None
                if hostname:
                    try:
                        ed_pub_hex = pubkey.hex() if isinstance(pubkey, (bytes, bytearray)) else str(pubkey)
                        new_event_id = self._record_hostname_key_seen_locked(
                            c=c,
                            hostname=hostname,
                            ed_pub_hex=ed_pub_hex,
                            fingerprint=fingerprint,
                            now=now,
                        )
                    except Exception:
                        # Detection failure must never block a peer
                        # upsert — log via daemon if needed, but the
                        # peer table is the source of truth.
                        pass
                rec = self._row_to_peer(row)
                if new_event_id is not None:
                    # Attach as a runtime-only attribute; the dataclass
                    # itself is unchanged so callers that don't care
                    # see no difference.
                    object.__setattr__(rec, "_pending_key_change_event_id", new_event_id)
                return rec
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
        applied_default_ttl = False
        with self._write_lock:
            row = self._conn.execute(
                "SELECT trust, dm_ttl_ms FROM peers WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            before = row["trust"] if row else None
            had_ttl = row and row["dm_ttl_ms"] is not None
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
            # v0.11.6: when transitioning to "pinned" for the first
            # time AND the user has a default disappearing-msg TTL
            # set globally AND this peer has no per-chat TTL, copy
            # the default in. This is the "applies to new pairings"
            # promise from the Storage settings pane.
            if (
                trust == "pinned"
                and before != "pinned"
                and not had_ttl
            ):
                raw = self._conn.execute(
                    "SELECT value FROM settings WHERE key = 'default_dm_ttl_ms'"
                ).fetchone()
                if raw is not None:
                    try:
                        default_ttl = int(raw["value"])
                    except (TypeError, ValueError):
                        default_ttl = 0
                    if default_ttl > 0:
                        self._conn.execute(
                            "UPDATE peers SET dm_ttl_ms = ? "
                            "WHERE fingerprint = ?",
                            (default_ttl, fingerprint),
                        )
                        applied_default_ttl = True
        # Returning intentionally None to preserve existing call
        # sites; applied_default_ttl is for tests + a future caller
        # that wants the signal.

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

    def activity_feed(
        self,
        *,
        since_ms: Optional[int] = None,
        kinds: Optional[Iterable[str]] = None,
        peer_fp: Optional[str] = None,
        limit: int = 200,
    ) -> list[dict]:
        """v0.9.1: cross-peer activity feed merging:
          - capability_audit (verify_set, verify_clear, trust_set,
            cap_policy_set, cap_policy_clear)
          - key_change_events (in + out)
          - transfers (file_send / file_recv complete + failed)
          - manifest_conflicts (detected + resolved)
          - peer first_seen synthetic events

        Returns newest-first rows, each shaped:
          {ts_ms, kind, severity, label, detail, peer_fp,
           peer_display_name, source}.

        Filters:
          - since_ms: drop rows with ts_ms < since_ms
          - kinds: keep only rows whose top-level kind matches
            (one of: trust, key_change, transfer, conflict, peer)
          - peer_fp: keep only rows attributable to this peer
          - limit: cap final list (default 200, hard max 2000)"""
        limit = max(1, min(int(limit), 2000))
        kinds_set = set(kinds) if kinds else None

        events: list[dict] = []
        peer_cache: dict[str, str] = {}

        def _peer_label(fp: Optional[str]) -> Optional[str]:
            if not fp:
                return None
            if fp in peer_cache:
                return peer_cache[fp]
            rec = self.get_peer(fp)
            label = rec.display_name if rec else fp[:8]
            peer_cache[fp] = label
            return label

        # 1. capability_audit → trust kind
        if kinds_set is None or "trust" in kinds_set:
            sql = (
                "SELECT id, ts_ms, fingerprint, kind, before_json,"
                " after_json, actor, note FROM capability_audit"
            )
            params: list[Any] = []
            wclauses: list[str] = []
            if since_ms is not None:
                wclauses.append("ts_ms >= ?"); params.append(int(since_ms))
            if peer_fp is not None:
                wclauses.append("fingerprint = ?"); params.append(peer_fp)
            if wclauses:
                sql += " WHERE " + " AND ".join(wclauses)
            sql += " ORDER BY ts_ms DESC LIMIT ?"
            params.append(limit)
            for r in self._conn.execute(sql, tuple(params)).fetchall():
                k = r["kind"]
                if k == "verify_set":
                    label, sev = "Verified in person", "good"
                elif k == "verify_clear":
                    label, sev = "Verification revoked", "warn"
                elif k == "trust_set":
                    after = json.loads(r["after_json"] or "null")
                    label = f"Trust → {after}"
                    sev = "info" if after == "pinned" else (
                        "bad" if after == "rejected" else "warn"
                    )
                elif k == "cap_policy_set":
                    label, sev = "Permissions changed", "info"
                elif k == "cap_policy_clear":
                    label, sev = "Permissions cleared (allow all)", "info"
                else:
                    label, sev = k.replace("_", " ").title(), "info"
                events.append({
                    "ts_ms": r["ts_ms"],
                    "kind": "trust",
                    "subkind": k,
                    "severity": sev,
                    "label": label,
                    "detail": r["note"] or "",
                    "peer_fp": r["fingerprint"],
                    "peer_display_name": _peer_label(r["fingerprint"]),
                    "source": "capability_audit",
                })

        # 2. key_change_events → key_change kind
        if kinds_set is None or "key_change" in kinds_set:
            sql = (
                "SELECT id, ts_ms, hostname, old_fingerprint,"
                " new_fingerprint, severity, acked_ms"
                " FROM key_change_events"
            )
            wclauses = []
            params = []
            if since_ms is not None:
                wclauses.append("ts_ms >= ?"); params.append(int(since_ms))
            if peer_fp is not None:
                wclauses.append("(new_fingerprint = ? OR old_fingerprint = ?)")
                params.extend([peer_fp, peer_fp])
            if wclauses:
                sql += " WHERE " + " AND ".join(wclauses)
            sql += " ORDER BY ts_ms DESC LIMIT ?"
            params.append(limit)
            for r in self._conn.execute(sql, tuple(params)).fetchall():
                sev = r["severity"] or "low"
                evsev = "bad" if sev == "high" else (
                    "warn" if sev == "medium" else "info"
                )
                events.append({
                    "ts_ms": r["ts_ms"],
                    "kind": "key_change",
                    "subkind": "detected",
                    "severity": evsev,
                    "label": f"Key change · {r['hostname']}",
                    "detail": (
                        f"old {r['old_fingerprint'][:8]}… → "
                        f"new {r['new_fingerprint'][:8]}…"
                        + (" (acknowledged)" if r["acked_ms"] else " (unacked)")
                    ),
                    "peer_fp": r["new_fingerprint"],
                    "peer_display_name": _peer_label(r["new_fingerprint"]),
                    "source": "key_change_events",
                })

        # 3. transfers → transfer kind. Only terminal states are
        # interesting in the feed (mid-flight is the chat bubble's job).
        if kinds_set is None or "transfer" in kinds_set:
            sql = (
                "SELECT id, direction, peer_fp, kind AS tkind, name,"
                " size, status, updated_ms, metadata_json"
                " FROM transfers"
                " WHERE status IN ('complete', 'failed')"
            )
            params = []
            if since_ms is not None:
                sql += " AND updated_ms >= ?"; params.append(int(since_ms))
            if peer_fp is not None:
                sql += " AND peer_fp = ?"; params.append(peer_fp)
            sql += " ORDER BY updated_ms DESC LIMIT ?"
            params.append(limit)
            for r in self._conn.execute(sql, tuple(params)).fetchall():
                ok = (r["status"] == "complete")
                direction = r["direction"]
                verb = (
                    "Received" if (ok and direction == "in") else
                    "Sent" if (ok and direction == "out") else
                    ("Receive failed" if direction == "in" else "Send failed")
                )
                label = f"{verb}: {r['name'] or '?'}"
                detail_parts = [r["tkind"] or "file"]
                if r["size"] is not None:
                    bsz = r["size"]
                    # Inline size formatting (KB/MB/GB) — same logic
                    # as fmtBytes on the client.
                    units = ["B", "KB", "MB", "GB", "TB"]
                    j = 0
                    while bsz >= 1024 and j < len(units) - 1:
                        bsz /= 1024
                        j += 1
                    fmt = f"{bsz:.1f} {units[j]}" if j > 0 and bsz < 10 else f"{int(bsz)} {units[j]}"
                    detail_parts.append(fmt)
                events.append({
                    "ts_ms": r["updated_ms"],
                    "kind": "transfer",
                    "subkind": "complete" if ok else "failed",
                    "severity": "good" if ok else "bad",
                    "label": label,
                    "detail": " · ".join(detail_parts),
                    "peer_fp": r["peer_fp"],
                    "peer_display_name": _peer_label(r["peer_fp"]),
                    "source": "transfers",
                })

        # 4. manifest_conflicts → conflict kind
        if kinds_set is None or "conflict" in kinds_set:
            sql = (
                "SELECT id, folder_name, file_path, peer_fp,"
                " detected_ms, resolved_ms, resolution"
                " FROM manifest_conflicts"
            )
            wclauses = []
            params = []
            if since_ms is not None:
                wclauses.append("detected_ms >= ?"); params.append(int(since_ms))
            if peer_fp is not None:
                wclauses.append("peer_fp = ?"); params.append(peer_fp)
            if wclauses:
                sql += " WHERE " + " AND ".join(wclauses)
            sql += " ORDER BY detected_ms DESC LIMIT ?"
            params.append(limit)
            for r in self._conn.execute(sql, tuple(params)).fetchall():
                events.append({
                    "ts_ms": r["detected_ms"],
                    "kind": "conflict",
                    "subkind": "resolved" if r["resolved_ms"] else "detected",
                    "severity": "warn" if not r["resolved_ms"] else "info",
                    "label": (
                        f"Folder conflict ({r['resolution']})" if r["resolved_ms"]
                        else "Folder conflict detected"
                    ),
                    "detail": f"{r['folder_name']}/{r['file_path']}",
                    "peer_fp": r["peer_fp"],
                    "peer_display_name": _peer_label(r["peer_fp"]),
                    "source": "manifest_conflicts",
                })

        # 5. peer first_seen synthetic events
        if kinds_set is None or "peer" in kinds_set:
            sql = "SELECT fingerprint, hostname, first_seen_ms FROM peers"
            wclauses = []
            params = []
            if since_ms is not None:
                wclauses.append("first_seen_ms >= ?"); params.append(int(since_ms))
            if peer_fp is not None:
                wclauses.append("fingerprint = ?"); params.append(peer_fp)
            if wclauses:
                sql += " WHERE " + " AND ".join(wclauses)
            sql += " ORDER BY first_seen_ms DESC LIMIT ?"
            params.append(limit)
            for r in self._conn.execute(sql, tuple(params)).fetchall():
                events.append({
                    "ts_ms": r["first_seen_ms"],
                    "kind": "peer",
                    "subkind": "first_seen",
                    "severity": "info",
                    "label": f"Device first seen · {r['hostname'] or r['fingerprint'][:8]}",
                    "detail": "",
                    "peer_fp": r["fingerprint"],
                    "peer_display_name": _peer_label(r["fingerprint"]),
                    "source": "peers",
                })

        events.sort(key=lambda e: e["ts_ms"], reverse=True)
        return events[:limit]

    def peer_trust_history(
        self,
        fingerprint: str,
        *,
        limit: int = 200,
    ) -> list[dict]:
        """v0.8.6: merged chronological trust history for one peer.

        Combines four sources into a single timeline (newest first):
          - peers row's first_seen_ms (synthetic 'first_seen' event)
          - capability_audit rows (verify_set, verify_clear, trust_set,
            cap_policy_set, cap_policy_clear)
          - key_change_events where this fingerprint is the new_fp
            OR the old_fp (rotation events affect both ends)
          - hostname_keys first_seen for any pubkey ever attached to
            the peer's hostname (synthetic 'pubkey_first_seen' event)

        Each entry is a uniform dict with keys: ts_ms, kind, label,
        detail, severity, source. The UI just renders the list — no
        further classification needed."""
        peer = self.get_peer(fingerprint)
        if peer is None:
            return []
        events: list[dict] = []

        # 1. First-seen synthetic event from the peers row.
        events.append({
            "ts_ms": peer.first_seen_ms,
            "kind": "first_seen",
            "label": "Device first seen",
            "detail": f"hostname: {peer.hostname or '(unknown)'}",
            "severity": "info",
            "source": "peers",
        })

        # 2. capability_audit: rich. Translate each kind to a human label.
        audit = self.recent_capability_audit(
            fingerprint=fingerprint, limit=limit,
        )
        for row in audit:
            kind = row["kind"]
            if kind == "verify_set":
                method = (row["after"] or {}).get("verified_method") if isinstance(row["after"], dict) else None
                events.append({
                    "ts_ms": row["ts_ms"],
                    "kind": kind,
                    "label": "Verified in person",
                    "detail": (
                        f"method: {method}" + (f" · note: {row['note']}" if row["note"] else "")
                        if method else (row["note"] or "")
                    ),
                    "severity": "good",
                    "source": "capability_audit",
                })
            elif kind == "verify_clear":
                events.append({
                    "ts_ms": row["ts_ms"],
                    "kind": kind,
                    "label": "Verification revoked",
                    "detail": row["note"] or "",
                    "severity": "warn",
                    "source": "capability_audit",
                })
            elif kind == "trust_set":
                before = row["before"]
                after = row["after"]
                events.append({
                    "ts_ms": row["ts_ms"],
                    "kind": kind,
                    "label": f"Trust changed: {before or '?'} → {after or '?'}",
                    "detail": row["note"] or "",
                    "severity": "info" if after == "pinned" else (
                        "bad" if after == "rejected" else "warn"
                    ),
                    "source": "capability_audit",
                })
            elif kind in ("cap_policy_set", "cap_policy_clear"):
                before = row["before"]
                after = row["after"]
                if kind == "cap_policy_clear":
                    label = "Permissions cleared (allow all)"
                    detail = ""
                else:
                    after_list = after if isinstance(after, list) else []
                    detail = (
                        f"now allow: {', '.join(after_list) or '(none)'}"
                    )
                    label = "Permissions changed"
                events.append({
                    "ts_ms": row["ts_ms"],
                    "kind": kind,
                    "label": label,
                    "detail": detail + ((" · " + row["note"]) if row["note"] else ""),
                    "severity": "info",
                    "source": "capability_audit",
                })
            else:
                events.append({
                    "ts_ms": row["ts_ms"],
                    "kind": kind,
                    "label": kind.replace("_", " ").title(),
                    "detail": row["note"] or "",
                    "severity": "info",
                    "source": "capability_audit",
                })

        # 3. key_change_events: include any event where this peer is
        # either the rotated-out fingerprint (old_fp) or rotated-in
        # fingerprint (new_fp). Both contexts are useful: "this device
        # used to be X, now it's Y" and "this device replaces Z".
        kce_in = self.list_key_change_events(
            new_fingerprint=fingerprint, limit=limit,
        )
        for ev in kce_in:
            sev = ev["severity"]
            events.append({
                "ts_ms": ev["ts_ms"],
                "kind": "key_change_in",
                "label": "Key change detected (this device replaces a prior one)",
                "detail": (
                    f"prior fp: {ev['old_fingerprint'][:8]}… · severity: {sev}"
                    + (" · acknowledged" if ev["acked_ms"] else " · UNACKNOWLEDGED")
                ),
                "severity": "bad" if sev == "high" else (
                    "warn" if sev == "medium" else "info"
                ),
                "source": "key_change_events",
            })
        # rotated-out (this peer's fingerprint shows up as old_fp).
        # No filter helper for old_fp; do a direct query.
        old_rows = self._conn.execute(
            "SELECT id, ts_ms, hostname, old_fingerprint, new_fingerprint,"
            " severity, acked_ms FROM key_change_events"
            " WHERE old_fingerprint = ? ORDER BY ts_ms DESC LIMIT ?",
            (fingerprint, int(limit)),
        ).fetchall()
        for r in old_rows:
            events.append({
                "ts_ms": r["ts_ms"],
                "kind": "key_change_out",
                "label": "This device was rotated out",
                "detail": (
                    f"replaced by: {r['new_fingerprint'][:8]}…"
                    + (" · acknowledged" if r["acked_ms"] else " · UNACKNOWLEDGED")
                ),
                "severity": "bad" if r["severity"] == "high" else (
                    "warn" if r["severity"] == "medium" else "info"
                ),
                "source": "key_change_events",
            })

        # Sort newest-first, cap to `limit`.
        events.sort(key=lambda e: e["ts_ms"], reverse=True)
        return events[:limit]

    # ─── key-change tracking (v0.7.8) ─────────────────────────────────

    def _record_hostname_key_seen_locked(
        self,
        *,
        c: sqlite3.Cursor,
        hostname: str,
        ed_pub_hex: str,
        fingerprint: str,
        now: int,
    ) -> Optional[int]:
        """Internal: insert/update the hostname_keys row for this
        observation, AND if the hostname has previously been seen with
        a DIFFERENT pubkey, emit a key_change_events row.

        Severity is graded by the strongest prior trust observed:
          - 'high'   ← any prior fingerprint for this hostname is pinned
          - 'medium' ← any prior fingerprint exists in peers (pending)
          - 'low'    ← only seen via discovery, never persisted in peers
        Caller must hold self._write_lock and pass an open cursor.
        Detection runs AFTER the upsert_peer INSERT so the new (hostname,
        pubkey) pair sees its own peers row — we filter it out via the
        `fingerprint != ?` clause below.

        Returns the integer id of the freshly-inserted key_change_events
        row (so the caller can broadcast it in real time), or None if
        no new conflict was logged."""
        # 1. Find any conflicting prior observation.
        prior_rows = c.execute(
            "SELECT ed_pub_hex, fingerprint FROM hostname_keys"
            " WHERE hostname = ? AND ed_pub_hex != ?"
            " ORDER BY last_seen_ms DESC",
            (hostname, ed_pub_hex),
        ).fetchall()
        # 2. Upsert the current (hostname, ed_pub_hex) row.
        c.execute(
            """
            INSERT INTO hostname_keys(
                hostname, ed_pub_hex, fingerprint,
                first_seen_ms, last_seen_ms
            ) VALUES(?, ?, ?, ?, ?)
            ON CONFLICT(hostname, ed_pub_hex) DO UPDATE SET
                last_seen_ms = excluded.last_seen_ms,
                fingerprint  = excluded.fingerprint
            """,
            (hostname, ed_pub_hex, fingerprint, now, now),
        )
        # 3. If we found a conflict AND haven't already logged this
        # exact (old_fp, new_fp) pair, write a key_change_events row.
        if not prior_rows:
            return None
        new_event_id: Optional[int] = None
        for old in prior_rows:
            old_fp = old["fingerprint"]
            old_pub_hex = old["ed_pub_hex"]
            if old_fp == fingerprint:
                # Hostname was reattached to a row we already wrote
                # under a different ed_pub_hex column — defensive guard,
                # shouldn't normally happen.
                continue
            # Idempotency: have we already logged THIS specific
            # (old_fp → new_fp) transition? If so, just bump nothing —
            # the existing row stays, acked or not.
            already = c.execute(
                "SELECT 1 FROM key_change_events"
                " WHERE hostname = ? AND old_fingerprint = ?"
                " AND new_fingerprint = ? LIMIT 1",
                (hostname, old_fp, fingerprint),
            ).fetchone()
            if already:
                continue
            # Severity grading via prior peers row's trust state.
            old_peer = c.execute(
                "SELECT trust FROM peers WHERE fingerprint = ?",
                (old_fp,),
            ).fetchone()
            if old_peer is not None and old_peer["trust"] == "pinned":
                severity = "high"
            elif old_peer is not None:
                severity = "medium"
            else:
                severity = "low"
            cur = c.execute(
                """
                INSERT INTO key_change_events(
                    ts_ms, hostname,
                    old_fingerprint, new_fingerprint,
                    old_pub_hex, new_pub_hex,
                    severity, acked_ms
                ) VALUES(?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    now, hostname,
                    old_fp, fingerprint,
                    old_pub_hex, ed_pub_hex,
                    severity,
                ),
            )
            # First conflict (most-recent prior, if multiple) wins as
            # the broadcast id. Subsequent prior_rows iterations will
            # only fire when the hostname has rotated keys 3+ times,
            # which is rare; keeping the freshest is the practical UX.
            if new_event_id is None:
                new_event_id = int(cur.lastrowid)
        return new_event_id

    def list_hostname_keys(self, hostname: str) -> list[dict]:
        """Return every (ed_pub_hex, fingerprint, first_seen, last_seen)
        we've observed for a hostname, freshest first. Powers the
        device drawer's 'Key history' section."""
        rows = self._conn.execute(
            "SELECT hostname, ed_pub_hex, fingerprint,"
            " first_seen_ms, last_seen_ms FROM hostname_keys"
            " WHERE hostname = ? ORDER BY last_seen_ms DESC",
            (hostname,),
        ).fetchall()
        return [
            {
                "hostname": r["hostname"],
                "ed_pub_hex": r["ed_pub_hex"],
                "fingerprint": r["fingerprint"],
                "first_seen_ms": r["first_seen_ms"],
                "last_seen_ms": r["last_seen_ms"],
            }
            for r in rows
        ]

    def list_key_change_events(
        self,
        *,
        unacked_only: bool = False,
        new_fingerprint: Optional[str] = None,
        limit: int = 200,
    ) -> list[dict]:
        """Return key-change events, freshest first. UI surfaces use
        `unacked_only=True` to drive the red banner; the device drawer
        passes `new_fingerprint=fp` to list events targeting that
        specific peer."""
        sql = (
            "SELECT id, ts_ms, hostname, old_fingerprint, new_fingerprint,"
            " old_pub_hex, new_pub_hex, severity, acked_ms"
            " FROM key_change_events"
        )
        clauses: list[str] = []
        params: list[Any] = []
        if unacked_only:
            clauses.append("acked_ms IS NULL")
        if new_fingerprint is not None:
            clauses.append("new_fingerprint = ?")
            params.append(new_fingerprint)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY ts_ms DESC, id DESC LIMIT ?"
        params.append(int(limit))
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [
            {
                "id": r["id"],
                "ts_ms": r["ts_ms"],
                "hostname": r["hostname"],
                "old_fingerprint": r["old_fingerprint"],
                "new_fingerprint": r["new_fingerprint"],
                "old_pub_hex": r["old_pub_hex"],
                "new_pub_hex": r["new_pub_hex"],
                "severity": r["severity"],
                "acked_ms": r["acked_ms"],
            }
            for r in rows
        ]

    def ack_key_change_event(self, event_id: int) -> bool:
        """Mark a key-change event acknowledged. Returns True if a
        previously-unacked row was just acked, False if the row didn't
        exist OR was already acked."""
        with self._write_lock:
            cur = self._conn.execute(
                "UPDATE key_change_events SET acked_ms = ?"
                " WHERE id = ? AND acked_ms IS NULL",
                (_now_ms(), int(event_id)),
            )
            return cur.rowcount > 0

    def ack_all_key_change_events_for(self, new_fingerprint: str) -> int:
        """Bulk-ack every unacked event targeting a peer (used when
        the device drawer's 'Got it' button is clicked). Returns the
        count of rows just acked."""
        with self._write_lock:
            cur = self._conn.execute(
                "UPDATE key_change_events SET acked_ms = ?"
                " WHERE new_fingerprint = ? AND acked_ms IS NULL",
                (_now_ms(), new_fingerprint),
            )
            return cur.rowcount or 0

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
        reply_to: Optional[str] = None,
        ts_ms: Optional[int] = None,
    ) -> None:
        with self._write_lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO group_messages(
                    id, group_id, sender_pub, epoch, counter,
                    direction, body, reply_to, ts_ms
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (id, group_id, sender_pub, int(epoch), int(counter),
                 direction, body, reply_to,
                 int(ts_ms if ts_ms is not None else _now_ms())),
            )

    def recent_group_messages(
        self,
        *,
        group_id: bytes,
        limit: int = 100,
    ) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, group_id, sender_pub, epoch, counter, direction, "
            "body, reply_to, edited_at_ms, original_body, deleted_at_ms, "
            "ts_ms FROM group_messages WHERE group_id = ? "
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
                "reply_to": r["reply_to"] if "reply_to" in r.keys() else None,
                "edited_at_ms": r["edited_at_ms"] if "edited_at_ms" in r.keys() else None,
                "original_body": r["original_body"] if "original_body" in r.keys() else None,
                "deleted_at_ms": r["deleted_at_ms"] if "deleted_at_ms" in r.keys() else None,
                "ts_ms": r["ts_ms"],
            }
            for r in rows
        ]

    def get_group_message(self, id: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT id, group_id, sender_pub, epoch, counter, direction, "
            "body, reply_to, edited_at_ms, original_body, deleted_at_ms, ts_ms "
            "FROM group_messages WHERE id = ?",
            (id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "group_id": row["group_id"],
            "sender_pub": row["sender_pub"],
            "epoch": row["epoch"],
            "counter": row["counter"],
            "direction": row["direction"],
            "body": row["body"],
            "reply_to": row["reply_to"],
            "edited_at_ms": row["edited_at_ms"],
            "original_body": row["original_body"],
            "deleted_at_ms": row["deleted_at_ms"],
            "ts_ms": row["ts_ms"],
        }

    def edit_group_message(
        self, *, id: str, new_body: str, edited_at_ms: int,
    ) -> Optional[dict]:
        cur = self.get_group_message(id)
        if cur is None or cur.get("deleted_at_ms"):
            return None
        original = cur.get("original_body") or cur.get("body")
        with self._write_lock:
            self._conn.execute(
                "UPDATE group_messages SET body = ?, edited_at_ms = ?, "
                "original_body = COALESCE(original_body, ?) "
                "WHERE id = ? AND deleted_at_ms IS NULL",
                (new_body, int(edited_at_ms), original, id),
            )
        return self.get_group_message(id)

    def delete_group_message(
        self, *, id: str, deleted_at_ms: int,
    ) -> Optional[dict]:
        cur = self.get_group_message(id)
        if cur is None:
            return None
        if cur.get("deleted_at_ms"):
            return cur
        with self._write_lock:
            self._conn.execute(
                "UPDATE group_messages SET body = NULL, deleted_at_ms = ? "
                "WHERE id = ? AND deleted_at_ms IS NULL",
                (int(deleted_at_ms), id),
            )
        return self.get_group_message(id)

    def _row_to_peer(self, row: sqlite3.Row) -> PeerRecord:
        cols = row.keys()
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
            local_alias=(
                row["local_alias"] if "local_alias" in cols else None
            ),
            muted=bool(row["muted"]) if "muted" in cols else False,
            verified_at_ms=(
                row["verified_at_ms"]
                if "verified_at_ms" in cols else None
            ),
            verified_method=(
                row["verified_method"]
                if "verified_method" in cols else None
            ),
            verified_note=(
                row["verified_note"]
                if "verified_note" in cols else None
            ),
            dm_ttl_ms=(
                row["dm_ttl_ms"]
                if "dm_ttl_ms" in cols else None
            ),
            muted_until_ms=(
                row["muted_until_ms"]
                if "muted_until_ms" in cols else None
            ),
        )

    def set_peer_profile(
        self,
        fingerprint: str,
        *,
        local_alias: Optional[str] = ...,  # type: ignore[assignment]
        muted: Optional[bool] = ...,       # type: ignore[assignment]
    ) -> Optional[PeerRecord]:
        """v0.7.3: update per-device profile fields. Pass `Ellipsis`
        (the default) to leave a field unchanged; pass None to
        explicitly clear the alias. Returns the refreshed record."""
        sets: list[str] = []
        params: list[Any] = []
        if local_alias is not Ellipsis:
            v = local_alias
            if v is not None:
                v = str(v).strip() or None
            sets.append("local_alias = ?")
            params.append(v)
        if muted is not Ellipsis:
            sets.append("muted = ?")
            params.append(1 if muted else 0)
        if not sets:
            return self.get_peer(fingerprint)
        params.append(fingerprint)
        with self._write_lock:
            self._conn.execute(
                f"UPDATE peers SET {', '.join(sets)} WHERE fingerprint = ?",
                params,
            )
        return self.get_peer(fingerprint)

    # ─── verification (v0.7.7) ────────────────────────────────────────

    _ALLOWED_VERIFY_METHODS = ("sas-digits", "sas-qr", "sas-audio", "manual")

    def set_peer_verified(
        self,
        fingerprint: str,
        *,
        method: str,
        note: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> Optional[PeerRecord]:
        """v0.7.7: mark a peer as verified-in-person via a side-channel
        SAS confirm. `method` records HOW the user verified (digits
        read aloud, QR scan, audio readback, manual override).
        Records a capability_audit row so the trust transition is
        forensically auditable. Returns the refreshed PeerRecord, or
        None if the peer doesn't exist."""
        if method not in self._ALLOWED_VERIFY_METHODS:
            raise ValueError(
                f"verify method must be one of "
                f"{self._ALLOWED_VERIFY_METHODS!r}, got {method!r}"
            )
        clean_note: Optional[str] = None
        if note is not None:
            clean_note = str(note).strip() or None
            if clean_note and len(clean_note) > 280:
                # Same upper bound as a tweet — long enough for a
                # location/context reminder, short enough to render
                # in the device drawer without truncation games.
                raise ValueError("verify note too long (max 280 chars)")
        now = _now_ms()
        with self._write_lock:
            row = self._conn.execute(
                "SELECT verified_at_ms, verified_method FROM peers"
                " WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if row is None:
                return None
            before = {
                "verified_at_ms": row["verified_at_ms"],
                "verified_method": row["verified_method"],
            }
            self._conn.execute(
                "UPDATE peers SET verified_at_ms = ?, verified_method = ?,"
                " verified_note = ? WHERE fingerprint = ?",
                (now, method, clean_note, fingerprint),
            )
            after = {
                "verified_at_ms": now,
                "verified_method": method,
                "verified_note": clean_note,
            }
            if before != {
                "verified_at_ms": after["verified_at_ms"],
                "verified_method": after["verified_method"],
            } or row["verified_at_ms"] is None:
                self._record_capability_audit(
                    fingerprint=fingerprint,
                    kind="verify_set",
                    before=before,
                    after=after,
                    actor=actor,
                    note=clean_note,
                )
        return self.get_peer(fingerprint)

    def clear_peer_verified(
        self,
        fingerprint: str,
        *,
        actor: Optional[str] = None,
        note: Optional[str] = None,
    ) -> Optional[PeerRecord]:
        """v0.7.7: revoke a verified-in-person mark (e.g. user no
        longer trusts the side channel, key changed, device changed
        hands). Audit log captures the before-state so the timeline
        survives the clear."""
        with self._write_lock:
            row = self._conn.execute(
                "SELECT verified_at_ms, verified_method, verified_note"
                " FROM peers WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if row is None:
                return None
            before = {
                "verified_at_ms": row["verified_at_ms"],
                "verified_method": row["verified_method"],
                "verified_note": row["verified_note"],
            }
            if row["verified_at_ms"] is None:
                # Idempotent no-op — nothing to clear, no audit row.
                return self.get_peer(fingerprint)
            self._conn.execute(
                "UPDATE peers SET verified_at_ms = NULL,"
                " verified_method = NULL, verified_note = NULL"
                " WHERE fingerprint = ?",
                (fingerprint,),
            )
            self._record_capability_audit(
                fingerprint=fingerprint,
                kind="verify_clear",
                before=before,
                after=None,
                actor=actor,
                note=note,
            )
        return self.get_peer(fingerprint)

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
        reply_to: Optional[str] = None,
        expires_at_ms: Optional[int] = None,
    ) -> None:
        with self._write_lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO messages(
                    id, ts_ms, direction, peer_fp, msg_type, body, room_id,
                    metadata_json, reply_to, expires_at_ms
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    id, ts_ms, direction, peer_fp, msg_type, body, room_id,
                    json.dumps(metadata or {}, separators=(",", ":")),
                    reply_to, expires_at_ms,
                ),
            )

    # ─── disappearing messages (v0.10.2) ──────────────────────────────

    # Friendly TTL labels — UI presents these; values are the ms.
    PEER_DM_TTL_PRESETS = {
        None: "Off",
        5 * 60 * 1000: "5 minutes",
        30 * 60 * 1000: "30 minutes",
        60 * 60 * 1000: "1 hour",
        24 * 60 * 60 * 1000: "1 day",
        7 * 24 * 60 * 60 * 1000: "1 week",
    }

    def set_peer_dm_ttl(
        self,
        fingerprint: str,
        ttl_ms: Optional[int],
    ) -> Optional[PeerRecord]:
        """v0.10.2: set the per-peer disappearing-message TTL. Pass
        None to clear (messages will no longer expire). Returns the
        refreshed PeerRecord, or None if the peer doesn't exist."""
        if ttl_ms is not None:
            if not isinstance(ttl_ms, int) or ttl_ms <= 0:
                raise ValueError("ttl_ms must be a positive integer")
            # Sanity cap: 30 days. Anything longer is "off" effectively;
            # we don't persist it because the UI's preset list doesn't
            # cover values that long.
            if ttl_ms > 30 * 24 * 60 * 60 * 1000:
                raise ValueError("ttl_ms too large (max 30 days)")
        with self._write_lock:
            row = self._conn.execute(
                "SELECT 1 FROM peers WHERE fingerprint = ?", (fingerprint,),
            ).fetchone()
            if row is None:
                return None
            self._conn.execute(
                "UPDATE peers SET dm_ttl_ms = ? WHERE fingerprint = ?",
                (ttl_ms, fingerprint),
            )
        return self.get_peer(fingerprint)

    def get_peer_dm_ttl(self, fingerprint: str) -> Optional[int]:
        rec = self.get_peer(fingerprint)
        return rec.dm_ttl_ms if rec else None

    def set_peer_muted_until(
        self, fingerprint: str, until_ms: Optional[int],
    ) -> None:
        """v0.11.2: per-chat mute with duration.

        until_ms semantics:
          None  → unmute (clear muted_until_ms + legacy muted=0)
          0     → mute forever (muted_until_ms=0, legacy muted=1)
          N > 0 → mute until wall-clock ms N

        We also keep the legacy `muted` boolean column in sync so
        old read paths that haven't been ported still see a sane
        derived state."""
        if until_ms is not None and until_ms < 0:
            raise ValueError("until_ms must be None, 0, or positive")
        legacy_muted = 0 if until_ms is None else 1
        with self._write_lock:
            self._conn.execute(
                "UPDATE peers SET muted_until_ms = ?, muted = ? "
                "WHERE fingerprint = ?",
                (until_ms, legacy_muted, fingerprint),
            )

    def get_peer_muted_until(self, fingerprint: str) -> Optional[int]:
        rec = self.get_peer(fingerprint)
        return rec.muted_until_ms if rec else None

    def expire_due_messages(self, *, now_ms: Optional[int] = None) -> list[str]:
        """v0.10.2: tombstone every message whose expires_at_ms has
        passed. Returns the list of msg_ids that were just expired
        so the daemon can broadcast msg_delete WS events.

        Idempotent — re-expiring a row that's already deleted is a
        no-op (the AND deleted_at_ms IS NULL clause filters them out)."""
        cutoff = now_ms if now_ms is not None else _now_ms()
        with self._write_lock:
            rows = self._conn.execute(
                "SELECT id FROM messages"
                " WHERE expires_at_ms IS NOT NULL"
                "   AND expires_at_ms <= ?"
                "   AND deleted_at_ms IS NULL",
                (cutoff,),
            ).fetchall()
            ids = [r["id"] for r in rows]
            if not ids:
                return []
            # Mark all expired in one statement.
            self._conn.execute(
                "UPDATE messages SET body = NULL, deleted_at_ms = ?"
                " WHERE expires_at_ms IS NOT NULL"
                "   AND expires_at_ms <= ?"
                "   AND deleted_at_ms IS NULL",
                (cutoff, cutoff),
            )
        return ids

    # ─── reactions (v0.7.5) ───────────────────────────────────────────

    def record_reaction(
        self, *, target_msg_id: str, peer_fp: str, emoji: str,
    ) -> bool:
        """Add a reaction. Idempotent on (target, peer, emoji).
        Returns True if a new row was inserted, False if it already
        existed."""
        if not target_msg_id or not peer_fp or not emoji:
            raise ValueError("target_msg_id, peer_fp, emoji required")
        # Bound emoji length — actual single grapheme can be up to
        # ~50 bytes in Unicode, but a "reaction" with hundreds of
        # combining marks is abuse.
        if len(emoji) > 64:
            raise ValueError("emoji too long")
        with self._write_lock:
            cur = self._conn.execute(
                """
                INSERT INTO message_reactions(
                    target_msg_id, peer_fp, emoji, ts_ms
                ) VALUES(?, ?, ?, ?)
                ON CONFLICT(target_msg_id, peer_fp, emoji) DO NOTHING
                """,
                (target_msg_id, peer_fp, emoji, _now_ms()),
            )
            return cur.rowcount > 0

    def remove_reaction(
        self, *, target_msg_id: str, peer_fp: str, emoji: str,
    ) -> bool:
        with self._write_lock:
            cur = self._conn.execute(
                "DELETE FROM message_reactions"
                " WHERE target_msg_id = ? AND peer_fp = ? AND emoji = ?",
                (target_msg_id, peer_fp, emoji),
            )
            return cur.rowcount > 0

    def list_reactions_for_messages(
        self, msg_ids: Iterable[str],
    ) -> dict[str, dict[str, list[str]]]:
        """Return {target_msg_id: {emoji: [peer_fp, ...], ...}}.
        Empty for messages with no reactions."""
        ids = [str(m) for m in msg_ids if m]
        if not ids:
            return {}
        placeholders = ",".join("?" for _ in ids)
        rows = self._conn.execute(
            f"SELECT target_msg_id, peer_fp, emoji FROM message_reactions"
            f" WHERE target_msg_id IN ({placeholders}) ORDER BY ts_ms ASC",
            ids,
        ).fetchall()
        out: dict[str, dict[str, list[str]]] = {}
        for r in rows:
            mid = r["target_msg_id"]
            out.setdefault(mid, {}).setdefault(r["emoji"], []).append(r["peer_fp"])
        return out

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

    def global_search(
        self,
        query: str,
        *,
        per_kind_limit: int = 10,
    ) -> dict:
        """v0.9.3: search across messages (FTS5), peers (LIKE), and
        groups (LIKE). Returns a dict keyed by kind so the caller
        can render each section.

        Query is escaped for FTS5 (`"…"` quoted) so user input
        with operators like AND / OR / NEAR doesn't accidentally
        change the search semantics. Empty query returns empty
        results without hitting the DB."""
        q = (query or "").strip()
        out: dict = {"messages": [], "peers": [], "groups": []}
        if not q:
            return out
        # 1. Messages via FTS5. Phrase-quoted so special chars don't
        # error out the parser ("auth: user" would otherwise be
        # parsed as field-restricted query).
        try:
            phrased = '"' + q.replace('"', '""') + '"'
            msgs = self.search_messages(phrased, limit=per_kind_limit)
        except Exception:
            msgs = []
        for m in msgs:
            out["messages"].append({
                "id": m.id,
                "ts_ms": m.ts_ms,
                "direction": m.direction,
                "peer_fp": m.peer_fp,
                "msg_type": m.msg_type,
                "body": (m.body or "")[:200],
                "room_id": m.room_id,
                "reply_to": m.reply_to,
            })
        # 2. Peers by hostname / display alias / short_id / fingerprint
        # prefix. Case-insensitive.
        like = f"%{q}%"
        peer_rows = self._conn.execute(
            "SELECT * FROM peers"
            " WHERE LOWER(IFNULL(hostname, '')) LIKE LOWER(?)"
            "    OR LOWER(IFNULL(local_alias, '')) LIKE LOWER(?)"
            "    OR LOWER(short_id) LIKE LOWER(?)"
            "    OR LOWER(fingerprint) LIKE LOWER(?)"
            " ORDER BY (trust = 'pinned') DESC, last_seen_ms DESC"
            " LIMIT ?",
            (like, like, like, like, int(per_kind_limit)),
        ).fetchall()
        for r in peer_rows:
            rec = self._row_to_peer(r)
            out["peers"].append({
                "fingerprint": rec.fingerprint,
                "short_id": rec.short_id,
                "hostname": rec.hostname,
                "display_name": rec.display_name,
                "trust": rec.trust,
                "is_verified": rec.is_verified,
                "last_seen_ms": rec.last_seen_ms,
            })
        # 3. Groups by name. groups.name was added in v0.6.2.
        try:
            grp_rows = self._conn.execute(
                "SELECT group_id, name, updated_ms FROM groups"
                " WHERE LOWER(IFNULL(name, '')) LIKE LOWER(?)"
                " ORDER BY updated_ms DESC LIMIT ?",
                (like, int(per_kind_limit)),
            ).fetchall()
        except Exception:
            grp_rows = []
        for r in grp_rows:
            gid = r["group_id"]
            try:
                gid_hex = gid.hex() if isinstance(gid, (bytes, bytearray)) else str(gid)
            except Exception:
                gid_hex = ""
            out["groups"].append({
                "group_id": gid_hex,
                "name": r["name"] or "",
                "updated_ms": r["updated_ms"],
            })
        return out

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
        cols = row.keys()
        return MessageRecord(
            id=row["id"],
            ts_ms=row["ts_ms"],
            direction=row["direction"],
            peer_fp=row["peer_fp"],
            msg_type=row["msg_type"],
            body=row["body"],
            room_id=row["room_id"],
            metadata=md,
            reply_to=row["reply_to"] if "reply_to" in cols else None,
            edited_at_ms=row["edited_at_ms"] if "edited_at_ms" in cols else None,
            original_body=row["original_body"] if "original_body" in cols else None,
            deleted_at_ms=row["deleted_at_ms"] if "deleted_at_ms" in cols else None,
            expires_at_ms=row["expires_at_ms"] if "expires_at_ms" in cols else None,
        )

    # ─── edit / delete (v0.7.6) ───────────────────────────────────────

    def edit_message(
        self, *, id: str, new_body: str, edited_at_ms: int,
    ) -> Optional[MessageRecord]:
        """v0.7.6: replace a message's body and stamp edited_at_ms.
        Preserves the original body in original_body the first time
        an edit happens (subsequent edits don't overwrite it).
        Returns the refreshed record, or None if not found / deleted."""
        cur = self.get_message(id)
        if cur is None or cur.is_deleted:
            return None
        original = cur.original_body or cur.body
        with self._write_lock:
            self._conn.execute(
                "UPDATE messages SET body = ?, edited_at_ms = ?,"
                " original_body = COALESCE(original_body, ?)"
                " WHERE id = ? AND deleted_at_ms IS NULL",
                (new_body, int(edited_at_ms), original, id),
            )
        return self.get_message(id)

    def clear_peer_history(self, peer_fp: str) -> int:
        """v0.11.5: hard-delete all message rows for a peer locally.
        Returns the number of rows deleted. The other side's copy
        is untouched — this is purely local data hygiene."""
        with self._write_lock:
            cur = self._conn.execute(
                "DELETE FROM messages WHERE peer_fp = ?",
                (peer_fp,),
            )
            return cur.rowcount or 0

    def clear_group_history(self, group_id_hex: str) -> int:
        """v0.11.5: hard-delete all group message rows locally.
        Group event log (membership) is preserved — only chat
        content is wiped. Returns row count.

        Tries `group_messages` table first; falls back to a no-op
        if the build doesn't have the table yet (very old schemas)."""
        with self._write_lock:
            try:
                cur = self._conn.execute(
                    "DELETE FROM group_messages WHERE group_id = ?",
                    (group_id_hex,),
                )
                return cur.rowcount or 0
            except Exception:
                return 0

    def storage_usage_by_peer(self) -> list[dict]:
        """v0.11.6: per-peer usage rollup for the Storage pane.
        Returns one entry per peer that has any messages, with
        msg_count and file_bytes (sum of metadata.size for file
        rows). The frontend joins this with peer display names."""
        rows = self._conn.execute(
            "SELECT peer_fp, COUNT(*) AS n, "
            "  SUM(CASE WHEN msg_type='file' THEN 1 ELSE 0 END) AS file_n "
            "FROM messages WHERE deleted_at_ms IS NULL "
            "GROUP BY peer_fp"
        ).fetchall()
        out: list[dict] = []
        for r in rows:
            fp = r["peer_fp"]
            # Sum metadata.size across the file rows for this peer.
            file_bytes = 0
            file_rows = self._conn.execute(
                "SELECT metadata_json FROM messages "
                "WHERE peer_fp = ? AND msg_type = 'file' "
                "  AND deleted_at_ms IS NULL",
                (fp,),
            ).fetchall()
            for fr in file_rows:
                try:
                    md = json.loads(fr["metadata_json"]) if fr["metadata_json"] else {}
                except Exception:
                    md = {}
                size = md.get("size")
                if isinstance(size, (int, float)):
                    file_bytes += int(size)
            out.append({
                "peer_fp": fp,
                "msg_count": int(r["n"] or 0),
                "file_count": int(r["file_n"] or 0),
                "file_bytes": file_bytes,
            })
        # Largest by file_bytes first, then by msg_count.
        out.sort(key=lambda d: (-d["file_bytes"], -d["msg_count"]))
        return out

    def storage_usage_by_group(self) -> list[dict]:
        """v0.11.6: per-group rollup. Falls back to empty list when
        the group_messages table doesn't exist on this build."""
        try:
            rows = self._conn.execute(
                "SELECT group_id, COUNT(*) AS n "
                "FROM group_messages GROUP BY group_id"
            ).fetchall()
        except Exception:
            return []
        out: list[dict] = []
        for r in rows:
            out.append({
                "group_id": r["group_id"]
                            if isinstance(r["group_id"], str)
                            else r["group_id"].hex(),
                "msg_count": int(r["n"] or 0),
            })
        out.sort(key=lambda d: -d["msg_count"])
        return out

    def list_peer_files(self, peer_fp: str) -> list[MessageRecord]:
        """v0.11.5: messages with file metadata for the media gallery.
        Returns oldest → newest so the gallery scrolls naturally."""
        rows = self._conn.execute(
            "SELECT * FROM messages "
            "WHERE peer_fp = ? AND msg_type = 'file' "
            "  AND (deleted_at_ms IS NULL) "
            "ORDER BY ts_ms ASC",
            (peer_fp,),
        ).fetchall()
        return [self._row_to_msg(r) for r in rows]

    def delete_message(
        self, *, id: str, deleted_at_ms: int,
    ) -> Optional[MessageRecord]:
        """v0.7.6: soft-delete. Body cleared; deleted_at_ms stamped.
        Idempotent on already-deleted rows."""
        cur = self.get_message(id)
        if cur is None:
            return None
        if cur.is_deleted:
            return cur
        with self._write_lock:
            self._conn.execute(
                "UPDATE messages SET body = NULL, deleted_at_ms = ?"
                " WHERE id = ?",
                (int(deleted_at_ms), id),
            )
        return self.get_message(id)

    def get_message(self, id: str) -> Optional[MessageRecord]:
        row = self._conn.execute(
            "SELECT * FROM messages WHERE id = ?", (id,),
        ).fetchone()
        return self._row_to_msg(row) if row else None

    # ─── read markers (v0.7.6) ────────────────────────────────────────

    def record_read_marker(self, peer_fp: str, up_to_ts_ms: int) -> None:
        """Mark all messages from `peer_fp` with ts ≤ `up_to_ts_ms`
        as read by us. Monotonic — older markers can't overwrite a
        newer one."""
        if not peer_fp:
            return
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO peer_read_markers(peer_fp, up_to_ts_ms, updated_ms)
                VALUES(?, ?, ?)
                ON CONFLICT(peer_fp) DO UPDATE SET
                    up_to_ts_ms = MAX(peer_read_markers.up_to_ts_ms, excluded.up_to_ts_ms),
                    updated_ms = excluded.updated_ms
                """,
                (peer_fp, int(up_to_ts_ms), _now_ms()),
            )

    def get_read_marker(self, peer_fp: str) -> Optional[int]:
        row = self._conn.execute(
            "SELECT up_to_ts_ms FROM peer_read_markers WHERE peer_fp = ?",
            (peer_fp,),
        ).fetchone()
        return int(row["up_to_ts_ms"]) if row else None

    def list_read_markers(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT peer_fp, up_to_ts_ms FROM peer_read_markers"
        ).fetchall()
        return {r["peer_fp"]: int(r["up_to_ts_ms"]) for r in rows}

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
        if status not in (
            "queued", "offered", "active", "complete", "failed", "paused",
        ):
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

    # ─── manifest conflicts (v0.8.9) ──────────────────────────────────

    def record_manifest_conflict(
        self,
        *,
        folder_name: str,
        file_path: str,
        peer_fp: Optional[str],
        local_blob_hash: Optional[str],
        local_size: Optional[int],
        local_mtime_ms: Optional[int],
        local_vclock: dict,
        remote_blob_hash: Optional[str],
        remote_size: Optional[int],
        remote_mtime_ms: Optional[int],
        remote_vclock: dict,
        applied_choice: str,
    ) -> int:
        """v0.8.9: log a CRDT-detected concurrent edit. Returns the
        new row id. The merge has ALREADY been applied by the caller —
        this row exists so the user can override that auto-decision
        via the Conflicts UI.

        Idempotency: if an unresolved conflict for the same
        (folder_name, file_path) with identical local + remote vclocks
        already exists, return that id instead of creating a duplicate.
        Avoids the manifest-resync flood scenario logging the same
        conflict 50 times."""
        if applied_choice not in ("local", "remote", "tombstone"):
            raise ValueError(
                f"applied_choice must be local|remote|tombstone, got {applied_choice!r}"
            )
        local_vc_json = json.dumps(local_vclock, separators=(",", ":"), sort_keys=True)
        remote_vc_json = json.dumps(remote_vclock, separators=(",", ":"), sort_keys=True)
        with self._write_lock:
            existing = self._conn.execute(
                "SELECT id FROM manifest_conflicts"
                " WHERE folder_name = ? AND file_path = ?"
                " AND local_vclock_json = ? AND remote_vclock_json = ?"
                " AND resolved_ms IS NULL"
                " LIMIT 1",
                (folder_name, file_path, local_vc_json, remote_vc_json),
            ).fetchone()
            if existing is not None:
                return int(existing["id"])
            cur = self._conn.execute(
                """
                INSERT INTO manifest_conflicts(
                    folder_name, file_path, detected_ms, peer_fp,
                    local_blob_hash, local_size, local_mtime_ms, local_vclock_json,
                    remote_blob_hash, remote_size, remote_mtime_ms, remote_vclock_json,
                    applied_choice
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    folder_name, file_path, _now_ms(), peer_fp,
                    local_blob_hash, local_size, local_mtime_ms, local_vc_json,
                    remote_blob_hash, remote_size, remote_mtime_ms, remote_vc_json,
                    applied_choice,
                ),
            )
            return int(cur.lastrowid)

    def list_manifest_conflicts(
        self,
        *,
        folder_name: Optional[str] = None,
        unresolved_only: bool = False,
        limit: int = 200,
    ) -> list[dict]:
        sql = (
            "SELECT * FROM manifest_conflicts"
        )
        clauses: list[str] = []
        params: list[Any] = []
        if folder_name is not None:
            clauses.append("folder_name = ?")
            params.append(folder_name)
        if unresolved_only:
            clauses.append("resolved_ms IS NULL")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY detected_ms DESC, id DESC LIMIT ?"
        params.append(int(limit))
        rows = self._conn.execute(sql, tuple(params)).fetchall()
        out: list[dict] = []
        for r in rows:
            out.append({
                "id":                 r["id"],
                "folder_name":        r["folder_name"],
                "file_path":          r["file_path"],
                "detected_ms":        r["detected_ms"],
                "peer_fp":            r["peer_fp"],
                "local_blob_hash":    r["local_blob_hash"],
                "local_size":         r["local_size"],
                "local_mtime_ms":     r["local_mtime_ms"],
                "local_vclock":       json.loads(r["local_vclock_json"]),
                "remote_blob_hash":   r["remote_blob_hash"],
                "remote_size":        r["remote_size"],
                "remote_mtime_ms":    r["remote_mtime_ms"],
                "remote_vclock":      json.loads(r["remote_vclock_json"]),
                "applied_choice":     r["applied_choice"],
                "resolved_ms":        r["resolved_ms"],
                "resolution":         r["resolution"],
                "resolved_by":        r["resolved_by"],
            })
        return out

    def get_manifest_conflict(self, conflict_id: int) -> Optional[dict]:
        rows = self.list_manifest_conflicts(limit=1)
        for r in self._conn.execute(
            "SELECT * FROM manifest_conflicts WHERE id = ?", (int(conflict_id),),
        ).fetchall():
            return {
                "id":                 r["id"],
                "folder_name":        r["folder_name"],
                "file_path":          r["file_path"],
                "detected_ms":        r["detected_ms"],
                "peer_fp":            r["peer_fp"],
                "local_blob_hash":    r["local_blob_hash"],
                "local_size":         r["local_size"],
                "local_mtime_ms":     r["local_mtime_ms"],
                "local_vclock":       json.loads(r["local_vclock_json"]),
                "remote_blob_hash":   r["remote_blob_hash"],
                "remote_size":        r["remote_size"],
                "remote_mtime_ms":    r["remote_mtime_ms"],
                "remote_vclock":      json.loads(r["remote_vclock_json"]),
                "applied_choice":     r["applied_choice"],
                "resolved_ms":        r["resolved_ms"],
                "resolution":         r["resolution"],
                "resolved_by":        r["resolved_by"],
            }
        return None

    def mark_manifest_conflict_resolved(
        self,
        conflict_id: int,
        *,
        resolution: str,
        resolved_by: str = "ui",
    ) -> bool:
        """Stamp a conflict resolved. Returns True iff the row was
        previously unresolved (so the caller can avoid double-applying
        a side-effect like 'write the conflict-suffix file')."""
        if resolution not in ("mine", "theirs", "both", "auto"):
            raise ValueError(
                f"resolution must be mine|theirs|both|auto, got {resolution!r}"
            )
        with self._write_lock:
            cur = self._conn.execute(
                "UPDATE manifest_conflicts"
                " SET resolved_ms = ?, resolution = ?, resolved_by = ?"
                " WHERE id = ? AND resolved_ms IS NULL",
                (_now_ms(), resolution, resolved_by, int(conflict_id)),
            )
            return cur.rowcount > 0

    def count_unresolved_manifest_conflicts(
        self, folder_name: Optional[str] = None,
    ) -> int:
        if folder_name is None:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM manifest_conflicts WHERE resolved_ms IS NULL"
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM manifest_conflicts"
                " WHERE folder_name = ? AND resolved_ms IS NULL",
                (folder_name,),
            ).fetchone()
        return int(row["n"]) if row else 0

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

    def record_chunk_available(
        self,
        chunk_hash: str,
        size: int,
        *,
        blob_hash: Optional[str] = None,
        chunk_index: Optional[int] = None,
        source: str = "local",
    ) -> None:
        now = _now_ms()
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO chunk_availability(
                    chunk_hash, size, blob_hash, chunk_index, source, updated_ms
                ) VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(chunk_hash) DO UPDATE SET
                    size = excluded.size,
                    blob_hash = COALESCE(excluded.blob_hash, chunk_availability.blob_hash),
                    chunk_index = COALESCE(excluded.chunk_index, chunk_availability.chunk_index),
                    source = excluded.source,
                    updated_ms = excluded.updated_ms
                """,
                (
                    chunk_hash,
                    int(size),
                    blob_hash,
                    chunk_index,
                    str(source or "local"),
                    now,
                ),
            )

    def has_chunk(self, chunk_hash: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM chunk_availability WHERE chunk_hash = ?",
            (chunk_hash,),
        ).fetchone()
        return row is not None

    def chunks_available(self, chunk_hashes: Iterable[str]) -> list[str]:
        clean = [str(h) for h in chunk_hashes if str(h)]
        if not clean:
            return []
        out: list[str] = []
        for i in range(0, len(clean), 500):
            batch = clean[i:i + 500]
            rows = self._conn.execute(
                "SELECT chunk_hash FROM chunk_availability "
                f"WHERE chunk_hash IN ({','.join('?' for _ in batch)})",
                tuple(batch),
            ).fetchall()
            out.extend(str(r["chunk_hash"]) for r in rows)
        have = set(out)
        return [h for h in clean if h in have]

    def record_chunk_source(
        self,
        chunk_hash: str,
        *,
        path: str,
        start: int,
        size: int,
        mtime_ms: int,
        file_size: int,
        source: str = "prior",
    ) -> None:
        now = _now_ms()
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO chunk_sources(
                    chunk_hash, path, start, size, mtime_ms, file_size,
                    source, updated_ms
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chunk_hash, path, start) DO UPDATE SET
                    size = excluded.size,
                    mtime_ms = excluded.mtime_ms,
                    file_size = excluded.file_size,
                    source = excluded.source,
                    updated_ms = excluded.updated_ms
                """,
                (
                    str(chunk_hash),
                    str(path),
                    int(start),
                    int(size),
                    int(mtime_ms),
                    int(file_size),
                    str(source or "prior"),
                    now,
                ),
            )
        self.record_chunk_available(
            str(chunk_hash),
            int(size),
            source=str(source or "prior"),
        )

    def get_chunk_sources(self, chunk_hash: str, *, limit: int = 8) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT chunk_hash, path, start, size, mtime_ms, file_size,
                   source, updated_ms
            FROM chunk_sources
            WHERE chunk_hash = ?
            ORDER BY updated_ms DESC
            LIMIT ?
            """,
            (str(chunk_hash), int(limit)),
        ).fetchall()
        return [
            {
                "chunk_hash": r["chunk_hash"],
                "path": r["path"],
                "start": int(r["start"]),
                "size": int(r["size"]),
                "mtime_ms": int(r["mtime_ms"]),
                "file_size": int(r["file_size"]),
                "source": r["source"],
                "updated_ms": int(r["updated_ms"]),
            }
            for r in rows
        ]

    def chunks_sourced(self, chunk_hashes: Iterable[str]) -> list[str]:
        clean = [str(h) for h in chunk_hashes if str(h)]
        if not clean:
            return []
        out: list[str] = []
        for i in range(0, len(clean), 500):
            batch = clean[i:i + 500]
            rows = self._conn.execute(
                "SELECT DISTINCT chunk_hash FROM chunk_sources "
                f"WHERE chunk_hash IN ({','.join('?' for _ in batch)})",
                tuple(batch),
            ).fetchall()
            out.extend(str(r["chunk_hash"]) for r in rows)
        have = set(out)
        return [h for h in clean if h in have]

    def list_chunks_for_blob(self, blob_hash: str) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT chunk_hash, size, blob_hash, chunk_index, source, updated_ms
            FROM chunk_availability
            WHERE blob_hash = ?
            ORDER BY chunk_index ASC, updated_ms DESC
            """,
            (blob_hash,),
        ).fetchall()
        return [
            {
                "chunk_hash": r["chunk_hash"],
                "size": int(r["size"]),
                "blob_hash": r["blob_hash"],
                "chunk_index": r["chunk_index"],
                "source": r["source"],
                "updated_ms": int(r["updated_ms"]),
            }
            for r in rows
        ]

    def record_file_index_cache(
        self,
        *,
        path: str,
        size: int,
        mtime_ns: int,
        ctime_ns: int,
        blob_hash: str,
        index_kind: str,
        chunks: Iterable[dict],
    ) -> None:
        clean_chunks: list[dict] = []
        for c in chunks:
            clean_chunks.append({
                "index": int(c["index"]),
                "start": int(c["start"]),
                "end": int(c["end"]),
                "size": int(c.get("size", int(c["end"]) - int(c["start"]))),
                "hash": str(c["hash"]),
            })
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO file_index_cache(
                    path, size, mtime_ns, ctime_ns, blob_hash, index_kind,
                    chunks_json, updated_ms
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    size = excluded.size,
                    mtime_ns = excluded.mtime_ns,
                    ctime_ns = excluded.ctime_ns,
                    blob_hash = excluded.blob_hash,
                    index_kind = excluded.index_kind,
                    chunks_json = excluded.chunks_json,
                    updated_ms = excluded.updated_ms
                """,
                (
                    str(path),
                    int(size),
                    int(mtime_ns),
                    int(ctime_ns),
                    str(blob_hash),
                    str(index_kind or "unknown"),
                    json.dumps(clean_chunks, separators=(",", ":")),
                    _now_ms(),
                ),
            )

    def get_file_index_cache(
        self,
        *,
        path: str,
        size: int,
        mtime_ns: int,
        ctime_ns: int,
    ) -> Optional[dict]:
        row = self._conn.execute(
            """
            SELECT path, size, mtime_ns, ctime_ns, blob_hash, index_kind,
                   chunks_json, updated_ms
            FROM file_index_cache
            WHERE path = ? AND size = ? AND mtime_ns = ? AND ctime_ns = ?
            """,
            (str(path), int(size), int(mtime_ns), int(ctime_ns)),
        ).fetchone()
        if row is None:
            return None
        try:
            chunks = json.loads(row["chunks_json"] or "[]")
        except Exception:
            chunks = []
        if not isinstance(chunks, list):
            chunks = []
        return {
            "path": row["path"],
            "size": int(row["size"]),
            "mtime_ns": int(row["mtime_ns"]),
            "ctime_ns": int(row["ctime_ns"]),
            "blob_hash": row["blob_hash"],
            "index_kind": row["index_kind"],
            "chunks": chunks,
            "updated_ms": int(row["updated_ms"]),
        }

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
