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
import contextlib
import logging
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)
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
        # v0.20.7 (security audit H21 + partial C5): optional
        # at-rest wrap for the highest-value secrets in the schema
        # (group sender chain_keys). Daemon wires a LockBox here at
        # boot when ONE_LINK_PASSPHRASE is set; absent passphrase →
        # None → values stored cleartext (legacy behavior). Wrapping
        # is transparent to read paths via lockbox.maybe_unwrap so a
        # mid-life passphrase opt-in coexists with legacy rows.
        self._lockbox = None  # set via set_lockbox()
        self._init_pragmas()
        self._migrate()

    def set_lockbox(self, lockbox) -> None:
        """v0.20.7: late-attach the at-rest wrap key. Daemon calls
        this once at boot after constructing State + the LockBox.
        Subsequent writes wrap; subsequent reads unwrap on demand."""
        self._lockbox = lockbox

    # v0.20.7 (security audit M30): path-PII encryptor. Daemon late-
    # attaches one of these at boot when the master seed is available;
    # all chunk_sources / file_index_cache writes go through wrap, all
    # reads go through unwrap. Legacy cleartext rows are detected by
    # absence of the marker prefix and remain readable.
    _path_pii = None

    def set_path_pii_encryptor(self, encryptor) -> None:
        self._path_pii = encryptor

    # AAD strings: distinct per column so a path that exists in both
    # tables encrypts to different ciphertext, ensuring a leak of one
    # column doesn't help an attacker pivot via the other.
    _PATH_PII_AAD_CHUNK_SOURCES = b"OL/state/chunk_sources/path|v1"
    _PATH_PII_AAD_FILE_INDEX = b"OL/state/file_index_cache/path|v1"

    def _wrap_path(self, value: str, *, aad: bytes) -> str:
        if self._path_pii is None or not value:
            return value
        return self._path_pii.wrap(value, aad=aad)

    def _unwrap_path(self, value: str, *, aad: bytes) -> str:
        if self._path_pii is None or not value:
            return value
        out = self._path_pii.unwrap(value, aad=aad)
        # If unwrap returned None, the value is wrapped but
        # un-decryptable (tamper / wrong install). Surface the
        # opaque marker so callers don't accidentally treat stale
        # ciphertext as a real filesystem path.
        return out if out is not None else value

    def _init_pragmas(self) -> None:
        c = self._conn.cursor()
        c.execute("PRAGMA journal_mode = WAL")
        c.execute("PRAGMA synchronous = NORMAL")
        c.execute("PRAGMA foreign_keys = ON")
        c.execute("PRAGMA temp_store = MEMORY")
        c.execute("PRAGMA cache_size = -8000")  # 8 MB
        # v0.20.7 (security audit H22): zero freed pages on delete so
        # the disappearing-messages reaper actually erases plaintext
        # bodies from the file. Adds ~10% write cost; worth it.
        c.execute("PRAGMA secure_delete = ON")
        # v0.20.7: checkpoint WAL frequently so deleted-row plaintext
        # does not linger in state.db-wal between application
        # checkpoints. 50 pages ~= ~200KB worst case.
        c.execute("PRAGMA wal_autocheckpoint = 50")
        # 2026-05-21 audit T3-X: surface a corrupt state.db on boot
        # instead of the first ad-hoc query crashing the daemon.
        # ``quick_check`` validates page integrity + WAL consistency;
        # full check would walk every index too (expensive). On a
        # corrupt DB we LOG the failure and keep going — the operator
        # can then decide whether to rename-and-rebootstrap. We do
        # NOT auto-rename: silently rebuilding state.db would lose
        # pinned peers / keys / audit log on a transient I/O blip.
        try:
            res = c.execute("PRAGMA quick_check").fetchone()
            if res and res[0] != "ok":
                log.error(
                    "state.db integrity check FAILED: %s. "
                    "The daemon will keep running but operations "
                    "against the corrupted store may fail. Consider "
                    "renaming the file and bootstrapping fresh.",
                    res[0],
                )
        except Exception as exc:  # pragma: no cover — defensive
            log.warning("state.db integrity check raised: %s", exc)
        c.close()

    def _migrate(self) -> None:
        """Run schema migrations atomically.

        v0.20.7 (security audit H20): each migration step + its
        version stamp run inside a single ``BEGIN IMMEDIATE`` /
        ``COMMIT`` transaction. A SIGKILL between an ALTER TABLE and
        the version-stamp INSERT used to leave the DB in a half-
        migrated state (table already had the new column but
        ``schema_version`` claimed the old version, so the next boot
        re-ran the migration and either errored on duplicate column
        or quietly mis-stamped). With per-step transactions, the WAL
        rolls back on crash and the next boot retries the same step
        from a clean baseline.

        SQLite's ``isolation_level=None`` (autocommit) still permits
        explicit ``BEGIN``/``COMMIT`` to delimit a transaction, which
        is what we want here — every other code path stays in
        autocommit mode.
        """
        with self._write_lock:
            c = self._conn.cursor()
            try:
                # Bootstrap v1. SCHEMA_V1 is composed entirely of
                # ``CREATE ... IF NOT EXISTS`` statements (tables,
                # virtual tables, triggers, indexes), so a crash mid-
                # script is safe: the next boot re-runs the script and
                # idempotently fills in whatever is missing. We can't
                # wrap ``executescript`` in BEGIN IMMEDIATE because
                # SQLite's executescript implicitly commits the open
                # transaction — but the idempotency property keeps v1
                # bootstrap safe on its own.
                c.executescript(SCHEMA_V1)
                cur = c.execute("SELECT MAX(version) FROM schema_version")
                row = cur.fetchone()
                current = row[0] if row and row[0] is not None else 0
                if current < 1:
                    c.execute("INSERT INTO schema_version(version) VALUES(1)")
                    current = 1

                # vN+ migrations: each (apply_fn, target_version) pair
                # runs in its own transaction so a crash in the middle
                # of vN does not leave the schema with vN's tables but
                # vN-1's stamp.
                steps = [
                    (2, self._migrate_v2_folder_sandboxes),
                    (3, self._migrate_v3_peer_profile),
                    (4, self._migrate_v4_messages_reply_to),
                    (5, self._migrate_v5_edit_delete_read),
                    (6, self._migrate_v6_group_reply),
                    (7, self._migrate_v7_group_edit_delete),
                    (8, self._migrate_v8_peer_verification),
                    (9, self._migrate_v9_key_change_tracking),
                    (10, self._migrate_v10_folder_conflicts),
                    (11, self._migrate_v11_chunk_availability),
                    (12, self._migrate_v12_disappearing_messages),
                    (13, self._migrate_v13_prior_chunk_sources),
                    (14, self._migrate_v14_mute_until),
                    (15, self._migrate_v15_file_index_cache),
                    (16, self._migrate_v16_route_memory),
                    (17, self._migrate_v17_route_candidates),
                    (18, self._migrate_v18_personal_device_mesh),
                    (19, self._migrate_v19_self_mesh_enrollment),
                    (20, self._migrate_v20_self_mesh_performance),
                    (21, self._migrate_v21_device_guardian),
                ]
                for target_version, apply_fn in steps:
                    self._run_atomic_migration(
                        c,
                        target_version=target_version,
                        current_version=current,
                        apply=apply_fn,
                    )
            finally:
                c.close()

    def _run_atomic_migration(
        self,
        c: sqlite3.Cursor,
        *,
        target_version: int,
        apply,
        current_version: Optional[int] = None,
    ) -> None:
        """Apply ``apply(cursor)`` and (if first-time-crossing) stamp
        ``target_version`` in one transaction.

        Each migration step is idempotent — most use ``CREATE ... IF
        NOT EXISTS`` and PRAGMA-introspected ``ALTER TABLE``, and a few
        also serve as boot-time backfills (e.g. v2's root_id sweep).
        We therefore always run ``apply`` so backfills keep healing
        any drifted rows, but only INSERT the version stamp the first
        time we cross the boundary. The whole thing is wrapped in a
        single ``BEGIN IMMEDIATE`` so a crash mid-step rolls back
        cleanly — no half-applied DDL with a stale version stamp.
        """
        if current_version is None:
            row = c.execute("SELECT MAX(version) FROM schema_version").fetchone()
            current_version = (
                row[0] if row and row[0] is not None else 0
            )
        c.execute("BEGIN IMMEDIATE")
        try:
            apply(c)
            if current_version < target_version:
                c.execute(
                    "INSERT INTO schema_version(version) VALUES(?)",
                    (target_version,),
                )
            c.execute("COMMIT")
        except Exception:
            try:
                c.execute("ROLLBACK")
            except Exception:
                pass
            raise

    def _migrate_v16_route_memory(self, c: sqlite3.Cursor) -> None:
        """v0.14.2: durable route memory for adaptive transfers."""
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS route_memory (
                peer_fp       TEXT NOT NULL,
                route         TEXT NOT NULL,
                attempts      INTEGER NOT NULL,
                successes     INTEGER NOT NULL,
                failures      INTEGER NOT NULL,
                score         REAL NOT NULL,
                latency_ms    REAL,
                bandwidth_bps REAL,
                updated_ms    INTEGER NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY(peer_fp, route)
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_route_memory_peer "
            "ON route_memory(peer_fp, updated_ms)"
        )

    def _migrate_v17_route_candidates(self, c: sqlite3.Cursor) -> None:
        """Durable concrete route candidates for the universal fabric.

        route_memory scores broad route families. route_candidates remembers
        actual dial targets learned from verified sessions, endpoint updates,
        signed QR/audio/BLE route tokens, and future transports. A route
        candidate is not trusted because it exists; callers still do the
        normal pinned-key handshake before promotion/use.
        """
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS route_candidates (
                peer_fp       TEXT NOT NULL,
                route         TEXT NOT NULL,
                transport     TEXT NOT NULL,
                host          TEXT NOT NULL,
                port          INTEGER NOT NULL,
                source        TEXT NOT NULL,
                verified      INTEGER NOT NULL DEFAULT 0,
                attempts      INTEGER NOT NULL DEFAULT 0,
                successes     INTEGER NOT NULL DEFAULT 0,
                failures      INTEGER NOT NULL DEFAULT 0,
                latency_ms    REAL,
                bandwidth_bps REAL,
                last_error    TEXT,
                first_seen_ms INTEGER NOT NULL,
                updated_ms    INTEGER NOT NULL,
                expires_ms    INTEGER,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY(peer_fp, route, transport, host, port)
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_route_candidates_peer "
            "ON route_candidates(peer_fp, verified, updated_ms)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_route_candidates_expiry "
            "ON route_candidates(expires_ms)"
        )

    def _migrate_v18_personal_device_mesh(self, c: sqlite3.Cursor) -> None:
        """Phase F5: Personal Device Mesh persistence.

        self_mesh_devices stores separately addressable devices under a
        shared root identity. self_mesh_presence stores LWW presence
        facts. remote_instruction_seen is the replay wall for signed
        phone-to-laptop command envelopes.
        """
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS self_mesh_devices (
                root_pub      BLOB NOT NULL,
                device_pub    BLOB NOT NULL,
                cert          BLOB,
                device_kind   TEXT NOT NULL,
                label         TEXT NOT NULL DEFAULT '',
                local         INTEGER NOT NULL DEFAULT 0,
                trusted       INTEGER NOT NULL DEFAULT 1,
                revoked       INTEGER NOT NULL DEFAULT 0,
                added_ms      INTEGER NOT NULL,
                updated_ms    INTEGER NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY(root_pub, device_pub)
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_self_mesh_devices_root "
            "ON self_mesh_devices(root_pub, revoked, updated_ms)"
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS self_mesh_presence (
                device_pub     BLOB PRIMARY KEY,
                state          TEXT NOT NULL,
                sequence       INTEGER NOT NULL,
                updated_ms     INTEGER NOT NULL,
                battery_pct    INTEGER,
                network        TEXT NOT NULL DEFAULT 'unknown',
                free_bytes     INTEGER,
                route          TEXT,
                latency_ms     REAL,
                bandwidth_bps  REAL,
                metadata_json  TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_self_mesh_presence_state "
            "ON self_mesh_presence(state, updated_ms)"
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS remote_instruction_seen (
                command_id            TEXT PRIMARY KEY,
                first_seen_ms         INTEGER NOT NULL,
                expires_ms            INTEGER NOT NULL,
                action                TEXT NOT NULL DEFAULT '',
                controller_device_pub BLOB,
                target_device_pub     BLOB
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_remote_instruction_expiry "
            "ON remote_instruction_seen(expires_ms)"
        )

    def _migrate_v19_self_mesh_enrollment(self, c: sqlite3.Cursor) -> None:
        """Phase F5 continuation: enrollment roots + audit trail."""
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS self_mesh_roots (
                root_pub      BLOB PRIMARY KEY,
                label         TEXT NOT NULL DEFAULT '',
                root_seed     BLOB,
                created_ms    INTEGER NOT NULL,
                updated_ms    INTEGER NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_self_mesh_roots_updated "
            "ON self_mesh_roots(updated_ms)"
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS self_mesh_audit (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ms                 INTEGER NOT NULL,
                event                 TEXT NOT NULL,
                severity              TEXT NOT NULL DEFAULT 'info',
                root_pub              BLOB,
                device_pub            BLOB,
                peer_fp               TEXT,
                command_id            TEXT,
                action                TEXT,
                path                  TEXT,
                detail                TEXT NOT NULL DEFAULT '',
                metadata_json         TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_self_mesh_audit_ts "
            "ON self_mesh_audit(ts_ms)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_self_mesh_audit_root "
            "ON self_mesh_audit(root_pub, ts_ms)"
        )

    def _migrate_v20_self_mesh_performance(self, c: sqlite3.Cursor) -> None:
        """Phase F5 polish: persisted performance telemetry."""
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS self_mesh_perf_samples (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ms                 INTEGER NOT NULL,
                route_probe_runs      INTEGER NOT NULL DEFAULT 0,
                route_probe_ready     INTEGER NOT NULL DEFAULT 0,
                route_probe_total_ms  REAL NOT NULL DEFAULT 0,
                route_probe_avg_ms    REAL NOT NULL DEFAULT 0,
                presence_rows         INTEGER NOT NULL DEFAULT 0,
                device_rows           INTEGER NOT NULL DEFAULT 0,
                recent_audit_rows     INTEGER NOT NULL DEFAULT 0,
                status                TEXT NOT NULL DEFAULT 'unknown',
                metadata_json         TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_self_mesh_perf_samples_ts "
            "ON self_mesh_perf_samples(ts_ms)"
        )

    def _migrate_v21_device_guardian(self, c: sqlite3.Cursor) -> None:
        """Device Guardian: anti-theft safety state + tamper-evident events."""
        cols = {r[1] for r in c.execute("PRAGMA table_info(self_mesh_devices)").fetchall()}
        if "safety_state" not in cols:
            c.execute(
                "ALTER TABLE self_mesh_devices "
                "ADD COLUMN safety_state TEXT NOT NULL DEFAULT 'trusted'"
            )
        if "safety_updated_ms" not in cols:
            c.execute(
                "ALTER TABLE self_mesh_devices "
                "ADD COLUMN safety_updated_ms INTEGER NOT NULL DEFAULT 0"
            )
        if "guardian_epoch" not in cols:
            c.execute(
                "ALTER TABLE self_mesh_devices "
                "ADD COLUMN guardian_epoch INTEGER NOT NULL DEFAULT 0"
            )
        if "safety_reason" not in cols:
            c.execute(
                "ALTER TABLE self_mesh_devices "
                "ADD COLUMN safety_reason TEXT NOT NULL DEFAULT ''"
            )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS device_guardian_events (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_ms                 INTEGER NOT NULL,
                root_pub              BLOB NOT NULL,
                device_pub            BLOB NOT NULL,
                actor_device_pub      BLOB,
                from_state            TEXT NOT NULL,
                to_state              TEXT NOT NULL,
                decision              TEXT NOT NULL,
                reason                TEXT NOT NULL DEFAULT '',
                proofs_json           TEXT NOT NULL DEFAULT '[]',
                effects_json          TEXT NOT NULL DEFAULT '[]',
                event_hash            TEXT NOT NULL,
                prev_hash             TEXT NOT NULL DEFAULT '',
                metadata_json         TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_device_guardian_events_device "
            "ON device_guardian_events(root_pub, device_pub, ts_ms)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_device_guardian_events_hash "
            "ON device_guardian_events(event_hash)"
        )
        c.execute(
            """
            UPDATE self_mesh_devices
            SET safety_state = 'revoked',
                safety_updated_ms = CASE
                    WHEN safety_updated_ms = 0 THEN updated_ms
                    ELSE safety_updated_ms
                END,
                safety_reason = CASE
                    WHEN safety_reason = '' THEN 'backfilled from revoked flag'
                    ELSE safety_reason
                END
            WHERE revoked = 1 AND safety_state != 'revoked'
            """
        )

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
        # 2026-05-21 audit T3-W: previously returned ``[]`` on JSON
        # decode failure — that's "deny-all", which is asymmetric with
        # the row-missing return of ``None`` ("allow-all-after-pair").
        # A corrupt row could silently lock out a paired peer entirely.
        # Raise instead: the caller (daemon ._capability_allowed) now
        # catches and fails CLOSED with a loud audit-log entry, which
        # is the correct safer default (T1-D).
        try:
            return list(json.loads(row["allowed_json"]))
        except Exception as exc:
            raise RuntimeError(
                f"peer_capability_policy.allowed_json corrupted for "
                f"{fingerprint[:8]}: {exc}"
            ) from exc

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
        cutoff_raw = self.get_setting("activity_cleared_before_ms")
        if cutoff_raw:
            with contextlib.suppress(ValueError, TypeError):
                cutoff_ms = int(cutoff_raw)
                since_ms = max(int(since_ms or 0), cutoff_ms)

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
        if kinds_set is None or "self_mesh" in kinds_set:
            sql = "SELECT * FROM self_mesh_audit"
            wclauses = []
            params = []
            if since_ms is not None:
                wclauses.append("ts_ms >= ?"); params.append(int(since_ms))
            if peer_fp is not None:
                wclauses.append("peer_fp = ?"); params.append(peer_fp)
            if wclauses:
                sql += " WHERE " + " AND ".join(wclauses)
            sql += " ORDER BY ts_ms DESC LIMIT ?"
            params.append(limit)
            for r in self._conn.execute(sql, tuple(params)).fetchall():
                ev = r["event"]
                action = r["action"] or ""
                detail = r["detail"] or action.replace("_", " ")
                events.append({
                    "ts_ms": r["ts_ms"],
                    "kind": "self_mesh",
                    "subkind": ev,
                    "severity": r["severity"] or "info",
                    "label": f"My devices · {ev.replace('_', ' ')}",
                    "detail": detail,
                    "peer_fp": r["peer_fp"],
                    "peer_display_name": _peer_label(r["peer_fp"]),
                    "source": "self_mesh_audit",
                })

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
            if new_event_id is None and cur.lastrowid is not None:
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
        # v0.20.7 (security audit H21): wrap the chain_key at rest if
        # the daemon was started with ONE_LINK_PASSPHRASE. Reads
        # detect the wrap marker and decrypt transparently; a stolen-
        # disk attacker without the passphrase sees AEAD ciphertext.
        # When no lockbox is configured this is a no-op passthrough
        # (cleartext on disk — same as before this fix).
        from one_link.lockbox import maybe_wrap as _lb_wrap
        chain_key_at_rest = _lb_wrap(chain_key, self._lockbox)
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
                 chain_key_at_rest, int(counter), _now_ms()),
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
        # v0.20.7 (security audit H21): unwrap if the stored value
        # is lockbox-wrapped. Use length-based disambiguation: a
        # cleartext chain_key is exactly 32 bytes (validated at
        # write time), and a lockbox-wrapped one is 61 bytes
        # (marker + nonce + ct + tag). This avoids the 1/256 false
        # positive that a generic is_wrapped check would have on
        # the small-marker-byte collision class.
        chain_key = bytes(row["chain_key"])
        if len(chain_key) != 32:
            from one_link.lockbox import LockBox  # noqa: F401
            if self._lockbox is None:
                raise RuntimeError(
                    "found a non-cleartext chain_key but no lockbox is "
                    "configured (was ONE_LINK_PASSPHRASE removed?)"
                )
            chain_key = self._lockbox.unwrap(chain_key)
        return {
            "epoch": row["epoch"],
            "chain_key": chain_key,
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
                f"UPDATE peers SET {', '.join(sets)} WHERE fingerprint = ?",  # nosec B608
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
            f" WHERE target_msg_id IN ({placeholders}) ORDER BY ts_ms ASC",  # nosec B608
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
            f"SELECT * FROM messages WHERE {where} "  # nosec B608
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
        sql = f"SELECT * FROM messages{where} ORDER BY ts_ms DESC LIMIT ?"  # nosec B608
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

    def _delete_all_locked(self, table: str, where: str = "", params: tuple = ()) -> int:
        sql = f"DELETE FROM {table}" + (f" WHERE {where}" if where else "")  # nosec B608
        try:
            cur = self._conn.execute(sql, params)
            return int(cur.rowcount or 0)
        except sqlite3.Error:
            return 0

    def clear_chat_traces(self) -> dict[str, int]:
        """Hard-delete local chat traces without removing peers/groups."""
        with self._write_lock:
            counts = {
                "messages": self._delete_all_locked("messages"),
                "group_messages": self._delete_all_locked("group_messages"),
                "message_reactions": self._delete_all_locked("message_reactions"),
                "outbox": self._delete_all_locked("outbox"),
            }
            return counts

    def clear_file_traces(self) -> dict[str, int]:
        """Clear file-transfer records and file metadata caches only.

        This intentionally does not delete inbox files or source files
        from the user's filesystem.
        """
        with self._write_lock:
            counts = {
                "file_messages": self._delete_all_locked(
                    "messages",
                    "LOWER(msg_type) IN ('file', 'file_done', 'file_offer')",
                ),
                "transfers": self._delete_all_locked(
                    "transfers", "LOWER(kind) = 'file'",
                ),
                "file_index_cache": self._delete_all_locked("file_index_cache"),
                "chunk_sources": self._delete_all_locked("chunk_sources"),
                "chunk_availability": self._delete_all_locked("chunk_availability"),
            }
            return counts

    def clear_folder_traces(self) -> dict[str, int]:
        """Remove folder-sync metadata without deleting watched folders."""
        with self._write_lock:
            counts = {
                "folders": self._delete_all_locked("folders"),
                "folder_manifest": self._delete_all_locked("folder_manifest"),
                "folder_audit": self._delete_all_locked("folder_audit"),
                "manifest_conflicts": self._delete_all_locked("manifest_conflicts"),
                "folder_permissions": self._delete_all_locked(
                    "settings", "key LIKE 'folder_permission:%'",
                ),
            }
            return counts

    def clear_activity_traces(self) -> dict[str, int]:
        """Clear local audit/activity rows. Peer identities are preserved."""
        with self._write_lock:
            self._conn.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                ("activity_cleared_before_ms", str(_now_ms())),
            )
            counts = {
                "transfers": self._delete_all_locked("transfers"),
                "capability_audit": self._delete_all_locked("capability_audit"),
                "key_change_events": self._delete_all_locked("key_change_events"),
                "folder_audit": self._delete_all_locked("folder_audit"),
                "self_mesh_audit": self._delete_all_locked("self_mesh_audit"),
                "self_mesh_perf_samples": self._delete_all_locked("self_mesh_perf_samples"),
                "device_guardian_events": self._delete_all_locked("device_guardian_events"),
                "remote_instruction_seen": self._delete_all_locked("remote_instruction_seen"),
            }
            return counts

    def clear_all_app_traces(self) -> dict[str, dict[str, int] | int]:
        """Clear local app traces while preserving identity, peers, and trust.

        The wipe removes local records/caches that reveal app activity.
        It does not delete user files from the filesystem and does not
        revoke device identity or pairing/trust state.
        """
        with self._write_lock:
            result: dict[str, dict[str, int] | int] = {
                "chat": self.clear_chat_traces(),
                "files": self.clear_file_traces(),
                "folders": self.clear_folder_traces(),
                "activity": self.clear_activity_traces(),
            }
            result["route_memory"] = self._delete_all_locked("route_memory")
            result["route_candidates"] = self._delete_all_locked("route_candidates")
            result["courier_outbox"] = self._delete_all_locked("courier_outbox")
            result["settings_trace_keys"] = self._delete_all_locked(
                "settings",
                "key LIKE 'chatpref:%'",
            )
            return result

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
        # 2026-05-21 audit T3-K: hold the write lock across both the
        # read and the upsert. Without this, two concurrent updates
        # to the same transfer (e.g. parallel chunk ACK + a status
        # flip) each read the same `current`, each rebuild the full
        # record, and the second write clobbers the first — progress
        # counters and metadata.path could regress. The lock is an
        # RLock so callers that already hold it (e.g. a chunk-ACK
        # batch processor) re-enter cleanly.
        with self._write_lock:
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
                f"DELETE FROM transfers WHERE {where}{keep_clause}",  # nosec B608
                params,
            )
            return int(cur.rowcount)

    # ─── outbox (v0.7.1: store-and-forward) ──────────────────────────

    def upsert_route_memory(
        self,
        *,
        peer_fp: str,
        route: str,
        attempts: int,
        successes: int,
        failures: int,
        score: float,
        latency_ms: float | None = None,
        bandwidth_bps: float | None = None,
        metadata: Optional[dict] = None,
    ) -> None:
        if not peer_fp:
            raise ValueError("peer_fp is required")
        if not route:
            raise ValueError("route is required")
        attempts_i = max(0, int(attempts))
        successes_i = max(0, min(attempts_i, int(successes)))
        failures_i = max(0, min(attempts_i - successes_i, int(failures)))
        now = _now_ms()
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO route_memory(
                    peer_fp, route, attempts, successes, failures, score,
                    latency_ms, bandwidth_bps, updated_ms, metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(peer_fp, route) DO UPDATE SET
                    attempts = excluded.attempts,
                    successes = excluded.successes,
                    failures = excluded.failures,
                    score = excluded.score,
                    latency_ms = excluded.latency_ms,
                    bandwidth_bps = excluded.bandwidth_bps,
                    updated_ms = excluded.updated_ms,
                    metadata_json = excluded.metadata_json
                """,
                (
                    peer_fp,
                    route,
                    attempts_i,
                    successes_i,
                    failures_i,
                    float(score),
                    float(latency_ms) if latency_ms is not None else None,
                    float(bandwidth_bps) if bandwidth_bps is not None else None,
                    now,
                    json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True),
                ),
            )

    def list_route_memory(self, peer_fp: Optional[str] = None) -> list[dict]:
        if peer_fp:
            rows = self._conn.execute(
                """
                SELECT * FROM route_memory
                WHERE peer_fp = ?
                ORDER BY score DESC, updated_ms DESC
                """,
                (peer_fp,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM route_memory ORDER BY peer_fp, score DESC"
            ).fetchall()
        out: list[dict] = []
        for row in rows:
            try:
                metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
            except json.JSONDecodeError:
                metadata = {}
            out.append({
                "peer_fp": row["peer_fp"],
                "route": row["route"],
                "attempts": int(row["attempts"]),
                "successes": int(row["successes"]),
                "failures": int(row["failures"]),
                "score": float(row["score"]),
                "latency_ms": (
                    float(row["latency_ms"]) if row["latency_ms"] is not None else None
                ),
                "bandwidth_bps": (
                    float(row["bandwidth_bps"]) if row["bandwidth_bps"] is not None else None
                ),
                "updated_ms": int(row["updated_ms"]),
                "metadata": metadata if isinstance(metadata, dict) else {},
            })
        return out

    def upsert_route_candidate(
        self,
        *,
        peer_fp: str,
        route: str,
        transport: str,
        host: str,
        port: int,
        source: str,
        verified: bool = False,
        attempts: int | None = None,
        successes: int | None = None,
        failures: int | None = None,
        latency_ms: float | None = None,
        bandwidth_bps: float | None = None,
        last_error: str | None = None,
        expires_ms: int | None = None,
        metadata: Optional[dict] = None,
    ) -> None:
        if not peer_fp:
            raise ValueError("peer_fp is required")
        if not route:
            raise ValueError("route is required")
        if not transport:
            raise ValueError("transport is required")
        host_s = str(host or "").strip()
        if not host_s:
            raise ValueError("host is required")
        port_i = int(port)
        if port_i <= 0 or port_i > 65535:
            raise ValueError("port must be 1..65535")
        current = self.get_route_candidate(
            peer_fp=peer_fp,
            route=str(route),
            transport=str(transport),
            host=host_s,
            port=port_i,
        )
        attempts_i = (
            int((current or {}).get("attempts") or 0)
            if attempts is None else max(0, int(attempts))
        )
        successes_i = (
            int((current or {}).get("successes") or 0)
            if successes is None else max(0, int(successes))
        )
        failures_i = (
            int((current or {}).get("failures") or 0)
            if failures is None else max(0, int(failures))
        )
        now = _now_ms()
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO route_candidates(
                    peer_fp, route, transport, host, port, source, verified,
                    attempts, successes, failures, latency_ms, bandwidth_bps,
                    last_error, first_seen_ms, updated_ms, expires_ms, metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(peer_fp, route, transport, host, port) DO UPDATE SET
                    source = excluded.source,
                    verified = MAX(route_candidates.verified, excluded.verified),
                    attempts = CASE
                        WHEN excluded.attempts IS NULL THEN route_candidates.attempts
                        ELSE excluded.attempts
                    END,
                    successes = CASE
                        WHEN excluded.successes IS NULL THEN route_candidates.successes
                        ELSE excluded.successes
                    END,
                    failures = CASE
                        WHEN excluded.failures IS NULL THEN route_candidates.failures
                        ELSE excluded.failures
                    END,
                    latency_ms = COALESCE(excluded.latency_ms, route_candidates.latency_ms),
                    bandwidth_bps = COALESCE(excluded.bandwidth_bps, route_candidates.bandwidth_bps),
                    last_error = excluded.last_error,
                    updated_ms = excluded.updated_ms,
                    expires_ms = excluded.expires_ms,
                    metadata_json = excluded.metadata_json
                """,
                (
                    peer_fp,
                    str(route),
                    str(transport),
                    host_s,
                    port_i,
                    str(source)[:80],
                    1 if verified else 0,
                    attempts_i,
                    successes_i,
                    failures_i,
                    float(latency_ms) if latency_ms is not None else None,
                    float(bandwidth_bps) if bandwidth_bps is not None else None,
                    str(last_error)[:240] if last_error else None,
                    now,
                    now,
                    int(expires_ms) if expires_ms else None,
                    json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True),
                ),
            )

    def observe_route_candidate(
        self,
        *,
        peer_fp: str,
        route: str,
        transport: str,
        host: str,
        port: int,
        ok: bool,
        source: str = "runtime",
        latency_ms: float | None = None,
        bandwidth_bps: float | None = None,
        error: str | None = None,
        verified: bool | None = None,
        expires_ms: int | None = None,
        metadata: Optional[dict] = None,
    ) -> None:
        current = self.get_route_candidate(
            peer_fp=peer_fp,
            route=route,
            transport=transport,
            host=host,
            port=port,
        )
        attempts = int((current or {}).get("attempts") or 0) + 1
        successes = int((current or {}).get("successes") or 0) + (1 if ok else 0)
        failures = int((current or {}).get("failures") or 0) + (0 if ok else 1)
        self.upsert_route_candidate(
            peer_fp=peer_fp,
            route=route,
            transport=transport,
            host=host,
            port=port,
            source=source,
            verified=bool(verified if verified is not None else ok),
            attempts=attempts,
            successes=successes,
            failures=failures,
            latency_ms=latency_ms,
            bandwidth_bps=bandwidth_bps,
            last_error=None if ok else error,
            expires_ms=expires_ms,
            metadata={**((current or {}).get("metadata") or {}), **(metadata or {})},
        )

    def get_route_candidate(
        self,
        *,
        peer_fp: str,
        route: str,
        transport: str,
        host: str,
        port: int,
    ) -> Optional[dict]:
        row = self._conn.execute(
            """
            SELECT * FROM route_candidates
            WHERE peer_fp = ? AND route = ? AND transport = ? AND host = ? AND port = ?
            """,
            (peer_fp, route, transport, str(host), int(port)),
        ).fetchone()
        return self._row_to_route_candidate(row) if row else None

    def list_route_candidates(
        self,
        peer_fp: Optional[str] = None,
        *,
        verified_only: bool = False,
        include_expired: bool = False,
        limit: int = 64,
    ) -> list[dict]:
        now = _now_ms()
        clauses: list[str] = []
        params: list[Any] = []
        if peer_fp:
            clauses.append("peer_fp = ?")
            params.append(peer_fp)
        if verified_only:
            clauses.append("verified = 1")
        if not include_expired:
            clauses.append("(expires_ms IS NULL OR expires_ms > ?)")
            params.append(now)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"""
            SELECT * FROM route_candidates
            {where}
            ORDER BY
                verified DESC,
                successes DESC,
                failures ASC,
                COALESCE(bandwidth_bps, 0) DESC,
                COALESCE(latency_ms, 999999) ASC,
                updated_ms DESC
            LIMIT ?
            """  # nosec B608
        rows = self._conn.execute(
            sql,
            (*params, max(1, min(512, int(limit)))),
        ).fetchall()
        return [self._row_to_route_candidate(r) for r in rows]

    def prune_route_candidates(self, *, now_ms: int | None = None) -> int:
        now = _now_ms() if now_ms is None else int(now_ms)
        with self._write_lock:
            cur = self._conn.execute(
                "DELETE FROM route_candidates WHERE expires_ms IS NOT NULL AND expires_ms <= ?",
                (now,),
            )
            return int(cur.rowcount)

    def upsert_self_mesh_device(
        self,
        *,
        root_pub: bytes,
        device_pub: bytes,
        device_kind: str,
        cert: bytes | None = None,
        label: str = "",
        local: bool = False,
        trusted: bool = True,
        revoked: bool = False,
        safety_state: str | None = None,
        metadata: Optional[dict] = None,
        added_ms: int | None = None,
    ) -> dict:
        """Record one separately addressable device under a root identity."""
        from one_link.device_guardian import normalize_safety_state

        self._validate_self_mesh_pub(root_pub, "root_pub")
        self._validate_self_mesh_pub(device_pub, "device_pub")
        kind = str(device_kind or "").strip()
        if not kind:
            raise ValueError("device_kind is required")
        now = _now_ms()
        added = now if added_ms is None else int(added_ms)
        safety = normalize_safety_state(
            safety_state or ("revoked" if revoked else "trusted")
        )
        meta_json = json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True)
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO self_mesh_devices(
                    root_pub, device_pub, cert, device_kind, label, local,
                    trusted, revoked, added_ms, updated_ms, metadata_json,
                    safety_state, safety_updated_ms, guardian_epoch, safety_reason
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(root_pub, device_pub) DO UPDATE SET
                    cert = COALESCE(excluded.cert, self_mesh_devices.cert),
                    device_kind = excluded.device_kind,
                    label = excluded.label,
                    local = excluded.local,
                    trusted = CASE
                        WHEN self_mesh_devices.safety_state IN (
                            'maybe_lost', 'frozen', 'revoked', 'quarantined'
                        ) OR excluded.safety_state IN (
                            'maybe_lost', 'frozen', 'revoked', 'quarantined'
                        )
                        THEN 0
                        ELSE excluded.trusted
                    END,
                    revoked = CASE
                        WHEN self_mesh_devices.safety_state = 'revoked'
                             OR excluded.safety_state = 'revoked'
                        THEN 1
                        ELSE excluded.revoked
                    END,
                    updated_ms = excluded.updated_ms,
                    metadata_json = excluded.metadata_json,
                    safety_state = CASE
                        WHEN self_mesh_devices.safety_state = 'trusted'
                        THEN excluded.safety_state
                        ELSE self_mesh_devices.safety_state
                    END,
                    safety_updated_ms = CASE
                        WHEN self_mesh_devices.safety_updated_ms = 0
                        THEN excluded.safety_updated_ms
                        ELSE self_mesh_devices.safety_updated_ms
                    END
                """,
                (
                    bytes(root_pub),
                    bytes(device_pub),
                    bytes(cert) if cert is not None else None,
                    kind[:64],
                    str(label or "")[:120],
                    1 if local else 0,
                    1 if trusted else 0,
                    1 if revoked else 0,
                    added,
                    now,
                    meta_json,
                    safety,
                    now,
                    1 if safety == "revoked" else 0,
                    "enrolled revoked" if safety == "revoked" else "",
                ),
            )
        row = self._conn.execute(
            "SELECT * FROM self_mesh_devices WHERE root_pub = ? AND device_pub = ?",
            (bytes(root_pub), bytes(device_pub)),
        ).fetchone()
        return self._row_to_self_mesh_device(row)

    def upsert_self_mesh_root(
        self,
        *,
        root_pub: bytes,
        label: str = "",
        root_seed: bytes | None = None,
        metadata: Optional[dict] = None,
    ) -> dict:
        """Create/update a personal mesh root identity.

        ``root_seed`` is optional. When present, it is wrapped with the
        daemon LockBox if one is configured, matching other high-value
        state secrets.
        """
        self._validate_self_mesh_pub(root_pub, "root_pub")
        if root_seed is not None and len(bytes(root_seed)) != 32:
            raise ValueError("root_seed must be 32 bytes")
        from one_link.lockbox import maybe_wrap as _lb_wrap

        now = _now_ms()
        seed_at_rest = (
            _lb_wrap(bytes(root_seed), self._lockbox)
            if root_seed is not None else None
        )
        meta_json = json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True)
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO self_mesh_roots(
                    root_pub, label, root_seed, created_ms, updated_ms,
                    metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(root_pub) DO UPDATE SET
                    label = excluded.label,
                    root_seed = COALESCE(excluded.root_seed, self_mesh_roots.root_seed),
                    updated_ms = excluded.updated_ms,
                    metadata_json = excluded.metadata_json
                """,
                (
                    bytes(root_pub),
                    str(label or "")[:120],
                    seed_at_rest,
                    now,
                    now,
                    meta_json,
                ),
            )
        row = self._conn.execute(
            "SELECT * FROM self_mesh_roots WHERE root_pub = ?",
            (bytes(root_pub),),
        ).fetchone()
        return self._row_to_self_mesh_root(row, include_seed=False)

    def list_self_mesh_roots(self, *, include_seed: bool = False) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM self_mesh_roots ORDER BY updated_ms DESC, label ASC"
        ).fetchall()
        return [
            self._row_to_self_mesh_root(r, include_seed=include_seed)
            for r in rows
        ]

    def get_self_mesh_root(
        self,
        root_pub: bytes,
        *,
        include_seed: bool = False,
    ) -> dict | None:
        self._validate_self_mesh_pub(root_pub, "root_pub")
        row = self._conn.execute(
            "SELECT * FROM self_mesh_roots WHERE root_pub = ?",
            (bytes(root_pub),),
        ).fetchone()
        return (
            self._row_to_self_mesh_root(row, include_seed=include_seed)
            if row else None
        )

    def get_self_mesh_device(
        self,
        *,
        root_pub: bytes,
        device_pub: bytes,
    ) -> dict | None:
        self._validate_self_mesh_pub(root_pub, "root_pub")
        self._validate_self_mesh_pub(device_pub, "device_pub")
        row = self._conn.execute(
            "SELECT * FROM self_mesh_devices WHERE root_pub = ? AND device_pub = ?",
            (bytes(root_pub), bytes(device_pub)),
        ).fetchone()
        return self._row_to_self_mesh_device(row) if row else None

    def revoke_self_mesh_device(
        self,
        *,
        root_pub: bytes,
        device_pub: bytes,
    ) -> dict | None:
        self._validate_self_mesh_pub(root_pub, "root_pub")
        self._validate_self_mesh_pub(device_pub, "device_pub")
        now = _now_ms()
        with self._write_lock:
            self._conn.execute(
                """
                UPDATE self_mesh_devices
                SET revoked = 1, trusted = 0, safety_state = 'revoked',
                    guardian_epoch = guardian_epoch + 1,
                    safety_updated_ms = ?, safety_reason = 'legacy revoke',
                    updated_ms = ?
                WHERE root_pub = ? AND device_pub = ?
                """,
                (now, now, bytes(root_pub), bytes(device_pub)),
            )
        return self.get_self_mesh_device(root_pub=root_pub, device_pub=device_pub)

    def set_self_mesh_device_safety(
        self,
        *,
        root_pub: bytes,
        device_pub: bytes,
        requested_state: str,
        actor_device_pub: bytes | None = None,
        proofs: Any = None,
        reason: str = "",
        actor_is_local: bool = True,
        active_suspicion: bool = False,
        metadata: Optional[dict] = None,
        ts_ms: int | None = None,
    ) -> dict:
        from one_link.device_guardian import (
            decide_device_safety_transition,
            event_hash,
            normalize_proofs,
        )

        self._validate_self_mesh_pub(root_pub, "root_pub")
        self._validate_self_mesh_pub(device_pub, "device_pub")
        if actor_device_pub is not None:
            self._validate_self_mesh_pub(actor_device_pub, "actor_device_pub")
        now = _now_ms() if ts_ms is None else int(ts_ms)
        with self._write_lock:
            row = self._conn.execute(
                "SELECT * FROM self_mesh_devices WHERE root_pub = ? AND device_pub = ?",
                (bytes(root_pub), bytes(device_pub)),
            ).fetchone()
            if row is None:
                raise ValueError("device is not enrolled")
            current = row["safety_state"] if "safety_state" in row.keys() else (
                "revoked" if row["revoked"] else "trusted"
            )
            decision = decide_device_safety_transition(
                current,
                requested_state,
                proofs=proofs,
                actor_is_local=actor_is_local,
                active_suspicion=active_suspicion,
                now=now,
            )
            prev = self._conn.execute(
                """
                SELECT event_hash FROM device_guardian_events
                WHERE root_pub = ? AND device_pub = ?
                ORDER BY id DESC LIMIT 1
                """,
                (bytes(root_pub), bytes(device_pub)),
            ).fetchone()
            prev_hash = str(prev["event_hash"]) if prev else ""
            proof_list = sorted(normalize_proofs(proofs))
            event_body = {
                "ts_ms": now,
                "root_pub": bytes(root_pub).hex(),
                "device_pub": bytes(device_pub).hex(),
                "actor_device_pub": bytes(actor_device_pub).hex() if actor_device_pub else "",
                "from_state": current,
                "to_state": decision.target_state,
                "allowed": decision.allowed,
                "event": decision.event,
                "reason": str(reason or decision.detail)[:500],
                "proofs": proof_list,
                "effects": list(decision.effects),
            }
            digest = event_hash(event_body, prev_hash)
            self._conn.execute(
                """
                INSERT INTO device_guardian_events(
                    ts_ms, root_pub, device_pub, actor_device_pub,
                    from_state, to_state, decision, reason, proofs_json,
                    effects_json, event_hash, prev_hash, metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    bytes(root_pub),
                    bytes(device_pub),
                    bytes(actor_device_pub) if actor_device_pub is not None else None,
                    current,
                    decision.target_state,
                    "allowed" if decision.allowed else "denied",
                    str(reason or decision.detail)[:500],
                    json.dumps(proof_list, separators=(",", ":")),
                    json.dumps(list(decision.effects), separators=(",", ":")),
                    digest,
                    prev_hash,
                    json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True),
                ),
            )
            if decision.allowed and decision.target_state != current:
                revoked = decision.target_state == "revoked"
                trusted = decision.target_state in {"trusted", "recovered", "suspicious"}
                self._conn.execute(
                    """
                    UPDATE self_mesh_devices
                    SET safety_state = ?, safety_updated_ms = ?,
                        safety_reason = ?, updated_ms = ?,
                        revoked = ?, trusted = ?,
                        guardian_epoch = guardian_epoch + ?
                    WHERE root_pub = ? AND device_pub = ?
                    """,
                    (
                        decision.target_state,
                        now,
                        str(reason or decision.detail)[:500],
                        now,
                        1 if revoked else 0,
                        1 if trusted and not revoked else 0,
                        1 if decision.target_state in {"frozen", "revoked", "quarantined"} else 0,
                        bytes(root_pub),
                        bytes(device_pub),
                    ),
                )
            device = self.get_self_mesh_device(root_pub=root_pub, device_pub=device_pub)
            return {
                "ok": bool(decision.allowed),
                "decision": decision.to_dict(),
                "device": device,
                "event_hash": digest,
                "previous_hash": prev_hash,
            }

    def list_self_mesh_devices(
        self,
        *,
        root_pub: bytes | None = None,
        include_revoked: bool = True,
    ) -> list[dict]:
        clauses: list[str] = []
        params: list[Any] = []
        if root_pub is not None:
            self._validate_self_mesh_pub(root_pub, "root_pub")
            clauses.append("root_pub = ?")
            params.append(bytes(root_pub))
        if not include_revoked:
            clauses.append("revoked = 0")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"""
            SELECT * FROM self_mesh_devices
            {where}
            ORDER BY local DESC, revoked ASC, updated_ms DESC, label ASC
            """  # nosec B608
        rows = self._conn.execute(
            sql,
            params,
        ).fetchall()
        return [self._row_to_self_mesh_device(r) for r in rows]

    def list_device_guardian_events(
        self,
        *,
        root_pub: bytes | None = None,
        device_pub: bytes | None = None,
        limit: int = 200,
    ) -> list[dict]:
        clauses: list[str] = []
        params: list[Any] = []
        if root_pub is not None:
            self._validate_self_mesh_pub(root_pub, "root_pub")
            clauses.append("root_pub = ?")
            params.append(bytes(root_pub))
        if device_pub is not None:
            self._validate_self_mesh_pub(device_pub, "device_pub")
            clauses.append("device_pub = ?")
            params.append(bytes(device_pub))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(max(1, min(int(limit), 2000)))
        sql = (
            "SELECT * FROM device_guardian_events"
            f"{where} ORDER BY ts_ms DESC, id DESC LIMIT ?"  # nosec B608
        )
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_device_guardian_event(r) for r in rows]

    def upsert_self_mesh_presence(
        self,
        *,
        device_pub: bytes,
        state: str,
        updated_ms: int,
        sequence: int = 0,
        battery_pct: int | None = None,
        network: str = "unknown",
        free_bytes: int | None = None,
        route: str | None = None,
        latency_ms: float | None = None,
        bandwidth_bps: float | None = None,
        metadata: Optional[dict] = None,
    ) -> dict:
        """Merge a self-mesh presence fact using (sequence, updated_ms)."""
        self._validate_self_mesh_pub(device_pub, "device_pub")
        if state not in {"awake", "asleep", "dormant", "offline"}:
            raise ValueError("invalid self-mesh presence state")
        if network not in {"ethernet", "wifi", "cellular", "bluetooth", "offline", "unknown"}:
            raise ValueError("invalid self-mesh network")
        if battery_pct is not None and not (0 <= int(battery_pct) <= 100):
            raise ValueError("battery_pct must be 0..100")
        if free_bytes is not None and int(free_bytes) < 0:
            raise ValueError("free_bytes must be non-negative")
        seq = max(0, int(sequence))
        updated = int(updated_ms)
        meta_json = json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True)
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO self_mesh_presence(
                    device_pub, state, sequence, updated_ms, battery_pct,
                    network, free_bytes, route, latency_ms, bandwidth_bps,
                    metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_pub) DO UPDATE SET
                    state = excluded.state,
                    sequence = excluded.sequence,
                    updated_ms = excluded.updated_ms,
                    battery_pct = excluded.battery_pct,
                    network = excluded.network,
                    free_bytes = excluded.free_bytes,
                    route = excluded.route,
                    latency_ms = excluded.latency_ms,
                    bandwidth_bps = excluded.bandwidth_bps,
                    metadata_json = excluded.metadata_json
                WHERE
                    excluded.sequence > self_mesh_presence.sequence
                    OR (
                        excluded.sequence = self_mesh_presence.sequence
                        AND excluded.updated_ms >= self_mesh_presence.updated_ms
                    )
                """,
                (
                    bytes(device_pub),
                    state,
                    seq,
                    updated,
                    int(battery_pct) if battery_pct is not None else None,
                    network,
                    int(free_bytes) if free_bytes is not None else None,
                    str(route)[:80] if route else None,
                    float(latency_ms) if latency_ms is not None else None,
                    float(bandwidth_bps) if bandwidth_bps is not None else None,
                    meta_json,
                ),
            )
        row = self._conn.execute(
            "SELECT * FROM self_mesh_presence WHERE device_pub = ?",
            (bytes(device_pub),),
        ).fetchone()
        return self._row_to_self_mesh_presence(row)

    def list_self_mesh_presence(self) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT * FROM self_mesh_presence
            ORDER BY updated_ms DESC, sequence DESC
            """
        ).fetchall()
        return [self._row_to_self_mesh_presence(r) for r in rows]

    def mark_remote_instruction_seen(
        self,
        *,
        command_id: str,
        expires_ms: int,
        action: str = "",
        controller_device_pub: bytes | None = None,
        target_device_pub: bytes | None = None,
        now_ms: int | None = None,
    ) -> bool:
        """Remember a remote-instruct command id.

        Returns True on first sight and False for a replay. Expired rows
        are pruned before insertion so the table stays bounded.
        """
        cid = str(command_id or "").strip()
        if not cid:
            raise ValueError("command_id is required")
        if len(cid) > 128:
            raise ValueError("command_id is too long")
        now = _now_ms() if now_ms is None else int(now_ms)
        exp = int(expires_ms)
        if exp <= now:
            raise ValueError("expires_ms must be in the future")
        if controller_device_pub is not None:
            self._validate_self_mesh_pub(controller_device_pub, "controller_device_pub")
        if target_device_pub is not None:
            self._validate_self_mesh_pub(target_device_pub, "target_device_pub")
        with self._write_lock:
            self._conn.execute(
                "DELETE FROM remote_instruction_seen WHERE expires_ms <= ?",
                (now,),
            )
            cur = self._conn.execute(
                """
                INSERT OR IGNORE INTO remote_instruction_seen(
                    command_id, first_seen_ms, expires_ms, action,
                    controller_device_pub, target_device_pub
                ) VALUES(?, ?, ?, ?, ?, ?)
                """,
                (
                    cid,
                    now,
                    exp,
                    str(action or "")[:80],
                    bytes(controller_device_pub) if controller_device_pub is not None else None,
                    bytes(target_device_pub) if target_device_pub is not None else None,
                ),
            )
            return int(cur.rowcount) == 1

    def record_self_mesh_audit(
        self,
        *,
        event: str,
        severity: str = "info",
        root_pub: bytes | None = None,
        device_pub: bytes | None = None,
        peer_fp: str | None = None,
        command_id: str | None = None,
        action: str | None = None,
        path: str | None = None,
        detail: str = "",
        metadata: Optional[dict] = None,
        ts_ms: int | None = None,
    ) -> int:
        ev = str(event or "").strip()
        if not ev:
            raise ValueError("event is required")
        sev = str(severity or "info")
        if sev not in {"good", "info", "warn", "bad"}:
            raise ValueError("invalid self-mesh audit severity")
        if root_pub is not None:
            self._validate_self_mesh_pub(root_pub, "root_pub")
        if device_pub is not None:
            self._validate_self_mesh_pub(device_pub, "device_pub")
        now = _now_ms() if ts_ms is None else int(ts_ms)
        meta_json = json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True)
        with self._write_lock:
            cur = self._conn.execute(
                """
                INSERT INTO self_mesh_audit(
                    ts_ms, event, severity, root_pub, device_pub, peer_fp,
                    command_id, action, path, detail, metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    ev[:80],
                    sev,
                    bytes(root_pub) if root_pub is not None else None,
                    bytes(device_pub) if device_pub is not None else None,
                    str(peer_fp or "")[:128] if peer_fp else None,
                    str(command_id or "")[:128] if command_id else None,
                    str(action or "")[:80] if action else None,
                    str(path or "")[:1000] if path else None,
                    str(detail or "")[:500],
                    meta_json,
                ),
            )
            return int(cur.lastrowid or 0)

    def list_self_mesh_audit(
        self,
        *,
        since_ms: int | None = None,
        root_pub: bytes | None = None,
        limit: int = 200,
    ) -> list[dict]:
        clauses: list[str] = []
        params: list[Any] = []
        if since_ms is not None:
            clauses.append("ts_ms >= ?")
            params.append(int(since_ms))
        if root_pub is not None:
            self._validate_self_mesh_pub(root_pub, "root_pub")
            clauses.append("root_pub = ?")
            params.append(bytes(root_pub))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(max(1, min(int(limit), 2000)))
        sql = f"""
            SELECT * FROM self_mesh_audit
            {where}
            ORDER BY ts_ms DESC, id DESC
            LIMIT ?
            """  # nosec B608
        rows = self._conn.execute(
            sql,
            params,
        ).fetchall()
        return [self._row_to_self_mesh_audit(r) for r in rows]

    def record_self_mesh_perf_sample(
        self,
        sample: dict,
        *,
        ts_ms: int | None = None,
    ) -> int:
        now = _now_ms() if ts_ms is None else int(ts_ms)
        metadata = {
            k: v for k, v in dict(sample).items()
            if k not in {
                "route_probe_runs",
                "route_probe_ready",
                "route_probe_total_ms",
                "route_probe_avg_ms",
                "presence_rows",
                "device_rows",
                "recent_audit_rows",
                "status",
            }
        }
        with self._write_lock:
            cur = self._conn.execute(
                """
                INSERT INTO self_mesh_perf_samples(
                    ts_ms, route_probe_runs, route_probe_ready,
                    route_probe_total_ms, route_probe_avg_ms, presence_rows,
                    device_rows, recent_audit_rows, status, metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    int(sample.get("route_probe_runs") or 0),
                    int(sample.get("route_probe_ready") or 0),
                    float(sample.get("route_probe_total_ms") or 0.0),
                    float(sample.get("route_probe_avg_ms") or 0.0),
                    int(sample.get("presence_rows") or 0),
                    int(sample.get("device_rows") or 0),
                    int(sample.get("recent_audit_rows") or 0),
                    str(sample.get("status") or "unknown")[:40],
                    json.dumps(metadata, separators=(",", ":"), sort_keys=True),
                ),
            )
            # Keep the table bounded without needing a background task.
            self._conn.execute(
                """
                DELETE FROM self_mesh_perf_samples
                WHERE id NOT IN (
                    SELECT id FROM self_mesh_perf_samples
                    ORDER BY ts_ms DESC, id DESC
                    LIMIT 1000
                )
                """
            )
            return int(cur.lastrowid or 0)

    def list_self_mesh_perf_samples(self, *, limit: int = 120) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT * FROM self_mesh_perf_samples
            ORDER BY ts_ms DESC, id DESC
            LIMIT ?
            """,
            (max(1, min(int(limit), 1000)),),
        ).fetchall()
        return [self._row_to_self_mesh_perf_sample(r) for r in rows]

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
            if cur.rowcount > 0 and cur.lastrowid is not None:
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
        sql = "DELETE FROM outbox WHERE " + " AND ".join(clauses)  # nosec B608
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

    def _row_to_route_candidate(self, row: sqlite3.Row) -> dict:
        try:
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            metadata = {}
        return {
            "peer_fp": row["peer_fp"],
            "route": row["route"],
            "transport": row["transport"],
            "host": row["host"],
            "port": int(row["port"]),
            "source": row["source"],
            "verified": bool(row["verified"]),
            "attempts": int(row["attempts"]),
            "successes": int(row["successes"]),
            "failures": int(row["failures"]),
            "latency_ms": (
                float(row["latency_ms"]) if row["latency_ms"] is not None else None
            ),
            "bandwidth_bps": (
                float(row["bandwidth_bps"]) if row["bandwidth_bps"] is not None else None
            ),
            "last_error": row["last_error"],
            "first_seen_ms": int(row["first_seen_ms"]),
            "updated_ms": int(row["updated_ms"]),
            "expires_ms": int(row["expires_ms"]) if row["expires_ms"] is not None else None,
            "metadata": metadata if isinstance(metadata, dict) else {},
        }

    @staticmethod
    def _validate_self_mesh_pub(value: bytes, name: str) -> None:
        if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
            raise ValueError(f"{name} must be 32 bytes")

    def _row_to_self_mesh_root(
        self,
        row: sqlite3.Row,
        *,
        include_seed: bool = False,
    ) -> dict:
        try:
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            metadata = {}
        out = {
            "root_pub": bytes(row["root_pub"]),
            "label": row["label"],
            "has_root_seed": row["root_seed"] is not None,
            "created_ms": int(row["created_ms"]),
            "updated_ms": int(row["updated_ms"]),
            "metadata": metadata if isinstance(metadata, dict) else {},
        }
        if include_seed and row["root_seed"] is not None:
            from one_link.lockbox import maybe_unwrap as _lb_unwrap
            out["root_seed"] = _lb_unwrap(bytes(row["root_seed"]), self._lockbox)
        return out

    def _row_to_self_mesh_device(self, row: sqlite3.Row) -> dict:
        try:
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            metadata = {}
        cols = row.keys()
        return {
            "root_pub": bytes(row["root_pub"]),
            "device_pub": bytes(row["device_pub"]),
            "cert": bytes(row["cert"]) if row["cert"] is not None else None,
            "device_kind": row["device_kind"],
            "label": row["label"],
            "local": bool(row["local"]),
            "trusted": bool(row["trusted"]),
            "revoked": bool(row["revoked"]),
            "added_ms": int(row["added_ms"]),
            "updated_ms": int(row["updated_ms"]),
            "safety_state": (
                row["safety_state"] if "safety_state" in cols
                else ("revoked" if row["revoked"] else "trusted")
            ),
            "safety_updated_ms": (
                int(row["safety_updated_ms"]) if "safety_updated_ms" in cols else int(row["updated_ms"])
            ),
            "guardian_epoch": (
                int(row["guardian_epoch"]) if "guardian_epoch" in cols else (1 if row["revoked"] else 0)
            ),
            "safety_reason": row["safety_reason"] if "safety_reason" in cols else "",
            "metadata": metadata if isinstance(metadata, dict) else {},
        }

    def _row_to_device_guardian_event(self, row: sqlite3.Row) -> dict:
        def _json_list(name: str) -> list:
            try:
                value = json.loads(row[name]) if row[name] else []
            except Exception:
                value = []
            return value if isinstance(value, list) else []

        try:
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            metadata = {}
        return {
            "id": int(row["id"]),
            "ts_ms": int(row["ts_ms"]),
            "root_pub": bytes(row["root_pub"]),
            "device_pub": bytes(row["device_pub"]),
            "actor_device_pub": (
                bytes(row["actor_device_pub"]) if row["actor_device_pub"] is not None else None
            ),
            "from_state": row["from_state"],
            "to_state": row["to_state"],
            "decision": row["decision"],
            "reason": row["reason"],
            "proofs": _json_list("proofs_json"),
            "effects": _json_list("effects_json"),
            "event_hash": row["event_hash"],
            "prev_hash": row["prev_hash"],
            "metadata": metadata if isinstance(metadata, dict) else {},
        }

    def _row_to_self_mesh_audit(self, row: sqlite3.Row) -> dict:
        try:
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            metadata = {}
        return {
            "id": int(row["id"]),
            "ts_ms": int(row["ts_ms"]),
            "event": row["event"],
            "severity": row["severity"],
            "root_pub": bytes(row["root_pub"]) if row["root_pub"] is not None else None,
            "device_pub": (
                bytes(row["device_pub"]) if row["device_pub"] is not None else None
            ),
            "peer_fp": row["peer_fp"],
            "command_id": row["command_id"],
            "action": row["action"],
            "path": row["path"],
            "detail": row["detail"],
            "metadata": metadata if isinstance(metadata, dict) else {},
        }

    def _row_to_self_mesh_perf_sample(self, row: sqlite3.Row) -> dict:
        try:
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            metadata = {}
        return {
            "id": int(row["id"]),
            "ts_ms": int(row["ts_ms"]),
            "route_probe_runs": int(row["route_probe_runs"]),
            "route_probe_ready": int(row["route_probe_ready"]),
            "route_probe_total_ms": float(row["route_probe_total_ms"]),
            "route_probe_avg_ms": float(row["route_probe_avg_ms"]),
            "presence_rows": int(row["presence_rows"]),
            "device_rows": int(row["device_rows"]),
            "recent_audit_rows": int(row["recent_audit_rows"]),
            "status": row["status"],
            "metadata": metadata if isinstance(metadata, dict) else {},
        }

    def _row_to_self_mesh_presence(self, row: sqlite3.Row) -> dict:
        try:
            metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        except Exception:
            metadata = {}
        return {
            "device_pub": bytes(row["device_pub"]),
            "state": row["state"],
            "sequence": int(row["sequence"]),
            "updated_ms": int(row["updated_ms"]),
            "battery_pct": (
                int(row["battery_pct"]) if row["battery_pct"] is not None else None
            ),
            "network": row["network"],
            "free_bytes": (
                int(row["free_bytes"]) if row["free_bytes"] is not None else None
            ),
            "route": row["route"],
            "latency_ms": (
                float(row["latency_ms"]) if row["latency_ms"] is not None else None
            ),
            "bandwidth_bps": (
                float(row["bandwidth_bps"]) if row["bandwidth_bps"] is not None else None
            ),
            "metadata": metadata if isinstance(metadata, dict) else {},
        }

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
            assert cur.lastrowid is not None, "INSERT did not return a rowid"
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
            assert cur.lastrowid is not None, "INSERT did not return a rowid"
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

    def record_chunks_available_batch(
        self,
        records: "list[dict]",
    ) -> int:
        """Batched cousin of :meth:`record_chunk_available`. Wraps
        all inserts in a single explicit transaction so a
        thousand-chunk transfer pays one commit instead of one
        thousand. Returns the number of rows written.

        Each record is a dict with keys ``chunk_hash`` (required),
        ``size`` (required), ``blob_hash`` (optional),
        ``chunk_index`` (optional), ``source`` (optional, default
        ``"local"``). Unknown keys are dropped silently so the
        caller can over-supply.

        Bench gain: at 256 MiB / 256 KiB chunks = 1024 records,
        one transaction commit replaces 1024. Wall-time saving
        scales with chunk count; SQLite WAL log churn drops
        proportionally too.
        """
        if not records:
            return 0
        now = _now_ms()
        rows = []
        for r in records:
            try:
                rows.append((
                    str(r["chunk_hash"]),
                    int(r["size"]),
                    r.get("blob_hash"),
                    r.get("chunk_index"),
                    str(r.get("source") or "local"),
                    now,
                ))
            except (KeyError, TypeError, ValueError):
                # Skip malformed entries — don't poison the batch.
                continue
        if not rows:
            return 0
        with self._write_lock:
            c = self._conn.cursor()
            try:
                c.execute("BEGIN IMMEDIATE")
                c.executemany(
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
                    rows,
                )
                c.execute("COMMIT")
            except Exception:
                with contextlib.suppress(Exception):
                    c.execute("ROLLBACK")
                raise
        return len(rows)

    def forget_chunk_available(self, chunk_hash: str) -> None:
        """Drop a chunk_availability row. Called by the cache GC
        after the on-disk cache file has been unlinked so a future
        ``has_chunk`` query doesn't falsely claim we still hold it.

        Idempotent — if the row is already absent (or the schema
        somehow rejects the delete), we swallow it; the cache file
        is what matters and that's already gone.
        """
        try:
            with self._write_lock:
                self._conn.execute(
                    "DELETE FROM chunk_availability WHERE chunk_hash = ?",
                    (str(chunk_hash),),
                )
        except Exception:
            # Defensive — see docstring. State-DB errors must not
            # take down the daemon's startup path.
            pass

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
                f"WHERE chunk_hash IN ({','.join('?' for _ in batch)})",  # nosec B608
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
        # v0.20.7 (M30): wrap path before persisting.
        wrapped_path = self._wrap_path(
            str(path), aad=self._PATH_PII_AAD_CHUNK_SOURCES,
        )
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
                    wrapped_path,
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

    def record_chunk_sources_for_file(
        self,
        *,
        path: str,
        file_size: int,
        mtime_ms: int,
        chunks: Iterable[dict],
        source: str = "file_index",
    ) -> int:
        """Record many chunk sources for one stable file in one write pass.

        Live file sends already have a deterministic manifest for the source
        file. Recording path+offset sources lets future CHUNK_PULL requests
        read directly from that file instead of eagerly copying every chunk
        into One Link's cache during the send hot path.
        """

        now = _now_ms()
        # v0.20.7 (M30): wrap path once for the whole batch — same
        # plaintext path → same ciphertext (AES-SIV deterministic),
        # so the existing PRIMARY KEY de-duplication still works.
        wrapped_path = self._wrap_path(
            str(path), aad=self._PATH_PII_AAD_CHUNK_SOURCES,
        )
        clean: list[tuple[str, str, int, int, int, int, str, int]] = []
        avail: list[tuple[str, int, str, int]] = []
        for c in chunks:
            try:
                chunk_hash = str(c["hash"])
                start = int(c["start"])
                size = int(c.get("size", int(c["end"]) - start))
            except Exception:
                continue
            if not chunk_hash or start < 0 or size <= 0:
                continue
            clean.append((
                chunk_hash,
                wrapped_path,
                start,
                size,
                int(mtime_ms),
                int(file_size),
                str(source or "file_index"),
                now,
            ))
            avail.append((chunk_hash, size, str(source or "file_index"), now))
        if not clean:
            return 0
        with self._write_lock:
            self._conn.executemany(
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
                clean,
            )
            self._conn.executemany(
                """
                INSERT INTO chunk_availability(
                    chunk_hash, size, blob_hash, chunk_index, source, updated_ms
                ) VALUES(?, ?, NULL, NULL, ?, ?)
                ON CONFLICT(chunk_hash) DO UPDATE SET
                    size = excluded.size,
                    source = excluded.source,
                    updated_ms = excluded.updated_ms
                """,
                avail,
            )
        return len(clean)

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
                # v0.20.7 (M30): unwrap on read; legacy cleartext rows
                # pass through untouched via PathPIIEncryptor.unwrap.
                "path": self._unwrap_path(
                    r["path"], aad=self._PATH_PII_AAD_CHUNK_SOURCES,
                ),
                "start": int(r["start"]),
                "size": int(r["size"]),
                "mtime_ms": int(r["mtime_ms"]),
                "file_size": int(r["file_size"]),
                "source": r["source"],
                "updated_ms": int(r["updated_ms"]),
            }
            for r in rows
        ]

    def find_complete_source_file(
        self,
        chunks: "list[dict]",
        *,
        max_candidates: int = 8,
    ) -> "Optional[dict]":
        """Find a local file that already contains every chunk in
        the manifest at its declared offset.

        Used by the hardlink warm-dedup path: when every chunk a
        new CDC FILE_OFFER asks for has already been recorded as
        sourced from one specific file, we can hardlink that file
        as the new transfer's output instead of re-reading every
        chunk through the cache and writing them out again. Wave
        2a — pulls warm-dedup latency at 16 MiB from ~100 ms down
        to milliseconds.

        ``chunks`` is the CDC manifest: list of dicts with at
        least ``hash``, ``start``, ``size`` keys, in any order.
        Returns a dict with ``path``, ``file_size``, ``mtime_ms``
        when a match is found, ``None`` otherwise.

        The match is strict: every chunk must be sourced from the
        SAME file at the SAME offset. If even one chunk is missing
        or has a different recorded start, we bail. The receiver
        does its own existence + size + mtime verification before
        hardlinking; this is just the index lookup.
        """
        if not chunks:
            return None
        # Pick the first chunk's candidate paths; intersect against
        # subsequent chunks' candidate paths to converge on the set
        # of files that hold all of them. Fail-fast when the
        # intersection becomes empty.
        try:
            first_hash = str(chunks[0]["hash"])
            first_start = int(chunks[0]["start"])
        except (KeyError, TypeError, ValueError):
            return None
        rows = self._conn.execute(
            """
            SELECT path, file_size, mtime_ms
            FROM chunk_sources
            WHERE chunk_hash = ? AND start = ?
            ORDER BY updated_ms DESC
            LIMIT ?
            """,
            (first_hash, first_start, int(max_candidates)),
        ).fetchall()
        # Map of wrapped-path -> (unwrapped_path, file_size, mtime_ms)
        # so the rest of the loop matches on the wrapped form (cheap,
        # avoids unwrap-per-row) and only unwraps the winner.
        candidates: dict[str, tuple[str, int, int]] = {}
        for r in rows:
            wrapped = str(r["path"])
            candidates[wrapped] = (
                wrapped,
                int(r["file_size"]),
                int(r["mtime_ms"]),
            )
        if not candidates:
            return None
        # Walk the remaining chunks; keep only candidates that
        # still contain each one. SQL constraints (chunk_hash,
        # start) ensure each row is uniquely matchable.
        for c in chunks[1:]:
            try:
                h = str(c["hash"])
                s = int(c["start"])
            except (KeyError, TypeError, ValueError):
                return None
            placeholders = ",".join("?" * len(candidates))
            sql = (
                "SELECT path FROM chunk_sources "
                "WHERE chunk_hash = ? AND start = ? "
                f"AND path IN ({placeholders})"  # nosec B608
            )
            params = (h, s, *candidates.keys())
            hits = {
                str(r["path"]) for r in self._conn.execute(sql, params).fetchall()
            }
            # Drop any candidate that doesn't have this chunk.
            candidates = {
                wrapped: meta for wrapped, meta in candidates.items()
                if wrapped in hits
            }
            if not candidates:
                return None
        # Survivor wins. Unwrap and return.
        wrapped, (_w, file_size, mtime_ms) = next(iter(candidates.items()))
        try:
            unwrapped = self._unwrap_path(
                wrapped, aad=self._PATH_PII_AAD_CHUNK_SOURCES,
            )
        except Exception:
            return None
        return {
            "path": unwrapped,
            "file_size": file_size,
            "mtime_ms": mtime_ms,
        }

    def chunks_sourced(self, chunk_hashes: Iterable[str]) -> list[str]:
        clean = [str(h) for h in chunk_hashes if str(h)]
        if not clean:
            return []
        out: list[str] = []
        for i in range(0, len(clean), 500):
            batch = clean[i:i + 500]
            rows = self._conn.execute(
                "SELECT DISTINCT chunk_hash FROM chunk_sources "
                f"WHERE chunk_hash IN ({','.join('?' for _ in batch)})",  # nosec B608
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
        # v0.20.7 (M30): wrap path before persisting.
        wrapped_path = self._wrap_path(
            str(path), aad=self._PATH_PII_AAD_FILE_INDEX,
        )
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
                    wrapped_path,
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
        # v0.20.7 (M30): wrap query path so the SELECT matches the
        # deterministic-encrypted row written in record_file_index_cache.
        # Same plaintext + AAD → same ciphertext (AES-SIV), so the
        # index lookup still works.
        wrapped_path = self._wrap_path(
            str(path), aad=self._PATH_PII_AAD_FILE_INDEX,
        )
        row = self._conn.execute(
            """
            SELECT path, size, mtime_ns, ctime_ns, blob_hash, index_kind,
                   chunks_json, updated_ms
            FROM file_index_cache
            WHERE path = ? AND size = ? AND mtime_ns = ? AND ctime_ns = ?
            """,
            (wrapped_path, int(size), int(mtime_ns), int(ctime_ns)),
        ).fetchone()
        # If the wrapped lookup missed but we have an encryptor, also
        # try the legacy cleartext path so pre-v0.20.7 rows still hit.
        if row is None and self._path_pii is not None and wrapped_path != str(path):
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
            "path": self._unwrap_path(
                row["path"], aad=self._PATH_PII_AAD_FILE_INDEX,
            ),
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
