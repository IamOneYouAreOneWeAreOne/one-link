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
            finally:
                c.close()

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

    def set_peer_trust(self, fingerprint: str, trust: str) -> None:
        if trust not in ("pinned", "pending", "rejected"):
            raise ValueError(f"invalid trust state: {trust!r}")
        with self._write_lock:
            self._conn.execute(
                "UPDATE peers SET trust = ? WHERE fingerprint = ?",
                (trust, fingerprint),
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

    def set_peer_capability_policy(self, fingerprint: str, allowed: Iterable[str]) -> None:
        values = sorted({str(c) for c in allowed if str(c)})
        with self._write_lock:
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

    def clear_peer_capability_policy(self, fingerprint: str) -> None:
        with self._write_lock:
            self._conn.execute(
                "DELETE FROM peer_capability_policy WHERE fingerprint = ?",
                (fingerprint,),
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

    def add_folder(self, *, name: str, local_path: str, shared_with: list[str]) -> None:
        with self._write_lock:
            self._conn.execute(
                """
                INSERT INTO folders(name, local_path, shared_with_json, created_ms)
                VALUES(?, ?, ?, ?)
                """,
                (name, local_path, json.dumps(shared_with), _now_ms()),
            )

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
        return {
            "name": row["name"],
            "local_path": row["local_path"],
            "shared_with": json.loads(row["shared_with_json"]),
            "created_ms": row["created_ms"],
        }

    def list_folders(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM folders ORDER BY name"
        ).fetchall()
        return [
            {
                "name": r["name"],
                "local_path": r["local_path"],
                "shared_with": json.loads(r["shared_with_json"]),
                "created_ms": r["created_ms"],
            }
            for r in rows
        ]

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

    # ─── lifecycle ────────────────────────────────────────────────────

    def close(self) -> None:
        with self._write_lock:
            self._conn.close()
