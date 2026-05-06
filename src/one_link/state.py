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
