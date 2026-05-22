I have enough. Let me also do one quick look at messages count + ledger updates per-chunk to confirm hot-path:

`_handle_file_native_chunk` likely calls `_update_transfer(transfer_id, progress_bytes=...)` per chunk. Each call does: get_transfer (no lock) + upsert (with lock). For a 10 MB file at 16 KB chunks = ~600 round trips. Not catastrophic but hot. More importantly, each update writes JSON-serialized metadata back, even if unchanged. SQLite WAL handles this OK with `synchronous = NORMAL`. Fine.

I have enough to write the audit. Final findings:

---

# One Link Persistence Layer — Top 15 Findings

1. **HIGH — `state.py:3295-3325` `update_transfer` lost-update race.** Reads `get_transfer(id)` outside `self._write_lock` then upserts. Two concurrent updates (e.g. parallel chunk ACKs + a status flip) each read the same `current`, each rebuild the full record, second write clobbers first — progress counters and `metadata.path` can regress. Fix: hold `self._write_lock` across both ops, or rewrite as a single `UPDATE ... SET col=col+?, metadata_json = json_patch(metadata_json, ?)` SQL statement.

2. **HIGH — `paths.py:142-146` data_dir mkdir without restrictive mode.** `data_dir().mkdir(parents=True, exist_ok=True)` inherits process umask, so `state.db` (DR chain keys, message bodies, group sender keys, peer trust) is world-readable on POSIX by default. `identity.key` / `master.seed` / `cap_root.key` chmod 0o600 but state.db never does. Fix: `os.chmod(self.db_path, 0o600)` after open in `state.py:421`; chmod 0o700 the dir.

3. **HIGH — `state.py:475-490` no `PRAGMA integrity_check` on boot.** A corrupted state.db crashes the daemon on first query with `sqlite3.DatabaseError`. No fallback / sidecar copy. Fix: run `PRAGMA quick_check` after `_init_pragmas`; if it fails, rename `state.db → state.db.corrupt.<ts>` and bootstrap fresh.

4. **MED — `state.py:233-244` outbox UNIQUE(peer_fp, msg_id) is at-least-once.** `record_outbox_attempt` increments without atomicity vs. send result; on crash between "ACK received" and `mark_outbox_delivered`, the same body is redelivered. The receiver must dedupe by `msg_id`. Verify receiver does — if not, duplicate messages.

5. **MED — `state.py:3160-3170` `list_peer_files` has no LIMIT.** Full table scan + materialized list of every file message ever for a peer. On a chatty peer with 10k file messages it ships megabytes per gallery render. Fix: paginate with `LIMIT ? OFFSET ?` or cursor on `ts_ms`.

6. **MED — `state.py:206-225` `transfers.metadata.path` carries raw absolute filesystem paths in plaintext.** Lockbox path-PII encryptor (`state.py:444-473`) covers `chunk_sources` + `file_index_cache` but NOT the transfers table. A stolen state.db exposes every file the user has sent. Fix: add `_PATH_PII_AAD_TRANSFER = b"OL/state/transfers/path|v1"` and wrap on upsert / unwrap on read.

7. **MED — `server.py:13016-13021` Content-Disposition header injection.** `download_name = rec.metadata["name"] or path.name` is interpolated unescaped into `f'inline; filename="{download_name}"'`. If a sent file's recorded `name` contains `"` + newline (attacker pre-seeded the ledger via a malicious peer who completed a transfer they later renamed locally), header smuggling / arbitrary header injection. Fix: `urllib.parse.quote(download_name, safe='')` + `filename*=UTF-8''...` form, or strip `\r\n"`.

8. **MED — `state.py:492-565` `_migrate` `current_version` captured once.** Local `current` is read once at the top of `_migrate` and passed unchanged to every `_run_atomic_migration(current_version=current)` call. The function uses it only to decide whether to INSERT the version stamp, so multiple version rows are inserted on a first-time upgrade from old DB. `MAX(version)` queries still work, but `schema_version` accumulates rows — and a `SELECT version FROM schema_version` (vs MAX) would see stale values. Cosmetic but ugly; refresh `current_version` inside the loop after each successful step.

9. **MED — `state.py:3303` `update_transfer` falls back to `current.metadata` silently.** If `get_transfer` returns a record whose `metadata_json` failed to JSON-decode (corrupt row), `current.metadata` is `{}` and the upsert silently wipes the on-disk metadata including `path`. Then `/api/outbound_files/<id>` returns 410. Fix: distinguish "no metadata field passed" from "explicit empty" via a sentinel.

10. **MED — `state.py:4358-4389` `enqueue_outbox` ignores msg_kind on conflict.** `INSERT ... ON CONFLICT DO NOTHING` returns the existing row id but doesn't update `msg_kind` or `msg_body_json`. If the caller re-enqueues the same `msg_id` with new body (edited message before send), the original body delivers. Document or change semantics.

11. **LOW — `state.py:4391-4415` `list_outbox` ordering by `enqueued_ms ASC, id ASC`.** OK in isolation, but `_now_ms()` is wall-clock; an NTP backward jump between two enqueues from the same peer means the later message gets a smaller `enqueued_ms` and ships first. Use `id` as primary sort.

12. **LOW — `state.py:225` `transfers` lacks `idx_transfers_status`.** `prune_transfers` filters `WHERE status IN (...)` with no index; on a long ledger this is O(n). Add `CREATE INDEX idx_transfers_status ON transfers(status, updated_ms)`.

13. **LOW — `state.py:475-490` `wal_autocheckpoint = 50` is aggressive.** Default is 1000. Forcing checkpoint every ~200 KB amplifies fsync cost. The secure_delete justification (don't leak plaintext in WAL) is sound but a 256-page (1 MB) checkpoint achieves the same in practice and halves write cost.

14. **LOW — `state.py:3327-3331` `get_transfer` accepts any string.** No format validation. `transfer_id="../../etc/passwd"` is harmless because it's used only as a SQL parameter PK lookup, BUT the field is also reflected back into `web.FileResponse(path)` via `metadata.path`. Defense-in-depth: validate `re.fullmatch(r"(out|in):[0-9a-f]{32,128}:[0-9a-f]{12}", id)` before the lookup.

15. **LOW — `state.py:485-489` `secure_delete = ON` covers state.db but not the inbox dir.** Disappearing-messages erases the row body, but the original received-file blob on disk in `inbox_dir()` survives at default OS perms. Fix: chmod 0o700 inbox_dir; for reaped files, overwrite-then-unlink.

---

**Files examined:**
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\state.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\transfer_intent.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\trust_ledger.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\cap_migration.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\paths.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\daemon.py` (send_file + upsert_transfer + _update_transfer)
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\server.py` (api_outbound_file_download)

**Notes on findings NOT raised:**
- Migrations ARE per-step transactional with `BEGIN IMMEDIATE` + ROLLBACK on failure (good).
- WAL mode IS on; concurrent reads during writes work.
- The memory's "GUID/varchar UUID footgun" applies to SmartChartIQ (SQLAlchemy + PG/SQLite dialect mismatch), NOT to One Link — One Link uses raw sqlite3 with TEXT columns throughout, no ORM, no dialect bridging.
- `/api/outbound_files/<id>` path-traversal is blocked at the SQL layer (id is PK lookup); only finding 7 (header injection via name) and 14 (defense-in-depth validation) remain.
- Identity/master-seed/cap-root keys ARE chmod 0o600 — only state.db and inbox dir leak via mode.