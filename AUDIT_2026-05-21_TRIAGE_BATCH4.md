# AUDIT 2026-05-21 — Batch 4 Triage (Native Rust + Capabilities + Transfer Engine)

Cross-referenced against the 57 already-shipped TIER 1/2/3 commits in
`AUDIT_2026-05-21.md` plus Batch P (commit `1be96bf`, landed 2026-05-22).
Tags:

- **SHIPPED** — closed by a T-tag commit
- **OBSOLETE** — transcript describes code that no longer matches reality
- **DUP** — duplicate of another finding
- **INFO** — informational / architecture survey only
- **NIT** — cosmetic; defer OK
- **SHIP** — genuinely-new, actionable, needs work

## Per-transcript triage

### agent-aee44db505556df60 — Native Rust crates survey

Entire transcript is an architectural survey of the 33 `ol_*` crates +
binding umbrella (LOC, test counts, PyO3 exposure, Phase status).
No exploit shapes or correctness breaks asserted.

- All content — **INFO** (inventory only, ~65% production / ~35% research
  assessment, no actionable findings)

### agent-afb47dcd568cbadce — Capabilities + caps enforcement (15 items)

| # | Tag | Map |
|---|-----|-----|
| 1 `_capability_allowed` state=None → True | **SHIPPED** | T1-D (`b8ca972`) — fail-closed on `state is None` |
| 2 `policy is None` → allow-all | **SHIPPED** | T1-E (`b8ca972`) — covered by the T1-D commit's policy/verifier fail-closed bundle |
| 3 Fail-open on verifier exception | **SHIPPED** | T1-D (`b8ca972`) |
| 4 CAPABILITY_GRANT accepted from any peer | **SHIPPED** | T1-J (`3e1be90`) — pinned-peer gate |
| 5 Delegation walker no trust filter on intermediates | **SHIPPED** | Batch P (`1be96bf`) — every hop must be currently pinned |
| 6 No rate limit on inbound CAPABILITY_GRANT | **SHIPPED** | Batch P (`1be96bf`) — 5/60s per-peer bucket |
| 7 `caps_grants` scope is opaque bytes; no caveat parser | **SHIP** | see SHIP-1 below |
| 8 `_ensure_folder_caps_for` no-ops when policy is None | **SHIP** | see SHIP-2 below |
| 9 `_handle_blob_request` "no folder" path gates on FILES only | **SHIP** | see SHIP-3 below |
| 10 Malformed `allowed_json` row → `[]` (silent deny-all) | **SHIPPED** | T3-W (`f1a65a0`) — raises now |
| 11 cap_root_key no rotation API | **SHIPPED** | T2-S (`dcae045`) |
| 12 `_emit_capability_request` no per-peer ceiling | **SHIPPED** | Batch P (`1be96bf`) — same 5/60s bucket |
| 13 Replay defense: revoke doesn't tombstone nonces | **SHIP** | see SHIP-4 below |
| 14 No durable audit row for grant accept/revoke | **SHIPPED** | T3-V (`d977eda`) |
| 15 CAPABILITY_GRANT 12-KB field cap too loose | **DUP** | item 6 — Batch P's rate limit closes the flood path; size still 12 KB but bounded to 5/min |

### agent-afc5530dbd7646307 — Transfer engine integrity (15 items)

| # | Tag | Map |
|---|-----|-----|
| 1 Fast-path AEAD ignored ratchet; nonce sender-controlled | **SHIPPED** | T1-B (`b1bc5d1`) — per-chunk ratchet-keyed AEAD via `ratchet.key_at(chunk_index)` |
| 2 Receiver trusts wire `chunk_index` | **SHIP** | see SHIP-5 below — T1-B re-keys per index but no strict monotonic / no replay window |
| 3 Legacy `NATIVE_TRANSFER_V1` (non-`_INDEXED`) collapses to `seq` | **SHIP** | see SHIP-6 below — still active at `daemon.py:7932` |
| 4 Chunk-store accepts peer `chunk_id` without re-hashing | **SHIPPED** | T2-D (`b8bfa79`) — `ONE_LINK_VERIFY_CHUNK_HASH=1` |
| 5 FILE_CDC_CHUNK retry → `unexpected_cdc_chunk` abort | **SHIP** | see SHIP-7 below — `daemon.py:8215` aborts on legit sender retry |
| 6 `pending_sizes` deque leaked on fallback raise | **SHIPPED** | Batch P T2-J (`1be96bf`) |
| 7 CDC source-mutation raises → receiver hangs | **SHIPPED** | T2-F (`40e3a36`) — FILE_ABORT before raise |
| 8 `path.stat().st_size` captured once; file grows mid-send | **SHIP** | see SHIP-8 below |
| 9 Three seq-mismatch handlers (two raise, one ACKs) | **SHIPPED** | T2-E (`3e1be90`) + Batch P T2-E follow-up (`1be96bf`) covers overrun/missing-payload |
| 10 `handle.truncate(size)` on non-sparse FS = pre-fill DoS | **SHIP** | see SHIP-9 below |
| 11 CDC empty-file emits zero-length tail chunk | **SHIPPED** | T3-S native+python (`65adf13` + `7c18496`) |
| 12 `transfer_doctor` `reopen_secure_session` does not rotate seed | **SHIP** | see SHIP-10 below |
| 13 FILE_WANTS unbounded ints | **SHIPPED** | T3-T (`40e3a36`) — bounded `[0, len(cdc_chunks))` |
| 14 NTFS ADS `:` in filename | **SHIPPED** | T3-R (`40e3a36`) |
| 15 Chunk-store append failure swallowed silently | **SHIP** | see SHIP-11 below |

## SHIP list — 11 actionable items

### SHIP-1. `caps_grants` scope is opaque bytes; no caveat parser
- File: `src\one_link\caps_grants.py:140-188` + callers in `daemon.py`
- Root cause: `resource_scope` is `bytes`; `has_capability` does `g.scope == query_scope`. No canonical form, no caveat-chain (file size, IP pin, time-of-day) — only global `not_before/not_after`. A UTF-8 vs raw-bytes mismatch in callers silently misses.
- Fix: Adopt the macaroon caveat list already in `cap_migration.py` (ADR-0021) as the only grant path; deprecate the raw-bytes scope.
- Severity: MED
- Bench-needed: no (cold path)

### SHIP-2. `_ensure_folder_caps_for` no-ops when policy is None
- File: `src\one_link\server.py:9744-9770` (line 9755: `if current is None: return  # default-allow legacy — nothing to add`)
- Root cause: Folder-share UI returns early for any default-allow-all peer, so the explicit "I shared this folder" consent never lands as a row. If the operator later flips strict mode the consent record is gone.
- Fix: Always materialize a policy row (with at least `{FOLDER_SYNC, MERKLE_SYNC}`) on first folder share; never treat `None` as a terminal sentinel.
- Severity: MED
- Bench-needed: no

### SHIP-3. `_handle_blob_request` no-folder path gates only on FILES
- File: `src\one_link\daemon.py:9023-9070` (line 9061: "No folder context — gate on the FILES capability instead")
- Root cause: When a `BLOB_REQUEST` arrives without `folder`, any peer with FILES can pull any blob we hold by hash. Two peers in separate shared folders that learn each other's blob hashes (gossip, dedupe ad, hash enumeration) can pull blobs they were never granted folder access to.
- Fix: Track per-blob origin folder when a blob first lands; require the requester share that folder OR carry an explicit share-link redeem token.
- Severity: HIGH
- Bench-needed: no

### SHIP-4. Revoke doesn't tombstone replay-cache nonces
- File: `src\one_link\cap_store.py:107-114` + `caps_grants.py:298-304`
- Root cause: OrderedDict-capped seen-nonces (100k). On `revoke_subject` / `revoke_granter` the revoked grant's nonce is NOT persisted to a tombstone; an attacker that re-presents the same blob (still within `not_after`) gets it re-accepted. Eviction pressure (fed by spam, now rate-limited but still possible at 5/min × peers) can drop the nonce silently.
- Fix: On any local `revoke_*`, persist the revoked nonce into a `capability_replay_tombstone` table; `accept()` consults the table before installing.
- Severity: MED
- Bench-needed: no

### SHIP-5. Receiver does not enforce strict-monotonic `chunk_index`
- File: `src\one_link\daemon.py:7932` (`chunk_index = int(msg.get("chunk_index", seq))`); decrypt at `native_transfer.py:521-535`
- Root cause: T1-B re-keys AEAD via `ratchet.key_at(chunk_index)` so a duplicate index alone no longer reuses nonce+key with different plaintext. BUT receiver still accepts wire-supplied chunk_index without a replay window or monotonicity gate — a sender that re-presents an already-decrypted (index, ciphertext) tuple causes a duplicate write at the same blob offset, wasting bandwidth and (with #8) confusing the receiver's `received` accounting.
- Fix: Track `seen_chunk_indices` per session (BitSet bounded to `len(cdc_chunks)`); reject `chunk_index <= last_seen - window` or already-seen.
- Severity: MED
- Bench-needed: yes (hot path — measure BitSet check vs current accept)

### SHIP-6. Legacy `NATIVE_TRANSFER_V1` (no `_INDEXED`) collapses `chunk_index` onto per-file `seq`
- File: `src\one_link\daemon.py:7929-7932`
- Root cause: For multi-file channels, the sender's session ratchet advances across files but `seq` resets per file. A peer that advertises `NATIVE_TRANSFER_V1` without `_INDEXED` decrypts file #2's first chunk with `idx=0` while the sender encrypted at session-absolute index — AEAD tag fails immediately and the transfer aborts.
- Fix: Either drop the legacy fallback entirely (peer must have `_INDEXED`) or have the sender re-key per-file when peer lacks `_INDEXED` and version the wire so the fallback is detectable.
- Severity: MED
- Bench-needed: no

### SHIP-7. FILE_CDC_CHUNK retry aborts the transfer instead of idempotent ACK
- File: `src\one_link\daemon.py:8215-8220`
- Root cause: `if idx < 0 or idx >= len(f.cdc_chunks) or idx not in f.cdc_missing: ... rejected="unexpected_cdc_chunk"` then `_abort_incoming_file`. A sender whose ACK was lost will retry the chunk; receiver sees `idx not in cdc_missing` (already streamed) and kills the whole transfer.
- Fix: When `idx in range AND idx in f.cdc_streamed AND BLAKE3(data) == expected_hash`, ACK as `duplicate_success` and return without abort.
- Severity: MED
- Bench-needed: no

### SHIP-8. `path.stat().st_size` snapshot bypasses size cap if file grows mid-send
- File: `src\one_link\native_transfer.py:340` (size captured) + read loop downstream
- Root cause: Manifest declares N bytes; if the file grows during send the loop keeps reading and yields extra encrypted chunks. The ratchet/nonce counter advances for the over-shoot chunks; receiver detects via `f.received + len(data) > f.size` (T2-E follow-up handles this without dropping the channel) but sender-side ratchet sync is broken for the next file on the channel.
- Fix: Cap the read loop by remaining declared bytes; truncate the final chunk and stop emitting once `bytes_sent >= declared_size`.
- Severity: MED
- Bench-needed: no

### SHIP-9. `handle.truncate(size)` pre-fills on non-sparse filesystems (exFAT / FAT32 USB)
- File: `src\one_link\daemon.py:4994-5005`
- Root cause: CDC stream-to-disk path calls `handle.truncate(size)` before any chunk arrives. On sparse-capable FS (NTFS, ext4) it costs nothing; on exFAT/FAT32 (common for removable inbox volumes) it physically writes zeros. A peer offering 16 TiB to a 16 GB USB exhausts the volume before per-chunk admission would have caught it. `transfer_safety.evaluate_transfer_admission` checked `shutil.disk_usage(...).free` only at offer time.
- Fix: Detect filesystem type; on non-sparse FS use `posix_fallocate` / `SetFileValidData` only when supported, else skip truncate and rely on the per-chunk admission gate.
- Severity: MED
- Bench-needed: no

### SHIP-10. `transfer_doctor.reopen_secure_session` does not rotate the cached native-transfer seed
- File: `src\one_link\transfer_doctor.py:206-218` + Channel seed cache
- Root cause: AEAD-tag failures route to `action="reopen_secure_session"`. Channel re-handshake re-runs `derive_native_transfer_secret`, which returns the **cached** `_native_transfer_seed` (T2-K eagerly seeds it at handshake; not invalidated on reopen). If the original failure was a transient ratchet-skip-cap overflow (T2-C cap hit) the same seed + same ratchet → same outcome → infinite reopen loop.
- Fix: `reopen_secure_session` must drop `Channel._native_transfer_seed` (force re-derive from fresh DR root_key) before the new session starts.
- Severity: MED
- Bench-needed: no

### SHIP-11. Chunk-store append failure swallowed with `log.warning` only
- File: `src\one_link\native_transfer.py:474-485`
- Root cause: `_maybe_store` catches `Exception` and logs; sender keeps yielding subsequent chunks as if dedup succeeded. A corrupted/exhausted local chunk store silently disables swarm-pull for future peers. Same anti-pattern flagged by the QUIC-fast-path memory note (no audit trail).
- Fix: Append a `{"kind": "native_chunk_store_append_failed", "blob": ..., "reason": ...}` entry to `self._degradation_events` (or daemon's ring); `/api/metrics` surfaces it; integration test asserts it fires on a simulated full-disk store.
- Severity: LOW
- Bench-needed: no

## Bottom line

- **Native Rust transcript**: 0 SHIP (pure inventory).
- **Capabilities transcript**: 11 of 15 already SHIPPED via T1-D/E/J + T2-S + T3-V/W + Batch P (the CRITICAL/HIGH cluster is closed); 4 SHIP residuals (caveat parser, folder-share-on-None, blob-request folder origin, revoke-tombstone).
- **Transfer Engine transcript**: 8 of 15 SHIPPED via T1-B + T2-D/E/F/J + T3-R/S/T; 7 SHIP residuals (chunk_index replay window, legacy compat, retry-as-abort, file-grew-mid-send, exFAT truncate, doctor-seed-rotation, store-append-audit).

Total **11 SHIP** items across the three transcripts. Highest priority:
SHIP-3 (cross-folder blob exposure, HIGH); the rest are MED/LOW
hardening with no exploit shape on the critical path.
