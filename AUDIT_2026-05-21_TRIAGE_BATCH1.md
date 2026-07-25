# Triage — Batch 1 (transcripts a1147246, a17e4fc3, a371fb98, a4794adc, a491c917)

> Historical record. The v1 HELLO opt-in rejection documented here was
> superseded on 2026-07-22: rejection is now the default; only the explicit
> temporary `ONE_LINK_ALLOW_V1_HELLO=1` migration override permits v1.

Scope: 5 transcripts (native crate inventory, server control plane, daemon
`send_file`, persistence + state.db, crypto + handshake). All findings
classified against the 57-row shipped table in `AUDIT_2026-05-21.md` and
verified against the live tree as of `1bfcc1d`.

Bottom line: most TIER 1/TIER 2 crypto + server + persist findings already
shipped (T1-A, T1-B, T1-I, T1-K, T2-A, T2-B, T2-C, T2-K, T2-O, T2-R,
T3-I, T3-J, T3-K, T3-L, T3-W, T3-X, `verify()` narrow). The daemon transcript
is an architecture wiring map (all INFO). The native-inventory transcript is
a dark-surface survey (all INFO; new-build proposals, not bugs). 5 genuinely-
new SHIP items remain — mostly LOW-severity defense-in-depth.

---

## SHIP items (need to actually fix)

### S1. data_dir + inbox_dir created without restrictive mode (POSIX)

- File: `src/one_link/paths.py:138`, `:145`, `:183` (`config_dir`, `data_dir`, `inbox_dir`)
- Root cause: `p.mkdir(parents=True, exist_ok=True)` inherits the process
  umask, so on POSIX the parent dir of `state.db` (and the inbox folder
  holding received files) is world-listable. T2-R chmod'd `state.db`
  itself to 0o600 but the containing directory keeps default 0o755 — a
  second account on the same box can still `ls` the inbox and see the
  file names of every received attachment.
- Fix: after each `p.mkdir(...)` in `config_dir/data_dir/inbox_dir`, call
  `os.chmod(p, 0o700)` inside a `with contextlib.suppress(OSError)` block
  (no-op on Windows where chmod is a stub).
- Severity: MED (POSIX) / N/A (Windows)
- Bench needed: no (boot path, not hot)

### S2. `update_transfer` silently wipes `metadata.path` if existing row's JSON is corrupt

- File: `src/one_link/state.py:3414` (`update_transfer`) ↔ `state.py:4820` (`_row_to_transfer`)
- Root cause: `_row_to_transfer` catches `json.loads` exceptions and
  returns `metadata={}`. `update_transfer` then takes
  `metadata = fields.pop("metadata", current.metadata)`, which for an
  update that doesn't pass `metadata=` defaults to that empty dict, then
  upserts it back, permanently dropping the on-disk `path` field. The
  T3-J path-PII wrap shipped, but it stores the cipher-text in the same
  field — if the unwrap path is what bombed (e.g. wrong key after a
  state-dir restore from backup) every subsequent `update_transfer` will
  blow the path away.
- Fix: distinguish "caller did not pass metadata" from "caller passed
  empty metadata" via a sentinel; only rewrite `metadata_json` when the
  caller explicitly opts in. Alternative: keep the raw `metadata_json`
  blob around on the record dataclass and round-trip it when no metadata
  override is supplied.
- Severity: LOW (rare; requires corrupt JSON or unwrap-fail state)
- Bench needed: no

### S3. `api_remove_folder` / `api_share_folder` / `api_unshare_folder` / `api_set_folder_policy` return `str(e)` and pass unvalidated folder names through

- File: `src/one_link/server.py:9772` (`api_remove_folder`), `:9784`
  (`api_share_folder`), and the unshare/policy peers nearby
- Root cause: `name = request.match_info["name"]` is forwarded straight
  to `folder_engine.remove_folder(name)` without a prior
  `state.get_folder(name)` existence check, then any exception's
  `str(e)` is reflected back in the 500 body. Inside the trust boundary
  CSRF + token gate the impact is small, but this is the same shape T3-E
  + T3-U/L closed elsewhere (no raw `str(exc)` to the wire).
- Fix: call `self.daemon.state.get_folder(name)` first and return
  `404 {"error": "no such folder"}` on miss (the pattern
  `api_folder_tree` at 9946 already uses); on the engine path, map
  exceptions through a `_translate_folder_error(e)` helper that returns
  a coarse `code` + friendly `error` and never the raw `str(e)`.
- Severity: LOW
- Bench needed: no

### S4. Handshake nonce replay → free responder CPU-DoS

- File: `src/one_link/channel.py:744-759` (initiator) + `:808-816` (responder)
- Root cause: `nonce_i` / `nonce_r` are 16 random bytes signed into the
  transcript but there's no peer-side cache. An attacker who has captured
  one valid HELLO can re-mail it to the same responder N times; each
  delivery forces a fresh Ed25519 verify + X25519 ephemeral + HKDF +
  sig_r emission. Session keys end up different (responder picks fresh
  `x_priv` each time) so the attack is harmless to confidentiality, but
  it's a cheap amplifier — one captured HELLO frame → unbounded crypto
  work per replay.
- Fix: add a small TTL-bounded LRU (`OrderedDict` of
  `(peer_ed_pub, nonce_i) -> ts`) with a 60-second window; reject
  duplicates at the top of `respond()` before any signature or DH work.
  Cap size at, say, 8192 entries.
- Severity: MED (cheap amplifier, real attack shape)
- Bench needed: yes — adds a dict lookup + 16-byte hash on every
  inbound HELLO; should be sub-µs but confirm.

### S5. `idx_transfers_status` missing — `prune_transfers` scans full table

- File: `src/one_link/state.py:228-229` (transfer indexes), `prune_transfers`
  filter
- Root cause: `transfers` has indexes on `updated_ms` and `peer_fp` but
  nothing on `status`. `prune_transfers` filters
  `WHERE status IN ('complete', 'failed', ...)` and on a long ledger that
  becomes a full table scan. T3-X added boot integrity-check; this is
  the same family of state-layer hardening it didn't touch.
- Fix: add
  `CREATE INDEX IF NOT EXISTS idx_transfers_status ON transfers(status, updated_ms);`
  in `SCHEMA_V1` and a v22 migration that runs the same `IF NOT EXISTS`
  for upgraded DBs.
- Severity: LOW (perf, not correctness)
- Bench needed: no (boot-time DDL only)

---

## Triage table (everything else)

### Native crate inventory — `agent-a1147246` (architecture survey, all INFO)

| Agent | # | Title | Class | Note |
|-------|---|-------|-------|------|
| a1147246 | 1 | Per-crate WIRED/AVAILABLE/INTERNAL status table | INFO | Pure inventory. |
| a1147246 | 2 | ol_transfer (2 709 LOC) has no pyo3 surface | INFO | New-build proposal, not a bug. ADR-0024 wiring matrix already accounts for this; `native_transfer.py` is the Python integrator. |
| a1147246 | 3 | ol_netcode (435 LOC) has no pyo3, no callers | INFO | A⊕B coded relays are spec, not yet a daemon hot path. |
| a1147246 | 4 | ol_device_mesh (21.5 KLOC) is INTERNAL_ONLY | INFO | Row 8 row 8 surface; future wiring. |
| a1147246 | 5 | ol_grammar / ol_duress / ol_codegen scaffolds dark | INFO | Phase D #5/#6 spec-only; no production caller yet. |
| a1147246 | 6 | ol_fuse / ol_winfs / ol_fskit mount() unbuilt | INFO | Per-platform FS surface, Phase B. |
| a1147246 | 7 | ol_coherence_field has 6 dark sub-functions | INFO | Surface is exposed; daemon wiring will land per-need. |
| a1147246 | 8 | Anchor + projection multicast not assembled | INFO | New `MulticastSession` / `ol_swarm` proposal, not a bug. |

### Server.py audit — `agent-a17e4fc3`

| Agent | # | Title | Class | Note |
|-------|---|-------|-------|------|
| a17e4fc3 | 1 | `/api/files/{name}` path-traversal `resolve()` defense | SHIPPED | T1-I `_resolve_inbox_api_file` (`b8ca972`) — adds `resolve(strict=True).relative_to(inbox)` guard. |
| a17e4fc3 | 2 | `/api/setup/device-invite/confirm` no SAS verify | SHIPPED | T1-L (`0d31f6e`). |
| a17e4fc3 | 3 | `api_courier_export` raw `str(exc)` leaks paths | NIT | Inside trust boundary (CSRF + token gate). `_translate_send_error` covers the send path. Many `str(exc)` paths remain across handlers — class-of-fix already documented by T3-E. |
| a17e4fc3 | 4 | `api_remove_folder` no validate + raw `str(e)` | SHIP | Promoted to S3. |
| a17e4fc3 | 5 | `api_set_rendezvous` no CSRF defense | OBSOLETE | T2-O `_csrf_origin_ok` shipped (`5b9f768`). Scheme validation already exists in `state.set_rendezvous_urls`. |
| a17e4fc3 | 6 | `_guarded` no CSRF defense | SHIPPED | T2-O (`5b9f768`). |
| a17e4fc3 | 7 | `api_send_file` exception sink returns `{"error": ""}` | SHIPPED | T3-E `_format_error` (`f1a65a0`); `_translate_send_error` returns code + hint. |
| a17e4fc3 | 8 | `api_global_search` no rate limit | SHIPPED | Batch O (`565618e`) added `_rate_limited("search", ..., limit=10, window=1.0)`. |
| a17e4fc3 | 9 | `api_file_reveal` resolves after `_resolve_inbox_api_file` | OBSOLETE | `_resolve_inbox_api_file` already enforces `relative_to(inbox)` via `_under_inbox`. The second `resolve()` is a no-op for a file already proven under the inbox. |
| a17e4fc3 | 10 | Invite token in QR-endpoint URL → access log | OBSOLETE | `web.AppRunner(self.app, access_log=None)` at server.py:13659 — access log disabled entirely. |
| a17e4fc3 | 11 | `api_folder_tree` no cap on entries | SHIPPED | Batch O (`565618e`) — `limit` query param default 10 000, clamped to 50 000. |
| a17e4fc3 | 12 | `api_edit/delete_message` no actor in audit | INFO | Single-user UI; would need a multi-user policy model first. |
| a17e4fc3 | 13 | `api_self_mesh_remote_instruct` scope validation | INFO | Already type-checks `scope must be object`; downstream signs the request. CSRF + token defends cross-tab. |
| a17e4fc3 | 14 | `_index` `==` not `compare_digest` on bootstrap token | SHIPPED | Batch O (`565618e`) — `hmac.compare_digest(_q_tok, self.token)`. |
| a17e4fc3 | 15 | `broadcast()` set-changed-during-iteration | OBSOLETE | `server.py:13629` already does `for ws in list(self._ws_clients)` (snapshot before iteration). |

### Daemon `send_file` integration map — `agent-a371fb98` (all INFO)

Pure forward-looking integration map for ol_selector / ol_field /
ol_radio_batcher / ol_op_graph / ol_cap / ol_tau_routing / active-inference.
No bugs claimed; the document specifies *where future hooks would land*.

| Agent | # | Title | Class | Note |
|-------|---|-------|-------|------|
| a371fb98 | 1 | Selector hook for CDC/stream/QUIC fork | INFO | Architecture proposal. Smart-Rules integration already partially wired via `c4af2cc` / `4accc87` / `b5da224`. |
| a371fb98 | 2 | Field-state read+write hooks | INFO | Forward design; `coherence_field_native` partial wiring at `_pick_best_relay` is the seed. |
| a371fb98 | 3 | Radio-batcher hook | INFO | New crate proposal. |
| a371fb98 | 4 | CRDT op-graph hook for `_handle_manifest_push` | INFO | Equation-of-One Phase D16 already swapped CRDT folder-sync authoritative (`851f755`). |
| a371fb98 | 5 | `_capability_allowed` cap-bound check hook | INFO | Forward design; current shape already has T1-D/F/J + Batch Q rate limits. |
| a371fb98 | 6 | `transport_choice_for_peer` is capability-only | INFO | Forward design for τ-routing in transport pick (relay sort at 10198 is the existing reference). |
| a371fb98 | 7 | `predict_next_files_for_peer` not used for scheduling | OBSOLETE | D08 pre-warm shipped at `daemon.py:16870-16883` (commit `3d5e328`). |
| a371fb98 | 8 | Time-mode integration (ol_timing) | INFO | Forward design; `_prune_loop` 20s tick is the convergence point. |

### Persistence + state.db — `agent-a4794adc`

| Agent | # | Title | Class | Note |
|-------|---|-------|-------|------|
| a4794adc | 1 | `update_transfer` lost-update race | SHIPPED | T3-K — write-lock held across read + upsert (`f1a65a0`, state.py:3422). |
| a4794adc | 2 | `data_dir`/`state.db`/inbox without restrictive mode | SHIPPED (state.db only) + SHIP (S1) | T2-R chmod'd state.db (0o600). `data_dir` + `inbox_dir` themselves still default umask — see S1. |
| a4794adc | 3 | No `PRAGMA integrity_check` on boot | SHIPPED | T3-X `PRAGMA quick_check` at state.py:517 (`f1a65a0`). |
| a4794adc | 4 | Outbox UNIQUE(peer,msg_id) → at-least-once | SHIPPED | T3-H contract test (`d977eda`) asserts receiver-dedup via `INSERT OR IGNORE`. |
| a4794adc | 5 | `list_peer_files` no LIMIT | SHIPPED | T3-I `limit`/`offset` paginated, clamped (`0d31f6e`). |
| a4794adc | 6 | `transfers.metadata.path` plaintext | SHIPPED | T3-J `_PATH_PII_AAD_TRANSFER` wrap (`31f6fcb`). |
| a4794adc | 7 | Content-Disposition injection | SHIPPED | T3-L RFC 5987 + ASCII fallback (`0d31f6e`). |
| a4794adc | 8 | `_migrate` `current_version` captured once → multiple schema_version rows | NIT | MAX(version) works; only cosmetic. The rows are all correct, just verbose. |
| a4794adc | 9 | `update_transfer` falls back to corrupt-`{}` metadata | SHIP | Promoted to S2. |
| a4794adc | 10 | `enqueue_outbox` ignores msg_kind on conflict | INFO | Idempotent by design; msg_id is unique per message (edited messages get new ids in the wire protocol). |
| a4794adc | 11 | `enqueued_ms` NTP backward jump | NIT | Order by `id` is monotonic; the current sort already breaks ties on `id`. |
| a4794adc | 12 | `idx_transfers_status` missing | SHIP | Promoted to S5. |
| a4794adc | 13 | `wal_autocheckpoint = 50` aggressive | INFO | Tuning suggestion; secure_delete justification is sound and bench didn't surface a regression. |
| a4794adc | 14 | `get_transfer` no transfer_id format validation | INFO | PK lookup; no traversal vector because metadata.path is daemon-supplied. |
| a4794adc | 15 | Inbox dir secure_delete + chmod | SHIP | Folded into S1. |

### Crypto + handshake — `agent-a491c917`

| Agent | # | Title | Class | Note |
|-------|---|-------|-------|------|
| a491c917 | 1 | `decrypted_seen` FIFO eviction → replay slip | OBSOLETE | T2-C cap means `pn > MAX_SKIP_KEYS` is REJECTED (no eviction triggered by the attacker shape). Replayed chain-decrypted frames can't re-decrypt because the chain key was already consumed (popped from `state.skipped` in `_try_skipped`). |
| a491c917 | 2 | `_is_small_order_x25519` `matched == 1` clarity | SHIPPED | Batch Q (`1be96bf`) — uses `matched != 0`. |
| a491c917 | 3 | recv() race-tolerance silently accepts legacy post-DR | SHIPPED | T2-A 1-frame cap (`9e05098`, channel.py:572-589). |
| a491c917 | 4 | v1 HELLO sig fallback unconditional | SHIPPED | T2-B `ONE_LINK_REJECT_V1_HELLO` env gate (`9e05098`). |
| a491c917 | 5 | `derive_native_transfer_secret` silent fallback ordering | SHIPPED | T2-K eager seed derive in `Channel.__post_init__` (`1be96bf`, channel.py:215-225). |
| a491c917 | 6 | Skipped-key eviction defeats OOO delivery (pn = MAX) | OBSOLETE | T2-C — `header.pn > state.recv_n + MAX_SKIP_KEYS` is now REJECTED at the top of `_dh_ratchet` (double_ratchet.py:426). Attacker can't force the 1000-skip eviction loop. |
| a491c917 | 7 | `_dh_ratchet` mutates state before AEAD verify | SHIPPED | T1-A snapshot/revert (`7ef3d2d`). |
| a491c917 | 8 | `init_alice` double-call → nonce reuse | OBSOLETE | `maybe_activate_ratchet` at channel.py:371 guards `if self._dr_state is not None: return False`. Idempotent by construction. |
| a491c917 | 9 | `verify()` swallows everything | SHIPPED | `verify()` narrow (`4aecdff`) — `except (InvalidSignature, ValueError)`. |
| a491c917 | 10 | No Zeroize anywhere | INFO | Acknowledged platform gap; documented. Python-level zeroize is meaningfully unsolvable without bytes-buffer-rewrite, native crates already Zeroize. |
| a491c917 | 11 | HKDF salt reuse between native-transfer + DR-root | NIT | HKDF semantics: different `info` yields independent outputs from the same `(salt, ikm)`. The auditor's "defense in depth" suggestion has no exploit shape today. |
| a491c917 | 12 | `note_caps_received` accepts None silently | NIT | `features=None → []` coercion + `_peer_dr_capable=False` is the safe (legacy AEAD) default. Adding a warning log would be cosmetic. |
| a491c917 | 13 | Identity key migration race | SHIPPED | T1-K `O_CREAT\|O_EXCL` lock file (`268015d`). |
| a491c917 | 14 | `MAX_MSG_PER_CHAIN = 2^32` | NIT | 64-bit nonce — no collision risk. Lower bound is hygiene, not a bug. |
| a491c917 | 15 | No handshake nonce replay cache | SHIP | Promoted to S4. |

---

## Cross-cutting observations

- **TIER 1/2 crypto-DoS class is closed**: T1-A (mutate-before-verify),
  T1-B (per-chunk ratchet key), T2-A (legacy AEAD bound), T2-B (v1 HELLO
  env gate), T2-C (skip-derive cap), T2-K (eager native seed) — covers
  every catastrophic crypto finding in the May 21 transcripts. Crypto
  findings #1, #6, #8 from `a491c917` are OBSOLETE artifacts of pre-T2-C
  reasoning.
- **Server CSRF + token + traversal**: T2-O + T1-I + T1-L + T3-L cover
  the entire `_guarded` mutating verb surface plus inbox traversal plus
  device-invite SAS plus header-injection. The `str(exc)` leakage in
  folder handlers (S3) is the one remaining LOW item.
- **Persistence**: T2-R (state.db chmod), T3-J (path-PII wrap),
  T3-K (write-lock), T3-X (quick_check on boot), T3-I (LIMIT) — only
  data_dir/inbox_dir mode (S1) and the corrupt-JSON wipe edge (S2)
  remain, both LOW.
- **The native crate "dark surface" set is intentional**: ol_device_mesh
  / ol_transfer / ol_netcode / ol_grammar / ol_duress are spec-shipped
  per Phase D / Row 8, but daemon wiring is per-need not per-completion.
  Treating these as bugs misreads the ADR-0024 wiring matrix.
