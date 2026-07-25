# Audit Triage — Batch 3 (2026-05-22)

Triages 4 transcripts:

- `audit_extracts_may21/agent-ac7b5e24234936a05.md` — Async concurrency
- `audit_extracts_may21/agent-ac8e452c9c6a9bbbd.md` — Service worker
- `audit_extracts_may21/agent-acdf77b834b45013a.md` — Half-implemented features
- `audit_extracts_may21/agent-ace70abc0a9a587a5.md` — QUIC cutover

Against shipped table in `AUDIT_2026-05-21.md` (T-tags T1-A…T1-L, T2-A…T2-S, T3-A…T3-Z) + post-table Batch P/Q/R (commits `1be96bf` + `6bf3358`).

Current date: 2026-05-22. Verified all classifications by reading current `daemon.py` / `server.py` / `peer_quic.py` / `sw.js`.

---

## Transcript A — Async concurrency (`agent-ac7b5e24234936a05.md`)

| # | Transcript finding | Class | Notes |
|---|---|---|---|
| 1 | `server.py:13451` `broadcast()` orphan tasks → OOM | SHIPPED | T2-H (`f1a65a0`) — `_ws_send_tasks` set + `add_done_callback` live at server.py:13626. |
| 2 | `daemon.py:20793` global `_quic_dial_lock` stalls all dials | SHIPPED | T2-I (`5b9f768`) — `_quic_dial_locks: dict[str, asyncio.Lock]` at daemon.py:1270; per-peer; pruned on revoke (daemon.py:14800). |
| 3 | `_outbound_session_create_locks` / `_outbox_flush_locks` / `_resume_lock_dict` never pruned | SHIP (partial) | Batch R (`1be96bf`) prunes `_outbound_session_create_locks` + `_quic_dial_locks` on revoke (daemon.py:14799-14800). **`_outbox_flush_locks` (line 1582) + `_resume_lock_dict` (line 16696) still leak per-peer.** |
| 4 | `_endpoint_verify_tasks` + `_quic_inbound_tasks` never cancelled in `stop()` | SHIP (partial) | `_endpoint_verify_tasks` cancellation shipped in Batch R (`1be96bf`) at daemon.py:21625-21635. **`_quic_inbound_tasks` (daemon.py:21202) is still not iterated/cancelled in stop().** Inbound frame tasks per accepted QUIC peer can leak past endpoint close. |
| 5 | `_finish_cdc_file_in_background` + 6 other `create_task(_runner())` orphan sites | SHIP | daemon.py:8687 `asyncio.create_task(_runner())` with no set/callback. The pattern repeats; not centralized. |
| 6 | `_courier_monitor_task` await without except-Exception | OBSOLETE | Transcript line-ref doesn't match current code. Server.py has no such task name; courier monitor was reworked. INFO/OBSOLETE either way — not a security finding. |
| 7 | Same-port QUIC rebind cancels `_quic_accept_task` without await | SHIP | daemon.py:20446-20450 cancels but creates the new task immediately. Two accept loops can run for up to 5s (the accept_blocking timeout). |
| 8 | `_quic_inbound_frame_loop` early-return state cleanup | INFO | Auditor self-verified the `finally` runs on `return`. No fix needed. |
| 9 | `_dm_reaper_loop` swallows DB errors after state.close() | NIT | Reaper is cancelled in stop() (daemon.py:21605). Post-state-close window is narrow + logged warnings are not exploitable. |
| 10 | `_quic_accept_loop` infinite 0.5s retry on permanently broken endpoint | NIT | Same condition + warning every 0.5s isn't a DoS. Daemon shutdown still cancels. Low value. |
| 11 | Lock-ordering hazard create_lock → sess.lock | NIT | Currently safe; auditor flagged future risk. Doc-comment fix only. |
| 12 | `for fp, conn in self._quic_outbound.items()` in async handler | NIT | Body doesn't await; cannot mutate mid-iter in CPython. Defensive `list()` is cheap polish. |
| 13 | `happy_eyeballs` doesn't await cancellations | SHIPPED | daemon.py:10063-10070 already does `for t in pending: t.cancel(); await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), 0.5)`. Transcript reflects pre-fix state. |
| 14 | `contextlib.suppress(Exception)` wrapping `create_task()` | NIT | `create_task()` only raises with no running loop; cosmetic. |
| 15 | `_prune_loop` swallows `Exception` from `_prune_chunk_cache` | NIT | Logging-only polish. |

---

## Transcript B — Service worker (`agent-ac8e452c9c6a9bbbd.md`)

| # | Transcript finding | Class | Notes |
|---|---|---|---|
| B1 | Unconditional `skipWaiting()` + `clients.claim()` | INFO | Local 127.0.0.1 daemon; trust boundary is the loopback. No production OTA path exists. Re-evaluate before wider deployment. |
| B2 | Missing pinned-signature verification for SW + shell | INFO | Already documented as "queued" in v0.20.5 audit (M3 SW signature pinning, project_one_link_v020_audit_findings.md). Not a 2026-05-21 finding. Pre-existing roadmap item. |
| B3 | `postMessage` handler without origin verification | SHIPPED | sw.js:198 now checks `event.origin && event.origin !== self.origin` + `_sanitizeNotifText()` caps user-supplied strings (sw.js:206-209). Pre-existing fix landed before 2026-05-21. |
| B4 | Cache-first for `/manifest.json` + `/static/*` with indefinite stale fallback | SHIPPED | sw.js:89-104 now does true stale-while-revalidate (background `fetch().then(put)` on every hit). Comment at sw.js:82-88 documents the prior cache-first → SWR upgrade. |
| B5 | Origin not checked in fetch handler | INFO | SW scope is `/` same-origin; not a viable attack under current CSP + scope. |
| B6 | No Content-Type validation before cache | NIT | Browsers re-detect MIME on serve. Cosmetic. |
| B7 | IDB outbox has no TTL on queued items | NIT | Designed-in resilience for offline send. UX trade-off; not security. |
| B8 | `notificationclick` opens `/` unconditionally | DUP | Same root as B3 (postMessage hardening already shipped). |

---

## Transcript C — Half-implemented features (`agent-acdf77b834b45013a.md`)

| # | Transcript finding | Class | Notes |
|---|---|---|---|
| C1 | `ol-modal-closed` CustomEvent dispatched, no listener (web/index.html:29485) | NIT | Forward-compatibility hook; auditor self-verified `try/catch` already wraps the dispatch and no visible feature regresses. |
| C2 | API endpoints all verified, onclick handlers all verified, no TODO/FIXME, localStorage flags all functional, missing button IDs covered by delegated handlers | INFO | Architecture survey, no actionable items. |

---

## Transcript D — QUIC cutover (`agent-ace70abc0a9a587a5.md`)

**Entire transcript is OBSOLETE** as of 2026-05-22. Verified against git log + current code.

| # | Transcript finding | Class | Notes |
|---|---|---|---|
| D1 | `make_endpoint()` stubbed, returns None — "Identity bridge not yet implemented" | OBSOLETE | Shipped as `make_server_endpoint(identity_pem, is_paired_callback, config)` at peer_quic.py:139 (Wave 2c). Identity bridge live via `_build_native_identity_from_pem`. |
| D2 | No daemon ever opens QUIC endpoint | OBSOLETE | `_quic_server_endpoint` is live (daemon.py:21205+); accept loop, frame loop, peer-fp ground-truth all shipped. |
| D3 | `transport_choice_for_peer()` defined but never called | OBSOLETE | QUIC chunk transport shipped in Wave 2f (`23fea1a feat(quic): batch FILE_NATIVE_CHUNK across parallel QUIC streams in send_file`). |
| D4 | `send_frame_stream_round_trips_count()` not wired in send_file | OBSOLETE | `fd6c91e feat(quic): send_chunks_via_quic_parallel — multi-stream batch sender`; `c2ffadc feat(file-engine): CDC chunks ride QUIC streams when peer supports it`. Live. |
| D5 | No NAT traversal / rendezvous for QUIC | INFO | LAN + same-port-as-TCP rebind (`e8f67d8`, `c5f2ce6`, `c90dd4f`) is the chosen path. WAN QUIC P2P is a roadmap item, not an audit gap. |
| D6 | "Zero" E2E QUIC tests | OBSOLETE | `25f1187 test(quic): parallel-stream chunk-round-trip validation`; `fb298fa fix(quic): un-skip the daemon-to-daemon QUIC ping test — full chain now verified`. |
| D7 | "7-10 days of focused work" estimate | OBSOLETE | All listed work items shipped between 2026-05-12 and 2026-05-22 (Waves 2c-2f + reliability batches). |

---

## SHIP list (genuinely-new, actionable)

Tight list. 4 items.

### 1. `_quic_inbound_tasks` never cancelled in `stop()`
- **File:line:** `src/one_link/daemon.py:21202` (set init) + `21505` (`stop()` body)
- **Root cause:** `stop()` cancels `_quic_accept_task` + `_endpoint_verify_tasks` but does not iterate `_quic_inbound_tasks` (per-accepted-connection frame-recv tasks). On shutdown they run against a closed endpoint / closed state.
- **Fix:** Add the same cancel+gather pattern used for `_endpoint_verify_tasks` at daemon.py:21625-21635, after `accept.cancel()` and before clearing `_quic_outbound`.
- **Severity:** MED
- **Bench:** no

### 2. `_outbox_flush_locks` + `_resume_lock_dict` not pruned on peer revoke
- **File:line:** `src/one_link/daemon.py:14799-14800` (Batch R prune block) + `1582` (`_outbox_flush_locks` init) + `16695` (`_resume_lock_dict` init)
- **Root cause:** Batch R pruned `_outbound_session_create_locks` + `_quic_dial_locks` on revoke. The other two per-peer Lock dicts still grow monotonically with the lifetime peer-set and a re-pair inherits the stale Lock.
- **Fix:** Add `self._outbox_flush_locks.pop(peer_fp, None)` and `if hasattr(self, "_resume_lock_dict"): self._resume_lock_dict.pop(peer_fp, None)` to the same Batch R block.
- **Severity:** LOW
- **Bench:** no

### 3. Orphan `create_task(_runner())` sites — centralize via `self._track()`
- **File:line:** `src/one_link/daemon.py:8687` (`_schedule_finish_cdc_file`), and the create_task sites called out at transcript lines 4534 (`send_file`), 3185 (`_execute_self_mesh_send`), 14614/14630/14846 (endpoint helpers), 18533 (`_control_shutdown`), 19058 (`broadcast_endpoint_to_paired`)
- **Root cause:** Tasks are fire-and-forget with no set membership and no done-callback. Exceptions surface only via the loop's default handler; "Task was destroyed but it is pending" warnings appear on shutdown if any are mid-flight.
- **Fix:** Add a `self._background_tasks: set[asyncio.Task]` + `self._track(coro)` helper mirroring the `_endpoint_verify_tasks.add(task); task.add_done_callback(set.discard)` pattern. Replace the 6-7 raw `create_task(...)` call sites. Cancel + gather the set in `stop()`.
- **Severity:** MED
- **Bench:** no

### 4. Same-port QUIC rebind doesn't await cancelled accept task
- **File:line:** `src/one_link/daemon.py:20446-20450`
- **Root cause:** `self._quic_accept_task.cancel()` immediately followed by `self._quic_accept_task = asyncio.create_task(self._quic_accept_loop())`. The cancelled task can still be inside `to_thread(accept_blocking, 5000)` for up to 5 s; two accept loops race + the old one writes to the now-rebound `_quic_inbound_tasks` set.
- **Fix:** `prior = self._quic_accept_task; prior.cancel(); try: await asyncio.wait_for(prior, timeout=0.5) except (asyncio.CancelledError, asyncio.TimeoutError, Exception): pass` before reassigning.
- **Severity:** LOW
- **Bench:** no

---

## Counts

- SHIPPED: 6
- SHIPPED (partial, see SHIP follow-ups): 2
- OBSOLETE: 8 (one full transcript)
- DUP: 1
- INFO: 7
- NIT: 8
- **SHIP: 4**
