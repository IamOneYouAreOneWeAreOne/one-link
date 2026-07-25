# AUDIT 2026-05-21 — Triage Batch 2 (5 transcripts)

Triaged against the 57 shipped fixes in `AUDIT_2026-05-21.md` and current code.

- **SHIPPED** — closed by a T1/T2/T3/Batch-P-Q-R commit
- **OBSOLETE** — transcript describes code that no longer matches reality
- **DUP** — same root cause as a sibling finding
- **INFO** — informational / architecture survey only
- **NIT** — cosmetic / sub-µs polish; defer fine
- **SHIP** — genuinely-new, actionable

Transcripts: agent-a522968418149ae17 (web UI), agent-a580a5c320383207d (transfer survey), agent-a65344dfb0d717b8a (tests), agent-a84e416dddb450b02 (QUIC + relay), agent-aa88bd73c820bb225 (daemon send/recv).

---

## SHIP items (worst first)

### S1. `_capability_allowed` fails OPEN when seed-tamper detector raises
- **File:** `daemon.py:11543-11562` (the `try/except Exception: pass` wrapping `self.detect_seed_file_tamper()` inside `_capability_allowed`).
- **Root cause:** `detect_seed_file_tamper` is the very defensive boundary against on-disk seed swap; if its `os.stat` / file-read itself raises (permission flip, race with rotation, antivirus lock), the broad `except: pass` falls through and the cap check continues — exact failure shape T1-D was meant to close, but T1-D fixed the verifier-exception and state=None paths only.
- **Fix:** `except Exception as exc: log.warning("seed_tamper_check_raised: %s", exc); self._record_capability_denial(reason="seed_tamper_check_failed", capability=cap); return False`.
- **Severity:** HIGH. **Bench-needed:** no (cold path).

### S2. FILE_OFFER_BATCH inner-offer failures silently swallowed
- **File:** `daemon.py:4641-4696` (`FILE_OFFER_BATCH` handler).
- **Root cause:** Per-offer exceptions are caught with `log.warning` only; the outer ACK reports `batch_processed=<int>` but the sender has no way to learn WHICH offers failed, so the resume protocol can't target them. Same "silent fallback" class that the audit's degradation_events ring was meant to make visible.
- **Fix:** Collect `failed_offers: list[dict]` (id, coarse reason) inside the loop, include in the outer ACK, and push one `degradation_events` entry per failure (kind `file_offer_batch_inner_failed`).
- **Severity:** HIGH. **Bench-needed:** no.

### S3. Legacy FILE_CHUNK hash-mismatch lacks quarantine pattern
- **File:** `daemon.py:5192-5195` (`with contextlib.suppress(OSError): f.out_path.unlink()` on `not ok`). Compare with the parallel quarantine block at `daemon.py:8148-8163` which renames to `.failed.<hex>` before unlink for forensic capture.
- **Root cause:** M23 quarantine discipline (shipped on the binary path's second EOF site) was never lifted into the legacy FILE_CHUNK EOF or the binary path's first EOF site at `daemon.py:8035-8038`.
- **Fix:** Extract the quarantine block into a `_quarantine_failed_inbox(path)` helper; call from all three EOF handlers (5192, 8035, plus the existing 8148 site can call through it).
- **Severity:** MED (forensic-trail loss; no exploit shape). **Bench-needed:** no.

### S4. ENDPOINT_UPDATE-supplied `quic_port` stashed without verify-dial
- **File:** `daemon.py:14874-14888` (`_handle_endpoint_update`).
- **Root cause:** TCP candidates funnel through `_verify_and_promote_endpoint`, but the QUIC port branch stashes `quic_port_raw` directly into `self._quic_peer_ports[peer_fp]` after only the `1024 <= port < 65536` filter shipped in T2-P. A compromised-but-pinned peer can still redirect our outbound QUIC dial to any high port on their host that they don't actually serve, breaking the QUIC fast path until next CAPS exchange.
- **Fix:** Mirror the host-side verify-dial: schedule a `quic_ping` / 1-byte handshake to the advertised `(addr, port)` and only promote `_quic_peer_ports[peer_fp]` on success.
- **Severity:** MED (defense-in-depth against pinned-but-compromised peer; pinned trust gate already blocks unpinned). **Bench-needed:** no.

### S5. QUIC `_quic_accept_loop` doesn't bind to endpoint identity
- **File:** `daemon.py:21189-21221` (the `while True: ... endpoint.accept_blocking(5000)` body).
- **Root cause:** The local `endpoint` variable is captured once at loop entry, but `self._quic_server_endpoint` can be swapped by the same-port rebind path (`daemon.py:20437-20450`). If rebind happens, the old loop keeps `accept_blocking`ing on the closed endpoint, catches the generic exception, sleeps 0.5s, and spins forever (one task per generation).
- **Fix:** Per-iteration guard `if self._quic_server_endpoint is not endpoint: return`; or pass the endpoint into the task as an explicit identity token and bail when it stops matching.
- **Severity:** MED (resource leak under WiFi roam / rebind path). **Bench-needed:** no.

### S6. QUIC same-port rebind cancels old accept-task without awaiting
- **File:** `daemon.py:20446-20450` (rebind branch in start).
- **Root cause:** `self._quic_accept_task.cancel()` then immediate `asyncio.create_task(self._quic_accept_loop())` — the old task may still be inside `accept_blocking` (5s window) and can return a Connection AFTER cancel is signalled, racing the new accept loop's frame-receiver registration.
- **Fix:** `with contextlib.suppress(asyncio.CancelledError, Exception): await asyncio.wait_for(self._quic_accept_task, timeout=6.0)` before overwriting.
- **Severity:** MED (race in rebind cold path). **Bench-needed:** no.

### S7. QUIC `recv_frame_blocking` returning None ambiguous between idle and closed
- **File:** `daemon.py:21337-21354` (`_quic_inbound_frame_loop`).
- **Root cause:** Comment claims "30 s with no frames — peer's still connected (otherwise the recv would have raised), just idle. Continue." But the native crate's `recv_frame_blocking` returning None is the documented timeout signal; a remote-closed connection often surfaces as None+is_disconnected rather than as an exception. The loop then `continue`s forever on the dead handle while never reaching the `finally:` that clears `_quic_inbound[peer_fp]`, poisoning subsequent dial cache lookups.
- **Fix:** After None, probe `getattr(conn, "is_connected", lambda: True)()` (or call `remote_address`/inspect a known attribute) and `return` on dead conn so the `finally:` fires.
- **Severity:** MED (cache poisoning, eventual FD leak). **Bench-needed:** no.

### S8. `_schedule_outbox_flush` inflight-set check races the populate
- **File:** `daemon.py:16670-16682` (check `if peer_fp in self._outbox_flush_inflight`) vs population inside `flush_outbox_for` at `daemon.py:16617`.
- **Root cause:** N near-simultaneous session-up events on the same peer all see an empty set, all spawn `create_task(self._flush_outbox_swallow(...))`, all do their own `state.get_peer` + `resolve_for_send` round-trip; only one wins the lock at a time. Thundering herd on session churn, not a correctness break.
- **Fix:** Add `peer_fp` to `_outbox_flush_inflight` immediately in `_schedule_outbox_flush`; wrap discard in finally so a coroutine crash still clears it.
- **Severity:** LOW (waste, not corruption). **Bench-needed:** no.

### S9. `rendezvous_client._lookup` cancels pending tasks without awaiting
- **File:** `rendezvous_client.py:242-252`.
- **Root cause:** `as_completed` race-the-URLs pattern cancels remaining tasks in `finally`, but never awaits the cancelled ones. aiohttp `async with session.get` exit handlers run after `session.close()` in shutdown races, surfacing as `Unclosed response` warnings under `pytest -W error`.
- **Fix:** `await asyncio.gather(*pending, return_exceptions=True)` after `cancel()`.
- **Severity:** LOW. **Bench-needed:** no.

### S10. `_get_or_dial_quic` falls back to `peer.port` (TCP port) for QUIC dial
- **File:** `daemon.py:21119`.
- **Root cause:** `port = self._quic_peer_ports.get(peer_fp) or getattr(peer, "port", None)`. This works on peers that successfully bound QUIC/UDP to the same numeric port as TCP. On peers where same-port bind failed (which is common: Windows firewall, port already held), the QUIC dial goes to the peer's TCP port, the OS firewall drops UDP, and `connect_blocking(10000)` burns 10s before WebRTC takes over.
- **Fix:** Track per-peer `same_port_likely` flag (set when last successful QUIC handshake used the TCP port; cleared on failure); only use the TCP-port fallback when flag is set.
- **Severity:** MED (10s per send latency penalty when ENDPOINT_UPDATE is missed). **Bench-needed:** yes (latency under packet-loss).

### S11. `BrowserPeerManager._close_peer` schedules `pc.close()` but never awaits
- **File:** `peer_rtc.py:543-555`.
- **Root cause:** `loop.create_task(pc.close())` is fire-and-forget. On daemon shutdown the task may be cancelled before aiortc finishes ICE teardown; if any MediaStream tracks are attached (v0.20.x audio/video call paths), they leak underlying socket handles and worker threads.
- **Fix:** Track close tasks in a set (mirror the `_send_tasks` pattern from T2-H); await all on `BrowserPeerManager.shutdown()` with a bounded timeout.
- **Severity:** LOW. **Bench-needed:** no.

### S12. DTLS-fingerprint change on an established envelope-bound peer warns but doesn't tear down
- **File:** `peer_rtc.py:1258-1268` (`_record_dtls_fingerprint`).
- **Root cause:** Returns `(fp, False)` on mismatch but caller's envelope signature path treats this purely advisory. For a previously-attested peer, a mid-session DTLS-cert change should clear `attested_ms` and close the peer; today the mismatch is a structured WARNING only.
- **Fix:** On mismatch when `previous is not None`, also call `_close_peer(peer)` AND clear `peer.attested_ms` so the next interaction re-attests from scratch.
- **Severity:** LOW (rare path; envelope sig is the load-bearing gate). **Bench-needed:** no.

### S13. `provenance_broadcast_failed` silently dropped on `_broadcast_tail` raise
- **File:** `daemon.py:5779-5786` in `_handle_file_provenance`.
- **Root cause:** A bug in `_broadcast_tail` (e.g. listener mid-removal) silently drops the provenance event for all subscribers. No `degradation_events` push and no log warning. Provenance is the auditable artifact; silent drop defeats the purpose.
- **Fix:** Replace the swallow with `log.warning("provenance broadcast failed: %s", exc)` and push a `degradation_events` entry `kind=provenance_broadcast_failed` — same pattern as the transfer-side silent-fallback gates.
- **Severity:** LOW. **Bench-needed:** no.

### S14. Tests: `_pick_best_relay` / `_relay_metrics_for` invoked with `object()` self
- **File:** `tests/unit/test_daemon_phase_d_wiring.py:22-53`.
- **Root cause:** Unbound-method-with-bare-`object()`-self exercises only the helper's input-only branches; the wiring of `self._relay_metrics` / `self._rendezvous_url` in the production `__init__` is uncovered. If the wiring regresses (e.g. an EWMA-surface refactor drops the attribute), tests still pass.
- **Fix:** Build a minimal `SimpleNamespace` (or a real Daemon under `_create_test_daemon`) with the production attribute names; assert by attribute access, not by argument.
- **Severity:** MED (test-quality; latent silent-degrade vector). **Bench-needed:** no.

### S15. Tests: `test_env_flag_*` reads `os.environ` directly, never calls daemon
- **File:** `tests/unit/test_native_transfer_cutover.py:299-339`.
- **Root cause:** Three tests `os.environ["ONE_LINK_NATIVE_TRANSFER"] = "0"` then assert `os.environ.get(...) != "0"`. They test `dict.get`, not the daemon's behavior — exactly the autonomous-agent half-commit gotcha from project memory.
- **Fix:** Patch `Daemon.send_file` (or a known dispatch helper) to record `actual_method`; run with each flag value; assert path matches.
- **Severity:** MED (test-quality). **Bench-needed:** no.

### S16. Tests: `test_daemon_brings_up_quic_endpoint` asserts nothing about QUIC
- **File:** `tests/test_quic_daemon_dial.py:188-206`.
- **Root cause:** Sets up a daemon pair, sends a probe, sleeps 2.0s, calls `status`, asserts `ok=True`. Comment explicitly says "what matters here is the daemon didn't crash on QUIC bring-up" — but the daemon would also report ok=True with QUIC silently failed at bind. The actual port lookup happens in `_wait_for_quic_peer_port` in the next test, which is opt-in.
- **Fix:** Assert `quic_status` returns `available=True` and `local_port > 0` for both daemons.
- **Severity:** MED. **Bench-needed:** no.

### S17. Tests: `pytest.skip` masks a real flaky-QUIC bug in concurrent_control
- **File:** `tests/test_concurrent_control.py:140-148`.
- **Root cause:** `if not ready: pytest.skip("QUIC port advertisement didn't land in time")`. This is the only concurrent QUIC ping test in the suite. Under load, this test silently no-ops — which is the exact failure mode (advertisement losing the race) it was supposed to detect.
- **Fix:** Promote skip to `pytest.fail`, raising the 30-second cap if needed; if it's persistently flaky, fix the underlying race.
- **Severity:** MED. **Bench-needed:** no.

### S18. Tests: I4 + I6 audit tests bypass production wiring
- **File:** `tests/test_audit_100pct_closeout.py:38-90` (I4 replay-cache uses `_FakeDaemon: pass`) and `:111-158` (I6 monotonic-advance tests simulate the dict-update logic inline rather than driving `_handle_attest_response`).
- **Root cause:** Wiring uncovered. The local dict gets exercised but the production code paths that consume it (`_handle_attest_response`, `_attestation_replay_check_and_record`) are never reached.
- **Fix:** Pair each existing test with an end-to-end variant that posts a `_fake_doc(...)` through `_handle_attest_response` and asserts on the manager's state afterward.
- **Severity:** MED. **Bench-needed:** no.

### S19. Tests: `NativeConnLike` mock for `_quic_connection_alive` locks in nothing
- **File:** `tests/test_quic_daemon_dial.py:35-40`.
- **Root cause:** Mock returns `(241, b"pong")` from `send_frame_round_trip`. The real `_quic_connection_alive` may evolve to require session-state or a `_dr_shared` check; the mock-based test would still pass.
- **Fix:** Use a real `one_link_native.quic.make_*_endpoint`-built Connection (module already requires native crate via skip).
- **Severity:** LOW. **Bench-needed:** no.

### S20. Tests: missing `degradation_events` empty-assertion on every send/file integration test
- **File:** Every `daemon_pair`-style file/send/quic_ping test except `test_soak_no_silent_drops` (which is now real per T2-N) and `test_send_file_stream_mode_survives_with_quic_route_available` (which already does it).
- **Root cause:** The audit cross-cutting recommendation called this out: ring assertion lives in <5 places, should be in every happy-path integration test. It's the cheapest possible regression net for the cascading-NULL / DR-wipe class of bugs.
- **Fix:** Add a fixture-style assertion (e.g. an `assert_no_degradation(p)` helper called at end of each test, scanning both peers' rings).
- **Severity:** MED. **Bench-needed:** no.

### S21. Tests: ~67 substring-grep tests across 20 files
- **File:** `tests/test_browser_peer_messages_v0192.py` + 4 siblings (~80 tests doing `assert 'MSG_PROTOCOL_VERSION = "OL-MSG-1"' in peer_html`); `tests/test_one_setup_v0220.py:24-32` + `test_one_health_center_v0221.py` (similar grep over `server.py` source).
- **Root cause:** Tests pass if literal string is present, regardless of correctness. T2-M's acorn JS analyzer fixed the JS-side undefined-call gap but the broader Python-side grep pattern remains.
- **Fix:** Hit the routes via the aiohttp test client (`test_one_setup_v*`) and run JS through Node (browser-peer-messages tests) — both already proven patterns in the suite.
- **Severity:** MED (coverage theater). **Bench-needed:** no.

### S22. UI: 6 visible XSS sites and inline `onerror` already shipped — but `state.messages.find` mutation race remains
- **File:** `index.html:20486, 20493, 20641, 20697` (msg_edit / msg_delete / reaction / msg WS handlers all do `state.messages.find(x => x.id === ...)` then mutate in place).
- **Root cause:** Multiple WS handlers mutate the same array entry without version stamping; `scheduleRenderMessages` is rAF-coalesced. If `msg_delete` fires after an in-flight `_markBubbleState` for the same id, the bubble can render `[message deleted]` with a ✓ tick (delete cleared body but didn't clear sending_state).
- **Fix:** Index `state.messages` by id in a Map; queue WS state-mutating events behind the same rAF that gates render.
- **Severity:** MED (UI inconsistency under fast-WS load). **Bench-needed:** no.

### S23. UI: `state.transfersById` Map not pruned when `state.transfers` array sliced
- **File:** `index.html:20764-20765` (`state.transfers.slice(0, 80)` then `state.transfersById.set(...)` with no symmetric delete).
- **Root cause:** Array hard-cap at 80 but Map grows unboundedly across long session. `transferForMessage` (now O(1) per T3-Z via the `transferByDirBlob` index) is fine, but `state.transfersById` itself bloats memory for thousands of stale transfer entries.
- **Fix:** After the slice, iterate `transfersById` and delete entries not in the new array; mirror prune `_trackTransferIndex` deletion.
- **Severity:** LOW (memory bloat on multi-hour sessions). **Bench-needed:** no.

### S24. UI: `document.querySelector` with un-escaped peer-controlled message id (one site)
- **File:** `index.html:23126`.
- **Root cause:** Three siblings at 15165, 19661, 23808 wrap `m.id` with `CSS.escape(...)`; line 23126 doesn't. A malformed / legacy message id with quote / backslash throws `SyntaxError` and aborts the enclosing async handler mid-flight.
- **Fix:** `CSS.escape(m.id)` to match siblings.
- **Severity:** LOW. **Bench-needed:** no.

### S25. UI: zero-byte transfer renders "Sending…" forever
- **File:** `index.html` in `renderFileBubble` (transfer rendering path) — `t.progress_pct` becomes NaN for `total === 0`, CSS `width: NaN%` resolves to 0, label sticks at "0 B / 0 B".
- **Root cause:** Empty-file edge — divide-by-zero in upstream pct calc, and no daemon-side guarantee that a zero-byte transfer emits status=complete.
- **Fix:** UI: short-circuit `total === 0 → label = "Empty file, sent"`; daemon: ensure `_finish_cdc_file` / `_handle_file_binary_chunk` emit status=complete for zero-byte transfers (verify path).
- **Severity:** LOW (rare edge). **Bench-needed:** no.

### S26. UI: 6 polling timers don't pause on auth loss (T3-P claims fixed; verify)
- **File:** `index.html` setInterval cluster.
- **Root cause:** T3-P shipped tracking + pause/resume in `state._mainPollTimers`. Audit transcript suggests this may still be an issue if the implementation only paused on first 401 and didn't cover banner-dismissal recovery edge. Worth confirming end-to-end before closing.
- **Fix:** Verify all 6 timers are in `_mainPollTimers`, that `_maybe401` invokes `pause`, and that successful recovery resumes them. Add an integration test that asserts no 401-spam after token-refresh recovery.
- **Severity:** LOW (verify-only). **Bench-needed:** no.

### S27. Tests: soak tests use fixed `time.sleep(N)` as synchronization (8+ sites)
- **File:** `tests/test_two_device_soak.py:188, 261, 282, 392, 418` etc.
- **Root cause:** T3-M closed one site via `_wait_for_inbound_text_count`; 8+ remain. Under suite-level load, 1.5-5s windows race CI runner variance. Memory rule `feedback_better_or_dont_ship`: a regression that slows the hot path would start losing tests here exactly when you want to catch it.
- **Fix:** Replace each `time.sleep` synchronizer with bounded polling on the relevant observable (`message_log`, `inbox_files`, `_wait_for_inbound_*` helpers already used elsewhere).
- **Severity:** LOW (flakiness under load). **Bench-needed:** no.

### S28. Tests: 2 soak tests still use `set` for collected bodies (T3-N partial)
- **File:** `tests/test_two_device_soak.py:190, 262`.
- **Root cause:** T3-N upgraded one site to `Counter`. Two more `received = {...}` set-comprehensions remain — duplicate-delivery signal still lost on those.
- **Fix:** Convert both to `Counter` so missing-AND-duplicate bodies surface.
- **Severity:** LOW. **Bench-needed:** no.

### S29. Tests: `os.environ` mutated directly without monkeypatch (2 files)
- **File:** `tests/test_lifecycle.py:354-387`, `tests/unit/test_bandit_route_selector_migration.py:103-174`.
- **Root cause:** Try/finally `os.environ.pop(...)` works for single-process runs but pytest-xdist surfaces this as flakiness on unrelated tests.
- **Fix:** Use `monkeypatch.setenv` / `monkeypatch.delenv`.
- **Severity:** LOW. **Bench-needed:** no.

### S30. Tests: `test_two_daemons_in_same_home_second_fails_gracefully` uses fixed sleeps for instance-lock contention
- **File:** `tests/test_resilience.py:212, 217`.
- **Root cause:** Two `time.sleep(2.0)` calls as the only synchronization between daemon-start and lock-check. Under slow CI, 2s may not let p1 hold the lock yet — false pass; or p2 hasn't exited yet — false fail.
- **Fix:** Poll the instance-lock file / a "ready" sentinel with a bounded timeout; assert on the polled state.
- **Severity:** LOW. **Bench-needed:** no.

---

## Per-transcript triage

### agent-a522968418149ae17 — Web UI (15 findings)

| # | Finding | Verdict |
|---|---------|---------|
| 1 | XSS via `e.message` in folder-conflicts modal (`index.html:16757`) | **SHIPPED** (T3-A) |
| 2 | Same XSS pattern in 5 sibling renderers | **SHIPPED** (T3-A) |
| 3 | Inline `onerror` handler in QR `<img>` | **SHIPPED** (T3-B, commit `1f2f4f9`) |
| 4 | Session token in `location.href` | **SHIPPED** (T3-C, commit `f614cf9`) |
| 5 | `querySelector` un-escaped at 22811 | **SHIP S24** (one site only — three siblings already use CSS.escape) |
| 6 | `state.messages.find` mutation race across WS handlers | **SHIP S22** |
| 7 | `transferForMessage` O(N·M) per render | **SHIPPED** (T3-Z via `transferByDirBlob` index) |
| 8 | Misleading "Drag the original in again" toast | **NIT** (cosmetic copy on legacy-only path) |
| 9 | Em-dashes in user-facing copy | **SHIPPED** (T3-G + T3-G rest) |
| 10 | Adversarial-framing copy (`We don't peek`, `We can't help you there`) | **SHIPPED** (T3-F) |
| 11 | `state.transfersById` grows unbounded | **SHIP S23** |
| 12 | `URL.createObjectURL` never revoked on tab close | **SHIPPED** (T3-O, commit `1f2f4f9`) |
| 13 | `setInterval` cluster never cleared on auth loss | **SHIPPED** (T3-P) — **SHIP S26** (verify, not refix) |
| 14 | No focus trap in modals | **SHIPPED** (T3-Q via global focus trap) |
| 15 | Zero-byte transfer renders "Sending…" forever | **SHIP S25** |

### agent-a580a5c320383207d — Transfer-stack survey (10 sections)

This whole transcript is an **INFO** architecture survey, not a list of bugs. Key claims to flag:

| Section | Claim | Verdict |
|---------|-------|---------|
| 1-2 | Native transfer is opt-in env-gated | **OBSOLETE** — default-flipped in `5c62a64` per memory `one_link_native_transfer_pipeline.md` |
| 3 | Native FILE_NATIVE_CHUNK uses nonce = `chunk_index.to_bytes` with constant key | **OBSOLETE / SHIPPED** — T1-B fixed: `ratchet.key_at(chunk_index, skipped=...)` derives per-chunk key |
| 3 | Double Ratchet not wired | **OBSOLETE** — DR is wired at channel level per `maybe_activate_ratchet` |
| 3 | At-rest encryption gap | **SHIPPED** — lockbox + path-PII wrap active per daemon.py 20094-20134 |
| 4 | QUIC peer↔peer cutover NOT WIRED | **OBSOLETE** — QUIC dial/accept loop + native CDC/Bin chunks flow through QUIC when peer advertises `NATIVE_TRANSFER_INDEXED_V1` + QUIC port |
| 7 | Manifest verification end-of-transfer | **INFO** |
| 8 | Resume-on-disconnect NOT SHIPPED | **INFO** — per v0.7.4 memory it is partially shipped; out-of-scope for this audit |
| 9 | Capability gating + mid-stream revoke | **SHIPPED** — confirmed at daemon.py 18101 |
| 10 | Limits 1 GiB / 16 TiB / 240B etc. | **INFO** |

Bottom line: the transcript was written against a pre-cutover snapshot. The "not yet default" claims are obsolete as of the May 11 default-flip.

### agent-a65344dfb0d717b8a — Tests + skip markers (15 findings)

| # | Finding | Verdict |
|---|---------|---------|
| 1 | `test_soak_no_silent_drops` is `assert True` | **SHIPPED** (T2-N, real diagnostics check now at tests/test_two_device_soak.py:300-318) |
| 2 | `test_pick_best_relay_*` with `object()` self | **SHIP S14** |
| 3 | `test_env_flag_*` reads `os.environ` | **SHIP S15** |
| 4 | Only one degradation_events assert + `NATIVE_TRANSFER_V1` reference is dead text | **SHIP S20** (broaden coverage). Note: cap-name claim is partially obsolete — capabilities.py still defines V1 but LOCAL_CAPABILITIES advertises only INDEXED_V1; daemon never honors V1-only peers (safe degradation, see Transfer-survey #4) |
| 5 | `test_daemon_brings_up_quic_endpoint` asserts nothing | **SHIP S16** |
| 6 | `pytest.skip` masks flaky concurrent QUIC ping | **SHIP S17** |
| 7 | I6 tests simulate update logic inline | **SHIP S18** (paired with #8) |
| 8 | I4 replay-cache uses `_FakeDaemon: pass` | **SHIP S18** (paired with #7) |
| 9 | Browser-peer tests substring-grep HTML | **SHIP S21** |
| 10 | `test_one_setup_v0220.py` substring-grep server.py source | **SHIP S21** |
| 11 | `NativeConnLike` mock locks in nothing | **SHIP S19** |
| 12 | 9+ fixed `time.sleep(N)` in soak tests | **SHIP S27** (partial — T3-M closed one) |
| 13 | `set` used for received bodies | **SHIP S28** (partial — T3-N closed one) |
| 14 | `os.environ` direct mutation without monkeypatch | **SHIP S29** |
| 15 | `test_two_daemons_in_same_home_second_fails_gracefully` fixed sleeps | **SHIP S30** |

### agent-a84e416dddb450b02 — QUIC + relay transport (15 findings)

| # | Finding | Verdict |
|---|---------|---------|
| 1 | QUIC accept loop spins forever after endpoint close | **SHIP S5** |
| 2 | Same-port rebind leaks old accept task on cancel | **SHIP S6** |
| 3 | `_quic_outbound` entries replaced without close | **SHIPPED** (T2-Q at daemon.py:21170-21179) |
| 4 | `recv_frame_blocking` None misinterpreted | **SHIP S7** |
| 5 | `_quic_recent_paired` FIFO race | **SHIPPED** (T1-H FULL FIX via `conn.peer_fingerprint()` at daemon.py:21249-21295) |
| 6 | `_NoopChannel.peer_caps={}` and class-level mutable default | **SHIPPED** (T1-G + Noop now uses per-instance `__init__` at daemon.py:21430-21452, proxies peer_caps + peer_ed_pub + peer_short_id) |
| 7 | ENDPOINT_UPDATE `quic_port` poisoning bypasses verify | **SHIP S4** (T2-P shipped well-known-port floor only; verify-dial pending) |
| 8 | `_handle_endpoint_update` rejects unpinned but races pinning | **NIT** (only fires for first frame after pair-confirm; re-emitted on next CAPS round-trip per design) |
| 9 | Relay-only fallback records no degradation event when candidates empty | **NIT** (degradation ring already records `direct_attempts_exhausted`-style events on the failure path; specific empty-candidates kind would be nice-to-have) |
| 10 | rendezvous `as_completed` doesn't await cancelled tasks | **SHIP S9** |
| 11 | DTLS fingerprint change warn-don't-reject | **SHIP S12** |
| 12 | `_NoopChannel` class-level mutable defaults | **SHIPPED** (per-instance `__init__` now, daemon.py:21434) |
| 13 | `pc.close()` never awaited | **SHIP S11** |
| 14 | QUIC send queue unbounded via `asyncio.gather` (QUIC_CDC_BATCH_SIZE = 1) | **NIT** (current value is 1; only an issue if the constant is bumped) |
| 15 | `_get_or_dial_quic` falls back to `peer.port` as QUIC port | **SHIP S10** |

### agent-aa88bd73c820bb225 — Daemon send/recv paths (15 + 3 honorables)

| # | Finding | Verdict |
|---|---------|---------|
| 1 | FILE_OFFER over QUIC computes peer_fp from empty bytes | **SHIPPED** (T1-G — `_NoopChannel` proxies real `peer_ed_pub` at daemon.py:21421-21436) |
| 2 | `_capability_allowed` fails OPEN on seed-tamper detect exception | **SHIP S1** (T1-D closed verifier-exception + state=None; tamper-detect-exception path still fail-open) |
| 3 | send_file capability check skipped when `peer_fp_for_policy` is None | **SHIPPED** (T1-F) |
| 4 | Sender ignores legacy `NATIVE_TRANSFER_V1` peers | **INFO** (intentional safe degradation — V1 has no per-chunk ratchet; FILE_BIN_CHUNK is the right fallback) |
| 5 | `NativeTransferSession.decrypt_chunk` advances ratchet before AEAD | **SHIPPED** (T1-B — `key_at(chunk_index, skipped=...)` is idempotent per index, no advance-before-verify) |
| 6 | Outbox flush "already inflight" guard reads before lock | **SHIP S8** |
| 7 | FILE_OFFER_BATCH swallows per-offer errors | **SHIP S2** |
| 8 | `derive_native_transfer_secret` cache-miss race after CAPS arrives mid-derive | **SHIPPED** (T2-K — eager seed derive in `Channel.__post_init__` at channel.py:210-225) |
| 9 | Empty `error` strings on best-effort send paths | **SHIPPED** (T3-E — `_format_error(e)` at daemon.py:16449) |
| 10 | `_inbound_live_channels` mutation during iteration | **SHIPPED** (T2-G via snapshot pattern — every reader does `list(...)` or `tuple(...)` at daemon.py:2954, 21406-21408) |
| 11 | FILE_BIN_CHUNK / FILE_NATIVE_CHUNK seq mismatch raises | **SHIPPED** (T2-E + Batch P/Q/R follow-up: overrun-size and missing-payload paths now ACK-reject) |
| 12 | Mid-stream cap revoke message-string-matched by transient classifier | **NIT** (classifier matches "rejected" / "decrypt" / specific markers; "capability revoked" doesn't match a transient marker → returns False → permanent fail; string-match is fragile but currently safe) |
| 13 | Legacy FILE_CHUNK quarantine missing on hash mismatch | **SHIP S3** |
| 14 | CAPABILITY_GRANT raw verifier error reflected to peer | **SHIPPED** (T3-U at daemon.py:4554-4561) |
| 15 | `_handle_file_provenance` broadcast errors swallowed | **SHIP S13** |
| HM1 | FILE_OFFER lacks `native_transfer_indexed_v1=True` hint | **NIT** |
| HM2 | Telemetry `try/except Exception: pass # pragma: no cover` hides ImportError | **NIT** |
| HM3 | "no peer succeeded (no transient errors recorded)" UI-hostile | **NIT** |

---

## Summary

- 30 SHIP items (S1-S30): S1, S2 = HIGH; S3-S7, S10, S14-S18, S20-S22 = MED; S8, S9, S11-S13, S19, S23-S30 = LOW.
- All TIER 1 / TIER 2 / TIER 3 findings from the 5 transcripts that already had commit hashes in `AUDIT_2026-05-21.md` are confirmed shipped against current source.
- Transfer-survey transcript is entirely **INFO/OBSOLETE** — it was written against pre-default-flip snapshot.
- The QUIC transcript's central concerns (FIFO race, `_NoopChannel` empty bytes) are closed; remaining QUIC items are accept-loop / rebind / dead-handle hygiene.
- The daemon send/recv transcript's CRITICALs are all closed; the remaining genuine SHIP item is the seed-tamper-detect exception fall-through (S1) and FILE_OFFER_BATCH inner-failure swallowing (S2).
