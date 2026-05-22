`test_i6_monotonic_advance_accepted` literally simulates the update logic in the test body — it's not calling production code, just asserting that `max(prev, new_issued)` works. `test_i6_clock_skew_tolerance` (line 140) asserts an inline boolean expression rather than calling a real method.

I have enough findings. Let me compile the report.

---

# One Link Test Suite Audit — Top 15 Findings

**1. CRITICAL — `tests/test_two_device_soak.py:245-257` (`test_soak_no_silent_drops`)**
What: Test body is literally `assert True` with a docstring admitting "this is a tautological smoke test."
Why: Name suggests it catches silent message drops; in reality it passes unconditionally. If the rest of the soak suite ever stops importing, CI still sees "no silent drops: PASS."
Fix: Delete it, or replace with an assertion that scans `transfer_diagnostics` / message_log for any `degradation_events` ring entries across the whole session.

**2. CRITICAL — `tests/unit/test_daemon_phase_d_wiring.py:22-53`**
What: `test_pick_best_relay_*` and `test_relay_metrics_for_returns_none_by_default` invoke `Daemon._pick_best_relay(object(), ...)` — unbound method with a bare object as self.
Why: Tests the helper's identity branch but bypasses every attribute the production caller relies on (`self._relay_metrics`, `self._rendezvous_url`). A bug where the real Daemon never wires `_relay_metrics` would still pass. Memory note `one_link_v021_alpha_batch2.md` says EWMA surface was just wired in — that wiring is uncovered.
Fix: Build a minimal Daemon instance (or `SimpleNamespace` with the real attribute names) so the helper exercises `self.*` access.

**3. CRITICAL — `tests/unit/test_native_transfer_cutover.py:299-339` (`test_env_flag_*`)**
What: Three "env flag" tests set `ONE_LINK_NATIVE_TRANSFER` then read `os.environ.get(...)` directly and assert the result.
Why: They never call `daemon.send_file` or any code that consults the flag. They're testing `dict.get`. The autonomous-agent half-commit gotcha that you logged (May 2026) is exactly this shape — capability advertised, never imported.
Fix: Patch the daemon's `send_file` call site to record which path it took, then assert that path matches the env value.

**4. CRITICAL — `tests/test_quic_daemon_dial.py:266-305`**
What: Only test asserting `degradation_events` ring is empty after a clean transfer; error message references stale `NATIVE_TRANSFER_V1` capability name.
Why: `unit/test_native_transfer_cutover.py:43` proves `NATIVE_TRANSFER_V1 not in LOCAL_CAPABILITIES` — only `NATIVE_TRANSFER_INDEXED_V1` is advertised. So this test now reasons about a capability that's never sent. If the indexed path silently degrades, this test would not catch the fallback because the precondition ("peer advertised V1") no longer holds.
Fix: Re-derive the precondition against `NATIVE_TRANSFER_INDEXED_V1` and add the symmetric assertion to `test_soak_large_file_round_trip`, `test_soak_small_file_round_trip`, all `daemon_pair` file transfer tests.

**5. HIGH — `tests/test_quic_daemon_dial.py:73-91` (`test_daemon_brings_up_quic_endpoint`)**
What: Test sets up a daemon pair, sends a probe, then comments "the status endpoint may or may not surface the QUIC port — what matters here is the daemon didn't crash." No assertion on the QUIC bring-up.
Why: This is the canonical "imports a module + asserts nothing meaningful" smoke test. If QUIC bring-up silently fails, this test passes; the actual gate happens in `_wait_for_quic_peer_port` which is opt-in to the next test.
Fix: Assert `a_status["native_status"]["quic_transport"]["available"] is True` and `local_port > 0` (data is already in the status payload).

**6. HIGH — `tests/test_concurrent_control.py:148`**
What: `pytest.skip("QUIC port advertisement didn't land in time")` on the only concurrent QUIC ping test.
Why: This is the "skip masks a real bug" pattern. If QUIC announcement is flaky under load, the test silently no-ops instead of failing. The whole point of a concurrent-ping test is to surface load-induced bugs.
Fix: Promote the skip to `pytest.fail(...)`. If it's flaky, fix the underlying race; if not, the skip is dead code.

**7. HIGH — `tests/test_audit_100pct_closeout.py:111-158` (I6 tests)**
What: `test_i6_first_attest_recorded`, `test_i6_monotonic_advance_accepted`, `test_i6_clock_skew_tolerance`, `test_i6_regression_flagged_as_fork` — all simulate the production update logic inline (`mgr._master_vk_last_issued_unix[vk] = max(prev, new_issued)`), then assert the dict contents.
Why: They test that Python `dict[]` assignment and `max()` work. If the production code in `_handle_attest_response` never calls the update at all (broken wiring), all four tests still pass.
Fix: Drive `_handle_attest_response(_fake_doc(...))` directly and assert on `mgr._master_vk_last_issued_unix` afterward.

**8. HIGH — `tests/test_audit_100pct_closeout.py:38-90` (I4 replay-cache)**
What: I4 replay-cache tests use `_FakeDaemon: pass` (a totally empty class) as the daemon argument.
Why: `BrowserPeerManager(_FakeDaemon())` will only construct if the manager doesn't touch the daemon during init. The cache test then exercises just the local dict. The real bug surface — "what if `_handle_attest_response` forgets to call `_attestation_replay_check_and_record`?" — is never exercised.
Fix: Pair the manager-level test with one that posts a duplicate attestation doc end-to-end via `_handle_attest_response`.

**9. HIGH — `tests/test_browser_peer_messages_v0192.py:56-92` (and 4 sibling browser-peer tests)**
What: ~80 tests across 5 files do `assert 'MSG_PROTOCOL_VERSION = "OL-MSG-1"' in peer_html` — literal substring match against `peer.html` source.
Why: They pass iff the literal string is present in the HTML source. They will NOT catch: (a) the JS function declared but never called, (b) any runtime error inside the function, (c) a renaming refactor that's correct but doesn't match the literal. Compare with the corruption pattern you logged: agent introduces NameError, tests still pass because they only grep source.
Fix: Run the relevant JS through Node (already done for some `test_call_ui_media.py` cases) or move to a headless-browser smoke that actually instantiates the IndexedDB store.

**10. HIGH — `tests/test_one_setup_v0220.py:24-32` (`test_setup_api_routes_exist`)**
What: Asserts `'r.add_get("/api/setup", self._guarded(self.api_setup_status))' in server.py source`. Eleven similar substring checks across this file.
Why: Pure-text grep over Python source. A typo in the route handler body, a missing `await`, or a route returning a stale snapshot all pass. Pairs with `tests/test_one_health_center_v0221.py` (same pattern). Memory says these are post-v0.22 surfaces.
Fix: Hit the routes via the aiohttp test client and assert response shape.

**11. HIGH — `tests/test_quic_daemon_dial.py:34-46` (`_quic_connection_alive`)**
What: `NativeConnLike` with hand-rolled `send_frame_round_trip` returning a hardcoded `(241, b"pong")`. Production `ChannelTransport` may use a different code or a different attribute name; the mock locks in nothing.
Why: Mock-shaped tests for `_quic_connection_alive` will pass for any predicate that says "if it has send_frame_round_trip → True". If the real check ever requires more (e.g. session-state, _dr_shared), this test still passes. Compounds with the DR-wipe / QUIC fast-path memory note.
Fix: Replace `NativeConnLike` with a real native QUIC connection object from `one_link_native.quic` (already required by the module skip).

**12. MEDIUM — `tests/test_two_device_soak.py:97, 114, 152, 206, 227, 331, 357` etc.**
What: 9+ `time.sleep(N)` calls in soak tests with N in [1.5, 5.0]s as the sole synchronization between send and assert.
Why: Under suite-level load, a 1.5s window is the race between "fast" and "slow" CI runners. Memory note `feedback_better_or_dont_ship` says regressions slow the system — sleep-based tests will start losing under hot-path slowdowns, exactly the regression you want to catch.
Fix: Replace with bounded polling on `message_log` / `inbox_files` (the `_wait_for_inbound` helper is already used elsewhere in the file).

**13. MEDIUM — `tests/test_two_device_soak.py:153-160, 207-211` etc.**
What: Multiple soak tests collect inbound bodies into a `set` then check via set difference.
Why: A set discards duplicates. If the protocol delivers `a-msg-005` twice and drops `a-msg-006`, the set diff says "missing 006" but you've lost the duplicate-delivery signal. Native Sphinx + folder-CRDT layers are exactly where double-delivery can sneak in.
Fix: Use `Counter` or sorted-list comparison so both missing AND duplicate bodies surface.

**14. MEDIUM — `tests/test_lifecycle.py:354-387` and `tests/unit/test_bandit_route_selector_migration.py:103-174`**
What: Mutate `os.environ` directly without `monkeypatch`, with manual `pop`/restore in a `try/finally`.
Why: If the body raises inside an `assert` (which is the whole point of a test), the `finally` does restore — but if an `os.environ.pop("...", None)` is called on a key that another concurrent test has already swapped, you've leaked test ordering into the global. Pytest-xdist will surface this as flakiness on unrelated tests.
Fix: Use `monkeypatch.setenv` / `monkeypatch.delenv` — automatic cleanup, no ordering risk.

**15. MEDIUM — `tests/test_resilience.py:212, 217` (`test_two_daemons_in_same_home_second_fails_gracefully`)**
What: Spawns daemon p1, `time.sleep(2.0)`, spawns p2, `time.sleep(2.0)`, asserts `p2.poll() is not None`.
Why: On a slow CI, 2s may not be enough for the instance-lock contention to resolve, so p2 might still be alive when polled — false fail. On a fast CI, p1 might not yet hold the lock at 2s — p2 succeeds and the duplicate-daemon bug regresses silently.
Fix: Replace fixed sleeps with bounded polling on the instance-lock file / a "ready" sentinel, then assert.

**Cross-cutting recommendations:**

- The `degradation_events` ring is checked in exactly **one** test (`tests/test_quic_daemon_dial.py:295`), and that test is tagged `@pytest.mark.soak` so it may not run in fast CI. Every `daemon_pair`-style test that exercises send / send_file / quic_ping should also assert `not degradation_events` — that's the single best regression net for the cascading-NULL and DR-wipe class of bugs (memory: `efd75fc6`, `6c48f047`, `dd937273`, `519a42e1`, `one_link_dr_bootstrap_wipe_gotcha.md`).
- `NATIVE_TRANSFER_V1` is dead capability text in the suite — the only live cap is `NATIVE_TRANSFER_INDEXED_V1`. Audit all 3 files that mention V1.
- No `@pytest.mark.xfail` found in tree (clean).
- No syntax errors in any test file (AST-parse clean).
- ~67 tests across 20 files grep HTML/source strings instead of executing — the dominant "looks-like-coverage" pattern in the suite.