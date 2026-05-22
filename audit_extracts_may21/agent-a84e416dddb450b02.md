Now I have enough material. Let me write up the findings.

# One Link transport-layer deep audit — top 15 bugs

## 1. **Inbound QUIC accept loop spins forever after endpoint close** — HIGH
**File:** `daemon.py:20856-20868` (`_quic_accept_loop`)
**What:** When `stop()` closes `_quic_server_endpoint` (line 21100), the in-flight `accept_blocking(5000)` raises. The `except Exception` branch logs and `await asyncio.sleep(0.5); continue`s the loop forever. Only `CancelledError` exits.
**Why:** `stop()` does cancel `_quic_accept_task` first (21086-21092), but if endpoint dies any other way (rebind path at 20094-20121 replaces it without cancelling the old task on a non-`same_port` failure path; `same_port_endpoint.close()` at 20120 with the old task still using it) the loop spins burning a thread per 0.5s.
**Fix:** Track endpoint identity per-iteration; bail when `self._quic_server_endpoint is not endpoint`.

## 2. **QUIC same-port rebind leaks the prior accept task on cancel** — HIGH
**File:** `daemon.py:20114-20118`
**What:** `self._quic_accept_task.cancel()` is called but never `await`ed before reassignment. The old task is still using the closed `old_endpoint`.
**Why:** Without awaiting, the cancel happens-after the new task starts; the old task's `accept_blocking` may already be unblocked with `conn != None`, ending up calling `_quic_inbound_frame_loop` against a closed endpoint and racing the new accept loop.
**Fix:** `await self._quic_accept_task` (with timeout) before assigning the new one.

## 3. **`_quic_outbound` entries replaced silently without close** — HIGH
**File:** `daemon.py:20827`
**What:** `self._quic_outbound[peer_fp] = conn` — if another path inserts under the dial lock's tiny window (e.g. inbound `_quic_inbound` mirroring, or a stale "alive" check that races), the prior `Connection` is overwritten without `.close()`. Same pattern in `_quic_inbound` at 20904 (line 20902 *does* close prior, good); but `send_chunk_via_quic`'s `pop` on failure (20680/20613/20731) drops a connection that may still be live elsewhere because `_quic_inbound` holds an *independent* handle bound to the same peer fp — close of outbound doesn't tear inbound, so the next ping looks healthy but the new outbound dials.
**Fix:** Always `close()` before overwrite; treat inbound+outbound as paired for tear-down.

## 4. **Inbound frame loop's `recv_frame_blocking` returning None is misinterpreted** — HIGH
**File:** `daemon.py:20952-20956`
**What:** Comment says "30 s with no frames — peer's still connected (otherwise the recv would have raised), just idle." But the native API's `recv_frame_blocking(timeout_ms)` returning None is the *timeout* signal; a closed remote raises. If the native crate returns None on connection close (common pattern), the loop `continue`s forever holding a dead `Connection`, never falling through to the `finally:` that clears `_quic_inbound[peer_fp]`. The cached entry then poisons the next `_get_or_dial_quic` path that consults inbound for synth channels.
**Fix:** Probe `conn.is_connected()` (or `remote_address`) inside the None branch.

## 5. **`_quic_recent_paired` FIFO race assigns wrong peer_fp to inbound conn** — CRITICAL
**File:** `daemon.py:20886-20908`
**What:** The is_paired callback fires on the native crate's pre-handshake thread; the accept loop pops the *front* of the deque. Two simultaneous handshakes (peer A and peer B both dial during the 5s window) can resolve in any order on the native side, so `accept_blocking` may return B's Connection while the front of the deque is A's fp.
**Why:** Comment claims "leftmost deque entry corresponds to this connection's handshake" but the native crate gives no ordering guarantee between `is_paired` invocations and `accept` returns under concurrent dials. Peer A's outbound chunk frame would then be dispatched as if from peer B, gating against B's caps + B's transfer registry. Untrusted-content vector.
**Fix:** Native crate must surface the peer fp on the returned Connection; until then, the daemon must perform a post-accept TLS-fingerprint re-derive and refuse if it doesn't match the deque-popped fp.

## 6. **`_NoopChannel` exposes `peer_caps={}` to native-chunk handler** — HIGH
**File:** `daemon.py:21014`
**What:** `peer_caps: dict = {}` (class-level mutable default — also a bug; shared across all synth instances). `_handle_file_native_chunk` and `_handle_file_cdc_chunk` consult `channel.peer_caps` to validate the peer advertised `NATIVE_TRANSFER_INDEXED_V1`. Empty caps means the gate either silently passes (if it's a check for *absence* of a deny cap) or silently fails (if it requires presence). Recent fix wired native-session lookup but didn't proxy `peer_caps`.
**Fix:** Proxy `peer_caps`, `peer_ed_pub`, `peer_short_id` from `_real_channel` exactly like `get_or_create_native_transfer_session`.

## 7. **ENDPOINT_UPDATE host poisoning bypasses verification on the hot path** — HIGH
**File:** `daemon.py:14605-14619, 9753-9756`
**What:** `_handle_endpoint_update` stashes `_quic_peer_ports[peer_fp] = quic_port_raw` *immediately* on receipt from any pinned peer, before any verification. `_collect_dial_candidates` then uses `(peer.address, live_port_hint)` as the highest-priority candidate — but `peer.address` here is the *current* DB value, not the unverified hosts from `cleaned`. That's safe for host. **However**, `quic_port` is taken on trust: a compromised pinned peer (or replayed legitimate ENDPOINT_UPDATE) can redirect *our outbound QUIC dial* to any port, including a port on their machine they don't actually serve, breaking the QUIC fast path for that peer indefinitely.
**Fix:** Treat `quic_port` like the TCP candidates — schedule a verify dial; only stash on success.

## 8. **`_handle_endpoint_update` rejects unpinned but races pinning** — MED
**File:** `daemon.py:14574-14578`
**What:** `_is_pinned(peer_fp)` check happens after AEAD authenticated the sender, but the channel was opened pre-pinning. The frame is dropped silently. There's no "we received an ENDPOINT_UPDATE before we managed to mark you pinned" recovery — if the peer's first frame after pair-confirm is ENDPOINT_UPDATE (likely on Wi-Fi roam), it gets dropped and their QUIC port is lost until next CAPS exchange.
**Fix:** Defer to a short retry queue when the channel is authenticated but not-yet-pinned, OR have peer side resend ENDPOINT_UPDATE after first CAPS round-trip.

## 9. **Relay dial fallback ignores `direct_err`-aware degradation if `peer.address` is empty** — MED
**File:** `daemon.py:9938-9984`
**What:** `_collect_dial_candidates` returns `[]` when peer has no address/port. The `if candidates:` block is skipped, `direct_err` stays None, relay is taken silently with **no degradation event**. Operators lose visibility into peers that have completely lost direct addressing.
**Fix:** Record a `no_direct_candidates_relay_only` degradation event when relay wins with empty candidates.

## 10. **Rendezvous lookup `as_completed` leaks task results on early return** — MED
**File:** `rendezvous_client.py:242-252`
**What:** Returns the first non-None hit, then cancels remaining tasks in `finally`. But `asyncio.as_completed` awaits already-completed coroutines and the late winners may have already populated `LookupAck` objects; the cancel is best-effort. More importantly, the cancel doesn't `await` the cancelled tasks, so the aiohttp `async with session.get` exit-handlers can run after `session.close()` in shutdown races — surfaces as `Unclosed response`.
**Fix:** `await asyncio.gather(*pending, return_exceptions=True)` after cancel.

## 11. **DTLS fingerprint change "warn-don't-reject" undermines pubkey binding** — MED
**File:** `peer_rtc.py:1258-1268`
**What:** Returns `(fp, False)` on mismatch but caller (envelope path) uses this purely advisory. Comment claims envelope signature already binds SDP to Ed25519 pubkey, but that's only the **offer** envelope. After connection establishment, an attacker who can MITM the WebRTC DataChannel (rare on a properly-DTLS-keyed link, but possible if a downstream DTLS session is established to an attacker who shares the daemon's signing key path post-pair) can present a different cert; this surfaces as a warning, not a tear-down.
**Fix:** On mismatch for a previously-attested peer, call `_close_peer` AND clear `attested_ms`.

## 12. **`_NoopChannel` class-level mutable defaults shared across synths** — MED
**File:** `daemon.py:21014` (`peer_caps: dict = {}`)
**What:** Mutation of `synth_channel.peer_caps[...]` by a downstream handler bleeds across every QUIC inbound. Probably never written in practice (proxy is read-only) but it's a latent foot-gun.
**Fix:** Move to `__init__`, or use a property that proxies the real channel's caps dict.

## 13. **WebRTC `_close_peer` schedules `pc.close()` but never awaits, MediaStream tracks never explicitly stopped** — MED
**File:** `peer_rtc.py:543-555`
**What:** `loop.create_task(pc.close())` is fire-and-forget; on daemon shutdown the task may be cancelled before aiortc actually finishes ICE teardown. aiortc's `RTCPeerConnection.close` is responsible for stopping receivers/transceivers; if cancelled mid-flight, MediaStream tracks (if any are attached for v0.20.x audio/file paths) leak their underlying socket handles + threads.
**Fix:** Track the task in a set, await on `BrowserPeerManager.shutdown()`.

## 14. **QUIC send queue is unbounded via `send_chunk_via_quic` parallel gather** — MED
**File:** `daemon.py:17734-17742`
**What:** `asyncio.gather(*tasks, ...)` over the full `cdc_quic_batch` (currently 1, but `QUIC_CDC_BATCH_SIZE=1` is a magic number — easy to bump). If raised, every chunk in the batch dispatches simultaneously through `asyncio.to_thread` → blocks N native threads holding the GIL release lock. No backpressure on the QUIC send path beyond the per-call `wait_for(timeout=5.0)`. Under multi-GB transfers the to_thread pool saturates and other native calls (Sphinx peel, attestation) stall behind chunk sends.
**Fix:** Bounded `asyncio.Semaphore` around `to_thread(send_frame_round_trip)` per peer, or use a single-stream native `send_chunks_parallel` API.

## 15. **`_get_or_dial_quic` falls back to `peer.port` as QUIC port — wrong protocol** — MED
**File:** `daemon.py:20781`
**What:** `port = self._quic_peer_ports.get(peer_fp) or getattr(peer, "port", None)` — `peer.port` is the TCP peer-server port. Quinn will speak UDP to that port; the peer's TCP server gets QUIC handshake garbage (or the OS firewall drops it). On peers where TCP and UDP same-port bind succeeded this happens to work (the "self-healing" intent); on peers where it didn't, every QUIC dial under a missed ENDPOINT_UPDATE goes to the wrong port and the `connect_blocking(10000)` burns 10s before falling back to WebRTC.
**Fix:** Only fall back to `peer.port` when the local daemon successfully bound same-port; track per-peer `same_port_likely` rather than blanket fallback.

---

Key files referenced (all absolute):
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\daemon.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\peer_quic.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\peer_rtc.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\rendezvous_client.py`
- `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\rendezvous_server.py`

The accept-loop FIFO-binding bug (#5) is the most concerning: it's a cross-peer identity confusion that the existing `_is_pinned` gate doesn't catch. Find #4 (None vs close-on-recv) is the likely root cause of the "dead handles linger" symptom you observed.