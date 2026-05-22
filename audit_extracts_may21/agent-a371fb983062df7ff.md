I have everything I need. Now I will produce the final detailed audit report.

---

# Coherence Mesh Integration Audit — `One_link/src/one_link/daemon.py`

File path: `c:\Users\Josh\Projects\Coherence\One_link\src\one_link\daemon.py` (17,917 lines)

Already-imported substrate (lines 74, 9219, 10219, 10245, 9248):
- `one_link_native.prefetch.Predictor` (TYPE_CHECKING)
- `one_link.routing_native as _rt` (HAS_NATIVE / `edge_weight` / `edge_cost`)
- `one_link.coherence_field_native as _cf` (HAS_NATIVE / `be_rar`)
- `one_link.prefetch_native` (HAS_NATIVE / `predictor()`)

Phase D + E hooks already exist in two narrow places. Everything below extends that pattern.

---

## 1. Selector hook (CDC vs stream vs QUIC fork)

**Module-level decision helper:** `_should_build_cdc_offer` at **line 367–392**. Returns `(bool, reason)` from `intent.can_offer_cdc`, file size, `CDC_AUTO_INDEX_MAX_BYTES`, and `native_cdc_status()`.

**Hot call site inside `send_file`:** **line 14004–14029**. The flow is:
1. Build `intent = plan_transfer_intent_for_manifest(...)` (14004).
2. Call `_should_build_cdc_offer(...)` (14004–14008) → `can_offer_cdc`.
3. **Hardcoded QUIC override** at **14020–14029** (`QUIC_SMALL_FILE_THRESHOLD = 512 * 1024`): if file ≤512 KiB AND peer has `NATIVE_TRANSFER_V1` AND `self._quic_peer_ports.get(peer_fp)` is set, flip `can_offer_cdc = False` and tag reason `quic_small_file_fast_path`.
4. `planned_wire_mode = "cdc" if can_offer_cdc else "stream"` at **14076**.

Then a **second selector layer** exists at **14117–14160**: `UniversalCommsFabric.from_inventory_and_candidates(...)` builds a `fabric_decision`, **but** its decision is recorded into `base_metadata["fabric_plan"]` (14211) and feeds `route_observations` — it does NOT override `can_offer_cdc` or `planned_wire_mode`.

The actual three-way fork lands at **14438**: `cdc_used = can_offer_cdc and first_reply.get("t") == "FILE_WANTS"` decides CDC vs baseline AFTER the offer round-trip. The QUIC-CDC sub-fork (`cdc_quic_eligible`) lives at **14602–14606** inside the CDC branch.

**Where `ol_selector` would slot in:** replace the manual ladder at **14020–14080** with a single call returning `(wire_mode, transport_kind, reason)`. Concretely:
- Delete the `QUIC_SMALL_FILE_THRESHOLD` override (14020–14029).
- Replace the `planned_wire_mode = "cdc" if can_offer_cdc else "stream"` at 14076 with `mode_decision = ol_selector.decide(size=size, peer_caps=peer_features, fabric=fabric_plan, brain=transfer_brain_decision, field=field_state)`.
- The second QUIC override at **14602–14606** (CDC-over-QUIC eligibility) becomes redundant.

Existing dependency that already points there: `transfer_brain.decision_from_observations(...)` at **14161–14174** already produces a unified decision dict — `ol_selector` is the natural fusion of `_should_build_cdc_offer` + the QUIC override + `UniversalCommsFabric.plan(...)` + `decision_from_observations(...)`.

---

## 2. Field-state read+write hooks

**No shared field store exists.** All state lives in per-peer dicts and ephemeral oracles:
- `self._chunk_holders` (registered at 9232, capped) — peer-set co-hold registry.
- `self._route_memory` dict, walked at **11437** (`_route_memory_for`).
- `self._relay_metrics` (EWMA dict), recorded at **10307** (`record_relay_observation`).
- `self._prefetch_predictor` (native), observed at **9268**.

**Write candidates** (peer observations that would update a field):
- Every `_update_transfer(...)` call (50+ sites; canonical helper at **3367–3376**) — the natural broadcast hook because every transfer state change funnels through here.
- `_observe_prefetch(peer_fp, blob_hex)` at **9213–9270** — already the cohold-registry write site (9229–9246). Mirror this for field state.
- `record_relay_observation(url, rtt_ms=, success=)` at **10307–...** — EWMA RTT+loss writer.
- `_handle_file_native_chunk` at **7289** — receiver-side chunk arrival, perfect peer observation point.

**Read candidates** (where selector/router could consume field):
- `_pick_best_relay` at **10198–10292** — already opens `from one_link import coherence_field_native as _cf` at 10245 and uses `_cf.be_rar(...)` at 10286. The pattern is established.
- `_mesh_node_signals(peer_fp, chunk_hit_rate=...)` at **11579** — called at 14134 and 14168 inside `send_file`; this is the natural place for `field.read(peer_fp)` to inject field-derived priors.
- `decision_from_observations(...)` at **14161** — accepts `observations` + `mesh_nodes`; injecting field-state-derived MeshNodeSignal entries lights up the transfer brain.

**What would land:** a `self._field_state` attribute initialized next to `self._chunk_holders` (around **line 1267–1349** where the prefetch/predictor state lives). One write per `_update_transfer` (3372) + per `_observe_prefetch` (9268) + per `record_relay_observation`. One read inside `_mesh_node_signals` (11579) and inside `_pick_best_relay`'s scoring loop (10250–10290) replacing the current single-scalar `be_rar` boost.

---

## 3. Radio-batcher hook (presence + sensor + background sync)

**Send queues currently used for low-priority traffic:**
- `broadcast_endpoint_to_paired()` at **12069–12152** — iterates `self.state.list_peers()`, builds `ENDPOINT_UPDATE` per peer (12127–12131), sends with a **10s per-peer timeout** at 12137–12140. This is a per-peer fan-out, NOT a batched broadcast.
- `broadcast_endpoint_to_paired_if_changed()` at **12163–12183** — wraps the above with a signature check.

**Periodic background loops** (radio-batcher candidates):
- `_prune_loop` at **16964–16986** (every 20s) — already runs `broadcast_endpoint_to_paired_if_changed()` at 16984, `_reap_stuck_transfers()` at 16980, `_schedule_due_transfer_retries()` at 16982, `_prune_chunk_cache()` at 16972, `discovery.prune_unreachable(...)` at 16968. **This is the single best place for a radio-batcher tick.**
- `_folder_sync_loop` at **17190–17201** (every 30s after 8s settle) — folder manifest push.
- `_immune_tick_loop` (started 17003) — 100ms cadence per the comment at 16990.
- `_dm_reaper_loop` at line **1879** (started 17059) — disappearing-message reaper.
- `_prior_index_loop` at **6334–6350** (every PRIOR_INDEX_INTERVAL_S = 120s) — local prior indexer.

**Startup detached task** at **17009–17026**: `_delayed_announcement` sleeps 2s then fires `broadcast_endpoint_to_paired()`.

**Where `ol_radio_batcher` would slot in:**
- The per-peer `asyncio.wait_for(self.send_to(peer_obj, [outer]), timeout=10.0)` at **12137–12140** is the natural batch boundary — replace with `radio.enqueue(peer_fp, outer, priority="presence")` and drain on a separate `_radio_drain_loop` task.
- The 20s `_prune_loop` tick at **16964** is where the batched drain (sensor + presence) belongs alongside `broadcast_endpoint_to_paired_if_changed` (16984).
- The control-plane `_schedule_resume_paused` fire-and-forget at **13555** (`loop.create_task(self._resume_paused_swallow(...))`) is a low-priority candidate for opportunistic batching.

---

## 4. CRDT op-graph hook for file_sync

**Folder sync entry points:**
- `_handle_manifest_push` at **8184–8257** — receives a remote manifest, computes wants via `self.folder_engine.receive_remote_manifest(...)` at 8236, replies `MANIFEST_WANTS` at 8252 with `merkle_root` (8254).
- `_handle_manifest_wants` at **8259+` — emits BLOB_OFFER/BLOB_CHUNK frames.
- `push_folder_to_peer` at **13603–13631+** — outbound side: MANIFEST_PUSH → MANIFEST_WANTS → BLOB_OFFER+BLOB_CHUNK per blob.
- `_folder_sync_loop` at **17190** drives it.

**Bytes-vs-delta decision currently:** there is none. The wire is always full-blob (BLOB_OFFER + BLOB_CHUNK). CDC dedup happens at **chunk** granularity inside `send_file`'s CDC mode (FILE_OFFER carries `chunks=[...]` at 14250–14251), and the receiver dedups via `_available_chunk_hashes` at **4231–4239** in the FILE_OFFER handler.

**File-OFFER receiver:** the FILE_OFFER branch starts at **line 4161** in `_on_peer_message`. Capability gate at 4162. Chunk-map normalization at 4211–4225. CDC dedup at 4226–4240. `evaluate_transfer_admission(...)` at 4241. The hooks for op-graph would land at **4230 (right before `_available_chunk_hashes`)** and at **8236 (right where `receive_remote_manifest` is called)**.

**FILE_NATIVE_CHUNK handler** at **7289** (called from 4664): the native_transfer fast-path. The cohold-registry write at `_observe_prefetch` (9213) fires from 4657 (`self._observe_prefetch(peer_fp, f.blob_hex)`).

**Where `ol_op_graph` would slot in:**
- Replace `foldersync.FolderEngine.receive_remote_manifest(...)` at **8236** with an op-graph merge — the wire message would carry CRDT ops instead of a full manifest, and the merge replies with want-set.
- The folder-engine instantiation at **17036–17042** is where the op-graph backend swap happens.
- The bytes-vs-delta selector belongs at the **FILE_OFFER receive at 4226–4240** (sender already advertised cdc_chunks; receiver decides per-chunk what to want). For folder sync, the equivalent is **MANIFEST_PUSH at 8184–8222** (receiver decides what to want from the merkle-root diff).

---

## 5. Cap-bound check hook

**Central predicate:** `_capability_allowed(peer_fp, cap, scope=b"")` at **10457–10537**. Already does:
- Seed-tamper gate at 10483–10495.
- Signed-grant lookup via `self._cap_store.has_capability` at 10503–10533.
- Delegation chain walk via `_cap_authorized_via_chain` (10539+) with `max_depth=2`.
- Policy fallback via `self.state.get_peer_capability_policy(peer_fp)` at 10536.

**Call sites on the transfer hot path:**
- `send_file` entry at **13812**: `if peer_fp_for_policy and not self._capability_allowed(peer_fp_for_policy, FILES)`.
- FILE_OFFER receiver at **4162** (FILES) — pre-allocation gate.
- Mid-stream re-check inside the CDC branch at **14696–14698** (FILES per chunk — "Audit M13" comment at 14688–14695). Same re-check happens around line **15173** for the stream branch (per the earlier grep).
- Folder sync gates at **5057–5086** (FOLDER_SYNC) and **8199** (`_handle_manifest_push`'s `folder_capability` check, which is a separate folder-scoped helper).
- `push_folder_to_peer` outbound gate at **13622**.

**Where `ol_cap` (coherence-bound) would slot in:**
- The `_capability_allowed` body itself at **10457–10537** is the single chokepoint — adding a `coherence_bound=True` branch here covers every call site.
- The mid-stream re-check at **14696–14698** is the natural place for `field_state.is_bound(peer_fp, cap, scope=blob_hex)` because the field measurement and the chunk-emission decision are co-located.
- `_cap_store` is initialized somewhere around line 1305 (per the comment grep "_cap_store; subsequent _capability_allowed checks" at 3973). Cap rotation logic if any is in `cap_store` module, not here.

---

## 6. τ-routing hook

**Already partially wired:** `_pick_best_relay` at **10198–10292** is the canonical example. It:
- Imports `routing_native as _rt` at 10219, gates on `_rt.HAS_NATIVE`.
- Imports `coherence_field_native as _cf` at 10245, gates on `_cf.HAS_NATIVE`.
- Computes `tau_c_s = max(1.0e-3, 1.0 / rtt_ms)` at 10260.
- Calls `_rt.edge_weight(tau_c_s, 100.0)` at 10281 OR `_rt.edge_cost(tau_c_s, 100.0, loss)` at 10289.

**Other path-selection sites NOT yet τ-routed:**
- `_resolve_peer_candidates` at **16144–16145** — just delegates to `self.discovery.registry.candidates(needle)`. No quality scoring.
- `resolve_for_send` at **16188+** — mDNS-first, rendezvous-fallback peer resolution.
- `transport_choice_for_peer` at **9630–9662** — picks QUIC vs WebRTC purely from capability advertisement, NO RTT/loss signal. This is the right place to consume τ-routing per peer.
- The fabric-plan probe at **14129–14139** in `send_file` builds `fabric_decision.observations` but feeds it back into `route_observations` (14148–14151) for the transfer brain — not into the transport pick.
- `_get_outbound_session` (called at 13882) — session dial.
- `_send_via_transport` at **9542–9608** — facade builder; consults `transport_choice_for_peer` at 9580.

**Per-peer route memory** at **11437** (`_route_memory_for`) — RouteMemory candidates feed the transfer brain at 14094–14096. The candidates already have `latency_ms`/`bandwidth_bps`/`successes`/`attempts` (visible at 6396–6400). These are τ-routing-ready.

**Where the next τ-hook lands:** `transport_choice_for_peer` at **9630** — extend with a τ_c read from `_route_memory_for(peer_fp).best()` plus relay metrics from `_relay_metrics_for`. Currently this function returns purely on capability presence (9658), which means a high-loss QUIC link will beat a clean WebRTC link.

---

## 7. Active-inference predictor hook (prefetch)

**Already present:**
- `_observe_prefetch(peer_fp, blob_hex)` at **9213–9270**: writes to native predictor at 9268.
- `predict_next_files_for_peer(peer_fp, n=3)` at **9272–9284**: reads top-N from `self._prefetch_predictor.predict_top_n(...)`.
- `_prefetch_predictor` initialized lazily at 9257–9258.
- Observation call sites: **4657** (receive-side FILE_NATIVE_CHUNK done), **15193** (per the grep — send-side).

**Resume / retry plumbing (where prediction-driven prefetch would fire):**
- `_schedule_resume_paused(peer_fp, force=)` at **13538–13555**: fire-and-forget task spawn (13555).
- `resume_paused_transfers_for(peer_fp, force=)` called at 13559.
- `_schedule_due_transfer_retries()` at **13563–13600**: scans `list_transfers(limit=500)` for `paused|queued` rows whose `next_retry_ms` has passed. Called from `_prune_loop` at 16982 and at boot at 17029.
- Trigger sites at **3487** (post first-send), **11092** (session re-up), **11185** (handshake complete), **15268+** (per the grep).

**Where the predictor hook lands:**
- Inside `_schedule_due_transfer_retries` at **13578–13599**: BEFORE the `for fp in peers: self._schedule_resume_paused(fp)` loop at 13598–13599, call `predict_next_files_for_peer(fp)` and **pre-warm** the CDC index for predicted files (warm `_record_file_index_cache`, the helper already used in send_file at 14034–14054).
- Alternative: a new periodic loop next to `_prior_index_loop` at **17060** that walks predicted (peer, file) pairs from `predict_next_files_for_peer` and submits speculative `send_file` calls (or speculative CDC indexing).
- The `_observe_prefetch` calls at 4657 and 15193 are the write sites — already correct. No change needed.

**`predict_next_files_for_peer`** is currently READ ONLY from `/api/status` (per the snapshot block at 9320–9371). No one in the daemon consumes it for scheduling yet. That's the gap.

---

## 8. Time-mode integration (background work scheduling)

**All long-running scheduled tasks** (cross-reference of `create_task` + `while True`):

| Loop | Start line | Period | Function |
|------|-----------|--------|----------|
| `_prune_loop` | 16988 (def 16964) | 20s | discovery prune, chunk-cache prune, transfer-watchdog, transfer-retry pump, endpoint-broadcast |
| `_immune_tick_loop` | 17003 (def 1821) | 100ms | call-immune system |
| `_folder_sync_loop` | 17050 (def 17190) | 30s | folder MANIFEST_PUSH fan-out |
| `_dm_reaper_loop` | 17059 (def 1879) | 30s | disappearing-message TTL |
| `_prior_index_loop` | 17060 (def 6334) | PRIOR_INDEX_INTERVAL_S = 120s | local prior-source indexing |
| update-check (opt-in) | 17062+ | 6h | GitHub Releases poll |
| `_delayed_announcement` | 17026 | one-shot after 2s | endpoint broadcast |
| `_schedule_due_transfer_retries` | 17029 + 16982 | event-driven | transfer-retry pump |

**Low-priority queues / fire-and-forget patterns:**
- `loop.create_task(self._flush_outbox_swallow(peer_fp))` at **13410**.
- `loop.create_task(self._resume_paused_swallow(peer_fp, force=force))` at **13555**.
- `asyncio.create_task(_delayed_announcement())` at **17026**.

**Where time-mode (ol_timing) would slot in:** the single `_prune_loop` at **16964–16986** is the canonical "operator tick" — every Coherence Mesh background concern already lives there or is one `with contextlib.suppress(Exception): ...` line away. Adding `radio_batcher.drain()`, `field_state.diffuse_tick()`, and `predictor.step()` to the 20s tick is the minimum viable wiring; finer-grained cadence work belongs in dedicated co-tasks following the `_immune_tick_loop` pattern (def at 1821, 100ms cadence).

---

## Summary cross-reference

The cleanest single-shot integration would land:
- `ol_selector` at **lines 14020–14080** of `send_file` (replacing both the hardcoded `QUIC_SMALL_FILE_THRESHOLD` and the `planned_wire_mode = "cdc" if ...` ternary), reading from a new `self._field_state` instance.
- `ol_field` writes piggybacked on `_update_transfer` at **3372**, `_observe_prefetch` at **9268**, and `record_relay_observation` at **10307+**; reads injected into `_mesh_node_signals` at **11579** and into `_pick_best_relay` at **10250–10290**.
- `ol_radio_batcher` enqueue at **12137–12140** (per-peer `send_to`) with drain on the **16964** prune-loop tick.
- `ol_op_graph` swap inside `_handle_manifest_push` at **8236** (`receive_remote_manifest` call) and FILE_OFFER receiver at **4226–4240**.
- `ol_cap` coherence-bound branch added inside `_capability_allowed` at **10457–10537**, transparent to all 17 call sites.
- `ol_tau_routing` added to `transport_choice_for_peer` at **9630** (currently capability-only) to complement the relay τ-sort at 10198.
- Active-inference scheduler hook at **13578–13599** in `_schedule_due_transfer_retries` (pre-warm via `predict_next_files_for_peer` already at 9272).
- All of the above batched on the `_prune_loop` at **16988** (20s cadence).

Native crates **already imported** in this file: `routing_native` (9377, 10219), `coherence_field_native` (10245), `prefetch_native` (9248), `peer_quic` (9642). The pattern for `_selector` / `_field` / `_radio_batcher` / `_op_graph` / `_cap` would mirror these (lazy import, `HAS_NATIVE` gate, swallow exceptions, fall back to existing Python).