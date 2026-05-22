Perfect! Now I have all the information I need. Let me compile my findings.

## Summary Report: QUIC File Chunk Transport Status

**All searches conducted in:** `C:\Users\Josh\Projects\Coherence\One_link\`

---

### 1. **`peer_quic.py` Module** ✓ EXISTS
**File:** `src/one_link/peer_quic.py`

The module **does exist** and exposes:
- `QuicPeerSession` class wrapping per-peer QUIC connections
- `make_endpoint()` — builds a QUIC endpoint (currently **stubbed to return None**)
- `open_outbound()` — dials a remote peer over QUIC
- `should_prefer_quic_for_peer()` — capability negotiation logic
- Exports frame constants: `FRAME_CHUNK_REQUEST`, `FRAME_CHUNK_RESPONSE`, etc. (lines 60-69)
- Advertises `QUIC_TRANSPORT_V1` capability for peer negotiation

**Per-peer manager:** `QuicPeerSession` exists (line 139) but is **never instantiated** because `make_endpoint()` always returns `None` (line 136).

---

### 2. **Wire Frame Definitions** ✓ FOUND
**Files:** `src/one_link/peer_quic.py:60-69`, `src/one_link/quic_native.py:67-84`

- `FRAME_CHUNK_REQUEST` and `FRAME_CHUNK_RESPONSE` are **re-exported from `one_link_native.quic`** (the Rust binding)
- These are for **QUIC stream framing**, not WebRTC
- Frame types defined in the Rust crate (`ol_quic`)
- Additional frames: `FRAME_MANIFEST_SYNC`, `FRAME_BLOOM_FILTER`, `FRAME_MISSING_CHUNKS`, etc.

---

### 3. **`daemon.py` QUIC Integration** ✓ PARTIAL
**Key locations:**
- `QUIC_TRANSPORT_V1` cap **is advertised** in `LOCAL_CAPABILITIES` (capabilities.py:115)
- `transport_choice_for_peer()` method exists (line 8861) and returns `"quic"` or `"webrtc"`
- Daemon checks if peer has the cap and endpoint is up; falls back to WebRTC otherwise
- `_ensure_quic_endpoint()` lazily initializes the endpoint (line 8843)

**Critical issue:** `make_endpoint()` is **stubbed** (peer_quic.py:136):
```python
# Identity bridge NOT YET IMPLEMENTED
# Endpoint.server() requires identity + is_paired_callback
# "the endpoint stays unbuilt at startup until the Identity bridge ships"
return None
```

**Result:** **No daemon ever actually opens a QUIC endpoint.** `transport_choice_for_peer()` always falls back to WebRTC because `_ensure_quic_endpoint()` always returns `None`.

---

### 4. **`one_link_native.quic` Connection Methods** ✓ FULL INVENTORY

**File:** `src/one_link/quic_native.py:252-401`

Exposed methods:
- ✓ `send_frame_round_trip()` — single request/response
- ✓ `send_frame_round_trips()` — batch sequential
- ✓ `send_frame_round_trips_parallel()` — batch parallel with `max_in_flight`
- ✓ `send_frame_stream_round_trips()` — **bulk stream** (many frames on one bidirectional stream — the fast path)
- ✓ `send_frame_stream_round_trips_parallel()` — bulk stream with parallel lanes
- ✓ `send_frame_stream_round_trips_count()` — bulk stream with response verification and byte counting
- ✓ `send_frame_stream_round_trips_count_parallel()` — parallel variant

**Note:** `send_frame_stream_round_trips_count()` exists (line 335) — the method name you asked about is there, ready for chunk batching.

---

### 5. **Capability + Transport Selection in `send_file`** ✗ NOT WIRED
**File:** `src/one_link/daemon.py:12998+`

- `transport_choice_for_peer()` **is defined** but **never called** in the send_file path
- `send_file()` always routes through `channel` (the WebRTC/encrypted session), line 13136
- `FILE_NATIVE_CHUNK` messages (line 13967) are encoded and queued to the WebRTC channel via `_queue_or_send(channel, ...)` (line 13978)
- **No branching logic** on `QUIC_TRANSPORT_V1` exists in the data path

The capability is **advertised-not-used** — it gates negotiation (peer discovery) but not actual file routing.

---

### 6. **NAT Traversal** ✗ NOT IMPLEMENTED
**Searches:** No references to STUN, TURN, hole-punching, or NAT traversal in peer_quic.py or quic_native.py

The `ol_quic` crate docs show client/server with `connect_blocking(addr, fingerprint)` — **direct IP dial only**. No rendezvous or address exchange for P2P QUIC. Browser-as-peer paths (where rendezvous would apply) stay on WebRTC anyway.

**Current state:** QUIC would require **out-of-band address delivery** (same as WebRTC signaling) or mDNS on the same LAN. **Not yet wired.**

---

### 7. **End-to-End Tests** ✗ ZERO
**Searches:** 
- `test_quic_native_v0210.py` — unit tests of low-level `one_link_native.quic` bindings (loopback, ping/pong, frame types) — **NOT** daemon-level
- `test_quic_batch_bridge.py` and `test_quic_dual_stack_wiring.py` — unit tests of capability negotiation logic, `should_prefer_quic_for_peer()` predicate
- `test_daemon_pair_quic_transport_capability_advertised_in_status` — only checks that the cap **appears in status**, not that it's used

**No tests** exercise end-to-end file transfer between two daemons via QUIC.

---

## Verdict: Effort Estimate

**Status:** QUIC transport is **scaffolding, not shipped.**

| Work | Status | Effort |
|------|--------|--------|
| Wire frame constants | Done | — |
| Capability advertisement | Done | — |
| Transport selector logic | Done | — |
| Native QUIC bindings (Connection methods) | Done | — |
| **Identity bridge + endpoint init** | **Stubbed** | **2–3 days** |
| **Route chunks through QUIC in send_file** | **Not started** | **1 day** |
| **Inbound QUIC chunk service** | **Not started** | **1 day** |
| **Rendezvous address exchange** | **Not started** | **2–3 days** |
| **E2E daemon pair tests** | **Zero** | **1 day** |

**To ship QUIC as default for file chunks: ~7–10 days of focused work**, with the identity bridge and chunk routing being the critical path. The native Rust crate is solid; the daemon plumbing is missing.

Per `PHASE_A2_QUIC_CUTOVER_PLAN.md`: **deliberately deferred** pending production soak on WebRTC + real hardware (cellular handoff, LAN throughput verification).