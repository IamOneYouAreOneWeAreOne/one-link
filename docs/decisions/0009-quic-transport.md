# ADR-0009: QUIC Transport via quinn — Wire Framing, Multi-Stream, Connection Migration

**Status:** ACCEPTED (Phase A2 acceptance number — do not revisit without ADR amendment)
**Phase:** A2 (item #10: QUIC transport)
**Depends on:** ADR-0003 (chunk record format), ADR-0007 (WAL framing semantics)

> **Integration truth review (2026-07-24):** this ADR records the transport
> design decision, not proof that every listed property is active in the
> product. The current daemon runtime-gates identity-bound native QUIC file
> lanes after capability/ABI checks; it has not replaced the authenticated
> control/message channel or browser WebRTC. The 0-RTT and connection-migration
> statements below are design requirements until their named physical and
> packaged-runtime gates are archived.

---

## Context

The daemon↔daemon hot path in v0.20.x uses WebRTC DataChannel over DTLS-SRTP via `aiortc`. That stack works for browser-as-peer (Phase A1 leaves it in place there) but for daemon-to-daemon transfers it's the wrong tool:

1. **Throughput**: WebRTC DataChannel adds DTLS framing and SRTP-style overhead designed for media; throughput on LAN typically caps around 200-400 Mbps even when the underlying network can push 10× more.
2. **Stream multiplexing**: WebRTC has data channels but no first-class multi-stream-with-shared-congestion-control. Multiple in-flight transfers compete for one pipe.
3. **Connection migration**: WebRTC ICE doesn't migrate gracefully across cellular↔WiFi handoff; the connection drops and renegotiates.
4. **0-RTT resumption**: WebRTC always re-handshakes, costing ~150-300 ms even on a warm connection.
5. **Aiortc dependency**: Python implementation, not on the hot path's cycles/byte budget.

QUIC (RFC 9000-9002) was designed to fix all five of these for the HTTP/3 era. For our use case it gives us:
- Multi-stream within a single connection (each chunk transfer on its own stream, no head-of-line blocking).
- 0-RTT resumption via session tickets.
- Native connection migration on RFC 9002 — the "cellular handoff with zero application-visible drop" Phase A2 acceptance gate.
- TLS 1.3-bound identity (ADR-0010 makes this peer-identity-bound).
- BBR / NewReno / Cubic congestion control ports already shipping in production-grade Rust QUIC stacks.

## Decision

**Use `quinn` (the Rust QUIC implementation maintained by Cloudflare-ecosystem alums; used by Iroh, Veilid, sn-quic interop tests). Wrap it in our `ol_quic` crate with a frame-typed wire protocol per stream.**

### Library choice rationale

| Library | License | Why we're not using it |
|---|---|---|
| **quinn** (chosen) | Apache-2.0 / MIT | Pure Rust, runtime-agnostic at trait level (we use tokio underneath), strong ecosystem footprint |
| msquic | MIT | Microsoft-maintained — explicit sovereignty rejection per FILE_ENGINE_V2_PLAN.md defang table |
| s2n-quic | Apache-2.0 | AWS-maintained, fewer downstream consumers, smaller production surface; reasonable second choice if quinn ever falters |
| quiche | BSD-3 | Cloudflare-maintained, C-FFI-first; less idiomatic from Rust; lacks first-class multipath in stable releases |

quinn pulls a tokio dependency. We accept this — async I/O is necessary for QUIC, and tokio is the de-facto Rust async runtime.

### Wire framing inside QUIC streams

Each QUIC stream carries a single typed frame protocol. Frames are length-prefixed with a varint. Multiple frames per stream are NOT supported in v1 of the wire protocol — one stream per logical operation. This keeps the framing simple and gives every operation its own QUIC flow-control window.

Frame layout:

```
+-----------+--------------+----------- payload -----------+
| frame_kind| length       | <length bytes>                |
| u8        | varint LE    |                               |
+-----------+--------------+-------------------------------+
```

`frame_kind` values:

| Kind | Operation | Payload |
|---|---|---|
| 0x01 | `ChunkRequest` | 32-byte chunk_id |
| 0x02 | `ChunkResponse` | full chunk_log record (kind + flags + 80-byte chunk-record header + ciphertext) |
| 0x03 | `ChunkNotFound` | 32-byte chunk_id |
| 0x10 | `ManifestSync` | u64 hlc_lower_bound + u64 limit |
| 0x11 | `ManifestRecord` | full manifest_log record |
| 0x12 | `ManifestSyncEnd` | (empty; signals batch complete) |
| 0x20 | `BloomFilter` | 4-byte length + Bloom filter bits |
| 0x21 | `MissingChunks` | u32 count + count × 32-byte chunk_ids |
| 0x30 | `CapabilityCheck` | canonical-encoded capability ticket |
| 0x31 | `CapabilityAck` | u8 verdict + u32 reason_code |
| 0xF0 | `Ping` | u64 nonce |
| 0xF1 | `Pong` | u64 nonce (echo) |
| 0xFE | `ProtoError` | u32 code + utf-8 message |
| 0xFF | `Close` | (empty; orderly stream end) |

**Design rules:**

- Each QUIC stream is bidirectional. The opener sends a request frame and reads a response frame on the same stream.
- One frame round-trip per stream. After the response, the stream closes. Re-issue on a new stream for the next operation.
- Bulk transfers (`ChunkResponse`, `ManifestRecord`) carry the on-disk record bytes verbatim — same format as the chunk_log / manifest_log per ADR-0003 — so the receiver can append directly to its own WAL without re-encoding.
- Non-bulk frames (Ping/Pong, BloomFilter, CapabilityCheck) cap at 64 KiB. Bulk frames cap at 1 MiB (matches `ol_wal::MAX_PAYLOAD_LEN`).

### Multi-stream policy

- **Bulk chunk transfers**: each chunk on its own stream. No head-of-line blocking; one slow chunk doesn't stall others.
- **Manifest sync**: one stream per sync session (carries multiple `ManifestRecord` frames terminated by `ManifestSyncEnd`).
- **Control plane** (Ping, BloomFilter, CapabilityCheck): each on its own short-lived stream.

Receivers cap concurrent inbound streams per connection at **256** by default (tunable). Senders cap concurrent outbound streams at the QUIC peer's advertised `initial_max_streams_bidi`.

### 0-RTT resumption

Enabled. Servers issue session tickets after the first successful handshake; clients store them keyed by `(remote_addr, peer_fingerprint)` and replay on reconnect. 0-RTT carries `ChunkRequest` / `BloomFilter` / `CapabilityCheck` only; `ChunkResponse` and bulk replies go on full handshake to avoid the well-known 0-RTT replay risk for state-mutating operations.

### Connection migration

Enabled by default (RFC 9002). On a cellular↔WiFi handoff:
- Client side: rebind the local UDP socket to the new interface; QUIC retains the connection state via the connection ID.
- Server side: accepts traffic from the new (addr, port) for the same connection ID without renegotiation.

Acceptance test: phone fetches a 100 MB chunk; switch from WiFi to cellular mid-stream; transfer completes without client-visible error.

### Idle timeout + keepalive

- Idle timeout: **30 seconds** on both sides.
- Keepalive Ping: every **10 seconds** on idle connections (server-only sends; clients piggyback on requests).
- Connections beyond idle timeout get gracefully closed; clients reconnect on demand.

## Consequences

**Positive:**
- 10-15× throughput vs WebRTC DataChannel on LAN (quinn benchmarks: 2-5 GiB/s on loopback; ~1 GiB/s on 10 GbE).
- True multi-stream with no HoL blocking — multiple chunks transfer in parallel without per-chunk handshake.
- 0-RTT resumption for warm connections drops connect cost from ~150 ms to <30 ms.
- Connection migration solves cellular↔WiFi handoff without app-layer code.
- TLS 1.3 by default; ADR-0010 makes the cert identity-bound.

**Negative:**
- tokio dependency in the binding crate (one_link_native gains a tokio runtime). Acceptable: tokio is small, stable, and handles the async machinery cleanly.
- Two transports during the migration: WebRTC for browser-as-peer (browsers don't speak raw QUIC), QUIC for daemon↔daemon. The daemon picks based on peer kind. Long-term, browsers will get raw QUIC via WebTransport (Phase B+).
- 0-RTT replay attack surface for the frames we allow on it. Mitigation: 0-RTT carries ONLY idempotent reads; never state mutations.
- Self-signed cert path (ADR-0010) is non-standard from the TLS PKI perspective; we accept this in exchange for sovereignty (no CA dependency).

## Verification

Phase A2 acceptance criteria:

1. **Throughput gate**: `ol_quic` loopback round-trip of a 100 MiB chunk in `<= 1.1 ×` raw-tokio-TCP-loopback baseline. (Within 10% of TCP per the plan.)
2. **0-RTT resume gate**: warm-cache reconnect to a recently-seen peer completes the handshake in `<= 50 ms` median across 100 trials.
3. **Connection migration gate**: simulated `bind()` change mid-stream (client switches local port without closing the connection) completes the in-flight transfer with zero application errors.
4. **Identity-bound TLS gate** (with ADR-0010): a peer presenting a cert whose pubkey doesn't match the expected `peer_fingerprint` is rejected at the TLS layer; no application-level data is delivered.
5. **Multi-stream gate**: 64 concurrent in-flight `ChunkRequest`/`ChunkResponse` round-trips on one connection, no deadlock, no head-of-line blocking observable in per-stream completion latency.

## References

- RFC 9000 (QUIC): https://datatracker.ietf.org/doc/html/rfc9000
- RFC 9001 (QUIC + TLS 1.3): https://datatracker.ietf.org/doc/html/rfc9001
- RFC 9002 (QUIC congestion control + recovery): https://datatracker.ietf.org/doc/html/rfc9002
- quinn: https://github.com/quinn-rs/quinn — pinned to a recent stable.
- ADR-0003 (chunk record format) — `ChunkResponse` carries the same bytes.
- ADR-0010 (identity-bound TLS) — companion ADR specifying the cert / verifier model.
