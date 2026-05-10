# ADR-0013: TransferEngine Architecture

**Status:** ACCEPTED (Phase B acceptance number)
**Phase:** B (the integration layer)
**Depends on:** ADR-0003 (chunk_log), ADR-0009 (QUIC frames), ADR-0010 (identity-bound TLS), ADR-0011 (Bloom-init)

---

## Context

Phase A1 shipped `ol_chunk_store` (storage). Phase A2 shipped `ol_quic` (transport). Both work in isolation. Neither knows about the other. The daemon currently has no path from "I want chunk X from peer Y" to "fetched and stored locally."

The TransferEngine is the integrator. It owns:

- A local chunk store (`ChunkStore`).
- A QUIC endpoint (`Endpoint`).
- A peer registry mapping peer fingerprints to their socket addresses.
- A connection cache reusing live QUIC connections per-peer.
- The wire-protocol logic that turns frame round-trips into chunk fetches.

This ADR specifies its architecture, the public API, the protocol semantics, and the failure modes.

## Decision

### Crate

New crate `ol_transfer` at `native/ol_transfer/`. Pure Rust async API; the daemon binds via `one_link_native::transfer` (Python sync surface, same pattern as `quic_native`).

### Public API

```rust
pub struct TransferEngine {
    store: Arc<ChunkStore>,
    endpoint: Arc<Endpoint>,
    peers: RwLock<HashMap<PeerFingerprint, PeerEntry>>,
    config: TransferConfig,
}

pub struct PeerEntry {
    addr: SocketAddr,
    /// Live cached connection (reused for multiple fetches).
    connection: Mutex<Option<Arc<Connection>>>,
}

pub struct TransferConfig {
    /// Max simultaneous in-flight chunk fetches per peer.
    pub max_inflight_per_peer: usize,
    /// How long to wait for a single chunk request before failing.
    pub chunk_request_timeout_ms: u64,
    /// How long an idle cached connection stays alive.
    pub connection_idle_ms: u64,
    /// Bloom filter target false-positive rate (default 0.01).
    pub bloom_target_fp: f64,
}

impl TransferEngine {
    pub async fn open(
        store: Arc<ChunkStore>,
        endpoint: Arc<Endpoint>,
        config: TransferConfig,
    ) -> Result<Self, TransferError>;

    /// Register a peer. Idempotent; updates address if peer already known.
    pub async fn register_peer(
        &self,
        fingerprint: PeerFingerprint,
        addr: SocketAddr,
    ) -> Result<(), TransferError>;

    /// Forget a peer. Closes any cached connection.
    pub async fn forget_peer(&self, fingerprint: &PeerFingerprint);

    /// Fetch a single chunk from a peer if not already in the local store.
    /// Idempotent (if already local, returns the cached chunk record).
    pub async fn fetch_chunk(
        &self,
        peer: &PeerFingerprint,
        chunk_id: &[u8; 32],
    ) -> Result<ChunkRecord, TransferError>;

    /// Bloom-init handshake. Sends the local memtable's Bloom; gets back
    /// the chunk_ids the peer thinks we don't have. Returns the list to
    /// fetch. Per ADR-0011.
    pub async fn bloom_handshake(
        &self,
        peer: &PeerFingerprint,
        manifest_chunk_ids: &[[u8; 32]],
    ) -> Result<Vec<[u8; 32]>, TransferError>;

    /// Fetch many chunks from a peer in parallel, bounded by
    /// `config.max_inflight_per_peer`. Returns a stream of completion
    /// events.
    pub async fn fetch_many(
        &self,
        peer: &PeerFingerprint,
        chunk_ids: Vec<[u8; 32]>,
    ) -> Result<Vec<FetchOutcome>, TransferError>;

    /// Server-side: handle inbound frames on this engine's endpoint.
    /// Spawned as a long-running task at engine open. Reads each frame,
    /// dispatches to the right handler (chunk_request, bloom, etc).
    pub async fn run_server(&self) -> Result<(), TransferError>;
}

pub enum FetchOutcome {
    Fetched { chunk_id: [u8; 32], length_plaintext: u32 },
    AlreadyLocal { chunk_id: [u8; 32] },
    NotFound { chunk_id: [u8; 32] },
    Error { chunk_id: [u8; 32], err: TransferError },
}
```

### Protocol semantics

#### Chunk fetch

1. Client checks local store (`store.has_chunk`). If present → return immediately (no transport).
2. Client opens / reuses a cached `Connection` to peer.
3. Client sends `ChunkRequest` frame (kind 0x01) with the 32-byte `chunk_id` payload.
4. Server-side handler:
   - Looks up `chunk_id` in its store.
   - If found: sends `ChunkResponse` (kind 0x02) carrying the full chunk_log record bytes (header + ciphertext) — same encoding used on disk.
   - If absent: sends `ChunkNotFound` (kind 0x03) with the requested chunk_id.
5. Client receives response; if `ChunkResponse`, decodes the chunk_log record and writes to its own store via `store.append_chunk` + `store.flush`.
6. Returns the decoded `ChunkRecord` to caller.

#### Bloom-init handshake

Per [ADR-0011](0011-bloom-transfer-init.md). Wire flow:

1. Client builds Bloom from local chunk_id list (memtable).
2. Client sends `BloomFilter` frame (kind 0x20) with the encoded filter.
3. Server-side handler iterates `manifest_chunk_ids` it intends to send; tests each against received Bloom; collects the `chunk_id`s the receiver does NOT have.
4. Server returns `MissingChunks` frame (kind 0x21) with the list of chunk_ids to fetch.
5. Client uses the returned list to drive `fetch_many`.

#### Connection caching

- Per peer, the engine caches up to one live `Connection` in the registry.
- A cached connection is reused across multiple fetches for the same peer (no per-fetch handshake).
- Connection is closed when:
  - Peer is forgotten (`forget_peer`).
  - Engine is closed.
  - Connection's `closed()` future resolves (peer dropped, idle timeout, etc).
- A new fetch on a previously-cached but now-closed connection transparently reconnects.

#### Backpressure

- Per-peer concurrent fetches bounded by `max_inflight_per_peer` (default 32). Excess fetches wait via a semaphore.
- This protects the peer from being flooded and matches the QUIC `max_concurrent_bidi_streams` default of 256 with substantial headroom for other engines (manifest sync, capability checks).

### Error model

```rust
#[derive(Debug, Error)]
pub enum TransferError {
    #[error("store: {0}")]
    Store(#[from] ChunkStoreError),

    #[error("transport: {0}")]
    Transport(#[from] QuicError),

    #[error("peer not registered: {fingerprint_hex_prefix}")]
    PeerUnknown { fingerprint_hex_prefix: String },

    #[error("chunk not found at peer: {chunk_id_hex_prefix}")]
    ChunkNotFound { chunk_id_hex_prefix: String },

    /// Server returned a frame whose kind doesn't match the request.
    #[error("protocol violation: expected {expected_kind:?}, got {actual_kind:?}")]
    ProtocolViolation {
        expected_kind: FrameKind,
        actual_kind: FrameKind,
    },

    /// Server returned a `ChunkResponse` whose chunk_id doesn't match
    /// what we asked for. Either the peer is buggy or this is an active
    /// MITM attempt; rejected loudly.
    #[error("response chunk_id mismatch: requested {requested_hex_prefix}, got {got_hex_prefix}")]
    ChunkIdMismatch {
        requested_hex_prefix: String,
        got_hex_prefix: String,
    },

    #[error("timed out after {timeout_ms} ms")]
    Timeout { timeout_ms: u64 },
}
```

### Server-side surface

`run_server` accepts incoming connections from the endpoint, then for each connection accepts inbound bidirectional streams in a loop. Each stream is one frame round-trip:

1. Read frame from `recv` half.
2. Dispatch by frame kind:
   - `ChunkRequest (0x01)` → look up + reply with `ChunkResponse` or `ChunkNotFound`.
   - `BloomFilter (0x20)` → compute missing list from manifest + reply with `MissingChunks`.
   - `Ping (0xF0)` → reply with `Pong (0xF1)` echoing the payload.
   - Unknown → reply with `ProtoError` and close stream.
3. Write reply on `send` half. `send.finish()`. Stream closes.

The dispatcher is concurrent: each inbound stream gets its own tokio task. Per-connection bound = `max_concurrent_bidi_streams`.

### Identity-bound trust

The endpoint already enforces identity-bound TLS via [ADR-0010](0010-identity-bound-tls.md). The TransferEngine relies on this: a connection accepted by `endpoint.accept().await` is guaranteed to come from a peer in the registry's `is_paired` predicate. The engine's `run_server` does not re-verify identity; it trusts the TLS layer.

For the dial side, the engine's peer registry is the source of `(fingerprint, addr)` pairs. The fingerprint is passed to `endpoint.connect` which pins it at the rustls verifier.

## Consequences

**Positive:**
- Single integration point — daemon imports one type (`TransferEngine`) instead of orchestrating chunk_store + endpoint manually.
- Connection caching gives per-peer warm-path latency (<1 ms via QUIC 0-RTT in the future) without leaking connection management to the daemon.
- Bloom-init handshake is the canonical "you want this manifest? here's just the missing chunks" path.
- Chunk_id mismatch detection catches buggy peers OR MITM (extremely unlikely given identity-bound TLS, but defense-in-depth is cheap).
- Protocol violation surface is small + typed; daemon error handling is straightforward.

**Negative:**
- The engine's `run_server` is a long-running task. Daemons that want to multiplex multiple engines per process need to spawn distinct tokio tasks per engine.
- Per-peer `max_inflight_per_peer` bounded at 32 by default. Workloads with bursts of cold-cache fetches (first-time pair) may saturate; tunable.
- Connection caching means a stuck connection (peer not responding to keepalives) only fails on the next fetch attempt, not proactively. Acceptable; QUIC idle timeout handles this within 30 seconds.

## Verification

1. **End-to-end fetch gate**: Two engines, paired peers. Engine A has chunk X; engine B does not. `B.fetch_chunk(A_fp, X)` returns the chunk record; B's store has it after.
2. **Idempotence**: `B.fetch_chunk(A_fp, X)` called twice returns the cached chunk on the second call without a transport round trip (verifiable via store stats).
3. **Bloom-init delta**: B has 1024 chunks, A has the same 1024 + 1024 new. `B.bloom_handshake(A, manifest_2048)` returns ~1024 chunk_ids (within FP allowance).
4. **Chunk_not_found**: B asks for chunk Y, A does not have Y. Engine returns `TransferError::ChunkNotFound`.
5. **Protocol violation handling**: A buggy peer sends `Pong` in response to `ChunkRequest`. Engine returns `ProtocolViolation` with both kinds populated.
6. **Cached connection reuse**: 100 sequential `fetch_chunk` calls reuse the same connection; observed via the engine's connection-open counter.
7. **Concurrent fetch backpressure**: 1000 simultaneous `fetch_chunk` calls; engine processes them in batches of 32 (the per-peer limit) without deadlock or memory blowup.

## References

- ADR-0009 (QUIC frames) — the wire protocol.
- ADR-0010 (identity-bound TLS) — the trust model.
- ADR-0011 (Bloom transfer init) — the handshake.
- ADR-0003 (on-disk chunk_log) — `ChunkResponse` carries these bytes verbatim.
