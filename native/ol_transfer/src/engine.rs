//! The [`TransferEngine`] type — owner of chunk_store + QUIC endpoint +
//! peer registry. Implements [ADR-0013](../../../docs/decisions/0013-transfer-engine.md).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;

use ol_bloom::Bloom;
use ol_chunk_store::{ChunkRecord, ChunkStore};
use ol_fountain::{FountainPacket, LtDecoder};
use ol_quic::{
    transport::{read_frame, write_frame},
    Connection, Endpoint, Frame, FrameKind, PeerFingerprint,
};
use tokio::sync::RwLock;

use crate::config::TransferConfig;
use crate::error::{hex_prefix_8, TransferError};
use crate::outcome::FetchOutcome;
use crate::peer::PeerEntry;
use crate::wire;

/// The integrated transfer engine. One per daemon identity.
///
/// `TransferEngine` is `Send + Sync`. Daemons typically hold an
/// `Arc<TransferEngine>` and clone it freely between the inbound server
/// task (started via [`TransferEngine::run_server`]) and the outbound
/// fetch path.
pub struct TransferEngine {
    /// Local chunk store. `std::sync::Mutex` because all calls into the
    /// store are sync I/O and we only hold the lock for short critical
    /// sections — never across an `.await`.
    pub(crate) store: Arc<StdRwLock<ChunkStore>>,

    /// QUIC endpoint. Either server+dialer (built via
    /// `Endpoint::server_for_identity`) or dial-only.
    pub(crate) endpoint: Arc<Endpoint>,

    /// Peer registry, keyed by fingerprint.
    pub(crate) peers: RwLock<HashMap<PeerFingerprint, Arc<PeerEntry>>>,

    /// Engine config.
    pub(crate) config: TransferConfig,
}

impl std::fmt::Debug for TransferEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransferEngine")
            .field("endpoint", &self.endpoint)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl TransferEngine {
    /// Open a new engine wrapping an existing chunk store + QUIC endpoint.
    ///
    /// Returns an `Arc<Self>` because the engine is designed to be shared
    /// freely between the inbound server task and outbound fetch callers.
    #[must_use]
    pub fn new(
        store: Arc<StdRwLock<ChunkStore>>,
        endpoint: Arc<Endpoint>,
        config: TransferConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            endpoint,
            peers: RwLock::new(HashMap::new()),
            config,
        })
    }

    /// Register a peer. Idempotent: re-registering with a different
    /// address updates the address but preserves any cached connection.
    ///
    /// # Errors
    ///
    /// None at present; reserved for future validation.
    pub async fn register_peer(
        &self,
        fingerprint: PeerFingerprint,
        addr: SocketAddr,
    ) -> Result<(), TransferError> {
        let mut peers = self.peers.write().await;
        if let Some(entry) = peers.get(&fingerprint) {
            *entry.addr.lock().await = addr;
        } else {
            peers.insert(fingerprint, Arc::new(PeerEntry::new(addr, &self.config)));
        }
        Ok(())
    }

    /// Forget a peer. Closes any cached connection.
    pub async fn forget_peer(&self, fingerprint: &PeerFingerprint) {
        let entry = {
            let mut peers = self.peers.write().await;
            peers.remove(fingerprint)
        };
        if let Some(entry) = entry {
            let mut conn = entry.connection.lock().await;
            if let Some(c) = conn.take() {
                c.close(0, b"forget_peer");
            }
        }
    }

    /// Snapshot of registered peer fingerprints. Diagnostic.
    pub async fn known_peers(&self) -> Vec<PeerFingerprint> {
        let peers = self.peers.read().await;
        peers.keys().copied().collect()
    }

    /// Snapshot of chunk-store stats (cheap; counters only).
    #[must_use]
    pub fn store_stats(&self) -> ol_chunk_store::StoreStats {
        self.store.read().expect("store rwlock poisoned").stats()
    }

    /// Snapshot of the engine's endpoint local address (diagnostic).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`ol_quic::QuicError`] from the endpoint.
    pub fn local_addr(&self) -> Result<SocketAddr, TransferError> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Fetch a chunk from a peer if not already in the local store.
    ///
    /// Idempotent: if the chunk is already local, returns the cached
    /// record without contacting the peer.
    ///
    /// # Errors
    ///
    /// - [`TransferError::PeerUnknown`] if the peer is not registered.
    /// - [`TransferError::ChunkNotFound`] if the peer doesn't have the chunk.
    /// - [`TransferError::Timeout`] if the request exceeds
    ///   [`TransferConfig::chunk_request_timeout_ms`].
    /// - [`TransferError::ProtocolViolation`] / [`TransferError::ChunkIdMismatch`]
    ///   for a buggy or malicious peer.
    /// - [`TransferError::Store`] / [`TransferError::Transport`] for the
    ///   underlying I/O failures.
    pub async fn fetch_chunk(
        &self,
        peer: &PeerFingerprint,
        chunk_id: &[u8; 32],
    ) -> Result<ChunkRecord, TransferError> {
        self.fetch_chunk_inner(peer, chunk_id, /* flush_on_write = */ true).await
    }

    /// Variant of [`Self::fetch_chunk`] that defers the post-write
    /// `flush` (fsync) for batched commit. The caller is responsible
    /// for invoking [`Self::commit`] before treating the chunk as
    /// durable. Used internally by [`Self::fetch_many`].
    async fn fetch_chunk_no_flush(
        &self,
        peer: &PeerFingerprint,
        chunk_id: &[u8; 32],
    ) -> Result<ChunkRecord, TransferError> {
        self.fetch_chunk_inner(peer, chunk_id, /* flush_on_write = */ false).await
    }

    async fn fetch_chunk_inner(
        &self,
        peer: &PeerFingerprint,
        chunk_id: &[u8; 32],
        flush_on_write: bool,
    ) -> Result<ChunkRecord, TransferError> {
        if let Some(rec) = self.read_local(chunk_id) {
            return Ok(rec);
        }

        let entry = self.peer_entry(peer).await?;
        let _permit = entry
            .inflight
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore not closed");

        let connection = self.connection_for(peer, &entry).await?;

        let request = Frame::new(FrameKind::ChunkRequest, wire::encode_chunk_request(chunk_id))?;
        let reply = self
            .send_request_with_timeout(&connection, request, self.config.chunk_request_timeout_ms)
            .await?;

        match reply.kind {
            FrameKind::ChunkResponse => {
                let (rec_kind, rec_flags, rec_payload) = wire::decode_chunk_response(&reply.payload)?;
                let record = ChunkRecord::decode(rec_kind, rec_flags, rec_payload)?;
                if &record.chunk_id != chunk_id {
                    return Err(TransferError::ChunkIdMismatch {
                        requested_hex_prefix: hex_prefix_8(chunk_id),
                        got_hex_prefix: hex_prefix_8(&record.chunk_id),
                    });
                }
                if flush_on_write {
                    self.write_local(&record)?;
                } else {
                    self.write_local_no_flush(&record)?;
                }
                Ok(record)
            }
            FrameKind::ChunkNotFound => {
                let got_id = wire::decode_chunk_not_found(&reply.payload)?;
                if &got_id != chunk_id {
                    return Err(TransferError::ChunkIdMismatch {
                        requested_hex_prefix: hex_prefix_8(chunk_id),
                        got_hex_prefix: hex_prefix_8(&got_id),
                    });
                }
                Err(TransferError::ChunkNotFound {
                    chunk_id_hex_prefix: hex_prefix_8(chunk_id),
                })
            }
            other => Err(TransferError::ProtocolViolation {
                expected_kind: FrameKind::ChunkResponse,
                actual_kind: other,
            }),
        }
    }

    /// Fetch many chunks from a peer with per-peer bounded concurrency.
    ///
    /// Returns one [`FetchOutcome`] per requested chunk_id, in the same
    /// order as the input vector.
    ///
    /// Per-peer bandwidth is bounded by
    /// [`TransferConfig::max_inflight_per_peer`].
    ///
    /// # Errors
    ///
    /// Returns early with [`TransferError::PeerUnknown`] if the peer
    /// isn't registered. Individual chunk failures are surfaced via
    /// [`FetchOutcome::Error`] in the result vector, not as a top-level
    /// `Err`.
    pub async fn fetch_many(
        self: &Arc<Self>,
        peer: &PeerFingerprint,
        chunk_ids: Vec<[u8; 32]>,
    ) -> Result<Vec<FetchOutcome>, TransferError> {
        let entry = self.peer_entry(peer).await?;
        // Eager connection setup so unreachable peers fail fast.
        let _ = self.connection_for(peer, &entry).await?;

        let mut handles = Vec::with_capacity(chunk_ids.len());
        for cid in chunk_ids {
            let engine = Arc::clone(self);
            let peer_fp = *peer;
            // Each task uses the no-flush write path; we batch-commit
            // ONCE at the end. This amortizes the fsync across N chunks
            // and is the primary cost of the wire-fetch hot path (per
            // the bench baseline, a single fsync costs ~500 µs vs ~100
            // µs for the QUIC round-trip itself).
            let handle = tokio::spawn(async move {
                match engine.fetch_chunk_no_flush(&peer_fp, &cid).await {
                    Ok(rec) => FetchOutcome::Fetched {
                        chunk_id: cid,
                        length_plaintext: rec.length_plaintext,
                    },
                    Err(TransferError::ChunkNotFound { .. }) => {
                        FetchOutcome::NotFound { chunk_id: cid }
                    }
                    Err(other) => FetchOutcome::Error {
                        chunk_id: cid,
                        err: other,
                    },
                }
            });
            handles.push(handle);
        }

        let mut out = Vec::with_capacity(handles.len());
        for h in handles {
            match h.await {
                Ok(outcome) => out.push(outcome),
                Err(join_err) => {
                    return Err(TransferError::MalformedPayload {
                        kind: FrameKind::ChunkResponse,
                        reason: if join_err.is_panic() {
                            "fetch task panicked"
                        } else {
                            "fetch task cancelled"
                        },
                    });
                }
            }
        }
        // Single batched fsync. After this returns, every Fetched
        // outcome in `out` is durable.
        if out
            .iter()
            .any(|o| matches!(o, FetchOutcome::Fetched { .. }))
        {
            self.commit()?;
        }
        Ok(out)
    }

    /// Bloom-init handshake per ADR-0011 + ADR-0013.
    ///
    /// We build a Bloom filter from `local_chunk_ids` (the chunk_ids we
    /// already have for the manifest scope), send it to the peer, and
    /// receive back the list of chunk_ids the peer thinks we still need.
    ///
    /// # Errors
    ///
    /// - [`TransferError::PeerUnknown`]
    /// - [`TransferError::Bloom`] on encode failure (filter too large).
    /// - [`TransferError::ProtocolViolation`] if the peer doesn't reply
    ///   with `MissingChunks`.
    /// - [`TransferError::Timeout`] on
    ///   [`TransferConfig::bloom_handshake_timeout_ms`].
    pub async fn bloom_handshake(
        &self,
        peer: &PeerFingerprint,
        local_chunk_ids: &[[u8; 32]],
    ) -> Result<Vec<[u8; 32]>, TransferError> {
        let entry = self.peer_entry(peer).await?;
        let connection = self.connection_for(peer, &entry).await?;

        let mut bloom = Bloom::with_target_fp(
            local_chunk_ids.len().max(1),
            self.config.bloom_target_fp,
        );
        for cid in local_chunk_ids {
            bloom.insert(cid);
        }
        let encoded = bloom.encode()?;
        let request = Frame::new(FrameKind::BloomFilter, encoded)?;
        let reply = self
            .send_request_with_timeout(
                &connection,
                request,
                self.config.bloom_handshake_timeout_ms,
            )
            .await?;

        match reply.kind {
            FrameKind::MissingChunks => wire::decode_missing_chunks(&reply.payload),
            other => Err(TransferError::ProtocolViolation {
                expected_kind: FrameKind::MissingChunks,
                actual_kind: other,
            }),
        }
    }

    /// Fetch a chunk via LT-fountain delivery per ADR-0015.
    ///
    /// Opens a fresh bi-directional stream, sends a `FountainRequest`
    /// frame carrying the chunk_id, then ingests the inbound stream of
    /// `FountainBurst` frames until the LT decoder reconstructs the
    /// chunk plaintext. Sends `FountainAck` to tell the sender to stop
    /// emitting once decode succeeds.
    ///
    /// Use this in preference to [`Self::fetch_chunk`] on lossy or
    /// many-receivers workloads where ARQ retransmission round-trips
    /// would dominate latency.
    ///
    /// # Errors
    ///
    /// - [`TransferError::ChunkNotFound`] if the server has no such chunk.
    /// - [`TransferError::ChunkIdMismatch`] if the decoded bytes hash to
    ///   a different chunk_id than requested (catches buggy / malicious peer).
    /// - [`TransferError::Timeout`] if the full decode exceeds the
    ///   chunk request timeout.
    /// - [`TransferError::Transport`] for QUIC stream errors.
    pub async fn fetch_chunk_fountain(
        &self,
        peer: &PeerFingerprint,
        chunk_id: &[u8; 32],
    ) -> Result<ChunkRecord, TransferError> {
        if let Some(rec) = self.read_local(chunk_id) {
            return Ok(rec);
        }
        let entry = self.peer_entry(peer).await?;
        let _permit = entry
            .inflight
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore not closed");

        let connection = self.connection_for(peer, &entry).await?;
        let (mut send, mut recv) = connection
            .open_bi_stream()
            .await
            .map_err(TransferError::Transport)?;

        // Request side.
        let req = Frame::new(FrameKind::FountainRequest, chunk_id.to_vec())?;
        write_frame(&mut send, &req)
            .await
            .map_err(TransferError::Transport)?;

        // Response loop with overall timeout.
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(self.config.chunk_request_timeout_ms);
        let mut decoder: Option<LtDecoder> = None;
        let mut chunk_source_len: u32 = 0;

        loop {
            let read_future = read_frame(&mut recv);
            let frame = match tokio::time::timeout_at(deadline, read_future).await {
                Ok(Ok(f)) => f,
                Ok(Err(e)) => return Err(TransferError::Transport(e)),
                Err(_) => {
                    return Err(TransferError::Timeout {
                        timeout_ms: self.config.chunk_request_timeout_ms,
                    });
                }
            };
            match frame.kind {
                FrameKind::FountainBurst => {
                    let pkt = FountainPacket::decode(&frame.payload)?;
                    if &pkt.chunk_id != chunk_id {
                        return Err(TransferError::ChunkIdMismatch {
                            requested_hex_prefix: hex_prefix_8(chunk_id),
                            got_hex_prefix: hex_prefix_8(&pkt.chunk_id),
                        });
                    }
                    let dec = decoder.get_or_insert_with(|| {
                        chunk_source_len = pkt.source_length;
                        LtDecoder::new(
                            pkt.k,
                            pkt.payload.len(),
                            pkt.source_length as usize,
                        )
                        .expect("packet parameters valid")
                    });
                    if dec.ingest(pkt.symbol_id, &pkt.payload)? {
                        // Decode complete; tell sender to stop.
                        let ack = Frame::new(
                            FrameKind::FountainAck,
                            chunk_id.to_vec(),
                        )?;
                        write_frame(&mut send, &ack)
                            .await
                            .map_err(TransferError::Transport)?;
                        let _ = send.finish();
                        break;
                    }
                }
                FrameKind::ChunkNotFound => {
                    return Err(TransferError::ChunkNotFound {
                        chunk_id_hex_prefix: hex_prefix_8(chunk_id),
                    });
                }
                other => {
                    return Err(TransferError::ProtocolViolation {
                        expected_kind: FrameKind::FountainBurst,
                        actual_kind: other,
                    });
                }
            }
        }

        let dec = decoder.expect("decoder created on first FountainBurst");
        let source_bytes = dec.finish()?;
        // Parse `(kind, flags, payload)` back into a ChunkRecord.
        if source_bytes.len() < 2 {
            return Err(TransferError::MalformedPayload {
                kind: FrameKind::FountainBurst,
                reason: "decoded chunk source < 2 bytes",
            });
        }
        let record = ChunkRecord::decode(source_bytes[0], source_bytes[1], &source_bytes[2..])?;
        if &record.chunk_id != chunk_id {
            return Err(TransferError::ChunkIdMismatch {
                requested_hex_prefix: hex_prefix_8(chunk_id),
                got_hex_prefix: hex_prefix_8(&record.chunk_id),
            });
        }
        // Persist durably.
        self.write_local(&record)?;
        let _ = chunk_source_len; // silence unused-mut warning on early-decode path
        Ok(record)
    }

    /// Scoped bloom-init handshake per ADR-0011 v2.
    ///
    /// Sends both a Bloom of `already_have` AND an explicit `want_list`
    /// of chunk_ids the client cares about. Server walks `want_list`
    /// against the bloom and returns the missing subset — avoiding the
    /// full memtable scan that [`Self::bloom_handshake`] triggers on
    /// large servers.
    ///
    /// Use this when the client knows the manifest scope it's syncing
    /// (the common case for shared folders). Fall back to
    /// `bloom_handshake` only when the scope is "everything the server
    /// has."
    ///
    /// # Errors
    ///
    /// - [`TransferError::PeerUnknown`]
    /// - [`TransferError::Bloom`] on encode failure (filter too large).
    /// - [`TransferError::ProtocolViolation`] if the peer doesn't reply
    ///   with `MissingChunks`.
    /// - [`TransferError::Timeout`] on
    ///   [`TransferConfig::bloom_handshake_timeout_ms`].
    pub async fn bloom_handshake_scoped(
        &self,
        peer: &PeerFingerprint,
        already_have: &[[u8; 32]],
        want_list: &[[u8; 32]],
    ) -> Result<Vec<[u8; 32]>, TransferError> {
        let entry = self.peer_entry(peer).await?;
        let connection = self.connection_for(peer, &entry).await?;

        let mut bloom = Bloom::with_target_fp(
            already_have.len().max(1),
            self.config.bloom_target_fp,
        );
        for cid in already_have {
            bloom.insert(cid);
        }
        let bloom_bytes = bloom.encode()?;
        let payload = wire::encode_scoped_bloom(want_list, &bloom_bytes);
        let request = Frame::new(FrameKind::ScopedBloomFilter, payload)?;
        let reply = self
            .send_request_with_timeout(
                &connection,
                request,
                self.config.bloom_handshake_timeout_ms,
            )
            .await?;

        match reply.kind {
            FrameKind::MissingChunks => wire::decode_missing_chunks(&reply.payload),
            other => Err(TransferError::ProtocolViolation {
                expected_kind: FrameKind::MissingChunks,
                actual_kind: other,
            }),
        }
    }

    /// Send a `Ping` frame and await `Pong`. Diagnostic / liveness.
    ///
    /// # Errors
    ///
    /// - [`TransferError::PeerUnknown`]
    /// - [`TransferError::Timeout`]
    /// - [`TransferError::ProtocolViolation`] if the reply isn't `Pong`.
    pub async fn ping(
        &self,
        peer: &PeerFingerprint,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, TransferError> {
        let entry = self.peer_entry(peer).await?;
        let connection = self.connection_for(peer, &entry).await?;
        let request = Frame::new(FrameKind::Ping, payload)?;
        let reply = self
            .send_request_with_timeout(&connection, request, self.config.chunk_request_timeout_ms)
            .await?;
        match reply.kind {
            FrameKind::Pong => Ok(reply.payload),
            other => Err(TransferError::ProtocolViolation {
                expected_kind: FrameKind::Pong,
                actual_kind: other,
            }),
        }
    }

    // ─────────────────────────── internals ─────────────────────────────

    fn read_local(&self, chunk_id: &[u8; 32]) -> Option<ChunkRecord> {
        let store = self.store.read().expect("store rwlock poisoned");
        if !store.has_chunk(chunk_id) {
            return None;
        }
        store.read_chunk(chunk_id).ok()
    }

    /// Persist a received chunk record durably (append + flush). Used
    /// by `fetch_chunk` for single-chunk fetches.
    pub(crate) fn write_local(&self, record: &ChunkRecord) -> Result<(), TransferError> {
        let mut store = self.store.write().expect("store rwlock poisoned");
        store.append_chunk(record)?;
        store.flush()?;
        Ok(())
    }

    /// Append a chunk record WITHOUT flushing. Used by `fetch_many` and
    /// other batch paths that amortize the fsync across many writes via
    /// a single trailing [`TransferEngine::commit`] call.
    ///
    /// **Durability:** the record is in the kernel page cache after this
    /// call but is **not** guaranteed to survive a crash. Caller MUST
    /// invoke `commit()` before treating the chunk as durable.
    pub(crate) fn write_local_no_flush(
        &self,
        record: &ChunkRecord,
    ) -> Result<(), TransferError> {
        let mut store = self.store.write().expect("store rwlock poisoned");
        store.append_chunk(record)?;
        Ok(())
    }

    /// Flush both chunk_log and manifest_log to durable storage. After
    /// this returns, all chunks previously appended via the
    /// `write_local_no_flush` path are durable.
    ///
    /// # Errors
    ///
    /// Returns [`TransferError::Store`] on I/O failure during fsync.
    pub fn commit(&self) -> Result<(), TransferError> {
        let mut store = self.store.write().expect("store rwlock poisoned");
        store.flush()?;
        Ok(())
    }

    pub(crate) async fn peer_entry(
        &self,
        peer: &PeerFingerprint,
    ) -> Result<Arc<PeerEntry>, TransferError> {
        let peers = self.peers.read().await;
        peers.get(peer).cloned().ok_or_else(|| TransferError::PeerUnknown {
            fingerprint_hex_prefix: hex_prefix_8(peer),
        })
    }

    pub(crate) async fn connection_for(
        &self,
        peer: &PeerFingerprint,
        entry: &Arc<PeerEntry>,
    ) -> Result<Arc<Connection>, TransferError> {
        let mut slot = entry.connection.lock().await;
        if let Some(conn) = slot.as_ref() {
            return Ok(conn.clone());
        }
        let addr = *entry.addr.lock().await;
        let conn = self
            .endpoint
            .connect(addr, *peer)
            .await
            .map_err(TransferError::Transport)?;
        let conn_arc = Arc::new(conn);
        *slot = Some(conn_arc.clone());
        Ok(conn_arc)
    }

    /// Force-drop a cached connection (used when a request hits a
    /// transport error and we don't want to reuse the broken pipe).
    pub async fn drop_cached_connection(&self, peer: &PeerFingerprint) {
        if let Ok(entry) = self.peer_entry(peer).await {
            let mut slot = entry.connection.lock().await;
            if let Some(c) = slot.take() {
                c.close(0, b"transport-error-reset");
            }
        }
    }

    async fn send_request_with_timeout(
        &self,
        connection: &Connection,
        request: Frame,
        timeout_ms: u64,
    ) -> Result<Frame, TransferError> {
        let fut = connection.send_frame_request_response(request);
        match tokio::time::timeout(Duration::from_millis(timeout_ms), fut).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(e)) => Err(TransferError::Transport(e)),
            Err(_) => Err(TransferError::Timeout { timeout_ms }),
        }
    }
}
