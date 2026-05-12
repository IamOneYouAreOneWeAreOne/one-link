//! Inbound frame dispatch for the [`crate::TransferEngine`].
//!
//! `run_server` is a long-running task that accepts incoming connections
//! from the endpoint, then for each connection accepts inbound
//! bidirectional streams in a loop. Each stream carries one frame
//! round-trip: read request, dispatch, write reply, finish.

use std::sync::Arc;

use ol_bloom::Bloom;
use ol_fountain::{FountainPacket, LtEncoder};
use ol_quic::{
    transport::{read_frame, write_frame},
    Connection, Frame, FrameKind,
};
use tracing::{debug, trace, warn};

use crate::engine::TransferEngine;
use crate::error::TransferError;
use crate::wire;

/// Server-side LT-encode parameters per ADR-0015.
const FOUNTAIN_SYMBOL_LEN: usize = 1024;

/// Hard cap on symbols a server will emit for one chunk before
/// declaring the receiver unable to decode. Matches
/// `ol_fountain::MAX_ENCODED_PER_CHUNK`.
const FOUNTAIN_MAX_SYMBOLS: u32 = ol_fountain::MAX_ENCODED_PER_CHUNK - 1;

impl TransferEngine {
    /// Accept incoming connections on this engine's endpoint and
    /// dispatch each one to [`handle_connection`]. Runs until the
    /// endpoint is closed.
    ///
    /// Typically the daemon spawns this on a dedicated tokio task:
    ///
    /// ```ignore
    /// let engine = TransferEngine::new(store, endpoint, config);
    /// let engine_clone = Arc::clone(&engine);
    /// tokio::spawn(async move { engine_clone.run_server().await });
    /// ```
    ///
    /// # Errors
    ///
    /// Returns the first non-transient error encountered while accepting
    /// or handling a connection. Transient per-connection errors are
    /// logged via `tracing` and do not stop the server loop.
    pub async fn run_server(self: Arc<Self>) -> Result<(), TransferError> {
        loop {
            let next = self.endpoint.accept().await;
            match next {
                None => {
                    debug!("endpoint closed; run_server exiting");
                    return Ok(());
                }
                Some(Err(e)) => {
                    warn!(error = ?e, "endpoint accept error; continuing");
                    continue;
                }
                Some(Ok(conn)) => {
                    let engine = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = engine.handle_connection(conn).await {
                            warn!(error = ?e, "connection handler exited with error");
                        }
                    });
                }
            }
        }
    }

    /// Handle one accepted connection: loop accepting bi-streams until
    /// the connection closes or errors out.
    async fn handle_connection(self: Arc<Self>, conn: Connection) -> Result<(), TransferError> {
        debug!(remote = ?conn.remote_address(), "new inbound connection");
        loop {
            match conn.accept_bi_stream().await {
                Ok((mut send, mut recv)) => {
                    let engine = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = engine.handle_stream(&mut send, &mut recv).await {
                            trace!(error = ?e, "stream handler exited with error");
                        }
                    });
                }
                Err(e) => {
                    debug!(error = ?e, "connection closed; handler exiting");
                    return Ok(());
                }
            }
        }
    }

    /// Handle one inbound bi-stream: read a frame, dispatch, write reply.
    async fn handle_stream(
        self: Arc<Self>,
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
    ) -> Result<(), TransferError> {
        let request = read_frame(recv).await?;
        // FountainRequest is special: it streams many response frames
        // on the same bi-stream, then optionally reads back a
        // FountainAck. Dispatch separately.
        if request.kind == FrameKind::FountainRequest {
            return self.handle_fountain_request(&request, send, recv).await;
        }
        let reply = match request.kind {
            FrameKind::ChunkRequest => self.handle_chunk_request(&request).await?,
            FrameKind::BloomFilter => self.handle_bloom_filter(&request, &[]).await?,
            FrameKind::ScopedBloomFilter => self.handle_scoped_bloom_filter(&request).await?,
            FrameKind::Ping => Frame::new(FrameKind::Pong, request.payload.clone())?,
            FrameKind::Close => {
                debug!("peer requested stream close");
                return Ok(());
            }
            other => {
                let body = format!("unexpected frame kind on server side: {other:?}");
                Frame::new(FrameKind::ProtoError, body.into_bytes())?
            }
        };
        write_frame(send, &reply).await?;
        send.finish()
            .map_err(|e| TransferError::Transport(e.into()))?;
        Ok(())
    }

    /// Server-side handler for `FountainRequest`. Looks up the chunk,
    /// serializes its on-disk record bytes, and streams LT-fountain
    /// symbols on the same bi-stream until either:
    ///
    /// 1. The receiver sends `FountainAck` (decode complete).
    /// 2. We've emitted [`FOUNTAIN_MAX_SYMBOLS`] without an ack
    ///    (receiver gave up; we close the stream).
    /// 3. The peer closes the stream.
    async fn handle_fountain_request(
        self: Arc<Self>,
        request: &Frame,
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
    ) -> Result<(), TransferError> {
        // Parse the chunk_id from the request payload.
        if request.payload.len() != 32 {
            let err = Frame::new(
                FrameKind::ProtoError,
                b"FountainRequest payload must be 32-byte chunk_id".to_vec(),
            )?;
            write_frame(send, &err).await?;
            send.finish()
                .map_err(|e| TransferError::Transport(e.into()))?;
            return Ok(());
        }
        let mut chunk_id = [0u8; 32];
        chunk_id.copy_from_slice(&request.payload);

        // Look up the chunk; serialize to "source bytes" = (kind, flags, payload).
        let record_opt = {
            let store = self.store.read().expect("store rwlock poisoned");
            if store.has_chunk(&chunk_id) {
                Some(store.read_chunk(&chunk_id)?)
            } else {
                None
            }
        };
        let Some(record) = record_opt else {
            let reply = Frame::new(FrameKind::ChunkNotFound, chunk_id.to_vec())?;
            write_frame(send, &reply).await?;
            send.finish()
                .map_err(|e| TransferError::Transport(e.into()))?;
            return Ok(());
        };
        let (kind_byte, flags_byte, body) = record.encode();
        let mut source = Vec::with_capacity(2 + body.len());
        source.push(kind_byte);
        source.push(flags_byte);
        source.extend_from_slice(&body);

        let encoder = LtEncoder::new(&source, FOUNTAIN_SYMBOL_LEN)?;
        let k = encoder.k();
        let source_len_u32 = u32::try_from(source.len()).unwrap_or(u32::MAX);

        // Phase B-2 emission protocol:
        //   Step 1: emit `initial_burst` = ceil(K * 1.25) symbols (the
        //           "25% overhead" from ADR-0015's robust-soliton
        //           targets ≥99.9% decode probability on loss-free links).
        //   Step 2: await ACK with a bounded timeout. If ACK arrives,
        //           stop. If timeout, emit another `top_up` = ceil(K * 0.25)
        //           and repeat until ACK or `FOUNTAIN_MAX_SYMBOLS`.
        //
        // This avoids the broken pattern where we'd emit every symbol
        // up to the cap because a 0-duration peek never observes the
        // client's ACK in flight.
        let initial_burst = k.saturating_add(k / 4).max(k + 4);
        let top_up = (k / 4).max(2);
        // 2ms ack wait: loopback ACKs arrive in tens of microseconds; on
        // LAN/WAN the bound is sub-RTT. If the client genuinely needs
        // more symbols (loss > overhead margin) we top up after this
        // timeout, repeated until ACK or MAX_ENCODED_PER_CHUNK.
        let ack_wait = std::time::Duration::from_millis(2);

        let mut sid: u32 = 0;
        // Step 1: initial burst.
        while sid < initial_burst && sid < FOUNTAIN_MAX_SYMBOLS {
            let symbol = encoder.encode_symbol(sid);
            let packet = FountainPacket::new(chunk_id, k, sid, source_len_u32, symbol).encode();
            let frame = Frame::new(FrameKind::FountainBurst, packet)?;
            write_frame(send, &frame).await?;
            sid += 1;
        }

        // Step 2: wait-for-ACK + optional top-up loop.
        loop {
            match tokio::time::timeout(ack_wait, read_frame(recv)).await {
                Ok(Ok(ack)) if ack.kind == FrameKind::FountainAck => break,
                Ok(Ok(_)) => break,  // unexpected frame; bail
                Ok(Err(_)) => break, // stream error; bail
                Err(_) => {
                    // Timeout: top up if there's headroom.
                    if sid >= FOUNTAIN_MAX_SYMBOLS {
                        break;
                    }
                    let limit = (sid + top_up).min(FOUNTAIN_MAX_SYMBOLS);
                    while sid < limit {
                        let symbol = encoder.encode_symbol(sid);
                        let packet =
                            FountainPacket::new(chunk_id, k, sid, source_len_u32, symbol).encode();
                        let frame = Frame::new(FrameKind::FountainBurst, packet)?;
                        write_frame(send, &frame).await?;
                        sid += 1;
                    }
                }
            }
        }
        send.finish()
            .map_err(|e| TransferError::Transport(e.into()))?;
        Ok(())
    }

    /// Server-side handler for `ChunkRequest`. Looks up the chunk and
    /// either replies with `ChunkResponse` (full record bytes) or
    /// `ChunkNotFound` echoing the requested id.
    async fn handle_chunk_request(&self, request: &Frame) -> Result<Frame, TransferError> {
        let chunk_id = wire::decode_chunk_request(&request.payload)?;
        let record_opt = {
            let store = self.store.read().expect("store rwlock poisoned");
            if store.has_chunk(&chunk_id) {
                Some(store.read_chunk(&chunk_id)?)
            } else {
                None
            }
        };
        match record_opt {
            Some(record) => {
                let (kind, flags, payload) = record.encode();
                let payload = wire::encode_chunk_response(kind, flags, &payload);
                Ok(Frame::new(FrameKind::ChunkResponse, payload)?)
            }
            None => {
                let payload = wire::encode_chunk_not_found(&chunk_id);
                Ok(Frame::new(FrameKind::ChunkNotFound, payload)?)
            }
        }
    }

    /// Server-side handler for `ScopedBloomFilter`. Parses the want_list
    /// + bloom from the payload, walks the want_list against the bloom,
    /// and returns the subset NOT in the bloom (i.e. chunks the peer
    /// doesn't yet have).
    ///
    /// Crucially, this path does **not** scan the local memtable — the
    /// scope is fully client-supplied. For large servers (≥ 1M chunks)
    /// this is the difference between O(server_memtable) and
    /// O(want_list) work per handshake.
    async fn handle_scoped_bloom_filter(&self, request: &Frame) -> Result<Frame, TransferError> {
        let (want_list, bloom_bytes) = wire::decode_scoped_bloom(&request.payload)?;
        let bloom = Bloom::decode(bloom_bytes)?;
        let missing: Vec<[u8; 32]> = want_list
            .into_iter()
            .filter(|cid| !bloom.contains(cid))
            .collect();
        let payload = wire::encode_missing_chunks(&missing);
        Ok(Frame::new(FrameKind::MissingChunks, payload)?)
    }

    /// Server-side handler for `BloomFilter`. Given a peer-supplied
    /// Bloom filter `bloom`, computes the subset of `manifest_chunk_ids`
    /// the peer does NOT have (those for which `!bloom.contains(cid)`),
    /// and returns a `MissingChunks` frame.
    ///
    /// For the v1 wire protocol we expose the manifest set as a hint
    /// from the caller; the server-side default uses `&[]` which means
    /// "no manifest scope known" → empty `MissingChunks`. Callers that
    /// want the meaningful behavior should pre-register a manifest hook
    /// via [`TransferEngine::set_manifest_scope`] (future API; v1 uses
    /// the local memtable's chunk_ids as the implicit scope).
    async fn handle_bloom_filter(
        &self,
        request: &Frame,
        _explicit_scope: &[[u8; 32]],
    ) -> Result<Frame, TransferError> {
        let bloom = Bloom::decode(&request.payload)?;
        // v1 default: scope = entire local memtable. Phase B-2 may
        // narrow this to a specific manifest's chunk set; for v1 we
        // serve the engine's whole inventory.
        let local_ids: Vec<[u8; 32]> = {
            let store = self.store.read().expect("store rwlock poisoned");
            store.collect_chunk_ids()
        };
        let missing: Vec<[u8; 32]> = local_ids
            .into_iter()
            .filter(|cid| !bloom.contains(cid))
            .collect();
        let payload = wire::encode_missing_chunks(&missing);
        Ok(Frame::new(FrameKind::MissingChunks, payload)?)
    }
}
