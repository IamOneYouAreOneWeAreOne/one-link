//! Inbound frame dispatch for the [`crate::TransferEngine`].
//!
//! `run_server` is a long-running task that accepts incoming connections
//! from the endpoint, then for each connection accepts inbound
//! bidirectional streams in a loop. Each stream carries one frame
//! round-trip: read request, dispatch, write reply, finish.

use std::sync::Arc;

use ol_bloom::Bloom;
use ol_quic::{
    transport::{read_frame, write_frame},
    Connection, Frame, FrameKind,
};
use tracing::{debug, trace, warn};

use crate::engine::TransferEngine;
use crate::error::TransferError;
use crate::wire;

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
        let reply = match request.kind {
            FrameKind::ChunkRequest => self.handle_chunk_request(&request).await?,
            FrameKind::BloomFilter => self.handle_bloom_filter(&request, &[]).await?,
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
        send.finish().map_err(|e| TransferError::Transport(e.into()))?;
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
        let missing: Vec<[u8; 32]> =
            local_ids.into_iter().filter(|cid| !bloom.contains(cid)).collect();
        let payload = wire::encode_missing_chunks(&missing);
        Ok(Frame::new(FrameKind::MissingChunks, payload)?)
    }
}
