//! Errors for `ol_transfer`.

use ol_bloom::BloomError;
use ol_chunk_store::ChunkStoreError;
use ol_fountain::FountainError;
use ol_quic::{FrameKind, QuicError};
use thiserror::Error;

/// Errors produced by `TransferEngine` operations.
#[derive(Debug, Error)]
pub enum TransferError {
    /// Underlying chunk-store error.
    #[error("store: {0}")]
    Store(#[from] ChunkStoreError),

    /// Underlying QUIC transport error.
    #[error("transport: {0}")]
    Transport(#[from] QuicError),

    /// Bloom filter encode/decode error.
    #[error("bloom: {0}")]
    Bloom(#[from] BloomError),

    /// LT-fountain encode/decode error (ADR-0015).
    #[error("fountain: {0}")]
    Fountain(#[from] FountainError),

    /// I/O error from a non-WAL non-QUIC source.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// Asked to fetch from / register a peer that's not in the registry.
    #[error("peer not registered: {fingerprint_hex_prefix}")]
    PeerUnknown {
        /// Hex prefix of the unknown fingerprint (8 bytes = 16 hex chars).
        fingerprint_hex_prefix: String,
    },

    /// Peer reported the requested chunk_id is not stored at their end.
    #[error("chunk not found at peer: {chunk_id_hex_prefix}")]
    ChunkNotFound {
        /// Hex prefix of the missing chunk_id (8 bytes = 16 hex chars).
        chunk_id_hex_prefix: String,
    },

    /// Server returned a frame whose kind doesn't match the request.
    /// Indicates a buggy / malicious peer; the engine rejects loudly.
    #[error("protocol violation: expected {expected_kind:?}, got {actual_kind:?}")]
    ProtocolViolation {
        /// Frame kind we expected as the reply.
        expected_kind: FrameKind,
        /// Frame kind the peer actually sent.
        actual_kind: FrameKind,
    },

    /// Peer returned a `ChunkResponse` whose `chunk_id` doesn't match
    /// what we asked for. Either the peer is buggy or an active
    /// substitution attack snuck past the QUIC layer. Identity-bound
    /// TLS makes the latter implausible, but defense-in-depth is cheap.
    #[error("chunk_id mismatch: requested {requested_hex_prefix}, got {got_hex_prefix}")]
    ChunkIdMismatch {
        /// Hex prefix of the chunk_id we asked for.
        requested_hex_prefix: String,
        /// Hex prefix of the chunk_id the peer sent.
        got_hex_prefix: String,
    },

    /// Frame had a payload shape we don't recognize at this engine layer
    /// (e.g. a `ChunkRequest` payload that isn't 32 bytes).
    #[error("malformed payload for {kind:?}: {reason}")]
    MalformedPayload {
        /// Frame kind whose payload was malformed.
        kind: FrameKind,
        /// What was wrong.
        reason: &'static str,
    },

    /// Operation hit its deadline without completing.
    #[error("timed out after {timeout_ms} ms")]
    Timeout {
        /// Timeout in milliseconds.
        timeout_ms: u64,
    },

    /// Engine was closed and a subsequent call was made.
    #[error("transfer engine closed")]
    Closed,
}

/// Helper: 8-byte hex prefix for error messages.
#[inline]
pub(crate) fn hex_prefix_8(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let n = bytes.len().min(8);
    let mut out = String::with_capacity(n * 2);
    for &b in &bytes[..n] {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}
