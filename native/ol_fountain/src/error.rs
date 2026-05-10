//! Errors for `ol_fountain`.

use thiserror::Error;

/// Errors produced by the LT fountain encoder / decoder.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum FountainError {
    /// `symbol_len` was zero or otherwise invalid.
    #[error("invalid symbol length: {0}")]
    InvalidSymbolLen(&'static str),

    /// Encoder was given an empty source buffer (K would be 0).
    #[error("empty source buffer not encodable")]
    EmptySource,

    /// Decoder receives a packet with a different K than the one it was
    /// constructed for.
    #[error("k mismatch: decoder configured for {expected}, got {got}")]
    KMismatch {
        /// K the decoder was constructed with.
        expected: u32,
        /// K embedded in the received packet.
        got: u32,
    },

    /// Decoder receives a packet with the wrong symbol length.
    #[error("symbol length mismatch: decoder configured for {expected}, got {got}")]
    SymbolLenMismatch {
        /// Symbol length the decoder was constructed with.
        expected: usize,
        /// Symbol length of the received payload.
        got: usize,
    },

    /// `finish()` called on a decoder that hasn't completed.
    #[error("decode incomplete: {resolved}/{k} sources recovered")]
    IncompleteDecode {
        /// Source symbols resolved so far.
        resolved: u32,
        /// Total source symbols.
        k: u32,
    },

    /// Wire-format packet failed to decode (too short, version mismatch,
    /// reserved bytes non-zero, etc).
    #[error("malformed packet: {0}")]
    MalformedPacket(&'static str),

    /// Packet's `symbol_id` exceeds the per-chunk encode cap. Returned
    /// by the decoder when a peer floods the same chunk_id with too
    /// many distinct symbol_ids (anti-flood).
    #[error("symbol_id exceeds per-chunk cap: {got} > {max}")]
    SymbolIdOverflow {
        /// Received symbol_id.
        got: u32,
        /// Per-chunk encode cap.
        max: u32,
    },
}
