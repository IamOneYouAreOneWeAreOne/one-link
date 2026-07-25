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

    /// The source buffer exceeds the per-chunk resource bound.
    #[error("source length exceeds per-chunk cap: {got} > {max}")]
    SourceTooLarge {
        /// Source bytes requested or declared.
        got: usize,
        /// Maximum source bytes accepted by one decoder.
        max: usize,
    },

    /// K is zero or exceeds the per-chunk source-symbol bound.
    #[error("invalid source-symbol count k={got}; require 1..={max}")]
    InvalidSourceSymbolCount {
        /// K requested or declared by the peer.
        got: u32,
        /// Maximum supported K.
        max: u32,
    },

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
    /// by the decoder when a peer floods the same `chunk_id` with too
    /// many distinct `symbol_ids` (anti-flood).
    #[error("symbol_id exceeds per-chunk cap: {got} > {max}")]
    SymbolIdOverflow {
        /// Received `symbol_id`.
        got: u32,
        /// Per-chunk encode cap.
        max: u32,
    },

    /// Holding another distinct encoded packet would exceed the
    /// decoder's aggregate payload-memory budget.
    #[error("decoder payload budget exceeded: {got} bytes > max {max} bytes")]
    DecoderMemoryLimit {
        /// Bytes that would be retained after accepting the packet.
        got: usize,
        /// Aggregate retained-payload cap.
        max: usize,
    },
}
