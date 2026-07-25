//! Error types for `ol_chunk_store`.

use thiserror::Error;

/// Errors produced by chunk-store operations.
#[derive(Debug, Error)]
pub enum ChunkStoreError {
    /// Underlying WAL error (I/O, header validation, CRC, rotation).
    #[error("WAL: {0}")]
    Wal(#[from] ol_wal::WalError),

    /// Underlying I/O error not surfaced through the WAL.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    /// On-disk record body is malformed (length doesn't match header,
    /// reserved bytes non-zero, etc). Distinct from WAL CRC failure
    /// because the CRC may have validated but the higher-level body
    /// invariants don't.
    #[error("malformed record at chunk_log offset {offset}: {reason}")]
    MalformedRecord {
        /// Offset within the `chunk_log`.
        offset: u64,
        /// Specific reason.
        reason: &'static str,
    },

    /// Stripe descriptor field has invalid contents.
    #[error("invalid stripe descriptor: {0}")]
    InvalidStripeDescriptor(&'static str),

    /// Asked to read a chunk that's not in the store.
    #[error("chunk not found: {chunk_id_hex_prefix}")]
    ChunkNotFound {
        /// Hex prefix of the requested `chunk_id` (full hash redacted to
        /// keep error messages bounded).
        chunk_id_hex_prefix: String,
    },

    /// Manifest record references a `chunk_log_anchor` that doesn't
    /// resolve to a valid `chunk_log` location during recovery.
    #[error("dangling chunk_log_anchor in manifest record at offset {offset}: {anchor}")]
    DanglingChunkLogAnchor {
        /// Offset within the `manifest_log`.
        offset: u64,
        /// The anchor value found.
        anchor: u64,
    },

    /// A rotating-WAL coordinate cannot be represented by the packed u64
    /// manifest anchor (u32 file id + u32 in-file offset).
    #[error("chunk-log anchor coordinate out of range: file_id={file_id}, offset={offset}")]
    AnchorCoordinateOutOfRange {
        /// One-based chunk-log WAL file id.
        file_id: u64,
        /// Byte offset within the WAL file.
        offset: u64,
    },

    /// Tried to use the store after [`crate::store::ChunkStore::close`].
    #[error("chunk store is closed")]
    Closed,
}
