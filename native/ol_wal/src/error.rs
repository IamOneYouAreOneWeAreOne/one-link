//! Error types for `ol_wal`.

use std::io;

use thiserror::Error;

/// Errors produced by WAL operations.
#[derive(Debug, Error)]
pub enum WalError {
    /// Underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// File header magic did not match.
    #[error("WAL file at {path}: magic mismatch (got {got_hex}, expected {expected_hex})")]
    MagicMismatch {
        /// File path (for diagnostics).
        path: String,
        /// Hex of the 8 bytes we found.
        got_hex: String,
        /// Hex of the 8 bytes we expected (per [`crate::file::LogKind`]).
        expected_hex: String,
    },

    /// File header version is newer than this build supports.
    #[error("WAL file at {path}: format version {got} > supported {supported}")]
    UnsupportedVersion {
        /// File path (for diagnostics).
        path: String,
        /// Version we found.
        got: u32,
        /// Highest version this build can read.
        supported: u32,
    },

    /// File header reserved bytes were not zero.
    #[error("WAL file at {path}: reserved header bytes are non-zero")]
    InvalidHeaderReserved {
        /// File path.
        path: String,
    },

    /// Record payload exceeds the per-record maximum (1 MiB).
    #[error("record payload too large: {got} > max {max}")]
    PayloadTooLarge {
        /// Length received.
        got: usize,
        /// Hard cap.
        max: usize,
    },

    /// One encoded record cannot fit in an otherwise-empty WAL file.
    #[error("WAL file would exceed rotation cap of {cap} bytes (current {current})")]
    RotationCapExceeded {
        /// Current file size.
        current: u64,
        /// Cap from [`crate::file::ROTATION_SIZE`].
        cap: u64,
    },

    /// Record reserved bytes (after `flags`) were not zero — corruption.
    #[error("WAL record at offset {offset}: reserved bytes are non-zero")]
    InvalidRecordReserved {
        /// Offset within the file.
        offset: u64,
    },

    /// Corruption appeared before the active log's crash-repairable tail.
    #[error("non-tail WAL corruption at {path}:{offset}; refusing destructive truncation")]
    NonTailCorruption {
        /// Corrupt WAL path.
        path: String,
        /// First corrupt record offset.
        offset: u64,
    },
}
