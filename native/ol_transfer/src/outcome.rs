//! Per-chunk outcome enum surfaced by [`crate::TransferEngine::fetch_many`].

use crate::error::TransferError;

/// Result of fetching a single chunk. `fetch_many` returns one of these
/// per requested `chunk_id`.
#[derive(Debug)]
pub enum FetchOutcome {
    /// Chunk was fetched from the peer and is now in the local store.
    Fetched {
        /// The `chunk_id` that was fetched.
        chunk_id: [u8; 32],
        /// Plaintext length recorded in the `chunk_log` header.
        length_plaintext: u32,
    },
    /// Chunk was already in the local store; no transport round trip.
    AlreadyLocal {
        /// The `chunk_id` that was found locally.
        chunk_id: [u8; 32],
    },
    /// Peer doesn't have the chunk.
    NotFound {
        /// The `chunk_id` the peer reported missing.
        chunk_id: [u8; 32],
    },
    /// Fetch failed for some other reason. Carries the underlying error.
    Error {
        /// The `chunk_id` whose fetch failed.
        chunk_id: [u8; 32],
        /// Reason the fetch failed.
        err: TransferError,
    },
}

impl FetchOutcome {
    /// The `chunk_id` this outcome refers to.
    #[must_use]
    pub fn chunk_id(&self) -> &[u8; 32] {
        match self {
            Self::Fetched { chunk_id, .. }
            | Self::AlreadyLocal { chunk_id }
            | Self::NotFound { chunk_id }
            | Self::Error { chunk_id, .. } => chunk_id,
        }
    }

    /// Convenience: did the outcome represent a successful fetch (either
    /// over the wire or from local cache)?
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Fetched { .. } | Self::AlreadyLocal { .. })
    }
}
