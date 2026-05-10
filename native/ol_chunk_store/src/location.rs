//! `ChunkLocation` — the in-memory index value for the chunk store.
//!
//! Maps `chunk_id` → on-disk location + per-chunk metadata needed for
//! decrypt without re-reading the chunk_log header.

use crate::stripe::StripeDescriptor;

/// Where a chunk lives within the chunk_log family.
///
/// Pure value type; `Copy` for cheap return-by-value from memtable lookup.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ChunkLocation {
    /// chunk_log file id (1-based; `000001.wal`, `000002.wal`, ...).
    pub file_id: u64,
    /// Byte offset within the file where the WAL record header starts.
    /// (Per ADR-0007: this is the offset of the kind byte; the
    /// per-record CRC32C is at the trailing edge.)
    pub wal_offset: u64,
    /// Plaintext length of the chunk in bytes.
    pub length_plaintext: u32,
    /// Ciphertext length (= plaintext length + frame_count * 16).
    pub length_ciphertext: u32,
    /// 16-byte ratchet_key_id for AEAD key reconstitution.
    pub ratchet_key_id: [u8; 16],
    /// Stripe descriptor (per ADR-0004).
    pub stripe_descriptor: StripeDescriptor,
}

impl ChunkLocation {
    /// Total on-disk record size including the WAL framing
    /// (8-byte WAL header + 80-byte chunk-record header + ciphertext +
    /// 4-byte CRC trailer).
    #[inline]
    #[must_use]
    pub fn on_disk_record_size(&self) -> u64 {
        const WAL_HEADER_LEN: u64 = 8;
        const WAL_TRAILER_LEN: u64 = 4;
        const CHUNK_RECORD_HEADER_LEN: u64 = 80;
        WAL_HEADER_LEN
            + CHUNK_RECORD_HEADER_LEN
            + u64::from(self.length_ciphertext)
            + WAL_TRAILER_LEN
    }
}
