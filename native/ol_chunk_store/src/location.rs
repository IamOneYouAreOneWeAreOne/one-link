//! `ChunkLocation` — the in-memory index value for the chunk store.
//!
//! Maps `chunk_id` → on-disk location + per-chunk metadata needed for
//! decrypt without re-reading the `chunk_log` header.

use crate::stripe::StripeDescriptor;
use crate::ChunkStoreError;

/// Number of low bits reserved for the in-file byte offset in a manifest
/// chunk-log anchor. WAL files rotate at 256 MiB, so u32 is ample.
const ANCHOR_OFFSET_BITS: u32 = 32;

/// Pack a rotating chunk-log coordinate into the existing u64 manifest field.
///
/// Layout: `file_id:u32 || wal_offset:u32`. This repairs the original
/// implementation's bare-offset ambiguity without changing the 52-byte
/// on-disk manifest header. Existing pre-rotation anchors are decoded as
/// legacy file-1 offsets by [`decode_chunk_log_anchor`].
pub fn encode_chunk_log_anchor(file_id: u64, wal_offset: u64) -> Result<u64, ChunkStoreError> {
    if file_id == 0 || file_id > u64::from(u32::MAX) || wal_offset > u64::from(u32::MAX) {
        return Err(ChunkStoreError::AnchorCoordinateOutOfRange {
            file_id,
            offset: wal_offset,
        });
    }
    Ok((file_id << ANCHOR_OFFSET_BITS) | wal_offset)
}

/// Decode a packed chunk-log anchor into `(file_id, wal_offset)`.
///
/// `0` means "no chunk reference". Anchors written by the old
/// implementation have a zero high word and are interpreted as file 1.
#[must_use]
pub fn decode_chunk_log_anchor(anchor: u64) -> Option<(u64, u64)> {
    if anchor == 0 {
        return None;
    }
    let encoded_file_id = anchor >> ANCHOR_OFFSET_BITS;
    let offset = anchor & u64::from(u32::MAX);
    Some((
        if encoded_file_id == 0 {
            1
        } else {
            encoded_file_id
        },
        offset,
    ))
}

/// Where a chunk lives within the `chunk_log` family.
///
/// Pure value type; `Copy` for cheap return-by-value from memtable lookup.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ChunkLocation {
    /// `chunk_log` file id (1-based; `000001.wal`, `000002.wal`, ...).
    pub file_id: u64,
    /// Byte offset within the file where the WAL record header starts.
    /// (Per ADR-0007: this is the offset of the kind byte; the
    /// per-record CRC32C is at the trailing edge.)
    pub wal_offset: u64,
    /// Plaintext length of the chunk in bytes.
    pub length_plaintext: u32,
    /// Ciphertext length (one atomic tag or one tag per streaming frame).
    pub length_ciphertext: u32,
    /// 16-byte `ratchet_key_id` for AEAD key reconstitution.
    pub ratchet_key_id: [u8; 16],
    /// Stripe descriptor (per ADR-0004).
    pub stripe_descriptor: StripeDescriptor,
}

impl ChunkLocation {
    /// Globally-unique manifest anchor for this rotating-WAL location.
    pub fn manifest_anchor(&self) -> Result<u64, ChunkStoreError> {
        encode_chunk_log_anchor(self.file_id, self.wal_offset)
    }

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
