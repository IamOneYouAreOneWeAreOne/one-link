//! WAL record format per [ADR-0007](../../../docs/decisions/0007-crash-only-wal-format.md).
//!
//! Every record on disk:
//!
//! ```text
//! +------+-------+-------+----------+--- payload ---+----------+
//! | kind | flags | rsvd  | length   | <length bytes>| crc32c   |
//! | u8   | u8    | u16=0 | u32 LE   |               | u32 LE   |
//! +------+-------+-------+----------+---------------+----------+
//!  0      1       2       4          8               8+length
//! ```
//!
//! Total on-disk size = 8 (header) + `length` + 4 (crc) = 12 + payload.
//!
//! The CRC32-Castagnoli is computed over `header + payload` (12 + payload
//! bytes). The whole record is written via a single `pwrite()` so the
//! kernel cannot interleave a partial write with a concurrent writer's
//! payload.

use crate::error::WalError;

/// Record header length in bytes (kind + flags + reserved + length).
pub const RECORD_HEADER_LEN: usize = 8;

/// Record CRC trailer length in bytes.
pub const RECORD_TRAILER_LEN: usize = 4;

/// Maximum payload length. Records larger than this must be split by
/// the higher-level crates (`ol_chunk_store`) into multiple records.
///
/// 1 MiB is generous for a WAL record; the `chunk_log` will use up to
/// 256 KiB chunk + 84-byte header and a `manifest_log` record will
/// usually be well under 16 KiB.
pub const MAX_PAYLOAD_LEN: usize = 1024 * 1024;

/// Parsed record header.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RecordHeader {
    /// Record kind byte (per-log-kind interpretation; see ADR-0003).
    pub kind: u8,
    /// Record flags byte (per-log-kind interpretation).
    pub flags: u8,
    /// Payload length in bytes.
    pub length: u32,
}

/// A complete WAL record: header + payload bytes.
///
/// Owned form — used by replay results and by the writer's pending batch.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Record {
    /// Record kind.
    pub kind: u8,
    /// Record flags.
    pub flags: u8,
    /// Payload bytes (max [`MAX_PAYLOAD_LEN`]).
    pub payload: Vec<u8>,
}

impl Record {
    /// On-disk length in bytes for this record.
    #[inline]
    #[must_use]
    pub fn on_disk_len(&self) -> usize {
        RECORD_HEADER_LEN + self.payload.len() + RECORD_TRAILER_LEN
    }

    /// Encode this record into a single contiguous byte buffer suitable
    /// for one atomic `pwrite()` syscall.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::PayloadTooLarge`] if the payload exceeds
    /// [`MAX_PAYLOAD_LEN`].
    pub fn encode(&self) -> Result<Vec<u8>, WalError> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(WalError::PayloadTooLarge {
                got: self.payload.len(),
                max: MAX_PAYLOAD_LEN,
            });
        }
        let total = self.on_disk_len();
        let mut buf = Vec::with_capacity(total);
        buf.push(self.kind);
        buf.push(self.flags);
        buf.extend_from_slice(&[0u8, 0u8]); // reserved
        let length =
            u32::try_from(self.payload.len()).expect("MAX_PAYLOAD_LEN is representable as a u32");
        buf.extend_from_slice(&length.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        // CRC32C over header (8 bytes) + payload (`length` bytes).
        let crc = crc32c::crc32c(&buf);
        buf.extend_from_slice(&crc.to_le_bytes());
        debug_assert_eq!(buf.len(), total);
        Ok(buf)
    }
}

/// Parse a header from the first [`RECORD_HEADER_LEN`] bytes of a
/// record-on-disk slice.
///
/// # Errors
///
/// - [`WalError::InvalidRecordReserved`] if the reserved bytes are not zero.
pub fn parse_header(
    header: &[u8; RECORD_HEADER_LEN],
    offset: u64,
) -> Result<RecordHeader, WalError> {
    let kind = header[0];
    let flags = header[1];
    if header[2] != 0 || header[3] != 0 {
        return Err(WalError::InvalidRecordReserved { offset });
    }
    let length = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    if length as usize > MAX_PAYLOAD_LEN {
        return Err(WalError::PayloadTooLarge {
            got: length as usize,
            max: MAX_PAYLOAD_LEN,
        });
    }
    Ok(RecordHeader {
        kind,
        flags,
        length,
    })
}

/// Verify a record's CRC32C trailer against its header + payload.
///
/// `record_bytes` is the complete `[header || payload || trailer]` slice.
/// Returns `true` if the CRC matches.
#[must_use]
pub fn crc_valid(record_bytes: &[u8]) -> bool {
    if record_bytes.len() < RECORD_HEADER_LEN + RECORD_TRAILER_LEN {
        return false;
    }
    let trailer_offset = record_bytes.len() - RECORD_TRAILER_LEN;
    let body = &record_bytes[..trailer_offset];
    let trailer = &record_bytes[trailer_offset..];
    let expected = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let computed = crc32c::crc32c(body);
    expected == computed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(kind: u8, flags: u8, payload: &[u8]) -> Record {
        Record {
            kind,
            flags,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn encode_then_crc_valid() {
        let r = rec(0x01, 0x05, b"hello");
        let bytes = r.encode().unwrap();
        assert!(crc_valid(&bytes));
    }

    #[test]
    fn parsed_length_is_bounded_before_replay_allocation() {
        let mut header = [0u8; RECORD_HEADER_LEN];
        header[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            parse_header(&header, 0),
            Err(WalError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn header_parse_round_trip() {
        let r = rec(0x42, 0xAA, &[0u8; 100]);
        let bytes = r.encode().unwrap();
        let mut header = [0u8; RECORD_HEADER_LEN];
        header.copy_from_slice(&bytes[..RECORD_HEADER_LEN]);
        let parsed = parse_header(&header, 64).unwrap();
        assert_eq!(parsed.kind, 0x42);
        assert_eq!(parsed.flags, 0xAA);
        assert_eq!(parsed.length, 100);
    }

    #[test]
    fn empty_payload_round_trip() {
        let r = rec(0x10, 0x00, &[]);
        let bytes = r.encode().unwrap();
        assert_eq!(bytes.len(), RECORD_HEADER_LEN + RECORD_TRAILER_LEN);
        assert!(crc_valid(&bytes));
    }

    #[test]
    fn max_payload_round_trip() {
        let r = rec(0x20, 0x01, &vec![0xFFu8; MAX_PAYLOAD_LEN]);
        let bytes = r.encode().unwrap();
        assert!(crc_valid(&bytes));
    }

    #[test]
    fn oversize_payload_rejected() {
        let r = rec(0x30, 0x00, &vec![0u8; MAX_PAYLOAD_LEN + 1]);
        let result = r.encode();
        assert!(matches!(result, Err(WalError::PayloadTooLarge { .. })));
    }

    #[test]
    fn bit_flip_in_payload_invalidates_crc() {
        let r = rec(0x01, 0x00, b"important data");
        let mut bytes = r.encode().unwrap();
        bytes[RECORD_HEADER_LEN + 3] ^= 0x01; // flip a payload byte
        assert!(!crc_valid(&bytes));
    }

    #[test]
    fn bit_flip_in_header_invalidates_crc() {
        let r = rec(0x01, 0x00, b"important data");
        let mut bytes = r.encode().unwrap();
        bytes[0] ^= 0x01; // flip the kind byte
        assert!(!crc_valid(&bytes));
    }

    #[test]
    fn bit_flip_in_trailer_invalidates_crc() {
        let r = rec(0x01, 0x00, b"important data");
        let mut bytes = r.encode().unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01; // flip a CRC byte
        assert!(!crc_valid(&bytes));
    }

    #[test]
    fn header_with_nonzero_reserved_rejected() {
        let r = rec(0x01, 0x00, b"data");
        let mut bytes = r.encode().unwrap();
        bytes[2] = 0x42; // poison reserved byte
        let mut header = [0u8; RECORD_HEADER_LEN];
        header.copy_from_slice(&bytes[..RECORD_HEADER_LEN]);
        let result = parse_header(&header, 0);
        assert!(matches!(
            result,
            Err(WalError::InvalidRecordReserved { .. })
        ));
    }
}
