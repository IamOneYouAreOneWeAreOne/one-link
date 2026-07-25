//! WAL file header layout per [ADR-0007](../../../docs/decisions/0007-crash-only-wal-format.md).
//!
//! The first 64 bytes of every WAL file:
//!
//! ```text
//! +------+--------------+------------+-----------+-------+
//! | 0  8 | magic[8]     | version u32| log_kind  | rsvd  |
//! |      | "OL-CLOG1"   | LE         | u32 LE    | 40 0 |
//! |      | "OL-MLOG1"   |            |           |       |
//! +------+--------------+------------+-----------+-------+
//! 0      8              16           20          24      64
//! ```
//!
//! The header is fsync'd at file creation BEFORE the first record is
//! written, so recovery distinguishes "valid empty WAL file" (header
//! present, no records) from "corrupt or partial header" (refuse to load).

use std::io::Write;

use crate::error::WalError;

/// Length of the per-file header in bytes.
pub const FILE_HEADER_LEN: u64 = 64;

/// Array/slice form of [`FILE_HEADER_LEN`].
///
/// Keeping the in-memory and on-disk coordinate types explicit avoids
/// architecture-dependent integer casts at allocation boundaries.
pub(crate) const FILE_HEADER_LEN_USIZE: usize = 64;

/// Size at which a WAL file rotates to a new sequence number.
///
/// 256 MiB per ADR-0007. With ~64 KiB average chunk records, a `chunk_log`
/// file holds ~4K records; recovery scan is ~50 ms on `NVMe`.
pub const ROTATION_SIZE: u64 = 256 * 1024 * 1024;

/// Highest format version this build can read or write.
pub const FORMAT_VERSION: u32 = 1;

/// Magic for the chunk-content log file.
pub const MAGIC_CHUNK_LOG: [u8; 8] = *b"OL-CLOG1";

/// Magic for the manifest log file.
pub const MAGIC_MANIFEST_LOG: [u8; 8] = *b"OL-MLOG1";

/// Which log this file represents.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum LogKind {
    /// `chunk_log` (ADR-0003 layer 1: chunk content + AEAD frames).
    ChunkLog,
    /// `manifest_log` (ADR-0003 layer 8: manifest CRDT ops + capability events).
    ManifestLog,
}

impl LogKind {
    /// The 8-byte magic for this log kind.
    #[inline]
    #[must_use]
    pub const fn magic(self) -> [u8; 8] {
        match self {
            Self::ChunkLog => MAGIC_CHUNK_LOG,
            Self::ManifestLog => MAGIC_MANIFEST_LOG,
        }
    }

    /// The 32-bit identifier embedded in the file header.
    #[inline]
    #[must_use]
    pub const fn id(self) -> u32 {
        match self {
            Self::ChunkLog => 1,
            Self::ManifestLog => 2,
        }
    }

    /// Map from a 32-bit identifier back to the kind. Returns `None` for
    /// unknown values.
    #[must_use]
    pub const fn from_id(id: u32) -> Option<Self> {
        match id {
            1 => Some(Self::ChunkLog),
            2 => Some(Self::ManifestLog),
            _ => None,
        }
    }

    /// Map a magic byte string to the corresponding kind, if any.
    #[must_use]
    pub fn from_magic(magic: &[u8; 8]) -> Option<Self> {
        if magic == &MAGIC_CHUNK_LOG {
            Some(Self::ChunkLog)
        } else if magic == &MAGIC_MANIFEST_LOG {
            Some(Self::ManifestLog)
        } else {
            None
        }
    }
}

/// Write the 64-byte WAL file header.
///
/// Produces the canonical layout: 8-byte magic, 4-byte version (LE),
/// 4-byte `log_kind` id (LE), 8 bytes reserved-zero, plus 40 bytes
/// reserved-zero padding to reach the 64-byte boundary.
///
/// # Errors
///
/// Returns the underlying I/O error if the write fails.
pub fn write_header<W: Write>(mut w: W, kind: LogKind) -> Result<(), WalError> {
    let mut buf = [0u8; FILE_HEADER_LEN_USIZE];
    buf[..8].copy_from_slice(&kind.magic());
    buf[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    buf[12..16].copy_from_slice(&kind.id().to_le_bytes());
    // bytes [16..64] remain zero (reserved + padding)
    w.write_all(&buf)?;
    Ok(())
}

/// Validate a 64-byte WAL file header, returning the parsed [`LogKind`]
/// on success.
///
/// Used by [`crate::replay::replay_log_file`] before scanning records.
///
/// # Errors
///
/// - [`WalError::MagicMismatch`] if the magic doesn't match a known kind.
/// - [`WalError::UnsupportedVersion`] if the format version is in the
///   future.
/// - [`WalError::InvalidHeaderReserved`] if the reserved bytes are not zero.
pub fn parse_header(
    header: &[u8; FILE_HEADER_LEN_USIZE],
    path_for_diag: &str,
) -> Result<LogKind, WalError> {
    let mut magic = [0u8; 8];
    magic.copy_from_slice(&header[..8]);
    let kind = LogKind::from_magic(&magic).ok_or_else(|| WalError::MagicMismatch {
        path: path_for_diag.to_string(),
        got_hex: hex_lower(&magic),
        expected_hex: format!(
            "{} or {}",
            hex_lower(&MAGIC_CHUNK_LOG),
            hex_lower(&MAGIC_MANIFEST_LOG),
        ),
    })?;
    let mut version_bytes = [0u8; 4];
    version_bytes.copy_from_slice(&header[8..12]);
    let version = u32::from_le_bytes(version_bytes);
    if version > FORMAT_VERSION {
        return Err(WalError::UnsupportedVersion {
            path: path_for_diag.to_string(),
            got: version,
            supported: FORMAT_VERSION,
        });
    }
    let mut kind_bytes = [0u8; 4];
    kind_bytes.copy_from_slice(&header[12..16]);
    let log_kind_id = u32::from_le_bytes(kind_bytes);
    let by_id = LogKind::from_id(log_kind_id);
    if by_id != Some(kind) {
        // Magic and id disagree — corruption.
        return Err(WalError::InvalidHeaderReserved {
            path: path_for_diag.to_string(),
        });
    }
    if !header[16..].iter().all(|b| *b == 0) {
        return Err(WalError::InvalidHeaderReserved {
            path: path_for_diag.to_string(),
        });
    }
    Ok(kind)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip_chunk_log() {
        let mut buf = Vec::new();
        write_header(&mut buf, LogKind::ChunkLog).unwrap();
        assert_eq!(buf.len(), FILE_HEADER_LEN_USIZE);
        let mut header = [0u8; FILE_HEADER_LEN_USIZE];
        header.copy_from_slice(&buf);
        let kind = parse_header(&header, "test").unwrap();
        assert_eq!(kind, LogKind::ChunkLog);
    }

    #[test]
    fn header_round_trip_manifest_log() {
        let mut buf = Vec::new();
        write_header(&mut buf, LogKind::ManifestLog).unwrap();
        let mut header = [0u8; FILE_HEADER_LEN_USIZE];
        header.copy_from_slice(&buf);
        let kind = parse_header(&header, "test").unwrap();
        assert_eq!(kind, LogKind::ManifestLog);
    }

    #[test]
    fn rejects_unknown_magic() {
        let mut header = [0u8; FILE_HEADER_LEN_USIZE];
        header[..8].copy_from_slice(b"XX-ZZZ99");
        let result = parse_header(&header, "test");
        assert!(matches!(result, Err(WalError::MagicMismatch { .. })));
    }

    #[test]
    fn rejects_future_version() {
        let mut buf = Vec::new();
        write_header(&mut buf, LogKind::ChunkLog).unwrap();
        let mut header = [0u8; FILE_HEADER_LEN_USIZE];
        header.copy_from_slice(&buf);
        // Override version to FORMAT_VERSION + 1.
        let bumped = (FORMAT_VERSION + 1).to_le_bytes();
        header[8..12].copy_from_slice(&bumped);
        let result = parse_header(&header, "test");
        assert!(matches!(result, Err(WalError::UnsupportedVersion { .. })));
    }

    #[test]
    fn rejects_nonzero_reserved() {
        let mut buf = Vec::new();
        write_header(&mut buf, LogKind::ChunkLog).unwrap();
        let mut header = [0u8; FILE_HEADER_LEN_USIZE];
        header.copy_from_slice(&buf);
        header[20] = 0x01;
        let result = parse_header(&header, "test");
        assert!(matches!(
            result,
            Err(WalError::InvalidHeaderReserved { .. })
        ));
    }

    #[test]
    fn magic_strings_are_canonical() {
        assert_eq!(&MAGIC_CHUNK_LOG, b"OL-CLOG1");
        assert_eq!(&MAGIC_MANIFEST_LOG, b"OL-MLOG1");
    }

    #[test]
    fn id_round_trip() {
        for kind in [LogKind::ChunkLog, LogKind::ManifestLog] {
            assert_eq!(LogKind::from_id(kind.id()), Some(kind));
        }
    }

    #[test]
    fn unknown_id_returns_none() {
        assert_eq!(LogKind::from_id(0), None);
        assert_eq!(LogKind::from_id(99), None);
    }
}
