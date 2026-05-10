//! Manifest-log record format per [ADR-0003] + [ADR-0005].
//!
//! Manifest records are wrapped in [`ol_wal`] records the same way
//! chunk records are. The WAL kind byte distinguishes manifest record
//! types; the WAL flags byte carries record-specific bits; the payload
//! is `[ManifestRecordHeader (52 bytes) || canonical-encoded body]`.
//!
//! Header layout per [ADR-0003]:
//!
//! ```text
//! +--------+------------------------------------------------------+
//! | Offset | Field                                                |
//! +--------+------------------------------------------------------+
//! | 0      | hlc_timestamp: u64 LE (hybrid logical clock)         |
//! | 8      | actor_id: [u8; 32] (peer fingerprint / CRDT actor)   |
//! | 40     | chunk_log_anchor: u64 LE (offset within chunk_log    |
//! |        |   that this manifest commit pairs with — ADR-0005)  |
//! | 48     | reserved: [u8; 4] (must be zero)                     |
//! +--------+------------------------------------------------------+
//! Total: 52 bytes.
//! ```
//!
//! [ADR-0003]: ../../../docs/decisions/0003-on-disk-format.md
//! [ADR-0005]: ../../../docs/decisions/0005-manifest-wal-coupling.md

use crate::error::ChunkStoreError;

/// Length of the manifest-record header in bytes.
pub const MANIFEST_RECORD_HEADER_LEN: usize = 52;

/// Kind byte for the manifest-log WAL record.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ManifestRecordKind {
    /// 0x10: a CRDT op on a folder manifest.
    ManifestVersion,
    /// 0x11: capability grant.
    CapabilityGrant,
    /// 0x12: capability revocation.
    CapabilityRevoke,
    /// 0x13: Merkle revocation log entry.
    MerkleRevocationLogEntry,
    /// 0x14: share-link record.
    ShareLink,
    /// 0xFF: rotation sentinel.
    Sentinel,
}

impl ManifestRecordKind {
    /// On-disk byte.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::ManifestVersion => 0x10,
            Self::CapabilityGrant => 0x11,
            Self::CapabilityRevoke => 0x12,
            Self::MerkleRevocationLogEntry => 0x13,
            Self::ShareLink => 0x14,
            Self::Sentinel => 0xFF,
        }
    }

    /// Decode from the on-disk byte.
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x10 => Some(Self::ManifestVersion),
            0x11 => Some(Self::CapabilityGrant),
            0x12 => Some(Self::CapabilityRevoke),
            0x13 => Some(Self::MerkleRevocationLogEntry),
            0x14 => Some(Self::ShareLink),
            0xFF => Some(Self::Sentinel),
            _ => None,
        }
    }
}

/// A complete manifest-log record (header + body) ready for the WAL.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ManifestRecord {
    /// Record kind.
    pub kind: ManifestRecordKind,
    /// Per-record-kind flags byte (interpreted by the layer above).
    pub flags: u8,
    /// Hybrid logical clock timestamp.
    pub hlc_timestamp: u64,
    /// 32-byte peer fingerprint (CRDT actor_id).
    pub actor_id: [u8; 32],
    /// Offset within the chunk_log that this manifest commit pairs with.
    /// Zero for records that don't reference a chunk (capability events,
    /// share-links, etc).
    pub chunk_log_anchor: u64,
    /// Canonical-encoded record body (per [`std.codec.canon`] design ref).
    pub body: Vec<u8>,
}

impl ManifestRecord {
    /// Encode to a (kind_byte, flags_byte, payload_bytes) tuple.
    pub fn encode(&self) -> (u8, u8, Vec<u8>) {
        let mut payload = Vec::with_capacity(MANIFEST_RECORD_HEADER_LEN + self.body.len());
        payload.extend_from_slice(&self.hlc_timestamp.to_le_bytes());
        payload.extend_from_slice(&self.actor_id);
        payload.extend_from_slice(&self.chunk_log_anchor.to_le_bytes());
        payload.extend_from_slice(&[0u8; 4]); // reserved
        debug_assert_eq!(payload.len(), MANIFEST_RECORD_HEADER_LEN);
        payload.extend_from_slice(&self.body);
        (self.kind.as_u8(), self.flags, payload)
    }

    /// Decode from a (kind_byte, flags_byte, payload_bytes) tuple.
    ///
    /// # Errors
    ///
    /// - [`ChunkStoreError::MalformedRecord`] if the payload is too short
    ///   or the reserved bytes are non-zero.
    pub fn decode(kind: u8, flags: u8, payload: &[u8]) -> Result<Self, ChunkStoreError> {
        let kind = ManifestRecordKind::from_u8(kind).ok_or(ChunkStoreError::MalformedRecord {
            offset: 0,
            reason: "unknown manifest-record kind",
        })?;
        if payload.len() < MANIFEST_RECORD_HEADER_LEN {
            return Err(ChunkStoreError::MalformedRecord {
                offset: 0,
                reason: "payload shorter than manifest-record header",
            });
        }
        let hlc_timestamp = u64::from_le_bytes(payload[0..8].try_into().expect("8 bytes"));
        let mut actor_id = [0u8; 32];
        actor_id.copy_from_slice(&payload[8..40]);
        let chunk_log_anchor = u64::from_le_bytes(payload[40..48].try_into().expect("8 bytes"));
        if !payload[48..52].iter().all(|b| *b == 0) {
            return Err(ChunkStoreError::MalformedRecord {
                offset: 0,
                reason: "manifest header reserved bytes non-zero",
            });
        }
        let body = payload[MANIFEST_RECORD_HEADER_LEN..].to_vec();
        Ok(Self {
            kind,
            flags,
            hlc_timestamp,
            actor_id,
            chunk_log_anchor,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(kind: ManifestRecordKind) -> ManifestRecord {
        ManifestRecord {
            kind,
            flags: 0x05,
            hlc_timestamp: 0x1234_5678_9ABC_DEF0,
            actor_id: [0x77u8; 32],
            chunk_log_anchor: 0xDEAD_BEEF_CAFE_F00D,
            body: b"canonical-encoded body bytes".to_vec(),
        }
    }

    #[test]
    fn round_trip_manifest_version() {
        let r = sample(ManifestRecordKind::ManifestVersion);
        let (kind, flags, payload) = r.encode();
        let parsed = ManifestRecord::decode(kind, flags, &payload).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn round_trip_each_kind() {
        for kind in [
            ManifestRecordKind::ManifestVersion,
            ManifestRecordKind::CapabilityGrant,
            ManifestRecordKind::CapabilityRevoke,
            ManifestRecordKind::MerkleRevocationLogEntry,
            ManifestRecordKind::ShareLink,
            ManifestRecordKind::Sentinel,
        ] {
            let r = sample(kind);
            let (kind_byte, flags, payload) = r.encode();
            let parsed = ManifestRecord::decode(kind_byte, flags, &payload).unwrap();
            assert_eq!(parsed.kind, kind);
        }
    }

    #[test]
    fn round_trip_empty_body() {
        let mut r = sample(ManifestRecordKind::CapabilityGrant);
        r.body.clear();
        let (kind, flags, payload) = r.encode();
        assert_eq!(payload.len(), MANIFEST_RECORD_HEADER_LEN);
        let parsed = ManifestRecord::decode(kind, flags, &payload).unwrap();
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn rejects_unknown_kind() {
        let r = sample(ManifestRecordKind::ManifestVersion);
        let (_kind, flags, payload) = r.encode();
        let result = ManifestRecord::decode(0x99, flags, &payload);
        assert!(matches!(
            result,
            Err(ChunkStoreError::MalformedRecord { .. })
        ));
    }

    #[test]
    fn rejects_payload_too_short() {
        let result = ManifestRecord::decode(0x10, 0, &[0u8; 10]);
        assert!(matches!(
            result,
            Err(ChunkStoreError::MalformedRecord { .. })
        ));
    }

    #[test]
    fn rejects_nonzero_reserved() {
        let r = sample(ManifestRecordKind::ManifestVersion);
        let (kind, flags, mut payload) = r.encode();
        payload[50] = 0x42; // poison reserved byte (in [48..52] range)
        let result = ManifestRecord::decode(kind, flags, &payload);
        assert!(matches!(
            result,
            Err(ChunkStoreError::MalformedRecord { .. })
        ));
    }
}
