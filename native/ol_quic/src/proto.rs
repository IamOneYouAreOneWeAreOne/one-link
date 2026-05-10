//! QUIC stream wire framing per [ADR-0009].
//!
//! Every QUIC stream carries one [`Frame`]. The frame is encoded as
//! `[kind: u8][length: varint LE][payload: length bytes]`.
//!
//! The frame kind drives the maximum payload size:
//!
//! - **Bulk frames** (`ChunkResponse`, `ManifestRecord`) cap at
//!   [`MAX_BULK_FRAME_BYTES`] = 1 MiB. Matches the WAL record cap.
//! - **Control frames** (everything else) cap at
//!   [`MAX_CONTROL_FRAME_BYTES`] = 64 KiB.
//!
//! [ADR-0009]: ../../../docs/decisions/0009-quic-transport.md

use crate::error::QuicError;

/// Bulk frame max payload bytes.
pub const MAX_BULK_FRAME_BYTES: u64 = 1024 * 1024;

/// Control frame max payload bytes.
pub const MAX_CONTROL_FRAME_BYTES: u64 = 64 * 1024;

/// Frame kind byte per ADR-0009.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum FrameKind {
    /// Request a chunk by chunk_id. Payload = 32-byte chunk_id.
    ChunkRequest,
    /// Response carrying a chunk's full chunk_log record bytes.
    ChunkResponse,
    /// Echo of a `ChunkRequest` when the peer doesn't have the chunk.
    ChunkNotFound,
    /// Request manifest delta from a peer.
    ManifestSync,
    /// One manifest record bundled in a manifest-sync stream.
    ManifestRecord,
    /// Sentinel marking the end of a manifest-sync exchange.
    ManifestSyncEnd,
    /// Bloom filter of chunk_ids the sender has (ADR-0011 init).
    BloomFilter,
    /// Response listing chunk_ids the receiver still needs (ADR-0011).
    MissingChunks,
    /// Capability check against a peer's pairing record.
    CapabilityCheck,
    /// Acknowledgement of a capability check (accept / deny).
    CapabilityAck,
    /// Liveness probe; arbitrary echo payload.
    Ping,
    /// Reply to `Ping` echoing the same payload.
    Pong,
    /// Protocol-level error (unknown frame kind, malformed payload, etc).
    ProtoError,
    /// Graceful close marker.
    Close,
}

impl FrameKind {
    /// On-wire byte for this frame kind.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::ChunkRequest => 0x01,
            Self::ChunkResponse => 0x02,
            Self::ChunkNotFound => 0x03,
            Self::ManifestSync => 0x10,
            Self::ManifestRecord => 0x11,
            Self::ManifestSyncEnd => 0x12,
            Self::BloomFilter => 0x20,
            Self::MissingChunks => 0x21,
            Self::CapabilityCheck => 0x30,
            Self::CapabilityAck => 0x31,
            Self::Ping => 0xF0,
            Self::Pong => 0xF1,
            Self::ProtoError => 0xFE,
            Self::Close => 0xFF,
        }
    }

    /// Decode from the on-wire byte.
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::ChunkRequest),
            0x02 => Some(Self::ChunkResponse),
            0x03 => Some(Self::ChunkNotFound),
            0x10 => Some(Self::ManifestSync),
            0x11 => Some(Self::ManifestRecord),
            0x12 => Some(Self::ManifestSyncEnd),
            0x20 => Some(Self::BloomFilter),
            0x21 => Some(Self::MissingChunks),
            0x30 => Some(Self::CapabilityCheck),
            0x31 => Some(Self::CapabilityAck),
            0xF0 => Some(Self::Ping),
            0xF1 => Some(Self::Pong),
            0xFE => Some(Self::ProtoError),
            0xFF => Some(Self::Close),
            _ => None,
        }
    }

    /// Maximum payload byte length for this frame kind.
    #[inline]
    #[must_use]
    pub const fn max_payload_bytes(self) -> u64 {
        match self {
            // Bulk frames carry full chunk_log / manifest_log records.
            Self::ChunkResponse | Self::ManifestRecord => MAX_BULK_FRAME_BYTES,
            // Everything else is control / fixed-size.
            _ => MAX_CONTROL_FRAME_BYTES,
        }
    }
}

/// A complete frame ready to be written to a QUIC stream.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Frame {
    /// Frame kind.
    pub kind: FrameKind,
    /// Frame payload bytes (length-prefixed on the wire).
    pub payload: Vec<u8>,
}

impl Frame {
    /// Construct a frame, validating the payload length against the
    /// per-kind maximum.
    ///
    /// # Errors
    ///
    /// Returns [`QuicError::FrameTooLarge`] if `payload.len()` exceeds
    /// [`FrameKind::max_payload_bytes`] for `kind`.
    pub fn new(kind: FrameKind, payload: Vec<u8>) -> Result<Self, QuicError> {
        let max = kind.max_payload_bytes();
        if payload.len() as u64 > max {
            return Err(QuicError::FrameTooLarge {
                kind: kind.as_u8(),
                got: payload.len() as u64,
                max,
            });
        }
        Ok(Self { kind, payload })
    }

    /// Encode the frame to its on-wire byte representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let len = self.payload.len() as u64;
        let mut buf = Vec::with_capacity(1 + varint_len(len) + self.payload.len());
        buf.push(self.kind.as_u8());
        encode_varint(&mut buf, len);
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// On-wire byte length: kind byte + varint length + payload.
    #[must_use]
    pub fn on_wire_len(&self) -> usize {
        1 + varint_len(self.payload.len() as u64) + self.payload.len()
    }
}

// ─────────────────────────── varint helpers ────────────────────────────
//
// We use a simple unsigned-LEB128 (Protobuf-compatible) varint to encode
// the frame length. 1-9 bytes; covers up to 2^63. For our 1 MiB cap, we
// always end up with 1-3 bytes.

/// Number of bytes the varint encoding takes for `n`.
#[must_use]
pub fn varint_len(mut n: u64) -> usize {
    let mut len = 1;
    while n >= 0x80 {
        n >>= 7;
        len += 1;
    }
    len
}

/// Encode `n` as an unsigned LEB128 varint into `buf`.
pub fn encode_varint(buf: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        buf.push((n as u8) | 0x80);
        n >>= 7;
    }
    buf.push(n as u8);
}

/// Decode an unsigned LEB128 varint from `buf` starting at `cursor`.
/// Returns `(value, bytes_consumed)`.
///
/// # Errors
///
/// Returns [`QuicError::MalformedFrame`] if the buffer ends mid-varint
/// or the value exceeds 9 bytes (more than `u64::MAX`).
pub fn decode_varint(buf: &[u8], cursor: usize) -> Result<(u64, usize), QuicError> {
    let mut result = 0u64;
    let mut shift = 0u32;
    let mut consumed = 0usize;
    loop {
        if cursor + consumed >= buf.len() {
            return Err(QuicError::MalformedFrame {
                offset: (cursor + consumed) as u64,
                reason: "varint truncated",
            });
        }
        let b = buf[cursor + consumed];
        consumed += 1;
        let chunk = u64::from(b & 0x7F);
        // Reject overflow (varint > 9 bytes for u64).
        if shift >= 63 && chunk > 1 {
            return Err(QuicError::MalformedFrame {
                offset: (cursor + consumed) as u64,
                reason: "varint overflow",
            });
        }
        result |= chunk << shift;
        if b & 0x80 == 0 {
            return Ok((result, consumed));
        }
        shift += 7;
        if shift > 63 {
            return Err(QuicError::MalformedFrame {
                offset: (cursor + consumed) as u64,
                reason: "varint overflow",
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_kind_round_trip() {
        for kind in [
            FrameKind::ChunkRequest,
            FrameKind::ChunkResponse,
            FrameKind::ChunkNotFound,
            FrameKind::ManifestSync,
            FrameKind::ManifestRecord,
            FrameKind::ManifestSyncEnd,
            FrameKind::BloomFilter,
            FrameKind::MissingChunks,
            FrameKind::CapabilityCheck,
            FrameKind::CapabilityAck,
            FrameKind::Ping,
            FrameKind::Pong,
            FrameKind::ProtoError,
            FrameKind::Close,
        ] {
            assert_eq!(FrameKind::from_u8(kind.as_u8()), Some(kind));
        }
    }

    #[test]
    fn unknown_kind_returns_none() {
        assert_eq!(FrameKind::from_u8(0x00), None);
        assert_eq!(FrameKind::from_u8(0x99), None);
    }

    #[test]
    fn frame_max_payload_caps() {
        assert_eq!(
            FrameKind::ChunkResponse.max_payload_bytes(),
            MAX_BULK_FRAME_BYTES
        );
        assert_eq!(
            FrameKind::ManifestRecord.max_payload_bytes(),
            MAX_BULK_FRAME_BYTES
        );
        assert_eq!(
            FrameKind::Ping.max_payload_bytes(),
            MAX_CONTROL_FRAME_BYTES
        );
    }

    #[test]
    fn frame_rejects_oversized_payload() {
        let payload = vec![0u8; (MAX_CONTROL_FRAME_BYTES + 1) as usize];
        let result = Frame::new(FrameKind::Ping, payload);
        assert!(matches!(result, Err(QuicError::FrameTooLarge { .. })));
    }

    #[test]
    fn varint_round_trip_small() {
        for n in [0u64, 1, 127, 128, 16383, 16384, 2097151, 2097152] {
            let mut buf = Vec::new();
            encode_varint(&mut buf, n);
            let (decoded, consumed) = decode_varint(&buf, 0).unwrap();
            assert_eq!(decoded, n);
            assert_eq!(consumed, buf.len());
            assert_eq!(consumed, varint_len(n));
        }
    }

    #[test]
    fn varint_round_trip_large() {
        for n in [u64::MAX / 2, u64::MAX] {
            let mut buf = Vec::new();
            encode_varint(&mut buf, n);
            let (decoded, _consumed) = decode_varint(&buf, 0).unwrap();
            assert_eq!(decoded, n);
        }
    }

    #[test]
    fn varint_truncated_rejected() {
        let buf = vec![0x80u8, 0x80]; // never terminates
        let result = decode_varint(&buf, 0);
        assert!(matches!(result, Err(QuicError::MalformedFrame { .. })));
    }

    #[test]
    fn frame_encode_then_decode() {
        let f = Frame::new(FrameKind::ChunkRequest, vec![0x42u8; 32]).unwrap();
        let encoded = f.encode();
        // First byte is the kind.
        assert_eq!(encoded[0], FrameKind::ChunkRequest.as_u8());
        // The encoded byte length matches on_wire_len.
        assert_eq!(encoded.len(), f.on_wire_len());

        // Decode manually: skip kind byte, read varint, read payload.
        let kind = FrameKind::from_u8(encoded[0]).unwrap();
        assert_eq!(kind, FrameKind::ChunkRequest);
        let (length, varint_consumed) = decode_varint(&encoded, 1).unwrap();
        assert_eq!(length, 32);
        let payload_start = 1 + varint_consumed;
        assert_eq!(&encoded[payload_start..], &f.payload[..]);
    }

    #[test]
    fn empty_payload_round_trip() {
        let f = Frame::new(FrameKind::Close, vec![]).unwrap();
        let encoded = f.encode();
        // 1 byte kind + 1 byte varint zero = 2 bytes total.
        assert_eq!(encoded.len(), 2);
        assert_eq!(encoded, vec![FrameKind::Close.as_u8(), 0u8]);
    }

    #[test]
    fn max_bulk_payload_round_trip() {
        let payload = vec![0xCDu8; MAX_BULK_FRAME_BYTES as usize];
        let f = Frame::new(FrameKind::ChunkResponse, payload.clone()).unwrap();
        let encoded = f.encode();
        // Decode the length back.
        let (length, consumed) = decode_varint(&encoded, 1).unwrap();
        assert_eq!(length, MAX_BULK_FRAME_BYTES);
        assert_eq!(&encoded[1 + consumed..], &payload[..]);
    }
}
