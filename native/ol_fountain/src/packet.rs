//! On-wire packet format for LT fountain transfer per ADR-0015.
//!
//! Wire shape:
//!
//! ```text
//! +----------+----------+---------+-------------+
//! | chunk_id | k        | symbol  | source      | encoded_payload
//! | 32B      | u32 LE   | u32 LE  | u32 LE      | (symbol_len B)
//! +----------+----------+---------+-------------+
//!   0..32      32..36     36..40    40..44        44..
//! ```
//!
//! 44-byte header + `symbol_len` byte payload. `source_length` is the
//! original chunk plaintext length (`length_plaintext` in ADR-0003).

use crate::error::FountainError;

/// Length of a fountain packet header on the wire.
pub const PACKET_HEADER_LEN: usize = 44;

/// A parsed fountain packet ready to feed into an [`crate::decoder::LtDecoder`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FountainPacket {
    /// 32-byte chunk_id this packet belongs to.
    pub chunk_id: [u8; 32],
    /// K = source-symbol count for the chunk.
    pub k: u32,
    /// Monotonically-increasing symbol_id from the sender.
    pub symbol_id: u32,
    /// Original chunk plaintext length (so the decoder can trim padding).
    pub source_length: u32,
    /// LT-encoded payload bytes.
    pub payload: Vec<u8>,
}

impl FountainPacket {
    /// Construct a new packet.
    #[must_use]
    pub fn new(
        chunk_id: [u8; 32],
        k: u32,
        symbol_id: u32,
        source_length: u32,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            chunk_id,
            k,
            symbol_id,
            source_length,
            payload,
        }
    }

    /// Encode to wire bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PACKET_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.chunk_id);
        out.extend_from_slice(&self.k.to_le_bytes());
        out.extend_from_slice(&self.symbol_id.to_le_bytes());
        out.extend_from_slice(&self.source_length.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode from wire bytes.
    ///
    /// # Errors
    ///
    /// [`FountainError::MalformedPacket`] if the buffer is shorter than
    /// the header.
    pub fn decode(bytes: &[u8]) -> Result<Self, FountainError> {
        if bytes.len() < PACKET_HEADER_LEN {
            return Err(FountainError::MalformedPacket("packet shorter than header"));
        }
        let mut chunk_id = [0u8; 32];
        chunk_id.copy_from_slice(&bytes[0..32]);
        let k = u32::from_le_bytes(bytes[32..36].try_into().expect("4 bytes"));
        let symbol_id = u32::from_le_bytes(bytes[36..40].try_into().expect("4 bytes"));
        let source_length = u32::from_le_bytes(bytes[40..44].try_into().expect("4 bytes"));
        if k == 0 {
            return Err(FountainError::MalformedPacket("k must be > 0"));
        }
        let payload = bytes[PACKET_HEADER_LEN..].to_vec();
        if payload.is_empty() {
            return Err(FountainError::MalformedPacket("empty payload"));
        }
        Ok(Self {
            chunk_id,
            k,
            symbol_id,
            source_length,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_packet(symbol_len: usize) -> FountainPacket {
        FountainPacket {
            chunk_id: [0xABu8; 32],
            k: 64,
            symbol_id: 42,
            source_length: 64 * 1024,
            payload: vec![0xCDu8; symbol_len],
        }
    }

    #[test]
    fn round_trip() {
        let p = sample_packet(1024);
        let encoded = p.encode();
        assert_eq!(encoded.len(), PACKET_HEADER_LEN + 1024);
        let parsed = FountainPacket::decode(&encoded).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn rejects_short() {
        let r = FountainPacket::decode(&[0u8; 20]);
        assert!(matches!(r, Err(FountainError::MalformedPacket(_))));
    }

    #[test]
    fn rejects_empty_payload() {
        let p = sample_packet(0);
        let encoded = p.encode();
        let r = FountainPacket::decode(&encoded);
        assert!(matches!(r, Err(FountainError::MalformedPacket(_))));
    }

    #[test]
    fn rejects_zero_k() {
        let mut p = sample_packet(1024);
        p.k = 0;
        let encoded = p.encode();
        let r = FountainPacket::decode(&encoded);
        assert!(matches!(r, Err(FountainError::MalformedPacket(_))));
    }
}
