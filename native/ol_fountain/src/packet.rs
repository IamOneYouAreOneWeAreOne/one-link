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

use crate::decoder::{
    MAX_ENCODED_PER_CHUNK, MAX_SOURCE_BYTES, MAX_SOURCE_SYMBOLS_PER_CHUNK, MAX_SYMBOL_LEN,
};
use crate::error::FountainError;

/// Length of a fountain packet header on the wire.
pub const PACKET_HEADER_LEN: usize = 44;

/// A parsed fountain packet ready to feed into an [`crate::decoder::LtDecoder`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FountainPacket {
    /// 32-byte `chunk_id` this packet belongs to.
    pub chunk_id: [u8; 32],
    /// K = source-symbol count for the chunk.
    pub k: u32,
    /// Monotonically-increasing `symbol_id` from the sender.
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

    /// Encode to wire bytes after validating all resource and shape fields.
    ///
    /// # Errors
    ///
    /// Returns the same bounded-shape errors as [`Self::validate`].
    pub fn encode(&self) -> Result<Vec<u8>, FountainError> {
        self.validate()?;
        let mut out = Vec::with_capacity(PACKET_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.chunk_id);
        out.extend_from_slice(&self.k.to_le_bytes());
        out.extend_from_slice(&self.symbol_id.to_le_bytes());
        out.extend_from_slice(&self.source_length.to_le_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Validate all attacker-controlled resource and shape fields.
    /// Callers constructing packets directly should invoke this before
    /// transport; [`Self::decode`] always invokes it.
    pub fn validate(&self) -> Result<(), FountainError> {
        if self.k == 0 || self.k > MAX_SOURCE_SYMBOLS_PER_CHUNK {
            return Err(FountainError::InvalidSourceSymbolCount {
                got: self.k,
                max: MAX_SOURCE_SYMBOLS_PER_CHUNK,
            });
        }
        if self.symbol_id >= MAX_ENCODED_PER_CHUNK {
            return Err(FountainError::SymbolIdOverflow {
                got: self.symbol_id,
                max: MAX_ENCODED_PER_CHUNK,
            });
        }
        if self.source_length == 0 {
            return Err(FountainError::InvalidSymbolLen(
                "source_length must be non-zero",
            ));
        }
        if self.source_length as usize > MAX_SOURCE_BYTES {
            return Err(FountainError::SourceTooLarge {
                got: self.source_length as usize,
                max: MAX_SOURCE_BYTES,
            });
        }
        if self.payload.is_empty() || self.payload.len() > MAX_SYMBOL_LEN {
            return Err(FountainError::InvalidSymbolLen(
                "packet payload must be in 1..=MAX_SYMBOL_LEN",
            ));
        }
        let padded_len = (self.k as usize)
            .checked_mul(self.payload.len())
            .ok_or(FountainError::InvalidSymbolLen("k * symbol_len overflow"))?;
        if self.source_length as usize > padded_len {
            return Err(FountainError::InvalidSymbolLen(
                "source_len > k * symbol_len",
            ));
        }
        Ok(())
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
        let mut field = [0u8; 4];
        field.copy_from_slice(&bytes[32..36]);
        let k = u32::from_le_bytes(field);
        field.copy_from_slice(&bytes[36..40]);
        let symbol_id = u32::from_le_bytes(field);
        field.copy_from_slice(&bytes[40..44]);
        let source_length = u32::from_le_bytes(field);
        let payload = bytes[PACKET_HEADER_LEN..].to_vec();
        let packet = Self {
            chunk_id,
            k,
            symbol_id,
            source_length,
            payload,
        };
        packet.validate()?;
        Ok(packet)
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
        let encoded = p.encode().unwrap();
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
        let r = p.encode();
        assert!(matches!(r, Err(FountainError::InvalidSymbolLen(_))));
    }

    #[test]
    fn rejects_zero_k() {
        let mut p = sample_packet(1024);
        p.k = 0;
        let r = p.encode();
        assert!(matches!(
            r,
            Err(FountainError::InvalidSourceSymbolCount { .. })
        ));
    }

    #[test]
    fn rejects_resource_exhaustion_headers() {
        let mut packet = sample_packet(1024);
        packet.k = u32::MAX;
        assert!(matches!(
            packet.encode(),
            Err(FountainError::InvalidSourceSymbolCount { .. })
        ));

        let mut packet = sample_packet(1024);
        packet.source_length = u32::MAX;
        assert!(matches!(
            packet.encode(),
            Err(FountainError::SourceTooLarge { .. })
        ));
    }
}
