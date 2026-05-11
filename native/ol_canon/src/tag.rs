//! Self-describing type-tag discriminants for the canonical wire
//! format. Values mirror `coherence_lang/std/codec/canon.cl` byte for
//! byte so a future codegen pass can replace this enum with a
//! generated copy without breaking existing encoded blobs.

use crate::error::DecodeError;

/// Discriminant byte that precedes every encoded value on the wire.
///
/// Holes in the value space (e.g. 0x03–0x0F between `True` and `UInt`)
/// are reserved for future tags; decoders MUST reject unknown tags
/// rather than silently skipping bytes.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeTag {
    /// Null value (no payload).
    Null = 0x00,
    /// Boolean `false` (no payload).
    False = 0x01,
    /// Boolean `true` (no payload).
    True = 0x02,
    /// Unsigned int, followed by an LEB128 varint.
    UInt = 0x10,
    /// Signed int, followed by a zigzag LEB128 varint.
    Int = 0x11,
    /// IEEE 754 binary32, followed by 4 big-endian bytes.
    Float32 = 0x20,
    /// IEEE 754 binary64, followed by 8 big-endian bytes.
    Float64 = 0x21,
    /// UTF-8 string, length-prefixed varint then bytes.
    String = 0x30,
    /// Raw byte slice, length-prefixed varint then bytes.
    Bytes = 0x31,
    /// Array / list, length-prefixed varint then N encoded values.
    Array = 0x40,
    /// Map, length-prefixed varint then N (key, value) pairs.
    /// **Caller MUST pre-sort keys** for canonical determinism.
    Map = 0x50,
    /// Struct: tag, type-id varint, field-count varint, then fields.
    Struct = 0x60,
    /// Enum variant: tag, type-id varint, variant-id varint, payload.
    Enum = 0x70,
    /// `Option::None` (no payload).
    None = 0x80,
    /// `Option::Some` (followed by the wrapped value).
    Some = 0x81,
    /// Timestamp: zigzag varint of microseconds since the Unix epoch.
    Timestamp = 0x90,
    /// 128-bit UUID, written as 16 raw bytes (no length prefix).
    Uuid = 0x91,
    /// Replica / node identifier: length-prefixed varint then bytes.
    NodeId = 0xA0,
    /// Vector clock: length-prefixed varint then N (key, value) pairs.
    /// Caller-sorted by node-id for canonical form.
    VectorClock = 0xA1,
    /// Hybrid logical clock: wall-time (zigzag varint), logical
    /// (varint), then a length-prefixed node id.
    HLC = 0xA2,
}

impl TypeTag {
    /// Build a `TypeTag` from a wire byte, rejecting unknown tags.
    pub fn from_byte(byte: u8) -> Result<Self, DecodeError> {
        match byte {
            0x00 => Ok(TypeTag::Null),
            0x01 => Ok(TypeTag::False),
            0x02 => Ok(TypeTag::True),
            0x10 => Ok(TypeTag::UInt),
            0x11 => Ok(TypeTag::Int),
            0x20 => Ok(TypeTag::Float32),
            0x21 => Ok(TypeTag::Float64),
            0x30 => Ok(TypeTag::String),
            0x31 => Ok(TypeTag::Bytes),
            0x40 => Ok(TypeTag::Array),
            0x50 => Ok(TypeTag::Map),
            0x60 => Ok(TypeTag::Struct),
            0x70 => Ok(TypeTag::Enum),
            0x80 => Ok(TypeTag::None),
            0x81 => Ok(TypeTag::Some),
            0x90 => Ok(TypeTag::Timestamp),
            0x91 => Ok(TypeTag::Uuid),
            0xA0 => Ok(TypeTag::NodeId),
            0xA1 => Ok(TypeTag::VectorClock),
            0xA2 => Ok(TypeTag::HLC),
            other => Err(DecodeError::UnknownTag(other)),
        }
    }

    /// Raw wire byte for this tag.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_every_defined_tag() {
        for tag in [
            TypeTag::Null,
            TypeTag::False,
            TypeTag::True,
            TypeTag::UInt,
            TypeTag::Int,
            TypeTag::Float32,
            TypeTag::Float64,
            TypeTag::String,
            TypeTag::Bytes,
            TypeTag::Array,
            TypeTag::Map,
            TypeTag::Struct,
            TypeTag::Enum,
            TypeTag::None,
            TypeTag::Some,
            TypeTag::Timestamp,
            TypeTag::Uuid,
            TypeTag::NodeId,
            TypeTag::VectorClock,
            TypeTag::HLC,
        ] {
            let byte = tag.to_byte();
            let decoded = TypeTag::from_byte(byte).expect("known tag");
            assert_eq!(decoded, tag);
        }
    }

    #[test]
    fn rejects_unknown_tag_byte() {
        let err = TypeTag::from_byte(0xFF).expect_err("unknown tag");
        assert!(matches!(err, DecodeError::UnknownTag(0xFF)));
    }
}
