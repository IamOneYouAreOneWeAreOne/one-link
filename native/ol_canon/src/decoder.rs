//! Canonical decoder. Reads bytes produced by [`crate::CanonEncoder`]
//! and surfaces typed values + length headers to the caller. Decoders
//! refuse to interpret an unknown tag and never silently advance past
//! corrupt input.

use crate::error::DecodeError;
use crate::tag::TypeTag;
use crate::varint::{decode_varint, decode_zigzag};

/// Read cursor over a canonical byte slice. Maintains position
/// internally so successive `decode_*` calls walk the stream.
#[derive(Debug)]
pub struct CanonDecoder<'a> {
    buffer: &'a [u8],
    position: usize,
}

impl<'a> CanonDecoder<'a> {
    /// Build a decoder over `buffer` starting at byte 0.
    #[must_use]
    pub fn new(buffer: &'a [u8]) -> Self {
        Self {
            buffer,
            position: 0,
        }
    }

    /// Bytes still ahead of the cursor.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.position)
    }

    /// True iff the cursor is at the end of the buffer.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.position >= self.buffer.len()
    }

    /// Current byte offset (useful for diagnostics).
    #[must_use]
    pub fn position(&self) -> usize {
        self.position
    }

    /// Peek at the next tag byte without advancing the cursor. Useful
    /// for branchy decoders that need to dispatch on type.
    pub fn peek_tag(&self) -> Result<TypeTag, DecodeError> {
        let byte = self.peek_byte()?;
        TypeTag::from_byte(byte)
    }

    /// Read a single byte, advancing the cursor.
    fn read_byte(&mut self) -> Result<u8, DecodeError> {
        let byte = self.peek_byte()?;
        self.position += 1;
        Ok(byte)
    }

    fn peek_byte(&self) -> Result<u8, DecodeError> {
        self.buffer
            .get(self.position)
            .copied()
            .ok_or(DecodeError::UnexpectedEof(self.position))
    }

    fn read_tag(&mut self) -> Result<TypeTag, DecodeError> {
        let byte = self.read_byte()?;
        TypeTag::from_byte(byte)
    }

    fn expect_tag(&mut self, expected: TypeTag) -> Result<(), DecodeError> {
        let found = self.read_tag()?;
        if found == expected {
            Ok(())
        } else {
            // Rewind so the caller can recover.
            self.position -= 1;
            Err(DecodeError::TagMismatch { expected, found })
        }
    }

    fn read_varint(&mut self) -> Result<u64, DecodeError> {
        let (value, n) = decode_varint(self.buffer, self.position)?;
        self.position += n;
        Ok(value)
    }

    fn read_zigzag(&mut self) -> Result<i64, DecodeError> {
        let (value, n) = decode_zigzag(self.buffer, self.position)?;
        self.position += n;
        Ok(value)
    }

    fn transaction<T>(
        &mut self,
        decode: impl FnOnce(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<T, DecodeError> {
        let checkpoint = self.position;
        match decode(self) {
            Ok(value) => Ok(value),
            Err(error) => {
                self.position = checkpoint;
                Err(error)
            }
        }
    }

    fn read_usize(&mut self) -> Result<usize, DecodeError> {
        let value = self.read_varint()?;
        usize::try_from(value).map_err(|_| DecodeError::NumericOverflow {
            value,
            target: "usize",
        })
    }

    fn read_u32(&mut self) -> Result<u32, DecodeError> {
        let value = self.read_varint()?;
        u32::try_from(value).map_err(|_| DecodeError::NumericOverflow {
            value,
            target: "u32",
        })
    }

    fn validate_collection_count(
        &self,
        count: usize,
        minimum_bytes_per_item: usize,
    ) -> Result<(), DecodeError> {
        let maximum = self.remaining() / minimum_bytes_per_item;
        if count > maximum {
            return Err(DecodeError::CollectionTooLarge {
                claimed: count as u64,
                maximum,
            });
        }
        Ok(())
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        if len > self.remaining() {
            return Err(DecodeError::LengthOverflow {
                claimed: len as u64,
                remaining: self.remaining(),
            });
        }
        let slice = &self.buffer[self.position..self.position + len];
        self.position += len;
        Ok(slice)
    }

    // ─── primitives ──────────────────────────────────────────────────

    /// Read a `null` marker. Fails if the next tag isn't [`TypeTag::Null`].
    pub fn decode_null(&mut self) -> Result<(), DecodeError> {
        self.transaction(|this| this.expect_tag(TypeTag::Null))
    }

    /// Read a boolean (`True` or `False` tag, no payload).
    pub fn decode_bool(&mut self) -> Result<bool, DecodeError> {
        self.transaction(|this| {
            let tag = this.read_tag()?;
            match tag {
                TypeTag::True => Ok(true),
                TypeTag::False => Ok(false),
                other => Err(DecodeError::TagMismatch {
                    expected: TypeTag::True,
                    found: other,
                }),
            }
        })
    }

    /// Read a u64.
    pub fn decode_u64(&mut self) -> Result<u64, DecodeError> {
        self.transaction(|this| {
            this.expect_tag(TypeTag::UInt)?;
            this.read_varint()
        })
    }

    /// Read an i64.
    pub fn decode_i64(&mut self) -> Result<i64, DecodeError> {
        self.transaction(|this| {
            this.expect_tag(TypeTag::Int)?;
            this.read_zigzag()
        })
    }

    /// Read an f32.
    pub fn decode_f32(&mut self) -> Result<f32, DecodeError> {
        self.transaction(|this| {
            this.expect_tag(TypeTag::Float32)?;
            let bytes = this.read_slice(4)?;
            let mut arr = [0u8; 4];
            arr.copy_from_slice(bytes);
            Ok(f32::from_be_bytes(arr))
        })
    }

    /// Read an f64.
    pub fn decode_f64(&mut self) -> Result<f64, DecodeError> {
        self.transaction(|this| {
            this.expect_tag(TypeTag::Float64)?;
            let bytes = this.read_slice(8)?;
            let mut arr = [0u8; 8];
            arr.copy_from_slice(bytes);
            Ok(f64::from_be_bytes(arr))
        })
    }

    /// Read a UTF-8 string.
    pub fn decode_string(&mut self) -> Result<String, DecodeError> {
        self.transaction(|this| {
            this.expect_tag(TypeTag::String)?;
            let len = this.read_usize()?;
            let slice = this.read_slice(len)?;
            std::str::from_utf8(slice)
                .map(str::to_owned)
                .map_err(|_| DecodeError::InvalidUtf8)
        })
    }

    /// Read a raw byte slice.
    pub fn decode_bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        self.transaction(|this| {
            this.expect_tag(TypeTag::Bytes)?;
            let len = this.read_usize()?;
            Ok(this.read_slice(len)?.to_vec())
        })
    }

    /// Read an array header. Returns the element count; caller decodes
    /// each element in turn.
    pub fn decode_array_header(&mut self) -> Result<usize, DecodeError> {
        self.transaction(|this| {
            this.expect_tag(TypeTag::Array)?;
            let count = this.read_usize()?;
            this.validate_collection_count(count, 1)?;
            Ok(count)
        })
    }

    /// Read a map header. Returns the pair count; caller decodes each
    /// (key, value) in turn.
    pub fn decode_map_header(&mut self) -> Result<usize, DecodeError> {
        self.transaction(|this| {
            this.expect_tag(TypeTag::Map)?;
            let count = this.read_usize()?;
            this.validate_collection_count(count, 2)?;
            Ok(count)
        })
    }

    /// Read a `None` marker.
    pub fn decode_none(&mut self) -> Result<(), DecodeError> {
        self.transaction(|this| this.expect_tag(TypeTag::None))
    }

    /// Read a `Some` marker (caller decodes the wrapped value next).
    pub fn decode_some(&mut self) -> Result<(), DecodeError> {
        self.transaction(|this| this.expect_tag(TypeTag::Some))
    }

    /// Read a timestamp (microseconds since the epoch).
    pub fn decode_timestamp(&mut self) -> Result<i64, DecodeError> {
        self.transaction(|this| {
            this.expect_tag(TypeTag::Timestamp)?;
            this.read_zigzag()
        })
    }

    /// Read a UUID (16 bytes, no length prefix).
    pub fn decode_uuid(&mut self) -> Result<[u8; 16], DecodeError> {
        self.transaction(|this| {
            this.expect_tag(TypeTag::Uuid)?;
            let slice = this.read_slice(16)?;
            let mut out = [0u8; 16];
            out.copy_from_slice(slice);
            Ok(out)
        })
    }

    /// Read a node id (length-prefixed bytes).
    pub fn decode_node_id(&mut self) -> Result<Vec<u8>, DecodeError> {
        self.transaction(|this| {
            this.expect_tag(TypeTag::NodeId)?;
            let len = this.read_usize()?;
            Ok(this.read_slice(len)?.to_vec())
        })
    }

    /// Read a struct header. Returns `(type_id, field_count)`; caller
    /// decodes the fields.
    pub fn decode_struct_header(&mut self) -> Result<(u32, usize), DecodeError> {
        self.transaction(|this| {
            this.expect_tag(TypeTag::Struct)?;
            let type_id = this.read_u32()?;
            let fields = this.read_usize()?;
            this.validate_collection_count(fields, 1)?;
            Ok((type_id, fields))
        })
    }

    /// Read an enum-variant header. Returns `(type_id, variant)`;
    /// caller decodes the payload.
    pub fn decode_enum_header(&mut self) -> Result<(u32, u32), DecodeError> {
        self.transaction(|this| {
            this.expect_tag(TypeTag::Enum)?;
            let type_id = this.read_u32()?;
            let variant = this.read_u32()?;
            Ok((type_id, variant))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::CanonEncoder;

    #[test]
    fn round_trip_primitives() {
        let mut e = CanonEncoder::new();
        e.encode_null().unwrap();
        e.encode_bool(true).unwrap();
        e.encode_bool(false).unwrap();
        e.encode_u64(0).unwrap();
        e.encode_u64(u64::MAX).unwrap();
        e.encode_i64(-1).unwrap();
        e.encode_i64(i64::MIN).unwrap();
        e.encode_string("hello").unwrap();
        e.encode_bytes(b"\x00\xFF").unwrap();
        let bytes = e.finish();

        let mut d = CanonDecoder::new(&bytes);
        d.decode_null().unwrap();
        assert!(d.decode_bool().unwrap());
        assert!(!d.decode_bool().unwrap());
        assert_eq!(d.decode_u64().unwrap(), 0);
        assert_eq!(d.decode_u64().unwrap(), u64::MAX);
        assert_eq!(d.decode_i64().unwrap(), -1);
        assert_eq!(d.decode_i64().unwrap(), i64::MIN);
        assert_eq!(d.decode_string().unwrap(), "hello");
        assert_eq!(d.decode_bytes().unwrap(), b"\x00\xFF");
        assert!(d.is_empty());
    }

    #[test]
    fn tag_mismatch_is_typed_error() {
        let mut e = CanonEncoder::new();
        e.encode_u64(42).unwrap();
        let bytes = e.finish();
        let mut d = CanonDecoder::new(&bytes);
        let err = d.decode_string().unwrap_err();
        assert!(matches!(err, DecodeError::TagMismatch { .. }));
    }

    #[test]
    fn length_overflow_rejected() {
        // Hand-craft a String tag with length > buffer.
        let bytes = vec![TypeTag::String.to_byte(), 0xFFu8, 0x01];
        let mut d = CanonDecoder::new(&bytes);
        let err = d.decode_string().unwrap_err();
        assert!(matches!(err, DecodeError::LengthOverflow { .. }));
        assert_eq!(d.position(), 0, "failed decode must roll back cursor");
    }

    #[test]
    fn invalid_utf8_rolls_back_cursor() {
        let bytes = [TypeTag::String.to_byte(), 1, 0xFF];
        let mut decoder = CanonDecoder::new(&bytes);
        assert_eq!(decoder.decode_string(), Err(DecodeError::InvalidUtf8));
        assert_eq!(decoder.position(), 0);
    }

    #[test]
    fn impossible_collection_counts_are_rejected_before_caller_loops() {
        let bytes = [TypeTag::Array.to_byte(), 100];
        let mut decoder = CanonDecoder::new(&bytes);
        assert!(matches!(
            decoder.decode_array_header(),
            Err(DecodeError::CollectionTooLarge { .. })
        ));
        assert_eq!(decoder.position(), 0);

        let bytes = [TypeTag::Map.to_byte(), 1, TypeTag::Null.to_byte()];
        let mut decoder = CanonDecoder::new(&bytes);
        assert!(matches!(
            decoder.decode_map_header(),
            Err(DecodeError::CollectionTooLarge { .. })
        ));
        assert_eq!(decoder.position(), 0);
    }

    #[test]
    fn oversized_u32_headers_are_rejected_without_truncation() {
        let mut bytes = vec![TypeTag::Enum.to_byte()];
        crate::encode_varint(u64::from(u32::MAX) + 1, &mut bytes);
        crate::encode_varint(0, &mut bytes);
        let mut decoder = CanonDecoder::new(&bytes);
        assert!(matches!(
            decoder.decode_enum_header(),
            Err(DecodeError::NumericOverflow { target: "u32", .. })
        ));
        assert_eq!(decoder.position(), 0);
    }
}
