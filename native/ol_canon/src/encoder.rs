//! Canonical encoder. Produces deterministic bytes that the decoder
//! round-trips to the original value.

use crate::error::EncodeError;
use crate::tag::TypeTag;
use crate::varint::{encode_varint, encode_zigzag};

/// Streaming encoder that builds a canonical byte sequence into an
/// internal `Vec<u8>`. Callers compose values by calling the
/// per-type `encode_*` methods; the output is the concatenation of
/// every emitted segment.
///
/// The encoder is single-pass and never re-reads its buffer, so the
/// order of `encode_*` calls IS the order of bytes on the wire.
#[derive(Debug, Clone, Default)]
pub struct CanonEncoder {
    buffer: Vec<u8>,
    max_size: usize,
}

impl CanonEncoder {
    /// Build an empty encoder with a small starting capacity. No size
    /// cap; the buffer grows on demand.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(256),
            max_size: 0,
        }
    }

    /// Build an encoder that returns [`EncodeError::BufferOverflow`]
    /// if any write would push the internal buffer past `max_size`
    /// bytes. Use for accepting attacker-supplied inputs that could
    /// otherwise drive unbounded allocation.
    #[must_use]
    pub fn with_limit(max_size: usize) -> Self {
        let cap = if max_size == 0 {
            256
        } else {
            max_size.min(256)
        };
        Self {
            buffer: Vec::with_capacity(cap),
            max_size,
        }
    }

    /// Consume the encoder and return the bytes it produced.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buffer
    }

    /// Bytes emitted so far. Useful for length checks before
    /// committing a frame.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// True iff the encoder has emitted no bytes yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Borrow the in-progress buffer without consuming the encoder.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }

    // ─── primitives ──────────────────────────────────────────────────

    /// Encode `null`.
    pub fn encode_null(&mut self) -> Result<(), EncodeError> {
        self.write_byte(TypeTag::Null.to_byte())
    }

    /// Encode a boolean.
    pub fn encode_bool(&mut self, value: bool) -> Result<(), EncodeError> {
        self.write_byte(if value {
            TypeTag::True.to_byte()
        } else {
            TypeTag::False.to_byte()
        })
    }

    /// Encode an unsigned 64-bit int.
    pub fn encode_u64(&mut self, value: u64) -> Result<(), EncodeError> {
        self.reserve(1 + 10)?;
        self.buffer.push(TypeTag::UInt.to_byte());
        encode_varint(value, &mut self.buffer);
        Ok(())
    }

    /// Encode a signed 64-bit int.
    pub fn encode_i64(&mut self, value: i64) -> Result<(), EncodeError> {
        self.reserve(1 + 10)?;
        self.buffer.push(TypeTag::Int.to_byte());
        encode_zigzag(value, &mut self.buffer);
        Ok(())
    }

    /// Encode an IEEE 754 binary32 with canonical NaN + -0.0 handling.
    pub fn encode_f32(&mut self, value: f32) -> Result<(), EncodeError> {
        let canonical = canonical_f32(value);
        self.reserve(1 + 4)?;
        self.buffer.push(TypeTag::Float32.to_byte());
        self.buffer.extend_from_slice(&canonical.to_be_bytes());
        Ok(())
    }

    /// Encode an IEEE 754 binary64 with canonical NaN + -0.0 handling.
    pub fn encode_f64(&mut self, value: f64) -> Result<(), EncodeError> {
        let canonical = canonical_f64(value);
        self.reserve(1 + 8)?;
        self.buffer.push(TypeTag::Float64.to_byte());
        self.buffer.extend_from_slice(&canonical.to_be_bytes());
        Ok(())
    }

    /// Encode a UTF-8 string.
    pub fn encode_string(&mut self, value: &str) -> Result<(), EncodeError> {
        let bytes = value.as_bytes();
        self.reserve(1 + 10 + bytes.len())?;
        self.buffer.push(TypeTag::String.to_byte());
        encode_varint(bytes.len() as u64, &mut self.buffer);
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    /// Encode a raw byte slice.
    pub fn encode_bytes(&mut self, value: &[u8]) -> Result<(), EncodeError> {
        self.reserve(1 + 10 + value.len())?;
        self.buffer.push(TypeTag::Bytes.to_byte());
        encode_varint(value.len() as u64, &mut self.buffer);
        self.buffer.extend_from_slice(value);
        Ok(())
    }

    /// Encode `None`.
    pub fn encode_none(&mut self) -> Result<(), EncodeError> {
        self.write_byte(TypeTag::None.to_byte())
    }

    /// Emit a `Some` tag. Caller must follow with the wrapped value's
    /// encoded bytes.
    pub fn encode_some(&mut self) -> Result<(), EncodeError> {
        self.write_byte(TypeTag::Some.to_byte())
    }

    /// Emit an array header. Caller writes `len` values immediately
    /// after.
    pub fn encode_array_header(&mut self, len: usize) -> Result<(), EncodeError> {
        self.reserve(1 + 10)?;
        self.buffer.push(TypeTag::Array.to_byte());
        encode_varint(len as u64, &mut self.buffer);
        Ok(())
    }

    /// Emit a map header. Caller MUST then write `len` (key, value)
    /// pairs **sorted by key's encoded bytes** for canonical output.
    pub fn encode_map_header(&mut self, len: usize) -> Result<(), EncodeError> {
        self.reserve(1 + 10)?;
        self.buffer.push(TypeTag::Map.to_byte());
        encode_varint(len as u64, &mut self.buffer);
        Ok(())
    }

    /// Emit a struct header (type-id + field count). Caller writes the
    /// `field_count` values in source-declaration order immediately
    /// after.
    pub fn encode_struct_header(
        &mut self,
        type_id: u32,
        field_count: usize,
    ) -> Result<(), EncodeError> {
        self.reserve(1 + 10 + 10)?;
        self.buffer.push(TypeTag::Struct.to_byte());
        encode_varint(u64::from(type_id), &mut self.buffer);
        encode_varint(field_count as u64, &mut self.buffer);
        Ok(())
    }

    /// Emit an enum variant header (type-id + variant-id). Caller
    /// writes the payload (if any) immediately after.
    pub fn encode_enum_header(&mut self, type_id: u32, variant: u32) -> Result<(), EncodeError> {
        self.reserve(1 + 10 + 10)?;
        self.buffer.push(TypeTag::Enum.to_byte());
        encode_varint(u64::from(type_id), &mut self.buffer);
        encode_varint(u64::from(variant), &mut self.buffer);
        Ok(())
    }

    // ─── CRDT primitives ─────────────────────────────────────────────

    /// Encode a timestamp (microseconds since the Unix epoch).
    pub fn encode_timestamp(&mut self, micros: i64) -> Result<(), EncodeError> {
        self.reserve(1 + 10)?;
        self.buffer.push(TypeTag::Timestamp.to_byte());
        encode_zigzag(micros, &mut self.buffer);
        Ok(())
    }

    /// Encode a UUID (16 raw bytes, no length prefix).
    pub fn encode_uuid(&mut self, bytes: &[u8; 16]) -> Result<(), EncodeError> {
        self.reserve(1 + 16)?;
        self.buffer.push(TypeTag::Uuid.to_byte());
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    /// Encode a node / replica id (length-prefixed bytes).
    pub fn encode_node_id(&mut self, node_id: &[u8]) -> Result<(), EncodeError> {
        self.reserve(1 + 10 + node_id.len())?;
        self.buffer.push(TypeTag::NodeId.to_byte());
        encode_varint(node_id.len() as u64, &mut self.buffer);
        self.buffer.extend_from_slice(node_id);
        Ok(())
    }

    /// Encode a vector clock from a pre-sorted `(node_id, counter)`
    /// iterator. Callers MUST sort by `node_id` for canonical output;
    /// the encoder writes entries in iteration order.
    pub fn encode_vector_clock(&mut self, entries: &[(Vec<u8>, u64)]) -> Result<(), EncodeError> {
        self.reserve(1 + 10)?;
        self.buffer.push(TypeTag::VectorClock.to_byte());
        encode_varint(entries.len() as u64, &mut self.buffer);
        for (node_id, counter) in entries {
            self.encode_node_id(node_id)?;
            self.encode_u64(*counter)?;
        }
        Ok(())
    }

    /// Encode an HLC timestamp (wall-time micros, logical counter,
    /// node id).
    pub fn encode_hlc(
        &mut self,
        wall_time: i64,
        logical: u32,
        node_id: &[u8],
    ) -> Result<(), EncodeError> {
        self.reserve(1 + 10 + 10 + 10 + node_id.len())?;
        self.buffer.push(TypeTag::HLC.to_byte());
        encode_zigzag(wall_time, &mut self.buffer);
        encode_varint(u64::from(logical), &mut self.buffer);
        encode_varint(node_id.len() as u64, &mut self.buffer);
        self.buffer.extend_from_slice(node_id);
        Ok(())
    }

    // ─── internals ───────────────────────────────────────────────────

    fn write_byte(&mut self, byte: u8) -> Result<(), EncodeError> {
        self.reserve(1)?;
        self.buffer.push(byte);
        Ok(())
    }

    fn reserve(&mut self, n: usize) -> Result<(), EncodeError> {
        if self.max_size > 0 && self.buffer.len() + n > self.max_size {
            Err(EncodeError::BufferOverflow)
        } else {
            Ok(())
        }
    }
}

/// Collapse every NaN bit pattern to the canonical IEEE 754 quiet NaN
/// and -0.0 to +0.0. Other values pass through untouched.
fn canonical_f32(value: f32) -> f32 {
    if value.is_nan() {
        f32::NAN
    } else if value == 0.0 {
        0.0
    } else {
        value
    }
}

/// f64 mirror of [`canonical_f32`].
fn canonical_f64(value: f64) -> f64 {
    if value.is_nan() {
        f64::NAN
    } else if value == 0.0 {
        0.0
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_encoder_is_empty() {
        let e = CanonEncoder::new();
        assert!(e.is_empty());
        assert_eq!(e.len(), 0);
    }

    #[test]
    fn limit_enforced() {
        let mut e = CanonEncoder::with_limit(4);
        e.encode_null().unwrap();
        e.encode_null().unwrap();
        e.encode_null().unwrap();
        e.encode_null().unwrap();
        let err = e.encode_null().unwrap_err();
        assert_eq!(err, EncodeError::BufferOverflow);
    }

    #[test]
    fn determinism_same_value_same_bytes() {
        let mut a = CanonEncoder::new();
        a.encode_u64(42).unwrap();
        a.encode_string("hello").unwrap();
        a.encode_bytes(b"\x00\xFF").unwrap();
        let mut b = CanonEncoder::new();
        b.encode_u64(42).unwrap();
        b.encode_string("hello").unwrap();
        b.encode_bytes(b"\x00\xFF").unwrap();
        assert_eq!(a.finish(), b.finish());
    }

    #[test]
    fn canonical_negative_zero_collapses() {
        let mut a = CanonEncoder::new();
        a.encode_f64(-0.0).unwrap();
        let mut b = CanonEncoder::new();
        b.encode_f64(0.0).unwrap();
        assert_eq!(a.finish(), b.finish());
    }

    #[test]
    fn canonical_nan_collapses() {
        let mut a = CanonEncoder::new();
        a.encode_f64(f64::NAN).unwrap();
        let mut b = CanonEncoder::new();
        // Bit-mangled NaN pattern (sign + payload != canonical).
        b.encode_f64(f64::from_bits(0x7FF8_0000_0000_0001)).unwrap();
        assert_eq!(a.finish(), b.finish());
    }
}
