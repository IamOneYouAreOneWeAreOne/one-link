//! Strict length-prefixed canonical encoding for pair-by-QR frames.
//!
//! Why a dedicated encoder instead of [`ol_canon`]:
//!
//! - QR codes have a tight byte budget. A self-describing type-tag
//!   per field would inflate the payload by 25-40%. Pair-QR frames
//!   have a known fixed shape — we can write a strict positional
//!   encoder and save every byte.
//! - The transcript hash is the trust anchor. Any encoder ambiguity
//!   = a downgrade attack vector. A small audit-able encoder beats
//!   a feature-rich one for this surface.
//!
//! ## Wire shape
//!
//! Every top-level struct begins with:
//!
//! ```text
//!     +-------+------+
//!     | ver   | tag  |
//!     | u8    | u8   |
//!     +-------+------+
//! ```
//!
//! followed by positional fields. Variable-length fields use a
//! `u16` big-endian length prefix; fixed-length fields are written
//! raw. Integers are big-endian, fixed-width. No varints — fixed
//! width is unambiguous and trivially constant-time.
//!
//! The decoder refuses any field length beyond [`MAX_FIELD_BYTES`]
//! before allocating, preventing memory-amplification by a hostile
//! frame.

use crate::errors::{PairError, PairResult};

/// Hard cap on any single variable-length field. Generous enough
/// for caps-scope payloads, small enough that a malicious 64 KiB
/// length prefix is rejected immediately.
pub const MAX_FIELD_BYTES: usize = 4096;

/// Reader cursor with bounds-checked primitive helpers.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a byte slice for sequential decoding.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Number of bytes remaining after the cursor.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// True if the cursor is at end-of-stream.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Total cursor position from the start of the buffer.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Read one byte; advance cursor.
    pub fn read_u8(&mut self) -> PairResult<u8> {
        self.need(1)?;
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Read a big-endian u16; advance cursor.
    pub fn read_u16(&mut self) -> PairResult<u16> {
        self.need(2)?;
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    /// Read a big-endian u32; advance cursor.
    pub fn read_u32(&mut self) -> PairResult<u32> {
        self.need(4)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(&self.buf[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_be_bytes(a))
    }

    /// Read a big-endian u64; advance cursor.
    pub fn read_u64(&mut self) -> PairResult<u64> {
        self.need(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_be_bytes(a))
    }

    /// Read `n` raw bytes; advance cursor.
    pub fn read_fixed(&mut self, n: usize) -> PairResult<&'a [u8]> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Read a `u16 BE`-prefixed variable-length field. Length is
    /// bounds-checked against [`MAX_FIELD_BYTES`] BEFORE the slice
    /// is materialized.
    pub fn read_var(&mut self) -> PairResult<&'a [u8]> {
        let len = self.read_u16()? as usize;
        if len > MAX_FIELD_BYTES {
            return Err(PairError::Oversize {
                got: len,
                cap: MAX_FIELD_BYTES,
            });
        }
        self.read_fixed(len)
    }

    /// Refuse if the buffer doesn't have `n` more bytes.
    fn need(&self, n: usize) -> PairResult<()> {
        if self.remaining() < n {
            Err(PairError::Truncated {
                needed: n,
                got: self.remaining(),
            })
        } else {
            Ok(())
        }
    }
}

/// Write-side helper with strict length-prefixed fields. Owns its
/// growable byte buffer.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// New empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// New writer pre-sized for a known target capacity (hint only).
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    /// Append one byte.
    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Append a big-endian u16.
    pub fn write_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Append a big-endian u32.
    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Append a big-endian u64.
    pub fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Append `n` raw bytes (no length prefix).
    pub fn write_fixed(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// Append a u16-length-prefixed variable-length field.
    ///
    /// Panics in debug builds if the slice exceeds [`MAX_FIELD_BYTES`]
    /// (caller bug — every caller is internal, and an oversize
    /// emission is always a programming error, never user-controlled).
    /// Release builds clamp the slice silently. The caller-facing
    /// invariant is that no producer in this crate constructs a
    /// frame that needs more than ~512 bytes per field.
    pub fn write_var(&mut self, b: &[u8]) {
        debug_assert!(
            b.len() <= MAX_FIELD_BYTES,
            "ol_pair_qr: write_var slice exceeds cap"
        );
        let len = b.len().min(MAX_FIELD_BYTES) as u16;
        self.write_u16(len);
        self.buf.extend_from_slice(&b[..len as usize]);
    }

    /// Consume the writer, returning the produced bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Borrow the produced bytes without consuming.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Current byte length of the produced output.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True iff nothing has been written yet.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_roundtrip() {
        let mut w = Writer::new();
        w.write_u8(0xAB);
        w.write_u16(0x1234);
        w.write_u32(0xDEAD_BEEF);
        w.write_u64(0x0123_4567_89AB_CDEF);
        w.write_var(b"hello");
        w.write_fixed(&[1, 2, 3]);
        let bytes = w.into_bytes();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_u8().unwrap(), 0xAB);
        assert_eq!(r.read_u16().unwrap(), 0x1234);
        assert_eq!(r.read_u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.read_u64().unwrap(), 0x0123_4567_89AB_CDEF);
        assert_eq!(r.read_var().unwrap(), b"hello");
        assert_eq!(r.read_fixed(3).unwrap(), &[1, 2, 3]);
        assert!(r.is_empty());
    }

    #[test]
    fn reader_refuses_truncated_var() {
        // length prefix says 100 but only 2 bytes follow
        let bytes = [0x00u8, 0x64, 0xAA, 0xBB];
        let mut r = Reader::new(&bytes);
        let err = r.read_var().unwrap_err();
        match err {
            PairError::Truncated {
                needed: 100,
                got: 2,
            } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn reader_refuses_oversize_var_before_allocation() {
        // length prefix says MAX_FIELD_BYTES + 1
        let too_big = (MAX_FIELD_BYTES + 1) as u16;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&too_big.to_be_bytes());
        let mut r = Reader::new(&bytes);
        let err = r.read_var().unwrap_err();
        match err {
            PairError::Oversize { got, cap } => {
                assert_eq!(got, MAX_FIELD_BYTES + 1);
                assert_eq!(cap, MAX_FIELD_BYTES);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn empty_buffer_read_u8_is_truncated() {
        let mut r = Reader::new(&[]);
        let err = r.read_u8().unwrap_err();
        assert!(matches!(err, PairError::Truncated { .. }));
    }

    #[test]
    fn writer_empty_state() {
        let w = Writer::new();
        assert!(w.is_empty());
        assert_eq!(w.len(), 0);
        assert!(w.as_bytes().is_empty());
    }

    #[test]
    fn writer_with_capacity_does_not_change_observable_len() {
        let w = Writer::with_capacity(1024);
        assert!(w.is_empty());
        assert_eq!(w.len(), 0);
    }
}
