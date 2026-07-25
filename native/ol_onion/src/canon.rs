//! Minimal length-prefixed byte reader/writer for `ol_onion` wire frames.
//!
//! Strictly positional, no per-field type tags — onion packets have
//! a fixed structure and the goal is auditability + zero overhead
//! per byte. Identical philosophy to `ol_pair_qr::canon`.

use crate::errors::{OnionError, OnionResult};

/// Bounded reader over a borrowed slice.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a byte slice.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes remaining after the cursor.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// True if the cursor is at end-of-stream.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Read one byte.
    pub fn read_u8(&mut self) -> OnionResult<u8> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    /// Read a big-endian u16.
    pub fn read_u16(&mut self) -> OnionResult<u16> {
        self.need(2)?;
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    /// Read `n` raw bytes.
    pub fn read_fixed(&mut self, n: usize) -> OnionResult<&'a [u8]> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn need(&self, n: usize) -> OnionResult<()> {
        if self.remaining() < n {
            Err(OnionError::Truncated {
                needed: n,
                got: self.remaining(),
            })
        } else {
            Ok(())
        }
    }
}

/// Write-side helper. Owns its growable byte buffer.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// New empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// New writer pre-sized.
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

    /// Append `n` raw bytes.
    pub fn write_fixed(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// Consume + return the underlying bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Borrow the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Current length.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True if no bytes written.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_round_trip() {
        let mut w = Writer::new();
        w.write_u8(0xAB);
        w.write_u16(0x1234);
        w.write_fixed(&[1, 2, 3]);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_u8().unwrap(), 0xAB);
        assert_eq!(r.read_u16().unwrap(), 0x1234);
        assert_eq!(r.read_fixed(3).unwrap(), &[1, 2, 3]);
        assert!(r.is_empty());
    }

    #[test]
    fn truncated_read_returns_typed_error() {
        let mut r = Reader::new(&[0xAB]);
        let _ = r.read_u8().unwrap();
        let err = r.read_u8().unwrap_err();
        assert!(matches!(err, OnionError::Truncated { .. }));
    }
}
