//! LEB128 varint + zigzag-LEB128 signed varint, the wire primitives
//! every length prefix + integer field uses.
//!
//! Encoding: 7 bits per byte, MSB set on continuation. Bytes go LSB
//! first. Max 10 bytes for u64 (9 full-7-bit groups + a 1-bit tail).

use crate::error::DecodeError;

/// Largest varint length for a u64 input (`ceil(64 / 7) = 10` bytes).
pub(crate) const MAX_VARINT_BYTES: usize = 10;

/// Encode an unsigned 64-bit value as an LEB128 varint into `out`.
pub fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Decode an LEB128 varint starting at `pos`. Returns `(value,
/// bytes_consumed)` on success.
pub fn decode_varint(input: &[u8], pos: usize) -> Result<(u64, usize), DecodeError> {
    let mut shift = 0u32;
    let mut value: u64 = 0;
    let mut bytes = 0usize;
    for &byte in input.iter().skip(pos).take(MAX_VARINT_BYTES) {
        bytes += 1;
        let chunk = u64::from(byte & 0x7F);
        // Reject overflow on the 10th byte where shift=63 leaves only
        // 1 bit of headroom.
        if shift >= 64 || chunk.checked_shl(shift).is_none() {
            return Err(DecodeError::VarintTooLong);
        }
        value |= chunk << shift;
        if byte & 0x80 == 0 {
            return Ok((value, bytes));
        }
        shift += 7;
    }
    if bytes == 0 {
        Err(DecodeError::UnexpectedEof(pos))
    } else {
        Err(DecodeError::VarintTooLong)
    }
}

/// Encode an i64 as a zigzag-LEB128 varint. The transform is
/// `(n << 1) ^ (n >> 63)` so small negatives stay tiny on the wire.
pub fn encode_zigzag(value: i64, out: &mut Vec<u8>) {
    // The cast keeps the sign-bit smear; we then shift left by 1 and
    // XOR with the smear so positive numbers become 2n and negative
    // -(n+1) becomes 2n+1.
    let zigzag = (value.cast_unsigned() << 1) ^ (value >> 63).cast_unsigned();
    encode_varint(zigzag, out);
}

/// Decode a zigzag-LEB128 signed varint. Inverse of [`encode_zigzag`].
pub fn decode_zigzag(input: &[u8], pos: usize) -> Result<(i64, usize), DecodeError> {
    let (raw, n) = decode_varint(input, pos)?;
    // (raw >> 1) ^ -(raw & 1) — the standard zigzag inverse.
    let value = (raw >> 1).cast_signed() ^ -(raw & 1).cast_signed();
    Ok((value, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_small_unsigned() {
        for v in [
            0u64,
            1,
            127,
            128,
            16_383,
            16_384,
            u64::from(u32::MAX),
            u64::MAX,
        ] {
            let mut out = Vec::new();
            encode_varint(v, &mut out);
            let (decoded, n) = decode_varint(&out, 0).unwrap();
            assert_eq!(decoded, v, "round trip failed for {v}");
            assert_eq!(n, out.len(), "decoded byte count != encoded length");
        }
    }

    #[test]
    fn round_trip_signed_zigzag() {
        for v in [0i64, -1, 1, -127, 127, -i64::MAX, i64::MAX, i64::MIN] {
            let mut out = Vec::new();
            encode_zigzag(v, &mut out);
            let (decoded, _) = decode_zigzag(&out, 0).unwrap();
            assert_eq!(decoded, v, "zigzag round trip failed for {v}");
        }
    }

    #[test]
    fn rejects_oversize_varint() {
        // 11 bytes all with continuation bit set — past the 10-byte
        // u64 max.
        let oversized = [0x80u8; 11];
        let err = decode_varint(&oversized, 0).unwrap_err();
        assert_eq!(err, DecodeError::VarintTooLong);
    }

    #[test]
    fn small_negatives_are_short() {
        // -1 zigzag-encodes to 1, which fits in 1 byte. Catches the
        // classic LEB128 sign-extension bug.
        let mut out = Vec::new();
        encode_zigzag(-1, &mut out);
        assert_eq!(out, vec![1]);
    }
}
