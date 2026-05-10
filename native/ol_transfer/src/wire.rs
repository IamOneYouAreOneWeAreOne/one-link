//! Wire-protocol payload formats for `ol_transfer` frames.
//!
//! Frame headers (kind + length) are handled by [`ol_quic::proto`]. This
//! module decodes / encodes the *payload* contents for each frame kind we
//! care about:
//!
//! - `ChunkRequest (0x01)` payload = 32 bytes (the chunk_id).
//! - `ChunkResponse (0x02)` payload = `[record_kind: u8][record_flags: u8][record_payload: N bytes]`
//!   — the chunk_record encoded form, same as on-disk before WAL framing.
//! - `ChunkNotFound (0x03)` payload = 32 bytes (the missing chunk_id).
//! - `BloomFilter (0x20)` payload = `[ol_bloom encoded bytes]` per ADR-0011.
//! - `MissingChunks (0x21)` payload = `[count: u32 LE][chunk_id_1..n: 32 bytes each]`.
//! - `Ping (0xF0)` / `Pong (0xF1)` payload = opaque echo bytes (≤64 KiB).
//! - `ProtoError (0xFE)` payload = ASCII reason (≤64 KiB).

use ol_quic::FrameKind;

use crate::error::TransferError;

/// Length of one chunk_id on the wire.
pub const CHUNK_ID_LEN: usize = 32;

/// Encode a `ChunkRequest` payload from a chunk_id.
#[inline]
#[must_use]
pub fn encode_chunk_request(chunk_id: &[u8; 32]) -> Vec<u8> {
    chunk_id.to_vec()
}

/// Decode a `ChunkRequest` payload into a chunk_id.
///
/// # Errors
///
/// [`TransferError::MalformedPayload`] if `payload` is not exactly 32 bytes.
pub fn decode_chunk_request(payload: &[u8]) -> Result<[u8; 32], TransferError> {
    if payload.len() != CHUNK_ID_LEN {
        return Err(TransferError::MalformedPayload {
            kind: FrameKind::ChunkRequest,
            reason: "expected 32-byte chunk_id",
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(payload);
    Ok(out)
}

/// Encode a `ChunkResponse` payload: prepends the record_kind + flags
/// bytes before the record payload.
#[inline]
#[must_use]
pub fn encode_chunk_response(record_kind: u8, record_flags: u8, record_payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + record_payload.len());
    out.push(record_kind);
    out.push(record_flags);
    out.extend_from_slice(record_payload);
    out
}

/// Decode a `ChunkResponse` payload into (record_kind, record_flags,
/// record_payload).
///
/// # Errors
///
/// [`TransferError::MalformedPayload`] if `payload` is shorter than the
/// 2-byte kind+flags prefix.
pub fn decode_chunk_response(payload: &[u8]) -> Result<(u8, u8, &[u8]), TransferError> {
    if payload.len() < 2 {
        return Err(TransferError::MalformedPayload {
            kind: FrameKind::ChunkResponse,
            reason: "chunk-response payload < 2 bytes",
        });
    }
    Ok((payload[0], payload[1], &payload[2..]))
}

/// Encode a `ChunkNotFound` payload.
#[inline]
#[must_use]
pub fn encode_chunk_not_found(chunk_id: &[u8; 32]) -> Vec<u8> {
    chunk_id.to_vec()
}

/// Decode a `ChunkNotFound` payload.
///
/// # Errors
///
/// [`TransferError::MalformedPayload`] if `payload` is not exactly 32 bytes.
pub fn decode_chunk_not_found(payload: &[u8]) -> Result<[u8; 32], TransferError> {
    if payload.len() != CHUNK_ID_LEN {
        return Err(TransferError::MalformedPayload {
            kind: FrameKind::ChunkNotFound,
            reason: "expected 32-byte chunk_id",
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(payload);
    Ok(out)
}

/// Encode a `MissingChunks` payload from an iterator of chunk_ids.
///
/// Format: `[count: u32 LE][chunk_id_1..n: 32 bytes each]`.
#[must_use]
pub fn encode_missing_chunks(ids: &[[u8; 32]]) -> Vec<u8> {
    let count = u32::try_from(ids.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(4 + ids.len() * CHUNK_ID_LEN);
    out.extend_from_slice(&count.to_le_bytes());
    for id in ids {
        out.extend_from_slice(id);
    }
    out
}

/// Decode a `MissingChunks` payload into a vector of chunk_ids.
///
/// # Errors
///
/// [`TransferError::MalformedPayload`] if the count header is missing
/// or the payload length doesn't match `count * 32 + 4`.
pub fn decode_missing_chunks(payload: &[u8]) -> Result<Vec<[u8; 32]>, TransferError> {
    if payload.len() < 4 {
        return Err(TransferError::MalformedPayload {
            kind: FrameKind::MissingChunks,
            reason: "missing-chunks payload < 4 bytes",
        });
    }
    let count = u32::from_le_bytes(payload[0..4].try_into().expect("4 bytes")) as usize;
    let expected_len = 4 + count * CHUNK_ID_LEN;
    if payload.len() != expected_len {
        return Err(TransferError::MalformedPayload {
            kind: FrameKind::MissingChunks,
            reason: "missing-chunks payload length doesn't match declared count",
        });
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let start = 4 + i * CHUNK_ID_LEN;
        let mut cid = [0u8; 32];
        cid.copy_from_slice(&payload[start..start + CHUNK_ID_LEN]);
        out.push(cid);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_request_round_trip() {
        let cid = [0x55u8; 32];
        let bytes = encode_chunk_request(&cid);
        assert_eq!(bytes.len(), 32);
        let parsed = decode_chunk_request(&bytes).unwrap();
        assert_eq!(parsed, cid);
    }

    #[test]
    fn chunk_request_rejects_wrong_length() {
        assert!(matches!(
            decode_chunk_request(&[0u8; 16]),
            Err(TransferError::MalformedPayload { .. })
        ));
        assert!(matches!(
            decode_chunk_request(&[0u8; 33]),
            Err(TransferError::MalformedPayload { .. })
        ));
    }

    #[test]
    fn chunk_response_round_trip() {
        let payload = encode_chunk_response(0x01, 0x42, b"hello-world");
        let (kind, flags, body) = decode_chunk_response(&payload).unwrap();
        assert_eq!(kind, 0x01);
        assert_eq!(flags, 0x42);
        assert_eq!(body, b"hello-world");
    }

    #[test]
    fn chunk_response_rejects_short() {
        assert!(matches!(
            decode_chunk_response(&[0u8; 1]),
            Err(TransferError::MalformedPayload { .. })
        ));
    }

    #[test]
    fn chunk_not_found_round_trip() {
        let cid = [0xAAu8; 32];
        let bytes = encode_chunk_not_found(&cid);
        assert_eq!(decode_chunk_not_found(&bytes).unwrap(), cid);
    }

    #[test]
    fn missing_chunks_round_trip() {
        let ids: Vec<[u8; 32]> = (0u8..5).map(|i| [i; 32]).collect();
        let payload = encode_missing_chunks(&ids);
        assert_eq!(payload.len(), 4 + 5 * 32);
        let parsed = decode_missing_chunks(&payload).unwrap();
        assert_eq!(parsed, ids);
    }

    #[test]
    fn missing_chunks_empty() {
        let payload = encode_missing_chunks(&[]);
        assert_eq!(payload, vec![0u8, 0, 0, 0]);
        let parsed = decode_missing_chunks(&payload).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn missing_chunks_rejects_length_mismatch() {
        // Header claims 2 chunks, payload only has 1.
        let mut buf = vec![2u8, 0, 0, 0];
        buf.extend_from_slice(&[0u8; 32]);
        assert!(matches!(
            decode_missing_chunks(&buf),
            Err(TransferError::MalformedPayload { .. })
        ));
    }
}
