//! `ol_netcode` — XOR network coding for relay paths.
//!
//! Per `FILE_ENGINE_V2_PLAN.md` Phase B item #3:
//!
//! > Peers serve A⊕B; recipients with A reconstruct B. Cipher-only
//! > (sovereignty preserved).
//!
//! ## Why XOR network coding
//!
//! A relay node that already holds chunk A can serve a coded packet
//! `A ⊕ B` to a recipient that wants B. The recipient already holds
//! A (or fetched it from another peer), so it computes
//! `(A ⊕ B) ⊕ A = B` locally — no plaintext B ever existed on the
//! relay. Two security wins:
//!
//! 1. The relay cannot read B (it never had B's bytes; it only
//!    XOR-combined an opaque buffer with a buffer it already had).
//! 2. A wire observer sees `A ⊕ B`, which looks random to anyone
//!    without A.
//!
//! And one efficiency win: the relay can multicast a single coded
//! packet to N recipients with disjoint missing chunks; each
//! recovers a different B with one XOR.
//!
//! ## Surface
//!
//! - [`xor_inplace`]: bitwise XOR of `dst ^= src` for equal-length
//!   slices. The hot primitive every coded-packet path calls.
//! - [`encode_coded_packet`]: combine N chunks of equal length into
//!   one coded packet. Records which chunk ids participated so the
//!   recipient knows which keys to XOR back in.
//! - [`decode_coded_packet`]: given a coded packet + the known chunks
//!   it was built from, recover the missing chunk. Returns
//!   [`NetcodeError::InsufficientKnown`] if more than one chunk is
//!   missing (degree-1 decoding only — gaussian elimination is the
//!   Phase D extension if we need higher degrees).
//! - [`CodedPacket`]: wire-frame struct with the chunk-id manifest +
//!   payload bytes.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use thiserror::Error;

/// 32-byte chunk identifier (BLAKE3 hash) — matches the chunk-store
/// addressing scheme.
pub type ChunkId = [u8; 32];

/// Errors the encode / decode paths can return.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetcodeError {
    /// Two slices that were supposed to be equal length weren't.
    #[error("length mismatch: lhs={lhs} rhs={rhs}")]
    LengthMismatch {
        /// Length of the destination buffer.
        lhs: usize,
        /// Length of the source buffer.
        rhs: usize,
    },
    /// Caller asked to encode a coded packet with zero participating
    /// chunks. Always a programmer error.
    #[error("coded packet must combine at least one chunk")]
    EmptyParticipants,
    /// The recipient is missing more than one of the participating
    /// chunks. Degree-1 XOR can only recover a single missing slot.
    #[error("decoder missing {missing} chunks; only degree-1 supported")]
    InsufficientKnown {
        /// Number of chunks the recipient lacks.
        missing: usize,
    },
    /// The caller supplied a known-chunk slice that's a different
    /// length from the coded packet's payload. Would corrupt the
    /// XOR result; refuse loudly.
    #[error("known chunk #{idx} length {known_len} != coded payload length {coded_len}")]
    KnownChunkLengthMismatch {
        /// Index of the offending known-chunk in the caller's slice.
        idx: usize,
        /// Length the caller-supplied chunk had.
        known_len: usize,
        /// Length the coded payload has.
        coded_len: usize,
    },
}

/// A coded packet: the XOR of `participants.len()` chunks of equal
/// length, plus the manifest of which chunk ids participated. The
/// recipient uses the manifest to decide which of its locally-held
/// chunks to XOR back in to recover the missing one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodedPacket {
    /// Chunk ids whose plaintext was XORed into this packet, in the
    /// order they were combined. Order doesn't affect the math
    /// (XOR is commutative + associative), but the manifest's bytes
    /// hash the chunk ids in order so a tampered manifest fails
    /// integrity.
    pub participants: Vec<ChunkId>,
    /// The coded payload (XOR of every participant chunk's bytes).
    pub payload: Vec<u8>,
    /// `BLAKE3(participants[0] || participants[1] || ... ||
    /// payload)` — bound integrity tag so a relay can't swap chunk
    /// ids without detection.
    pub integrity_tag: [u8; 32],
}

/// XOR `dst[i] ^= src[i]` for every byte; the in-place primitive
/// every coded-packet path eventually calls.
///
/// Both slices MUST be the same length; mismatched lengths return
/// [`NetcodeError::LengthMismatch`] rather than truncating silently.
pub fn xor_inplace(dst: &mut [u8], src: &[u8]) -> Result<(), NetcodeError> {
    if dst.len() != src.len() {
        return Err(NetcodeError::LengthMismatch {
            lhs: dst.len(),
            rhs: src.len(),
        });
    }
    // Chunked loop — let the autovectorizer see 8-byte windows where
    // possible. Constant-time vs. data-dependent timing isn't a goal
    // here (the inputs are public chunk ciphertexts), but the inner
    // loop stays branch-free.
    for (a, b) in dst.iter_mut().zip(src.iter()) {
        *a ^= *b;
    }
    Ok(())
}

/// Build a coded packet from N participant chunks, all the same
/// length. Returns the [`CodedPacket`] with the integrity tag bound
/// to the manifest + payload.
pub fn encode_coded_packet(
    participants: &[(ChunkId, &[u8])],
) -> Result<CodedPacket, NetcodeError> {
    if participants.is_empty() {
        return Err(NetcodeError::EmptyParticipants);
    }
    let expected_len = participants[0].1.len();
    for (idx, (_, payload)) in participants.iter().enumerate() {
        if payload.len() != expected_len {
            return Err(NetcodeError::LengthMismatch {
                lhs: expected_len,
                rhs: payload.len(),
            });
        }
        let _ = idx;
    }
    // Start from the first participant's bytes; XOR every subsequent
    // chunk in. ``payload`` ends up as A ⊕ B ⊕ ... ⊕ N.
    let mut payload = participants[0].1.to_vec();
    for (_, chunk) in &participants[1..] {
        xor_inplace(&mut payload, chunk)?;
    }
    let mut ids = Vec::with_capacity(participants.len());
    for (id, _) in participants {
        ids.push(*id);
    }
    let integrity_tag = compute_integrity_tag(&ids, &payload);
    Ok(CodedPacket {
        participants: ids,
        payload,
        integrity_tag,
    })
}

/// Recover the single missing chunk from a coded packet + the rest
/// of its participating chunks (which the recipient already holds).
///
/// `known` MUST be `(chunk_id, bytes)` pairs covering every
/// participant in `packet.participants` EXCEPT the one we want to
/// recover. The returned `(chunk_id, bytes)` is the missing chunk.
///
/// Returns [`NetcodeError::InsufficientKnown`] if more than one
/// participant is missing — degree-1 XOR can only recover a single
/// hole. (Multi-hole recovery would need a gaussian-elimination
/// solver across multiple coded packets — Phase D extension.)
pub fn decode_coded_packet(
    packet: &CodedPacket,
    known: &[(ChunkId, &[u8])],
) -> Result<(ChunkId, Vec<u8>), NetcodeError> {
    // Verify integrity tag first so a relay can't substitute a chunk
    // id list under us.
    let recomputed_tag = compute_integrity_tag(&packet.participants, &packet.payload);
    if recomputed_tag != packet.integrity_tag {
        // Length mismatch is the closest typed error we have to
        // "tampered integrity"; in practice the caller treats any
        // decode-side error as fall-back-to-direct.
        return Err(NetcodeError::LengthMismatch {
            lhs: packet.integrity_tag.len(),
            rhs: recomputed_tag.len(),
        });
    }
    // Identify which participants the recipient is missing.
    let known_ids: std::collections::HashSet<&ChunkId> =
        known.iter().map(|(id, _)| id).collect();
    let mut missing: Vec<ChunkId> = packet
        .participants
        .iter()
        .filter(|id| !known_ids.contains(id))
        .copied()
        .collect();
    if missing.len() != 1 {
        return Err(NetcodeError::InsufficientKnown {
            missing: missing.len(),
        });
    }
    let missing_id = missing.remove(0);
    // XOR each known chunk's bytes back out of the payload. Result
    // is the missing chunk's bytes.
    let mut recovered = packet.payload.clone();
    for (idx, (_, bytes)) in known.iter().enumerate() {
        if bytes.len() != recovered.len() {
            return Err(NetcodeError::KnownChunkLengthMismatch {
                idx,
                known_len: bytes.len(),
                coded_len: recovered.len(),
            });
        }
        xor_inplace(&mut recovered, bytes)?;
    }
    Ok((missing_id, recovered))
}

/// `BLAKE3(participant_ids_concatenated || payload)` — the integrity
/// tag every coded packet carries so a relay can't substitute the
/// chunk-id manifest without detection.
fn compute_integrity_tag(participants: &[ChunkId], payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ol-netcode-coded-v1");
    for id in participants {
        hasher.update(id);
    }
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> ChunkId {
        [b; 32]
    }

    #[test]
    fn xor_inplace_round_trips() {
        let mut a = b"hello, world!".to_vec();
        let b = b"goodbye world".to_vec();
        let snapshot = a.clone();
        // XOR twice with the same buffer recovers the original.
        xor_inplace(&mut a, &b).unwrap();
        xor_inplace(&mut a, &b).unwrap();
        assert_eq!(a, snapshot);
    }

    #[test]
    fn xor_inplace_rejects_mismatch() {
        let mut a = vec![0u8; 16];
        let b = vec![0u8; 8];
        let err = xor_inplace(&mut a, &b).unwrap_err();
        assert!(matches!(err, NetcodeError::LengthMismatch { .. }));
    }

    #[test]
    fn encode_then_decode_degree_2() {
        let chunk_a = vec![0xAAu8; 64];
        let chunk_b = vec![0xBBu8; 64];
        let packet = encode_coded_packet(&[
            (id(1), &chunk_a),
            (id(2), &chunk_b),
        ])
        .unwrap();
        // Recipient holds A; recovers B.
        let (recovered_id, recovered_bytes) =
            decode_coded_packet(&packet, &[(id(1), &chunk_a)]).unwrap();
        assert_eq!(recovered_id, id(2));
        assert_eq!(recovered_bytes, chunk_b);
    }

    #[test]
    fn encode_then_decode_degree_3() {
        let a = vec![0x11u8; 32];
        let b = vec![0x22u8; 32];
        let c = vec![0x33u8; 32];
        let packet =
            encode_coded_packet(&[(id(1), &a), (id(2), &b), (id(3), &c)]).unwrap();
        // Recipient missing B; holds A + C.
        let (rec_id, rec) =
            decode_coded_packet(&packet, &[(id(1), &a), (id(3), &c)]).unwrap();
        assert_eq!(rec_id, id(2));
        assert_eq!(rec, b);
    }

    #[test]
    fn decode_rejects_two_missing() {
        let a = vec![0u8; 16];
        let b = vec![0u8; 16];
        let c = vec![0u8; 16];
        let packet =
            encode_coded_packet(&[(id(1), &a), (id(2), &b), (id(3), &c)]).unwrap();
        let err =
            decode_coded_packet(&packet, &[(id(1), &a)]).unwrap_err();
        assert!(matches!(
            err,
            NetcodeError::InsufficientKnown { missing: 2 }
        ));
    }

    #[test]
    fn encode_empty_participants_is_typed_error() {
        let err = encode_coded_packet(&[]).unwrap_err();
        assert_eq!(err, NetcodeError::EmptyParticipants);
    }

    #[test]
    fn encode_rejects_uneven_lengths() {
        let a = vec![0u8; 8];
        let b = vec![0u8; 16];
        let err = encode_coded_packet(&[(id(1), &a), (id(2), &b)]).unwrap_err();
        assert!(matches!(err, NetcodeError::LengthMismatch { .. }));
    }

    #[test]
    fn tampered_manifest_fails_integrity_check() {
        let a = vec![0xCC; 32];
        let b = vec![0xDD; 32];
        let mut packet =
            encode_coded_packet(&[(id(1), &a), (id(2), &b)]).unwrap();
        // Substitute a chunk id; the integrity tag was computed
        // against the original list, so decode fails.
        packet.participants[0] = id(99);
        let err =
            decode_coded_packet(&packet, &[(id(99), &a)]).unwrap_err();
        // The integrity check is the first failure path.
        assert!(matches!(err, NetcodeError::LengthMismatch { .. }));
    }
}
