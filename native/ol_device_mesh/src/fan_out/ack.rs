//! Source-signed delivery receipt.
//!
//! Each successful chunk delivery is acknowledged by the SOURCE
//! signing a [`ChunkAck`] over `(file_id, chunk_hash, receiver_id,
//! delivered_unix, byte_offset)`. The receiver can persist these
//! as proof "I, source S, delivered chunk C to receiver R at T."
//! Useful for the bandit estimator (Phase D) and for the
//! anti-fan-out-abuse rate-limiter at a higher layer.

use ol_pqsig::{HybridVerifyingKey, HYBRID_SIG_LEN};

use crate::distributed_fs::{ChunkHash, FileId, CHUNK_HASH_LEN, FILE_ID_LEN};
use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::subkey::{DeviceSubkey, DEVICE_ID_LEN};

/// Domain-separation tag for ack signing.
pub const ACK_DOMAIN: &[u8] = b"OL-mesh-chunk-ack-v1";

/// Source-signed delivery receipt for one chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkAck {
    /// File the chunk belongs to.
    pub file_id: FileId,
    /// The chunk just delivered.
    pub chunk_hash: ChunkHash,
    /// Source device id.
    pub source_device_id: [u8; DEVICE_ID_LEN],
    /// Receiver device id (who got the chunk).
    pub receiver_device_id: [u8; DEVICE_ID_LEN],
    /// Source's subkey day-index at sign time.
    pub source_day_index: u64,
    /// Wall-clock seconds the delivery completed.
    pub delivered_unix: u64,
    /// Size in bytes of the chunk delivered.
    pub byte_size: u32,
    /// Source's subkey signature.
    pub source_sig: Vec<u8>,
}

impl ChunkAck {
    /// Canonical bytes the source's subkey signs over.
    #[must_use]
    pub fn canonical_transcript(
        file_id: &FileId,
        chunk_hash: &ChunkHash,
        source_device_id: &[u8; DEVICE_ID_LEN],
        receiver_device_id: &[u8; DEVICE_ID_LEN],
        source_day_index: u64,
        delivered_unix: u64,
        byte_size: u32,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            ACK_DOMAIN.len()
                + FILE_ID_LEN
                + CHUNK_HASH_LEN
                + DEVICE_ID_LEN
                + DEVICE_ID_LEN
                + 8
                + 8
                + 4,
        );
        out.extend_from_slice(ACK_DOMAIN);
        out.extend_from_slice(file_id);
        out.extend_from_slice(chunk_hash);
        out.extend_from_slice(source_device_id);
        out.extend_from_slice(receiver_device_id);
        out.extend_from_slice(&source_day_index.to_be_bytes());
        out.extend_from_slice(&delivered_unix.to_be_bytes());
        out.extend_from_slice(&byte_size.to_be_bytes());
        out
    }

    /// Verify the source's signature.
    pub fn verify(&self, source_vk: &HybridVerifyingKey) -> DeviceMeshResult<()> {
        if self.source_sig.len() != HYBRID_SIG_LEN {
            return Err(DeviceMeshError::BadLength {
                expected: HYBRID_SIG_LEN,
                got: self.source_sig.len(),
            });
        }
        let transcript = Self::canonical_transcript(
            &self.file_id,
            &self.chunk_hash,
            &self.source_device_id,
            &self.receiver_device_id,
            self.source_day_index,
            self.delivered_unix,
            self.byte_size,
        );
        source_vk
            .verify(&transcript, &self.source_sig)
            .map_err(|_| DeviceMeshError::ChunkAckVerifyFail)
    }
}

/// Sign a chunk-ack as the SOURCE.
pub fn sign_chunk_ack(
    source: &DeviceSubkey,
    file_id: FileId,
    chunk_hash: ChunkHash,
    receiver_device_id: [u8; DEVICE_ID_LEN],
    delivered_unix: u64,
    byte_size: u32,
) -> DeviceMeshResult<ChunkAck> {
    let transcript = ChunkAck::canonical_transcript(
        &file_id,
        &chunk_hash,
        source.device_id(),
        &receiver_device_id,
        source.day_index(),
        delivered_unix,
        byte_size,
    );
    let sig = source.sign(&transcript)?;
    Ok(ChunkAck {
        file_id,
        chunk_hash,
        source_device_id: *source.device_id(),
        receiver_device_id,
        source_day_index: source.day_index(),
        delivered_unix,
        byte_size,
        source_sig: sig.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master::MasterIdentity;
    use crate::subkey::{fresh_device_id, mint_subkey};
    use crate::DeviceClass;
    use rand::rngs::OsRng;

    fn make_sk() -> DeviceSubkey {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = fresh_device_id(&mut OsRng);
        let (sk, _) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        sk
    }

    #[test]
    fn sign_verify_round_trip() {
        let sk = make_sk();
        let ack = sign_chunk_ack(
            &sk,
            [0xAA; FILE_ID_LEN],
            [0xBB; CHUNK_HASH_LEN],
            [0xCC; DEVICE_ID_LEN],
            1_700_000_000,
            8192,
        )
        .unwrap();
        ack.verify(&sk.verifying_key()).unwrap();
    }

    #[test]
    fn cross_subkey_verify_fails() {
        let sk_a = make_sk();
        let sk_b = make_sk();
        let ack = sign_chunk_ack(
            &sk_a,
            [0xAA; FILE_ID_LEN],
            [0xBB; CHUNK_HASH_LEN],
            [0xCC; DEVICE_ID_LEN],
            1,
            128,
        )
        .unwrap();
        let err = ack.verify(&sk_b.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::ChunkAckVerifyFail));
    }

    #[test]
    fn tampered_byte_size_breaks_verify() {
        let sk = make_sk();
        let mut ack = sign_chunk_ack(
            &sk,
            [0xAA; FILE_ID_LEN],
            [0xBB; CHUNK_HASH_LEN],
            [0xCC; DEVICE_ID_LEN],
            1,
            128,
        )
        .unwrap();
        ack.byte_size = 9_999;
        let err = ack.verify(&sk.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::ChunkAckVerifyFail));
    }
}
