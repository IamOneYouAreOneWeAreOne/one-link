//! Receiver-side signed fetch request.
//!
//! A [`FetchRequest`] is "I, device R, want chunks `X` from you,
//! device S, for `FileId` `F`, by deadline `D`." The receiver's subkey
//! signs the canonical bytes; sources verify under the master-
//! attested subkey VK before serving.

use ol_pqsig::{HybridVerifyingKey, HYBRID_SIG_LEN};

use crate::distributed_fs::{ChunkHash, FileId, CHUNK_HASH_LEN, FILE_ID_LEN};
use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::subkey::{DeviceSubkey, DEVICE_ID_LEN};

/// Length of the per-request nonce.
pub const FETCH_NONCE_LEN: usize = 16;
/// Per-request nonce.
pub type FetchNonce = [u8; FETCH_NONCE_LEN];

/// Max chunks one request can name. Bounds wire size + verify cost.
pub const MAX_CHUNKS_PER_FETCH: usize = 8192;

/// Domain-separation tag for fetch-request signing.
pub const FETCH_REQUEST_DOMAIN: &[u8] = b"OL-mesh-fetch-request-v1";

/// Receiver's signed fetch request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest {
    /// File the receiver is reassembling.
    pub file_id: FileId,
    /// The device asking for chunks (receiver).
    pub receiver_device_id: [u8; DEVICE_ID_LEN],
    /// The device being asked to serve (source).
    pub source_device_id: [u8; DEVICE_ID_LEN],
    /// Sorted, de-duplicated list of chunk hashes the receiver wants.
    /// Sources MUST serve only the listed hashes.
    pub chunk_hashes: Vec<ChunkHash>,
    /// Receiver-supplied upper bound on bytes the source may deliver
    /// in response. Sources stop once they've delivered this much.
    pub max_byte_budget: u64,
    /// Wall-clock seconds after which the source must drop the request.
    pub deadline_unix: u64,
    /// Per-request nonce. Sources track recently-seen nonces to drop
    /// duplicate requests.
    pub nonce: FetchNonce,
    /// Receiver subkey day-index at sign time.
    pub receiver_day_index: u64,
    /// Wall-clock seconds at sign time.
    pub issued_unix: u64,
    /// Receiver's subkey signature over the canonical transcript.
    pub receiver_sig: Vec<u8>,
}

impl FetchRequest {
    /// Canonical bytes the receiver's subkey signs over.
    ///
    /// 9 args reflects the wire-format binding; structural, not
    /// a logical bundle.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn canonical_transcript(
        file_id: &FileId,
        receiver_device_id: &[u8; DEVICE_ID_LEN],
        source_device_id: &[u8; DEVICE_ID_LEN],
        chunk_hashes: &[ChunkHash],
        max_byte_budget: u64,
        deadline_unix: u64,
        nonce: &FetchNonce,
        receiver_day_index: u64,
        issued_unix: u64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            FETCH_REQUEST_DOMAIN.len()
                + FILE_ID_LEN
                + DEVICE_ID_LEN
                + DEVICE_ID_LEN
                + 4
                + chunk_hashes.len() * CHUNK_HASH_LEN
                + 8
                + 8
                + FETCH_NONCE_LEN
                + 8
                + 8,
        );
        out.extend_from_slice(FETCH_REQUEST_DOMAIN);
        out.extend_from_slice(file_id);
        out.extend_from_slice(receiver_device_id);
        out.extend_from_slice(source_device_id);
        let count = u32::try_from(chunk_hashes.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_be_bytes());
        for c in chunk_hashes {
            out.extend_from_slice(c);
        }
        out.extend_from_slice(&max_byte_budget.to_be_bytes());
        out.extend_from_slice(&deadline_unix.to_be_bytes());
        out.extend_from_slice(nonce);
        out.extend_from_slice(&receiver_day_index.to_be_bytes());
        out.extend_from_slice(&issued_unix.to_be_bytes());
        out
    }

    /// Validate the request's shape.
    pub fn shape_check(&self) -> DeviceMeshResult<()> {
        if self.chunk_hashes.is_empty() {
            return Err(DeviceMeshError::FetchRequestEmpty);
        }
        if self.chunk_hashes.len() > MAX_CHUNKS_PER_FETCH {
            return Err(DeviceMeshError::FetchRequestTooManyChunks {
                got: self.chunk_hashes.len(),
                max: MAX_CHUNKS_PER_FETCH,
            });
        }
        let mut prev: Option<&ChunkHash> = None;
        for c in &self.chunk_hashes {
            if let Some(p) = prev {
                if c <= p {
                    return Err(DeviceMeshError::FetchRequestChunksNotSorted);
                }
            }
            prev = Some(c);
        }
        if self.deadline_unix <= self.issued_unix {
            return Err(DeviceMeshError::FetchRequestDeadlineNotAfterIssue {
                issued_unix: self.issued_unix,
                deadline_unix: self.deadline_unix,
            });
        }
        if self.receiver_sig.len() != HYBRID_SIG_LEN {
            return Err(DeviceMeshError::BadLength {
                expected: HYBRID_SIG_LEN,
                got: self.receiver_sig.len(),
            });
        }
        Ok(())
    }

    /// Verify the receiver's signature.
    pub fn verify(&self, receiver_vk: &HybridVerifyingKey) -> DeviceMeshResult<()> {
        self.shape_check()?;
        let transcript = Self::canonical_transcript(
            &self.file_id,
            &self.receiver_device_id,
            &self.source_device_id,
            &self.chunk_hashes,
            self.max_byte_budget,
            self.deadline_unix,
            &self.nonce,
            self.receiver_day_index,
            self.issued_unix,
        );
        receiver_vk
            .verify(&transcript, &self.receiver_sig)
            .map_err(|_| DeviceMeshError::FetchRequestVerifyFail)
    }
}

/// Sign a fetch request. Chunk hashes are sorted + de-duplicated at
/// sign time so two receivers asking for the same set produce
/// identical transcripts (caches benefit).
///
/// 8 args reflects the protocol's signed-field surface.
#[allow(clippy::too_many_arguments)]
pub fn sign_fetch_request(
    receiver: &DeviceSubkey,
    source_device_id: [u8; DEVICE_ID_LEN],
    file_id: FileId,
    mut chunk_hashes: Vec<ChunkHash>,
    max_byte_budget: u64,
    issued_unix: u64,
    deadline_unix: u64,
    nonce: FetchNonce,
) -> DeviceMeshResult<FetchRequest> {
    if deadline_unix <= issued_unix {
        return Err(DeviceMeshError::FetchRequestDeadlineNotAfterIssue {
            issued_unix,
            deadline_unix,
        });
    }
    chunk_hashes.sort_unstable();
    chunk_hashes.dedup();
    if chunk_hashes.is_empty() {
        return Err(DeviceMeshError::FetchRequestEmpty);
    }
    if chunk_hashes.len() > MAX_CHUNKS_PER_FETCH {
        return Err(DeviceMeshError::FetchRequestTooManyChunks {
            got: chunk_hashes.len(),
            max: MAX_CHUNKS_PER_FETCH,
        });
    }
    let transcript = FetchRequest::canonical_transcript(
        &file_id,
        receiver.device_id(),
        &source_device_id,
        &chunk_hashes,
        max_byte_budget,
        deadline_unix,
        &nonce,
        receiver.day_index(),
        issued_unix,
    );
    let sig = receiver.sign(&transcript)?;
    Ok(FetchRequest {
        file_id,
        receiver_device_id: *receiver.device_id(),
        source_device_id,
        chunk_hashes,
        max_byte_budget,
        deadline_unix,
        nonce,
        receiver_day_index: receiver.day_index(),
        issued_unix,
        receiver_sig: sig.to_vec(),
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
        let req = sign_fetch_request(
            &sk,
            [0xBB; DEVICE_ID_LEN],
            [0xCC; FILE_ID_LEN],
            vec![[0x01; 32], [0x02; 32]],
            1_000_000,
            1,
            10_000,
            [0xDA; FETCH_NONCE_LEN],
        )
        .unwrap();
        req.verify(&sk.verifying_key()).unwrap();
    }

    #[test]
    fn deadline_before_issue_rejected() {
        let sk = make_sk();
        let err = sign_fetch_request(
            &sk,
            [0xBB; DEVICE_ID_LEN],
            [0xCC; FILE_ID_LEN],
            vec![[0x01; 32]],
            1,
            10,
            5,
            [0xDA; FETCH_NONCE_LEN],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::FetchRequestDeadlineNotAfterIssue { .. }
        ));
    }

    #[test]
    fn empty_chunk_list_rejected() {
        let sk = make_sk();
        let err = sign_fetch_request(
            &sk,
            [0xBB; DEVICE_ID_LEN],
            [0xCC; FILE_ID_LEN],
            vec![],
            1,
            1,
            10,
            [0xDA; FETCH_NONCE_LEN],
        )
        .unwrap_err();
        assert!(matches!(err, DeviceMeshError::FetchRequestEmpty));
    }

    #[test]
    fn duplicates_collapse_at_sign() {
        let sk = make_sk();
        let chunks = vec![[0x01; 32]; 5];
        let req = sign_fetch_request(
            &sk,
            [0xBB; DEVICE_ID_LEN],
            [0xCC; FILE_ID_LEN],
            chunks,
            1,
            1,
            10,
            [0xDA; FETCH_NONCE_LEN],
        )
        .unwrap();
        assert_eq!(req.chunk_hashes.len(), 1);
    }

    #[test]
    fn manual_unsort_rejected_at_verify() {
        let sk = make_sk();
        let mut req = sign_fetch_request(
            &sk,
            [0xBB; DEVICE_ID_LEN],
            [0xCC; FILE_ID_LEN],
            vec![[0x01; 32], [0x02; 32], [0x03; 32]],
            1,
            1,
            10,
            [0xDA; FETCH_NONCE_LEN],
        )
        .unwrap();
        req.chunk_hashes.swap(0, 2);
        let err = req.verify(&sk.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::FetchRequestChunksNotSorted));
    }

    #[test]
    fn tampered_file_id_breaks_verify() {
        let sk = make_sk();
        let mut req = sign_fetch_request(
            &sk,
            [0xBB; DEVICE_ID_LEN],
            [0xCC; FILE_ID_LEN],
            vec![[0x01; 32]],
            1,
            1,
            10,
            [0xDA; FETCH_NONCE_LEN],
        )
        .unwrap();
        req.file_id[0] ^= 0xFF;
        let err = req.verify(&sk.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::FetchRequestVerifyFail));
    }
}
