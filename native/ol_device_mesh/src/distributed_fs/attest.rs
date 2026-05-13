//! Per-device storage attestations.
//!
//! Periodically, each device announces "I am `device_id`; at time T
//! I held these chunk hashes; here's my subkey signature." Replicas
//! ingest these and update the per-chunk placement index. A device
//! that stops attesting for a chunk is implicitly dropped from the
//! placement; the under-replication detector picks up the slack on
//! the next repair sweep.

use ol_pqsig::{HybridVerifyingKey, HYBRID_SIG_LEN};

use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::subkey::{DeviceSubkey, DEVICE_ID_LEN};

use super::manifest::{ChunkHash, CHUNK_HASH_LEN};

/// Domain-separation tag for the attestation signing transcript.
pub const ATTEST_DOMAIN: &[u8] = b"OL-mesh-storage-attest-v1";

/// Maximum chunk hashes per attestation. Bounds wire size + verify
/// cost.
pub const MAX_CHUNKS_PER_ATTESTATION: usize = 8192;

/// Per-device storage attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageAttestation {
    /// The device claiming to hold these chunks.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// Device subkey's day-index at sign time.
    pub day_index: u64,
    /// Wall-clock seconds at issue time.
    pub attest_unix: u64,
    /// Sorted, de-duplicated list of chunk hashes the device holds.
    /// The canonical transcript hashes this slice in order, so the
    /// caller MUST sort before signing.
    pub chunk_hashes: Vec<ChunkHash>,
    /// Subkey signature over the canonical transcript.
    pub subkey_sig: Vec<u8>,
}

impl StorageAttestation {
    /// Canonical bytes the subkey signs over.
    pub fn canonical_transcript(
        device_id: &[u8; DEVICE_ID_LEN],
        day_index: u64,
        attest_unix: u64,
        chunk_hashes: &[ChunkHash],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            ATTEST_DOMAIN.len()
                + DEVICE_ID_LEN
                + 8
                + 8
                + 4
                + chunk_hashes.len() * CHUNK_HASH_LEN,
        );
        out.extend_from_slice(ATTEST_DOMAIN);
        out.extend_from_slice(device_id);
        out.extend_from_slice(&day_index.to_be_bytes());
        out.extend_from_slice(&attest_unix.to_be_bytes());
        let count = u32::try_from(chunk_hashes.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_be_bytes());
        for c in chunk_hashes {
            out.extend_from_slice(c);
        }
        out
    }

    /// Validate the attestation's shape.
    pub fn shape_check(&self) -> DeviceMeshResult<()> {
        if self.chunk_hashes.len() > MAX_CHUNKS_PER_ATTESTATION {
            return Err(DeviceMeshError::AttestationTooManyChunks {
                got: self.chunk_hashes.len(),
                max: MAX_CHUNKS_PER_ATTESTATION,
            });
        }
        // chunk_hashes MUST be sorted + de-duplicated. We check by
        // walking the slice; this is O(N) and keeps the verify path
        // honest.
        let mut prev: Option<&ChunkHash> = None;
        for c in &self.chunk_hashes {
            if let Some(p) = prev {
                if c <= p {
                    return Err(DeviceMeshError::AttestationChunksNotSorted);
                }
            }
            prev = Some(c);
        }
        if self.subkey_sig.len() != HYBRID_SIG_LEN {
            return Err(DeviceMeshError::BadLength {
                expected: HYBRID_SIG_LEN,
                got: self.subkey_sig.len(),
            });
        }
        Ok(())
    }

    /// Verify the signature under `subkey_vk`. Caller is responsible
    /// for proving the VK is the emitter's via a Layer-1
    /// [`crate::SubkeyAttestation`] under the master.
    pub fn verify(&self, subkey_vk: &HybridVerifyingKey) -> DeviceMeshResult<()> {
        self.shape_check()?;
        let transcript = Self::canonical_transcript(
            &self.device_id,
            self.day_index,
            self.attest_unix,
            &self.chunk_hashes,
        );
        subkey_vk
            .verify(&transcript, &self.subkey_sig)
            .map_err(|_| DeviceMeshError::StorageAttestVerifyFail)
    }
}

/// Sign a fresh attestation. The supplied chunk hashes are sorted
/// + de-duplicated before signing so two devices that hold the same
/// set produce byte-identical transcripts (cross-device dedup).
pub fn sign_storage_attestation(
    subkey: &DeviceSubkey,
    attest_unix: u64,
    mut chunk_hashes: Vec<ChunkHash>,
) -> DeviceMeshResult<StorageAttestation> {
    chunk_hashes.sort();
    chunk_hashes.dedup();
    if chunk_hashes.len() > MAX_CHUNKS_PER_ATTESTATION {
        return Err(DeviceMeshError::AttestationTooManyChunks {
            got: chunk_hashes.len(),
            max: MAX_CHUNKS_PER_ATTESTATION,
        });
    }
    let transcript = StorageAttestation::canonical_transcript(
        subkey.device_id(),
        subkey.day_index(),
        attest_unix,
        &chunk_hashes,
    );
    let sig = subkey.sign(&transcript)?;
    Ok(StorageAttestation {
        device_id: *subkey.device_id(),
        day_index: subkey.day_index(),
        attest_unix,
        chunk_hashes,
        subkey_sig: sig.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master::MasterIdentity;
    use crate::subkey::{fresh_device_id, mint_subkey};
    use crate::DeviceClass;
    use rand::rngs::OsRng;

    fn make_chunks(n: usize) -> Vec<ChunkHash> {
        (0..n)
            .map(|i| {
                let mut x = [0u8; CHUNK_HASH_LEN];
                x[0] = i as u8;
                x[1] = (i >> 8) as u8;
                x
            })
            .collect()
    }

    fn make_sk() -> DeviceSubkey {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = fresh_device_id(&mut OsRng);
        let (sk, _att) =
            mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        sk
    }

    #[test]
    fn sign_verify_round_trip() {
        let sk = make_sk();
        let att = sign_storage_attestation(&sk, 1, make_chunks(5)).unwrap();
        att.verify(&sk.verifying_key()).unwrap();
    }

    #[test]
    fn unsorted_chunks_get_sorted_at_sign() {
        let sk = make_sk();
        let mut chunks = make_chunks(5);
        chunks.reverse();
        let att = sign_storage_attestation(&sk, 1, chunks).unwrap();
        let mut sorted = att.chunk_hashes.clone();
        sorted.sort();
        assert_eq!(att.chunk_hashes, sorted);
    }

    #[test]
    fn manually_unsorted_attest_rejected_at_verify() {
        let sk = make_sk();
        let mut att =
            sign_storage_attestation(&sk, 1, make_chunks(5)).unwrap();
        // Manually scramble: signature won't match either way, but
        // shape_check fires first.
        att.chunk_hashes.reverse();
        let err = att.verify(&sk.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::AttestationChunksNotSorted));
    }

    #[test]
    fn duplicate_chunks_collapse_at_sign() {
        let sk = make_sk();
        let chunks = vec![[0u8; CHUNK_HASH_LEN]; 5];
        let att = sign_storage_attestation(&sk, 1, chunks).unwrap();
        assert_eq!(att.chunk_hashes.len(), 1);
    }

    #[test]
    fn oversize_chunk_list_rejected() {
        let sk = make_sk();
        let too_many: Vec<ChunkHash> = (0..(MAX_CHUNKS_PER_ATTESTATION + 1))
            .map(|i| {
                let mut x = [0u8; CHUNK_HASH_LEN];
                x[..4].copy_from_slice(&(i as u32).to_be_bytes());
                x
            })
            .collect();
        let err =
            sign_storage_attestation(&sk, 1, too_many).unwrap_err();
        assert!(matches!(err, DeviceMeshError::AttestationTooManyChunks { .. }));
    }

    #[test]
    fn tampered_attest_fails_verify() {
        let sk = make_sk();
        let mut att = sign_storage_attestation(&sk, 1, make_chunks(5)).unwrap();
        att.chunk_hashes[0][0] ^= 0xFF;
        // The above reverses sort order so the wrong-sort path fires;
        // restore sort then try a non-sort-breaking tamper.
        att.chunk_hashes.sort();
        att.attest_unix = 9_999;
        let err = att.verify(&sk.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::StorageAttestVerifyFail));
    }
}
