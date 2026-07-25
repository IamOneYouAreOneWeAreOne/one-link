//! File manifests and content addressing.
//!
//! A [`FileManifest`] is the canonical description of a file in the
//! distributed FS: ordered list of chunk hashes, total size, mime
//! type, erasure policy, creation timestamp. The [`FileId`] is
//! BLAKE3 over the canonical manifest bytes, so two devices that
//! produce identical manifests get identical `FileIds` (the dedup
//! property).

use blake3::Hasher;

use crate::errors::{DeviceMeshError, DeviceMeshResult};

use super::policy::ErasurePolicy;

/// Length of a [`FileId`] in bytes.
pub const FILE_ID_LEN: usize = 32;
/// Length of a [`ChunkHash`] in bytes.
pub const CHUNK_HASH_LEN: usize = 32;

/// 32-byte content-addressed file id.
pub type FileId = [u8; FILE_ID_LEN];
/// 32-byte content-addressed chunk hash.
pub type ChunkHash = [u8; CHUNK_HASH_LEN];

/// Maximum number of chunk hashes one manifest can carry. Bounds
/// canonical-encoding cost + memory at parse time. At 8 KiB
/// per chunk (the typical CDC mean), one manifest covers files
/// up to roughly 8 GiB — fine for the personal-FS use case.
pub const MAX_CHUNKS_PER_FILE: usize = 1_048_576;

/// Maximum mime-type string length.
pub const MAX_MIME_LEN: usize = 64;

/// Domain-separation tag for the manifest canonical-bytes form.
pub const MANIFEST_DOMAIN: &[u8] = b"OL-mesh-file-manifest-v1";

/// File manifest — the canonical record describing one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileManifest {
    /// Total plaintext size of the file in bytes.
    pub file_size: u64,
    /// Plaintext chunk size used during the chunking pass.
    pub chunk_size: u32,
    /// Ordered list of chunk hashes (after erasure encoding, so this
    /// is `k + m` shards per "row" if you laid them out as a matrix).
    pub chunks: Vec<ChunkHash>,
    /// Mime type. Bounded.
    pub mime: Vec<u8>,
    /// Unix-seconds creation timestamp.
    pub created_unix: u64,
    /// Erasure policy at mint time.
    pub policy: ErasurePolicy,
}

impl FileManifest {
    /// Validate the manifest's shape (bounds + chunk count rules).
    pub fn shape_check(&self) -> DeviceMeshResult<()> {
        self.policy.validate()?;
        if self.chunks.is_empty() {
            return Err(DeviceMeshError::FileManifestEmpty);
        }
        if self.chunks.len() > MAX_CHUNKS_PER_FILE {
            return Err(DeviceMeshError::FileManifestTooManyChunks {
                got: self.chunks.len(),
                max: MAX_CHUNKS_PER_FILE,
            });
        }
        if self.mime.len() > MAX_MIME_LEN {
            return Err(DeviceMeshError::FileManifestMimeTooLong {
                got: self.mime.len(),
                max: MAX_MIME_LEN,
            });
        }
        if self.chunk_size == 0 {
            return Err(DeviceMeshError::FileManifestZeroChunkSize);
        }
        // chunks count must be a multiple of (k + m) so the erasure
        // matrix is rectangular: each stripe contributes (k + m)
        // shards.
        let total = self.policy.total_shards() as usize;
        if !self.chunks.len().is_multiple_of(total) {
            return Err(DeviceMeshError::FileManifestChunkCountNotStripe {
                got: self.chunks.len(),
                stripe: total,
            });
        }
        Ok(())
    }

    /// Canonical byte serialization. Used both for computing the
    /// [`FileId`] and for transporting the manifest on the wire.
    ///
    /// Layout (length-prefixed, big-endian):
    ///
    /// ```text
    /// MANIFEST_DOMAIN    (24 bytes ASCII)
    /// file_size          (8  bytes)
    /// chunk_size         (4  bytes)
    /// policy.k           (1  byte)
    /// policy.m           (1  byte)
    /// policy.min_devices_per_shard (1 byte)
    /// created_unix       (8  bytes)
    /// mime_len_be        (2  bytes)
    /// mime               (mime_len bytes)
    /// chunk_count_be     (4  bytes)
    /// chunk_hashes       (CHUNK_HASH_LEN * chunk_count bytes)
    /// ```
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            MANIFEST_DOMAIN.len()
                + 8
                + 4
                + 3
                + 8
                + 2
                + self.mime.len()
                + 4
                + self.chunks.len() * CHUNK_HASH_LEN,
        );
        out.extend_from_slice(MANIFEST_DOMAIN);
        out.extend_from_slice(&self.file_size.to_be_bytes());
        out.extend_from_slice(&self.chunk_size.to_be_bytes());
        out.push(self.policy.k);
        out.push(self.policy.m);
        out.push(self.policy.min_devices_per_shard);
        out.extend_from_slice(&self.created_unix.to_be_bytes());
        let mime_len = u16::try_from(self.mime.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&mime_len.to_be_bytes());
        out.extend_from_slice(&self.mime[..mime_len as usize]);
        let chunk_count = u32::try_from(self.chunks.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&chunk_count.to_be_bytes());
        for c in &self.chunks {
            out.extend_from_slice(c);
        }
        out
    }

    /// Compute the content-addressed [`FileId`] for this manifest.
    #[must_use]
    pub fn file_id(&self) -> FileId {
        file_id(&self.canonical_bytes())
    }
}

/// Compute a [`FileId`] from raw canonical manifest bytes.
#[must_use]
pub fn file_id(manifest_bytes: &[u8]) -> FileId {
    let mut h = Hasher::new();
    h.update(b"OL-mesh-file-id-v1");
    h.update(manifest_bytes);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn round_trip_canonical_bytes_yields_stable_file_id() {
        let p = ErasurePolicy::new(2, 1, 1).unwrap();
        let m = FileManifest {
            file_size: 1234,
            chunk_size: 256,
            chunks: make_chunks(3),
            mime: b"text/plain".to_vec(),
            created_unix: 1_700_000_000,
            policy: p,
        };
        m.shape_check().unwrap();
        let id_a = m.file_id();
        let id_b = m.file_id();
        assert_eq!(id_a, id_b);
    }

    #[test]
    fn distinct_chunks_yield_distinct_file_ids() {
        let p = ErasurePolicy::new(2, 1, 1).unwrap();
        let mut a = FileManifest {
            file_size: 1234,
            chunk_size: 256,
            chunks: make_chunks(3),
            mime: b"text/plain".to_vec(),
            created_unix: 1_700_000_000,
            policy: p,
        };
        let b = a.clone();
        a.chunks[0][0] ^= 0xFF;
        assert_ne!(a.file_id(), b.file_id());
    }

    #[test]
    fn empty_chunks_rejected() {
        let p = ErasurePolicy::new(2, 1, 1).unwrap();
        let m = FileManifest {
            file_size: 0,
            chunk_size: 256,
            chunks: vec![],
            mime: b"".to_vec(),
            created_unix: 0,
            policy: p,
        };
        let err = m.shape_check().unwrap_err();
        assert!(matches!(err, DeviceMeshError::FileManifestEmpty));
    }

    #[test]
    fn forged_zero_shard_policy_is_rejected_without_modulo_by_zero() {
        let manifest = FileManifest {
            file_size: 1,
            chunk_size: 1,
            chunks: make_chunks(1),
            mime: Vec::new(),
            created_unix: 0,
            policy: ErasurePolicy {
                k: 0,
                m: 0,
                min_devices_per_shard: 1,
            },
        };
        assert!(matches!(
            manifest.shape_check(),
            Err(DeviceMeshError::ErasurePolicyZeroData)
        ));
    }

    #[test]
    fn non_stripe_chunk_count_rejected() {
        // (k=2, m=1) ⇒ stripe = 3. 4 chunks isn't a multiple of 3.
        let p = ErasurePolicy::new(2, 1, 1).unwrap();
        let m = FileManifest {
            file_size: 100,
            chunk_size: 32,
            chunks: make_chunks(4),
            mime: b"".to_vec(),
            created_unix: 0,
            policy: p,
        };
        let err = m.shape_check().unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::FileManifestChunkCountNotStripe { .. }
        ));
    }

    #[test]
    fn oversize_mime_rejected() {
        let p = ErasurePolicy::new(2, 1, 1).unwrap();
        let m = FileManifest {
            file_size: 1,
            chunk_size: 1,
            chunks: make_chunks(3),
            mime: vec![b'x'; MAX_MIME_LEN + 1],
            created_unix: 0,
            policy: p,
        };
        let err = m.shape_check().unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::FileManifestMimeTooLong { .. }
        ));
    }

    #[test]
    fn zero_chunk_size_rejected() {
        let p = ErasurePolicy::new(2, 1, 1).unwrap();
        let m = FileManifest {
            file_size: 1,
            chunk_size: 0,
            chunks: make_chunks(3),
            mime: b"".to_vec(),
            created_unix: 0,
            policy: p,
        };
        let err = m.shape_check().unwrap_err();
        assert!(matches!(err, DeviceMeshError::FileManifestZeroChunkSize));
    }
}
