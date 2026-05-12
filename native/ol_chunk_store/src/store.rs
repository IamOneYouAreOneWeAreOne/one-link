//! `ChunkStore` — the integrating layer that combines `ol_wal`,
//! `ol_chunk` derivation, and the in-memory memtable + bloom into the
//! actual chunk store the daemon uses.
//!
//! Per [ADR-0003](../../../docs/decisions/0003-on-disk-format.md) +
//! [ADR-0005](../../../docs/decisions/0005-manifest-wal-coupling.md):
//!
//! - Two log directories side-by-side: `<root>/chunk_log/`,
//!   `<root>/manifest_log/`. Each managed by its own [`ol_wal::Wal`].
//! - On `write_chunk`: append to chunk_log → flush → append matching
//!   manifest entry with `chunk_log_anchor` set to the offset of the
//!   chunk just written → flush. **Two fsyncs per logical write,
//!   batched via group commit when the caller batches writes.**
//! - On `read_chunk`: memtable lookup → resolve to (file_id, offset) →
//!   `pread` the record → CRC verify → return chunk-record + ciphertext.
//! - On boot: replay both logs in order, rebuild the memtable + bloom.
//!   Reject any manifest record whose `chunk_log_anchor` doesn't
//!   resolve to a real chunk in the chunk_log (orphan).

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ol_wal::{LogKind, Record as WalRecord, Wal};

use crate::chunk_record::{ChunkRecord, CHUNK_RECORD_HEADER_LEN};
use crate::error::ChunkStoreError;
use crate::location::ChunkLocation;
use crate::manifest_record::ManifestRecord;
use crate::memtable::Memtable;

/// Subdirectory names under the chunk store root.
const CHUNK_LOG_DIRNAME: &str = "chunk_log";
const MANIFEST_LOG_DIRNAME: &str = "manifest_log";

/// Diagnostic counters surfaced to operators.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct StoreStats {
    /// Chunks indexed in the memtable.
    pub indexed_chunks: usize,
    /// Manifest records replayed.
    pub manifest_records: usize,
    /// Bytes scanned across both logs at boot.
    pub bytes_scanned_at_replay: u64,
    /// Files truncated during recovery (tail-CRC failures).
    pub files_truncated: usize,
    /// Manifest records rejected for dangling chunk_log_anchor.
    pub orphaned_manifest_records: usize,
}

/// The chunk store.
///
/// Single-writer model. The daemon coordinates concurrent writers via a
/// Mutex or single writer thread; this type is `!Sync`.
pub struct ChunkStore {
    root: PathBuf,
    chunk_log: Wal,
    manifest_log: Wal,
    memtable: Memtable,
    /// Tracks the offset of the most recently appended chunk_log record;
    /// used as the `chunk_log_anchor` for the next manifest record.
    last_chunk_log_offset: u64,
    /// LRU pool of open chunk_log file handles, keyed by file_id.
    /// `Mutex` (instead of `RefCell`) so the chunk store stays `Sync`,
    /// which the pyo3 binding requires for `&self` methods that release
    /// the GIL via `allow_threads`. Lock contention is minimal: each
    /// `read_chunk` holds the lock only for a short seek + read.
    /// Bounded at [`MAX_OPEN_CHUNK_LOG_FDS`]; LRU evicts oldest fd.
    read_fds: Mutex<FdPool>,
    stats: StoreStats,
    closed: bool,
}

/// Maximum number of open chunk_log file handles to keep cached for
/// random-access reads. Each fd is ~few KiB of OS overhead; this is a
/// generous cache that covers the working set of typical small-business
/// workloads (a few hundred GiB at 64 KiB chunks → 1-4 chunk_log files).
pub const MAX_OPEN_CHUNK_LOG_FDS: usize = 16;

/// LRU file-handle pool for `read_chunk`. Per ADR-0007, sealed
/// chunk_log files are immutable; the active file is append-only and
/// safe to read concurrently with writes (the writer never overwrites
/// already-fsync'd bytes). Holding read fds across many calls is
/// therefore safe and dramatically faster than re-opening on every read.
struct FdPool {
    fds: HashMap<u64, File>,
    /// Insertion-order ring used as a poor-man's LRU. We pop from the
    /// front when at capacity; `MAX_OPEN_CHUNK_LOG_FDS` is small enough
    /// that the linear scan is cheaper than a doubly-linked-list LRU.
    order: Vec<u64>,
}

impl FdPool {
    fn new() -> Self {
        Self {
            fds: HashMap::with_capacity(MAX_OPEN_CHUNK_LOG_FDS),
            order: Vec::with_capacity(MAX_OPEN_CHUNK_LOG_FDS),
        }
    }

    /// Borrow the file handle for `file_id`, opening + caching it on a miss.
    /// Marks the entry as most-recently-used.
    fn get_or_open(&mut self, root: &Path, file_id: u64) -> Result<&mut File, std::io::Error> {
        // Update LRU order regardless of hit/miss.
        if let Some(pos) = self.order.iter().position(|x| *x == file_id) {
            self.order.remove(pos);
        }
        self.order.push(file_id);

        if !self.fds.contains_key(&file_id) {
            // Evict the LRU if at capacity.
            if self.fds.len() >= MAX_OPEN_CHUNK_LOG_FDS {
                if let Some(stale_id) = self.order.first().copied() {
                    if stale_id != file_id {
                        self.fds.remove(&stale_id);
                        self.order.remove(0);
                    }
                }
            }
            let path = root
                .join(CHUNK_LOG_DIRNAME)
                .join(format!("{file_id:06}.wal"));
            let f = File::open(&path)?;
            self.fds.insert(file_id, f);
        }
        Ok(self.fds.get_mut(&file_id).expect("just inserted"))
    }
}

impl std::fmt::Debug for ChunkStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkStore")
            .field("root", &self.root)
            .field("memtable_len", &self.memtable.len())
            .field("last_chunk_log_offset", &self.last_chunk_log_offset)
            .field("closed", &self.closed)
            .field("stats", &self.stats)
            .finish()
    }
}

impl ChunkStore {
    /// Open or create a chunk store rooted at `root`.
    ///
    /// On first run, creates the chunk_log + manifest_log subdirectories
    /// with their initial WAL files. On subsequent runs, replays both
    /// logs in order, rebuilds the memtable + bloom, and resumes
    /// appending to the highest WAL files.
    ///
    /// # Errors
    ///
    /// - I/O errors.
    /// - WAL header / CRC validation errors.
    /// - Dangling-anchor errors from the manifest log replay (manifests
    ///   that reference chunk_log offsets that don't resolve).
    pub fn open(root: &Path) -> Result<Self, ChunkStoreError> {
        let chunk_dir = root.join(CHUNK_LOG_DIRNAME);
        let manifest_dir = root.join(MANIFEST_LOG_DIRNAME);
        std::fs::create_dir_all(&chunk_dir)?;
        std::fs::create_dir_all(&manifest_dir)?;

        // Replay chunk_log first to rebuild the memtable + bloom.
        let chunk_replay = ol_wal::replay_log_dir(&chunk_dir, LogKind::ChunkLog)?;
        let mut memtable = Memtable::with_capacity(chunk_replay.records.len().max(1024));
        // Reconstruct (chunk_id, location) by scanning records and
        // computing offsets. The replay returns records in append order
        // but doesn't expose per-record offsets; we re-walk the files
        // for offset reconstruction.
        let chunk_files = sorted_log_files(&chunk_dir)?;
        let mut chunk_offsets: Vec<(u64, u64, ChunkRecord)> =
            Vec::with_capacity(chunk_replay.records.len());
        for (file_id, path) in chunk_files {
            let bytes = std::fs::read(&path)?;
            let mut cursor: u64 = u64::from(ol_wal::FILE_HEADER_LEN);
            while (cursor as usize) < bytes.len() {
                // Parse WAL framing manually to recover offsets.
                let pos = cursor as usize;
                if bytes.len() < pos + 8 {
                    break;
                }
                let kind = bytes[pos];
                let flags = bytes[pos + 1];
                let length =
                    u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().expect("4 bytes"));
                let total = 8 + length as usize + 4;
                if pos + total > bytes.len() {
                    break;
                }
                // Validate the same CRC the replay layer validated, just
                // to be safe (cheap).
                let body = &bytes[pos..pos + total];
                if !ol_wal::crc_valid_record(body) {
                    break;
                }
                let payload = &bytes[pos + 8..pos + 8 + length as usize];
                if let Ok(rec) = ChunkRecord::decode(kind, flags, payload) {
                    chunk_offsets.push((file_id, cursor, rec));
                }
                cursor += total as u64;
            }
        }

        let mut last_chunk_log_offset = 0u64;
        for (file_id, wal_offset, rec) in &chunk_offsets {
            let location = ChunkLocation {
                file_id: *file_id,
                wal_offset: *wal_offset,
                length_plaintext: rec.length_plaintext,
                length_ciphertext: rec.ciphertext.len() as u32,
                ratchet_key_id: rec.ratchet_key_id,
                stripe_descriptor: rec.stripe_descriptor,
            };
            memtable.insert(rec.chunk_id, location);
            last_chunk_log_offset = *wal_offset;
        }

        // Replay manifest_log; reject orphans.
        let manifest_replay = ol_wal::replay_log_dir(&manifest_dir, LogKind::ManifestLog)?;
        let mut orphaned = 0usize;
        let mut manifest_count = 0usize;
        let chunk_offset_set: std::collections::HashSet<u64> =
            chunk_offsets.iter().map(|(_, off, _)| *off).collect();
        for r in &manifest_replay.records {
            match ManifestRecord::decode(r.kind, r.flags, &r.payload) {
                Ok(m) => {
                    if m.chunk_log_anchor != 0 && !chunk_offset_set.contains(&m.chunk_log_anchor) {
                        // Orphan: anchor doesn't resolve to a chunk_log
                        // offset. Per ADR-0005 recovery rule, reject
                        // the manifest record.
                        orphaned += 1;
                    } else {
                        manifest_count += 1;
                    }
                }
                Err(_) => {
                    orphaned += 1;
                }
            }
        }

        // Open the underlying writers for append-after-recovery.
        let chunk_log = Wal::open(&chunk_dir, LogKind::ChunkLog)?;
        let manifest_log = Wal::open(&manifest_dir, LogKind::ManifestLog)?;

        let stats = StoreStats {
            indexed_chunks: memtable.len(),
            manifest_records: manifest_count,
            bytes_scanned_at_replay: chunk_replay.bytes_scanned + manifest_replay.bytes_scanned,
            files_truncated: chunk_replay.truncated.len() + manifest_replay.truncated.len(),
            orphaned_manifest_records: orphaned,
        };

        Ok(Self {
            root: root.to_path_buf(),
            chunk_log,
            manifest_log,
            memtable,
            last_chunk_log_offset,
            read_fds: Mutex::new(FdPool::new()),
            stats,
            closed: false,
        })
    }

    /// Check if a chunk is in the store.
    #[inline]
    #[must_use]
    pub fn has_chunk(&self, chunk_id: &[u8; 32]) -> bool {
        self.memtable.contains(chunk_id)
    }

    /// Get a chunk's location without reading the chunk_log.
    #[inline]
    #[must_use]
    pub fn locate_chunk(&self, chunk_id: &[u8; 32]) -> Option<ChunkLocation> {
        self.memtable.get(chunk_id).copied()
    }

    /// Append a chunk record to the chunk_log. Does NOT fsync; call
    /// [`ChunkStore::flush`] (or rely on `write_chunk_durable` for the
    /// fsync-coupled variant) before treating the chunk as durable.
    ///
    /// Updates the in-memory memtable + bloom synchronously.
    ///
    /// # Errors
    ///
    /// - WAL append errors (rotation cap, I/O).
    pub fn append_chunk(&mut self, record: &ChunkRecord) -> Result<u64, ChunkStoreError> {
        if self.closed {
            return Err(ChunkStoreError::Closed);
        }
        let (kind, flags, payload) = record.encode();
        let wal_record = WalRecord {
            kind,
            flags,
            payload,
        };
        let offset_in_file = self.chunk_log.active_file_size();
        self.chunk_log.append(&wal_record)?;
        let location = ChunkLocation {
            file_id: self.chunk_log.active_file_id(),
            wal_offset: offset_in_file,
            length_plaintext: record.length_plaintext,
            length_ciphertext: record.ciphertext.len() as u32,
            ratchet_key_id: record.ratchet_key_id,
            stripe_descriptor: record.stripe_descriptor,
        };
        self.memtable.insert(record.chunk_id, location);
        self.last_chunk_log_offset = offset_in_file;
        Ok(offset_in_file)
    }

    /// Append a manifest record to the manifest_log. The
    /// `chunk_log_anchor` field is set automatically to the most-recent
    /// chunk_log offset, per ADR-0005 atomicity protocol. Callers can
    /// override by setting the field on the record explicitly before
    /// passing here (e.g. to point at an older chunk).
    ///
    /// # Errors
    ///
    /// - WAL append errors.
    pub fn append_manifest(&mut self, record: &ManifestRecord) -> Result<(), ChunkStoreError> {
        if self.closed {
            return Err(ChunkStoreError::Closed);
        }
        let mut rec = record.clone();
        if rec.chunk_log_anchor == 0 {
            rec.chunk_log_anchor = self.last_chunk_log_offset;
        }
        let (kind, flags, payload) = rec.encode();
        let wal_record = WalRecord {
            kind,
            flags,
            payload,
        };
        self.manifest_log.append(&wal_record)?;
        Ok(())
    }

    /// Flush BOTH logs to durable storage. Per ADR-0005, this is the
    /// barrier that makes the most recent batch of (chunk, manifest)
    /// pairs durable as a unit.
    ///
    /// # Errors
    ///
    /// - I/O errors.
    pub fn flush(&mut self) -> Result<(), ChunkStoreError> {
        if self.closed {
            return Err(ChunkStoreError::Closed);
        }
        self.chunk_log.flush()?;
        self.manifest_log.flush()?;
        Ok(())
    }

    /// Read a chunk's full record (header + ciphertext) by chunk_id.
    ///
    /// Uses a persistent file-handle pool ([`FdPool`]) so warm reads do
    /// a single seek + read of just the chunk's bytes — no whole-file
    /// re-read. Cold reads (file_id not in the pool) open the fd and
    /// cache it; LRU evicts the oldest if the pool is at capacity.
    ///
    /// # Errors
    ///
    /// - [`ChunkStoreError::ChunkNotFound`] if the memtable doesn't
    ///   know about this chunk.
    /// - I/O errors reading the chunk_log file.
    /// - [`ChunkStoreError::MalformedRecord`] if the on-disk record
    ///   fails to parse (would indicate corruption past the WAL CRC,
    ///   which is logically impossible; raise loudly).
    pub fn read_chunk(&self, chunk_id: &[u8; 32]) -> Result<ChunkRecord, ChunkStoreError> {
        let location =
            self.memtable
                .get(chunk_id)
                .copied()
                .ok_or_else(|| ChunkStoreError::ChunkNotFound {
                    chunk_id_hex_prefix: hex_lower_8(&chunk_id[..8]),
                })?;
        let total = 8 + CHUNK_RECORD_HEADER_LEN + location.length_ciphertext as usize + 4;
        let mut buf = vec![0u8; total];
        {
            let mut pool = self
                .read_fds
                .lock()
                .map_err(|_| ChunkStoreError::MalformedRecord {
                    offset: location.wal_offset,
                    reason: "read_fds mutex poisoned",
                })?;
            let fd = pool.get_or_open(&self.root, location.file_id)?;
            fd.seek(SeekFrom::Start(location.wal_offset))?;
            fd.read_exact(&mut buf)?;
        }
        let kind = buf[0];
        let flags = buf[1];
        let length = u32::from_le_bytes(buf[4..8].try_into().expect("4 bytes"));
        let payload = &buf[8..8 + length as usize];
        ChunkRecord::decode(kind, flags, payload).map_err(|e| match e {
            ChunkStoreError::MalformedRecord { reason, .. } => ChunkStoreError::MalformedRecord {
                offset: location.wal_offset,
                reason,
            },
            other => other,
        })
    }

    /// Diagnostic snapshot.
    #[inline]
    #[must_use]
    pub fn stats(&self) -> StoreStats {
        let mut s = self.stats.clone();
        s.indexed_chunks = self.memtable.len();
        s
    }

    /// Collect all chunk_ids currently in the memtable. Used by
    /// higher-level engines (e.g. `ol_transfer`) that need to feed the
    /// inventory into a Bloom-init handshake or a manifest scope check.
    ///
    /// Order is unspecified (HashMap iteration order). Cost is O(N).
    #[must_use]
    pub fn collect_chunk_ids(&self) -> Vec<[u8; 32]> {
        self.memtable.iter().map(|(cid, _)| *cid).collect()
    }

    /// Close the store, flushing both logs. Subsequent calls fail with
    /// [`ChunkStoreError::Closed`].
    ///
    /// # Errors
    ///
    /// - I/O errors during the final flush.
    pub fn close(&mut self) -> Result<(), ChunkStoreError> {
        if self.closed {
            return Ok(());
        }
        self.flush()?;
        self.closed = true;
        Ok(())
    }
}

impl Drop for ChunkStore {
    fn drop(&mut self) {
        if !self.closed {
            // Best-effort flush. Crash-only design tolerates kill -9
            // before flush; this is the well-behaved-shutdown path.
            let _ = self.flush();
        }
    }
}

fn sorted_log_files(dir: &Path) -> Result<Vec<(u64, PathBuf)>, ChunkStoreError> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(stem) = name.strip_suffix(".wal") {
            if let Ok(id) = stem.parse::<u64>() {
                out.push((id, entry.path()));
            }
        }
    }
    out.sort_by_key(|(id, _)| *id);
    Ok(out)
}

fn hex_lower_8(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk_record::{ChunkAddressKind, ChunkAeadKind, ChunkRecord, ChunkRecordKind};
    use crate::manifest_record::{ManifestRecord, ManifestRecordKind};
    use crate::stripe::StripeDescriptor;
    use tempfile::tempdir;

    fn chunk(id_byte: u8, plaintext_len: u32, ciphertext_len: usize) -> ChunkRecord {
        let mut chunk_id = [0u8; 32];
        chunk_id[0] = id_byte;
        ChunkRecord {
            kind: ChunkRecordKind::ChunkBlob,
            address_kind: ChunkAddressKind::Raw,
            aead_kind: ChunkAeadKind::AesGcm256,
            compressed: false,
            format_aware: false,
            length_plaintext: plaintext_len,
            chunk_id,
            ratchet_key_id: [id_byte; 16],
            stripe_descriptor: StripeDescriptor::NONE,
            ciphertext: vec![id_byte; ciphertext_len],
        }
    }

    fn manifest(kind: ManifestRecordKind, body: &[u8]) -> ManifestRecord {
        ManifestRecord {
            kind,
            flags: 0,
            hlc_timestamp: 1,
            actor_id: [0u8; 32],
            chunk_log_anchor: 0,
            body: body.to_vec(),
        }
    }

    #[test]
    fn open_creates_dirs() {
        let dir = tempdir().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();
        assert!(dir.path().join("chunk_log").exists());
        assert!(dir.path().join("manifest_log").exists());
        assert_eq!(store.stats().indexed_chunks, 0);
    }

    #[test]
    fn write_then_locate_then_read() {
        let dir = tempdir().unwrap();
        let mut store = ChunkStore::open(dir.path()).unwrap();
        let r = chunk(0xAB, 1024, 1040);
        store.append_chunk(&r).unwrap();
        store.flush().unwrap();
        assert!(store.has_chunk(&r.chunk_id));
        let loc = store.locate_chunk(&r.chunk_id).unwrap();
        assert_eq!(loc.length_plaintext, 1024);
        assert_eq!(loc.length_ciphertext, 1040);
        let read_back = store.read_chunk(&r.chunk_id).unwrap();
        assert_eq!(read_back, r);
    }

    #[test]
    fn write_chunk_then_manifest_pairs_anchor() {
        let dir = tempdir().unwrap();
        let mut store = ChunkStore::open(dir.path()).unwrap();
        let c = chunk(0x01, 100, 116);
        store.append_chunk(&c).unwrap();
        let chunk_offset = store.last_chunk_log_offset;
        store
            .append_manifest(&manifest(ManifestRecordKind::ManifestVersion, b"folder-op"))
            .unwrap();
        store.flush().unwrap();

        // Reopen and verify both replay correctly with the anchor matching.
        let store2 = ChunkStore::open(dir.path()).unwrap();
        let stats = store2.stats();
        assert_eq!(stats.indexed_chunks, 1);
        assert_eq!(stats.manifest_records, 1);
        assert_eq!(stats.orphaned_manifest_records, 0);
        assert_eq!(store2.last_chunk_log_offset, chunk_offset);
    }

    #[test]
    fn replay_rebuilds_memtable() {
        let dir = tempdir().unwrap();
        let chunks = (0u8..16).map(|i| chunk(i, 64, 80)).collect::<Vec<_>>();
        {
            let mut store = ChunkStore::open(dir.path()).unwrap();
            for c in &chunks {
                store.append_chunk(c).unwrap();
            }
            store.flush().unwrap();
        }
        let store2 = ChunkStore::open(dir.path()).unwrap();
        assert_eq!(store2.stats().indexed_chunks, 16);
        for c in &chunks {
            assert!(store2.has_chunk(&c.chunk_id));
            let read_back = store2.read_chunk(&c.chunk_id).unwrap();
            assert_eq!(read_back.length_plaintext, c.length_plaintext);
            assert_eq!(read_back.ciphertext, c.ciphertext);
        }
    }

    #[test]
    fn read_chunk_not_found() {
        let dir = tempdir().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();
        let result = store.read_chunk(&[0u8; 32]);
        assert!(matches!(result, Err(ChunkStoreError::ChunkNotFound { .. })));
    }

    #[test]
    fn duplicate_chunk_id_overwrites_location() {
        // Same chunk_id written twice (different ciphertext) — second
        // wins in the memtable, both are in the chunk_log.
        let dir = tempdir().unwrap();
        let mut store = ChunkStore::open(dir.path()).unwrap();
        let mut c = chunk(0x77, 100, 116);
        store.append_chunk(&c).unwrap();
        let off_a = store.last_chunk_log_offset;
        c.ciphertext = vec![0xFFu8; 200]; // different content, same chunk_id
        c.length_plaintext = 184;
        store.append_chunk(&c).unwrap();
        let off_b = store.last_chunk_log_offset;
        assert_ne!(off_a, off_b);
        assert_eq!(store.locate_chunk(&c.chunk_id).unwrap().wal_offset, off_b);
    }

    #[test]
    fn close_then_use_returns_closed_error() {
        let dir = tempdir().unwrap();
        let mut store = ChunkStore::open(dir.path()).unwrap();
        store.close().unwrap();
        let result = store.append_chunk(&chunk(0x01, 100, 116));
        assert!(matches!(result, Err(ChunkStoreError::Closed)));
    }

    #[test]
    fn stats_track_replay_metrics() {
        let dir = tempdir().unwrap();
        {
            let mut store = ChunkStore::open(dir.path()).unwrap();
            for i in 0u8..5 {
                store.append_chunk(&chunk(i, 64, 80)).unwrap();
            }
            store
                .append_manifest(&manifest(ManifestRecordKind::ShareLink, b"share"))
                .unwrap();
            store.flush().unwrap();
        }
        let store2 = ChunkStore::open(dir.path()).unwrap();
        let stats = store2.stats();
        assert_eq!(stats.indexed_chunks, 5);
        assert_eq!(stats.manifest_records, 1);
        assert!(stats.bytes_scanned_at_replay > 0);
    }
}
