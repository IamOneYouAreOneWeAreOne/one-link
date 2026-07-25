//! WAL writer with group commit per [ADR-0007](../../../docs/decisions/0007-crash-only-wal-format.md).
//!
//! Usage shape:
//!
//! ```text
//! let mut wal = Wal::create(&dir, LogKind::ChunkLog)?;
//! wal.append(record_a)?;        // buffered, no fsync yet
//! wal.append(record_b)?;        // buffered
//! wal.flush()?;                 // single fdatasync / F_FULLFSYNC / FlushFileBuffers
//! // record_a and record_b are durable.
//! ```
//!
//! The writer holds the active file's fd, the in-memory buffer of
//! pending records, and the running file size. When the next record would
//! push the file past [`crate::file::ROTATION_SIZE`], [`Wal::append`]
//! transparently seals the old file and appends into a new one. Higher layers
//! therefore cannot accidentally turn the per-file cap into a lifetime cap.
//!
//! Single-writer model: the [`Wal`] is `!Sync`. Higher-level crates
//! coordinate batches via a Mutex or single writer thread per log.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::WalError;
use crate::file::{
    parse_header, write_header, LogKind, FILE_HEADER_LEN, FILE_HEADER_LEN_USIZE, ROTATION_SIZE,
};
use crate::record::Record;

/// WAL writer handle.
///
/// Encapsulates the active file fd, pending batch, and file size cursor.
/// Created via [`Wal::create`] (fresh log dir) or [`Wal::open`] (existing).
pub struct Wal {
    dir: PathBuf,
    kind: LogKind,
    file_id: u64,
    file: File,
    file_size: u64,
    pending: Vec<u8>,
}

/// Exact on-disk coordinate reserved for an appended record.
///
/// The file id is part of the identity: byte offsets repeat after rotation.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct AppendPosition {
    /// WAL file id (1-based).
    pub file_id: u64,
    /// Byte offset of the record header within that file.
    pub offset: u64,
}

impl std::fmt::Debug for Wal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wal")
            .field("dir", &self.dir)
            .field("kind", &self.kind)
            .field("file_id", &self.file_id)
            .field("file_size", &self.file_size)
            .field("pending_bytes", &self.pending.len())
            .finish_non_exhaustive()
    }
}

impl Wal {
    /// Create a new WAL writer rooted at `dir`. The directory is created
    /// if it doesn't exist; an initial file (`000001.wal`) is allocated
    /// with the canonical 64-byte header fsync'd.
    ///
    /// # Errors
    ///
    /// - I/O errors from directory or file creation.
    pub fn create(dir: &Path, kind: LogKind) -> Result<Self, WalError> {
        std::fs::create_dir_all(dir)?;
        let file_id = 1u64;
        let path = file_path(dir, file_id);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        write_header(&mut file, kind)?;
        file.sync_data()?;
        Ok(Self {
            dir: dir.to_path_buf(),
            kind,
            file_id,
            file,
            file_size: FILE_HEADER_LEN,
            pending: Vec::with_capacity(64 * 1024),
        })
    }

    /// Open an existing WAL log dir for *appending*. Discovers the highest
    /// `*.wal` file id in `dir`, opens it for append, and validates its
    /// header. Use [`crate::replay::replay_log_dir`] first to recover any
    /// crash-truncated tail before resuming writes.
    ///
    /// # Errors
    ///
    /// - I/O errors.
    /// - Header validation errors if the file is corrupted.
    pub fn open(dir: &Path, kind: LogKind) -> Result<Self, WalError> {
        let Some(file_id) = highest_file_id(dir)? else {
            return Self::create(dir, kind);
        };
        let path = file_path(dir, file_id);
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        // Validate header.
        let mut header = [0u8; FILE_HEADER_LEN_USIZE];
        std::io::Read::read_exact(&mut file, &mut header)?;
        let parsed = parse_header(&header, &path.to_string_lossy())?;
        if parsed != kind {
            return Err(WalError::MagicMismatch {
                path: path.to_string_lossy().to_string(),
                got_hex: format!("{parsed:?}"),
                expected_hex: format!("{kind:?}"),
            });
        }
        // Capture size, then seek to end so subsequent appends extend the file
        // rather than overwriting it.
        let file_size = file.metadata()?.len();
        std::io::Seek::seek(&mut file, std::io::SeekFrom::End(0))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            kind,
            file_id,
            file,
            file_size,
            pending: Vec::with_capacity(64 * 1024),
        })
    }

    /// Active file id.
    #[inline]
    #[must_use]
    pub fn active_file_id(&self) -> u64 {
        self.file_id
    }

    /// Current size of the active file in bytes (including the header).
    #[inline]
    #[must_use]
    pub fn active_file_size(&self) -> u64 {
        self.file_size + self.pending.len() as u64
    }

    /// Append a record to the in-memory pending buffer. Does not fsync unless
    /// the active file must rotate; rotation durably seals the previous file.
    ///
    /// # Errors
    ///
    /// - [`WalError::PayloadTooLarge`] from [`Record::encode`].
    /// - [`WalError::RotationCapExceeded`] only if one encoded record cannot
    ///   fit in an otherwise-empty WAL file.
    pub fn append(&mut self, record: &Record) -> Result<AppendPosition, WalError> {
        let encoded = record.encode()?;
        let encoded_len = encoded.len() as u64;
        if FILE_HEADER_LEN + encoded_len > ROTATION_SIZE {
            return Err(WalError::RotationCapExceeded {
                current: FILE_HEADER_LEN,
                cap: ROTATION_SIZE,
            });
        }
        let projected_total = self.file_size + self.pending.len() as u64 + encoded_len;
        if projected_total > ROTATION_SIZE {
            self.rotate()?;
        }
        let position = AppendPosition {
            file_id: self.file_id,
            offset: self.file_size + self.pending.len() as u64,
        };
        self.pending.extend_from_slice(&encoded);
        Ok(position)
    }

    /// Flush the pending batch to durable storage in a single barrier.
    ///
    /// After this returns successfully, every record passed to
    /// [`append`](Wal::append) since the previous flush is durable
    /// against power loss + kill -9.
    ///
    /// # Errors
    ///
    /// - I/O errors from the write or sync.
    pub fn flush(&mut self) -> Result<(), WalError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        // Single write of the whole batch — atomic up to the kernel's
        // pwrite semantics on this platform.
        self.file.write_all(&self.pending)?;
        // Durability barrier. Caveat on macOS: plain fsync/fdatasync does
        // not force the platter; truly durable writes need
        // fcntl(F_FULLFSYNC), which std does not expose. `sync_data` is the
        // closest portable surface today and the F_FULLFSYNC upgrade is a
        // named hardening item, not silently claimed.
        self.file.sync_data()?;
        self.file_size += self.pending.len() as u64;
        self.pending.clear();
        Ok(())
    }

    /// Rotate to the next file id. Closes the current file and allocates
    /// a new one with a fresh header. Pending records that haven't been
    /// flushed are flushed to the OLD file first.
    ///
    /// # Errors
    ///
    /// - I/O errors.
    pub fn rotate(&mut self) -> Result<(), WalError> {
        // Flush any in-flight bytes to the old file before sealing.
        self.flush()?;
        let new_id = self.file_id + 1;
        let path = file_path(&self.dir, new_id);
        let mut new_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        write_header(&mut new_file, self.kind)?;
        new_file.sync_data()?;
        self.file_id = new_id;
        self.file = new_file;
        self.file_size = FILE_HEADER_LEN;
        Ok(())
    }
}

impl Drop for Wal {
    fn drop(&mut self) {
        // Best-effort flush on drop. Crash-only design means losing the
        // pending buffer on Drop without flush is the same as a kill -9
        // before flush — recovery treats both as "those records weren't
        // committed." Still, normal Drop is a courtesy flush so users
        // who forget to call flush get the obvious behavior.
        let _ = self.flush();
    }
}

fn file_path(dir: &Path, file_id: u64) -> PathBuf {
    dir.join(format!("{file_id:06}.wal"))
}

fn highest_file_id(dir: &Path) -> Result<Option<u64>, WalError> {
    let mut max_id: Option<u64> = None;
    if !dir.exists() {
        return Ok(None);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(stem) = name.strip_suffix(".wal") {
            if let Ok(id) = stem.parse::<u64>() {
                max_id = Some(max_id.map_or(id, |m| m.max(id)));
            }
        }
    }
    Ok(max_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::Record;
    use tempfile::tempdir;

    fn rec(kind: u8, flags: u8, payload: &[u8]) -> Record {
        Record {
            kind,
            flags,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn create_writes_header() {
        let dir = tempdir().unwrap();
        let wal = Wal::create(dir.path(), LogKind::ChunkLog).unwrap();
        assert_eq!(wal.active_file_id(), 1);
        assert_eq!(wal.active_file_size(), FILE_HEADER_LEN);
        let path = file_path(dir.path(), 1);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), FILE_HEADER_LEN_USIZE);
        assert_eq!(&bytes[..8], &crate::file::MAGIC_CHUNK_LOG);
    }

    #[test]
    fn append_and_flush() {
        let dir = tempdir().unwrap();
        let mut wal = Wal::create(dir.path(), LogKind::ManifestLog).unwrap();
        wal.append(&rec(0x10, 0x00, b"first")).unwrap();
        wal.append(&rec(0x10, 0x01, b"second")).unwrap();
        wal.flush().unwrap();
        let path = file_path(dir.path(), 1);
        let bytes = std::fs::read(&path).unwrap();
        let header_len = FILE_HEADER_LEN_USIZE;
        let r1_len = 8 + 5 + 4; // header + payload + crc
        let r2_len = 8 + 6 + 4;
        assert_eq!(bytes.len(), header_len + r1_len + r2_len);
    }

    #[test]
    fn rotation_creates_new_file() {
        let dir = tempdir().unwrap();
        let mut wal = Wal::create(dir.path(), LogKind::ChunkLog).unwrap();
        wal.append(&rec(0x01, 0x00, b"in file 1")).unwrap();
        wal.flush().unwrap();
        wal.rotate().unwrap();
        assert_eq!(wal.active_file_id(), 2);
        wal.append(&rec(0x01, 0x00, b"in file 2")).unwrap();
        wal.flush().unwrap();
        assert!(file_path(dir.path(), 1).exists());
        assert!(file_path(dir.path(), 2).exists());
    }

    #[test]
    fn open_resumes_from_highest_file() {
        let dir = tempdir().unwrap();
        {
            let mut wal = Wal::create(dir.path(), LogKind::ManifestLog).unwrap();
            wal.append(&rec(0x10, 0x00, b"first")).unwrap();
            wal.flush().unwrap();
            wal.rotate().unwrap();
            wal.append(&rec(0x10, 0x00, b"in second file")).unwrap();
            wal.flush().unwrap();
        }
        // Reopen.
        let wal = Wal::open(dir.path(), LogKind::ManifestLog).unwrap();
        assert_eq!(wal.active_file_id(), 2);
    }

    #[test]
    fn append_transparently_rotates_at_cap() {
        let dir = tempdir().unwrap();
        let mut wal = Wal::create(dir.path(), LogKind::ChunkLog).unwrap();
        // Reuse the largest legal record until the active file fills. The
        // crossing append must land at the first record offset in file 2.
        let payload = vec![0u8; crate::record::MAX_PAYLOAD_LEN];
        let mut rotated_position = None;
        for _ in 0..=(ROTATION_SIZE / payload.len() as u64) {
            let pos = wal.append(&rec(0x01, 0x00, &payload)).unwrap();
            if pos.file_id == 2 {
                rotated_position = Some(pos);
                break;
            }
        }
        let pos = rotated_position.expect("append should have auto-rotated");
        assert_eq!(pos.offset, FILE_HEADER_LEN);
        assert_eq!(wal.active_file_id(), 2);
        wal.flush().unwrap();
        assert!(file_path(dir.path(), 1).exists());
        assert!(file_path(dir.path(), 2).exists());
    }

    #[test]
    fn empty_flush_is_noop() {
        let dir = tempdir().unwrap();
        let mut wal = Wal::create(dir.path(), LogKind::ChunkLog).unwrap();
        wal.flush().unwrap();
        wal.flush().unwrap();
        let bytes = std::fs::read(file_path(dir.path(), 1)).unwrap();
        assert_eq!(bytes.len(), FILE_HEADER_LEN_USIZE);
    }

    #[test]
    fn drop_flushes_pending() {
        let dir = tempdir().unwrap();
        {
            let mut wal = Wal::create(dir.path(), LogKind::ChunkLog).unwrap();
            wal.append(&rec(0x01, 0x00, b"on drop")).unwrap();
            // No explicit flush — drop should flush.
        }
        let path = file_path(dir.path(), 1);
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() > FILE_HEADER_LEN_USIZE);
    }
}
