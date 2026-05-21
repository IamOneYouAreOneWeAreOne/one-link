//! Platform-agnostic filesystem backend trait + reference in-memory
//! implementation. The daemon's chunk-store-backed implementation
//! lives in `one_link_native` and wires through this trait when the
//! mount endpoint goes live.

use std::collections::BTreeMap;
use std::sync::RwLock;

use thiserror::Error;

/// File metadata returned to the FUSE callback layer. Mirrors the
/// minimal subset of POSIX `struct stat` the kernel needs to satisfy
/// `getattr` + `readdir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    /// Filesystem object kind.
    pub kind: EntryKind,
    /// Size in bytes (regular files only; 0 for directories).
    pub size: u64,
    /// Last-modified time, milliseconds since the Unix epoch.
    pub mtime_ms: u64,
    /// POSIX mode bits (least-significant 9 bits matter — rwxrwxrwx).
    pub mode: u16,
}

/// Filesystem object kind reported by [`FilesystemBackend::getattr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// Regular file backed by a chunk-store blob.
    File,
    /// Directory containing other entries.
    Directory,
}

/// One entry returned by [`FilesystemBackend::readdir`]: a name and
/// its stat record. Order is backend-defined but stable across calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Bare name (no slashes), as the kernel will surface it.
    pub name: String,
    /// Metadata for the entry.
    pub stat: Stat,
}

/// Errors a backend can return. Maps 1:1 to POSIX errno values the
/// FUSE adapter translates to kernel return codes.
#[allow(missing_docs)]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FsError {
    #[error("path not found")]
    NotFound,
    #[error("not a directory")]
    NotADirectory,
    #[error("is a directory")]
    IsADirectory,
    #[error("permission denied")]
    PermissionDenied,
    #[error("backend exhausted (out of space / disk full)")]
    NoSpace,
    #[error("backend I/O error: {0}")]
    Io(String),
}

/// FUSE-shaped filesystem callbacks. Every method mirrors a libfuse
/// op the daemon's chunk-store-backed implementation needs to handle.
/// The contract is paranoid by design — callbacks never panic, and
/// any error path returns [`FsError`].
pub trait FilesystemBackend: Send + Sync {
    /// Return metadata for `path` (returns [`FsError::NotFound`] if
    /// no entry exists at that path).
    fn getattr(&self, path: &str) -> Result<Stat, FsError>;

    /// List directory contents at `path`. Errors with
    /// [`FsError::NotADirectory`] if `path` resolves to a regular
    /// file.
    fn readdir(&self, path: &str) -> Result<Vec<DirEntry>, FsError>;

    /// Read up to `size` bytes from `path` starting at `offset`.
    /// Short reads (returning fewer than `size` bytes) are valid at
    /// end-of-file. Errors with [`FsError::IsADirectory`] if `path`
    /// is a directory.
    fn read(&self, path: &str, offset: u64, size: u32) -> Result<Vec<u8>, FsError>;

    /// Write `data` to `path` starting at `offset`. Returns the number
    /// of bytes actually written. The path is created if missing
    /// (semantics match POSIX `O_CREAT | O_WRONLY`).
    fn write(&self, path: &str, offset: u64, data: &[u8]) -> Result<u32, FsError>;

    /// Remove the file or empty directory at `path`. Errors with
    /// [`FsError::NotFound`] if `path` doesn't exist.
    fn unlink(&self, path: &str) -> Result<(), FsError>;
}

/// Tiny reference implementation: an in-memory BTreeMap. Useful for
/// unit tests + the daemon's smoke tests before the chunk-store
/// backend lands. Not for production — no persistence, no fsync, no
/// concurrent-safety beyond `RwLock`.
#[derive(Debug, Default)]
pub struct MemoryBackend {
    inner: RwLock<MemoryInner>,
}

#[derive(Debug, Default)]
struct MemoryInner {
    files: BTreeMap<String, Vec<u8>>,
    mtimes: BTreeMap<String, u64>,
}

impl MemoryBackend {
    /// Construct an empty in-memory backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl FilesystemBackend for MemoryBackend {
    fn getattr(&self, path: &str) -> Result<Stat, FsError> {
        let inner = self.inner.read().expect("poisoned");
        // Root + intermediate directories: synthetic.
        if path.is_empty() || path == "/" {
            return Ok(Stat {
                kind: EntryKind::Directory,
                size: 0,
                mtime_ms: 0,
                mode: 0o755,
            });
        }
        if let Some(bytes) = inner.files.get(path) {
            let mtime = inner.mtimes.get(path).copied().unwrap_or(0);
            return Ok(Stat {
                kind: EntryKind::File,
                size: bytes.len() as u64,
                mtime_ms: mtime,
                mode: 0o644,
            });
        }
        // Maybe it's a synthetic directory: any prefix that's a parent
        // of a file we know about counts.
        let prefix = if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{}/", path)
        };
        if inner.files.keys().any(|k| k.starts_with(&prefix)) {
            return Ok(Stat {
                kind: EntryKind::Directory,
                size: 0,
                mtime_ms: 0,
                mode: 0o755,
            });
        }
        Err(FsError::NotFound)
    }

    fn readdir(&self, path: &str) -> Result<Vec<DirEntry>, FsError> {
        let inner = self.inner.read().expect("poisoned");
        let prefix = if path.is_empty() || path == "/" {
            String::new()
        } else if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{}/", path)
        };
        let mut out = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for key in inner.files.keys() {
            if !key.starts_with(&prefix) {
                continue;
            }
            let tail = &key[prefix.len()..];
            let bare = match tail.find('/') {
                Some(idx) => &tail[..idx],
                None => tail,
            };
            if bare.is_empty() || !seen.insert(bare.to_string()) {
                continue;
            }
            let full = format!("{}{}", prefix, bare);
            let is_file = inner.files.contains_key(&full);
            let stat = if is_file {
                Stat {
                    kind: EntryKind::File,
                    size: inner.files.get(&full).map_or(0, |v| v.len() as u64),
                    mtime_ms: inner.mtimes.get(&full).copied().unwrap_or(0),
                    mode: 0o644,
                }
            } else {
                Stat {
                    kind: EntryKind::Directory,
                    size: 0,
                    mtime_ms: 0,
                    mode: 0o755,
                }
            };
            out.push(DirEntry {
                name: bare.to_string(),
                stat,
            });
        }
        Ok(out)
    }

    fn read(&self, path: &str, offset: u64, size: u32) -> Result<Vec<u8>, FsError> {
        let inner = self.inner.read().expect("poisoned");
        let bytes = inner.files.get(path).ok_or(FsError::NotFound)?;
        let off = offset as usize;
        if off >= bytes.len() {
            return Ok(Vec::new());
        }
        let end = (off + size as usize).min(bytes.len());
        Ok(bytes[off..end].to_vec())
    }

    fn write(&self, path: &str, offset: u64, data: &[u8]) -> Result<u32, FsError> {
        let mut inner = self.inner.write().expect("poisoned");
        let entry = inner.files.entry(path.to_string()).or_default();
        let off = offset as usize;
        if entry.len() < off {
            entry.resize(off, 0);
        }
        let end = off + data.len();
        if entry.len() < end {
            entry.resize(end, 0);
        }
        entry[off..end].copy_from_slice(data);
        inner.mtimes.insert(path.to_string(), now_ms());
        Ok(data.len() as u32)
    }

    fn unlink(&self, path: &str) -> Result<(), FsError> {
        let mut inner = self.inner.write().expect("poisoned");
        if inner.files.remove(path).is_none() {
            return Err(FsError::NotFound);
        }
        inner.mtimes.remove(path);
        Ok(())
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// D27 — Read-only adapter that bridges a daemon-supplied manifest +
/// blob-reader closure to the FUSE [`FilesystemBackend`] trait.
///
/// The manifest is a flat ``path -> (size, mtime_ms, blob_hash)`` map;
/// directory structure is inferred from the path separators. The
/// blob reader is a closure that, given a 64-hex blob hash + offset
/// + length, returns the slice of bytes. This split keeps ol_fuse
/// crypto-free — the daemon already has the chunk-store + AEAD wired
/// up and can supply a closure that walks them.
///
/// Writes return [`FsError::PermissionDenied`] for now; mounting a
/// folder as read-only is the right v1 surface (the daemon's existing
/// folder-sync engine is the authoritative writer). Read-write
/// mounts will land in a follow-up with chunk-store cooperation.
pub struct FolderManifestBackend {
    files: BTreeMap<String, ManifestRow>,
    blob_reader: BlobReader,
}

/// Row in the manifest passed to [`FolderManifestBackend::new`].
#[derive(Debug, Clone)]
pub struct ManifestRow {
    /// Plaintext file size in bytes.
    pub size: u64,
    /// Last-modified time (milliseconds since Unix epoch).
    pub mtime_ms: u64,
    /// 64-hex BLAKE3 hash addressing the file in the blob store.
    pub blob_hash: String,
}

/// Closure shape passed to the read-only backend for fetching bytes
/// from a blob hash. `Send + Sync` so the backend itself is `Send +
/// Sync` (FUSE callbacks fire from a kernel-driven thread pool).
pub type BlobReader =
    Box<dyn Fn(&str, u64, u32) -> Result<Vec<u8>, FsError> + Send + Sync>;

impl FolderManifestBackend {
    /// Build a backend from a manifest + a blob reader closure.
    #[must_use]
    pub fn new(
        files: BTreeMap<String, ManifestRow>,
        blob_reader: BlobReader,
    ) -> Self {
        Self {
            files,
            blob_reader,
        }
    }
}

impl std::fmt::Debug for FolderManifestBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FolderManifestBackend")
            .field("files", &self.files.len())
            .finish()
    }
}

impl FilesystemBackend for FolderManifestBackend {
    fn getattr(&self, path: &str) -> Result<Stat, FsError> {
        if path.is_empty() || path == "/" {
            return Ok(Stat {
                kind: EntryKind::Directory,
                size: 0,
                mtime_ms: 0,
                mode: 0o555,
            });
        }
        let lookup = path.trim_start_matches('/').to_string();
        if let Some(row) = self.files.get(&lookup) {
            return Ok(Stat {
                kind: EntryKind::File,
                size: row.size,
                mtime_ms: row.mtime_ms,
                mode: 0o444,
            });
        }
        let prefix = if lookup.ends_with('/') {
            lookup
        } else {
            format!("{}/", lookup)
        };
        if self.files.keys().any(|k| k.starts_with(&prefix)) {
            return Ok(Stat {
                kind: EntryKind::Directory,
                size: 0,
                mtime_ms: 0,
                mode: 0o555,
            });
        }
        Err(FsError::NotFound)
    }

    fn readdir(&self, path: &str) -> Result<Vec<DirEntry>, FsError> {
        let trimmed = path.trim_start_matches('/');
        let prefix = if trimmed.is_empty() {
            String::new()
        } else if trimmed.ends_with('/') {
            trimmed.to_string()
        } else {
            format!("{}/", trimmed)
        };
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        for (key, row) in &self.files {
            if !key.starts_with(&prefix) {
                continue;
            }
            let tail = &key[prefix.len()..];
            let bare = match tail.find('/') {
                Some(idx) => &tail[..idx],
                None => tail,
            };
            if bare.is_empty() || !seen.insert(bare.to_string()) {
                continue;
            }
            let full = format!("{}{}", prefix, bare);
            let stat = if let Some(r) = self.files.get(&full) {
                Stat {
                    kind: EntryKind::File,
                    size: r.size,
                    mtime_ms: r.mtime_ms,
                    mode: 0o444,
                }
            } else {
                let _ = row;
                Stat {
                    kind: EntryKind::Directory,
                    size: 0,
                    mtime_ms: 0,
                    mode: 0o555,
                }
            };
            out.push(DirEntry {
                name: bare.to_string(),
                stat,
            });
        }
        if out.is_empty() && !prefix.is_empty() {
            // Path doesn't resolve to either a known file or a known
            // directory prefix.
            return Err(FsError::NotFound);
        }
        Ok(out)
    }

    fn read(&self, path: &str, offset: u64, size: u32) -> Result<Vec<u8>, FsError> {
        let lookup = path.trim_start_matches('/');
        let row = self.files.get(lookup).ok_or(FsError::NotFound)?;
        (self.blob_reader)(&row.blob_hash, offset, size)
    }

    fn write(&self, _path: &str, _offset: u64, _data: &[u8]) -> Result<u32, FsError> {
        // Read-only v1 — writes are intentionally rejected so the
        // FUSE mount doesn't race the folder-sync engine.
        Err(FsError::PermissionDenied)
    }

    fn unlink(&self, _path: &str) -> Result<(), FsError> {
        Err(FsError::PermissionDenied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_backend_round_trip_write_read() {
        let fs = MemoryBackend::new();
        let n = fs.write("hello.txt", 0, b"Hello, FUSE!").unwrap();
        assert_eq!(n, 12);
        let bytes = fs.read("hello.txt", 0, 64).unwrap();
        assert_eq!(bytes, b"Hello, FUSE!");
    }

    #[test]
    fn memory_backend_getattr_distinguishes_file_and_dir() {
        let fs = MemoryBackend::new();
        fs.write("docs/a.txt", 0, b"a").unwrap();
        fs.write("docs/b.txt", 0, b"bb").unwrap();
        let file = fs.getattr("docs/a.txt").unwrap();
        assert_eq!(file.kind, EntryKind::File);
        assert_eq!(file.size, 1);
        let dir = fs.getattr("docs").unwrap();
        assert_eq!(dir.kind, EntryKind::Directory);
        let root = fs.getattr("/").unwrap();
        assert_eq!(root.kind, EntryKind::Directory);
    }

    #[test]
    fn memory_backend_readdir_lists_children() {
        let fs = MemoryBackend::new();
        fs.write("a.txt", 0, b"a").unwrap();
        fs.write("b.txt", 0, b"b").unwrap();
        fs.write("sub/c.txt", 0, b"c").unwrap();
        let mut names: Vec<_> = fs
            .readdir("/")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        names.sort();
        assert_eq!(names, vec!["a.txt", "b.txt", "sub"]);
        let sub: Vec<_> = fs
            .readdir("sub")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(sub, vec!["c.txt"]);
    }

    #[test]
    fn memory_backend_read_at_offset_short_returns_at_eof() {
        let fs = MemoryBackend::new();
        fs.write("x.bin", 0, b"abcdef").unwrap();
        let bytes = fs.read("x.bin", 3, 10).unwrap();
        assert_eq!(bytes, b"def");
        let empty = fs.read("x.bin", 100, 10).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn memory_backend_unlink_then_getattr_returns_notfound() {
        let fs = MemoryBackend::new();
        fs.write("ghost.txt", 0, b"ephemeral").unwrap();
        fs.unlink("ghost.txt").unwrap();
        assert_eq!(fs.getattr("ghost.txt"), Err(FsError::NotFound));
    }

    #[test]
    fn memory_backend_unlink_missing_path_errors() {
        let fs = MemoryBackend::new();
        assert_eq!(fs.unlink("noexist"), Err(FsError::NotFound));
    }

    #[test]
    fn memory_backend_write_extends_with_zeros_on_sparse_offset() {
        let fs = MemoryBackend::new();
        fs.write("sparse.bin", 16, b"XYZ").unwrap();
        let bytes = fs.read("sparse.bin", 0, 32).unwrap();
        assert_eq!(bytes.len(), 19);
        assert_eq!(&bytes[..16], &[0u8; 16][..]);
        assert_eq!(&bytes[16..], b"XYZ");
    }

    // ---- D27 FolderManifestBackend ----

    fn _row(size: u64, mtime: u64, hash: &str) -> ManifestRow {
        ManifestRow {
            size,
            mtime_ms: mtime,
            blob_hash: hash.into(),
        }
    }

    #[test]
    fn folder_backend_getattr_root_is_dir() {
        let mut files = BTreeMap::new();
        files.insert("a.txt".to_string(), _row(3, 100, "hash_a"));
        let fs = FolderManifestBackend::new(
            files,
            Box::new(|_, _, _| Ok(Vec::new())),
        );
        let root = fs.getattr("/").unwrap();
        assert_eq!(root.kind, EntryKind::Directory);
        // Read-only mode: dir is r-xr-xr-x.
        assert_eq!(root.mode, 0o555);
    }

    #[test]
    fn folder_backend_getattr_known_file() {
        let mut files = BTreeMap::new();
        files.insert("docs/a.txt".to_string(), _row(99, 1234, "hash_a"));
        let fs = FolderManifestBackend::new(
            files,
            Box::new(|_, _, _| Ok(Vec::new())),
        );
        let stat = fs.getattr("docs/a.txt").unwrap();
        assert_eq!(stat.kind, EntryKind::File);
        assert_eq!(stat.size, 99);
        assert_eq!(stat.mtime_ms, 1234);
        // Read-only file mode.
        assert_eq!(stat.mode, 0o444);
    }

    #[test]
    fn folder_backend_getattr_intermediate_dir() {
        let mut files = BTreeMap::new();
        files.insert("docs/sub/x.txt".to_string(), _row(1, 0, "h"));
        let fs = FolderManifestBackend::new(
            files,
            Box::new(|_, _, _| Ok(Vec::new())),
        );
        let d = fs.getattr("docs").unwrap();
        assert_eq!(d.kind, EntryKind::Directory);
        let d2 = fs.getattr("docs/sub").unwrap();
        assert_eq!(d2.kind, EntryKind::Directory);
    }

    #[test]
    fn folder_backend_getattr_unknown_path_notfound() {
        let files = BTreeMap::new();
        let fs = FolderManifestBackend::new(
            files,
            Box::new(|_, _, _| Ok(Vec::new())),
        );
        assert_eq!(fs.getattr("ghost"), Err(FsError::NotFound));
    }

    #[test]
    fn folder_backend_readdir_root_lists_top() {
        let mut files = BTreeMap::new();
        files.insert("a.txt".to_string(), _row(1, 0, "ha"));
        files.insert("b.txt".to_string(), _row(2, 0, "hb"));
        files.insert("docs/x.txt".to_string(), _row(3, 0, "hd"));
        let fs = FolderManifestBackend::new(
            files,
            Box::new(|_, _, _| Ok(Vec::new())),
        );
        let mut names: Vec<_> = fs
            .readdir("/")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        names.sort();
        assert_eq!(names, vec!["a.txt", "b.txt", "docs"]);
    }

    #[test]
    fn folder_backend_read_calls_closure() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let mut files = BTreeMap::new();
        files.insert("x.bin".to_string(), _row(6, 0, "hash_x"));
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let fs = FolderManifestBackend::new(
            files,
            Box::new(move |hash, offset, size| {
                calls_clone.fetch_add(1, Ordering::SeqCst);
                assert_eq!(hash, "hash_x");
                assert_eq!(offset, 2);
                assert_eq!(size, 3);
                Ok(b"bcd".to_vec())
            }),
        );
        let out = fs.read("x.bin", 2, 3).unwrap();
        assert_eq!(out, b"bcd");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn folder_backend_read_unknown_path_notfound() {
        let files = BTreeMap::new();
        let fs = FolderManifestBackend::new(
            files,
            Box::new(|_, _, _| Ok(Vec::new())),
        );
        assert_eq!(
            fs.read("missing", 0, 10),
            Err(FsError::NotFound),
        );
    }

    #[test]
    fn folder_backend_write_rejected_read_only() {
        let files = BTreeMap::new();
        let fs = FolderManifestBackend::new(
            files,
            Box::new(|_, _, _| Ok(Vec::new())),
        );
        assert_eq!(
            fs.write("anything", 0, b"x"),
            Err(FsError::PermissionDenied),
        );
    }

    #[test]
    fn folder_backend_unlink_rejected_read_only() {
        let files = BTreeMap::new();
        let fs = FolderManifestBackend::new(
            files,
            Box::new(|_, _, _| Ok(Vec::new())),
        );
        assert_eq!(
            fs.unlink("anything"),
            Err(FsError::PermissionDenied),
        );
    }

    #[test]
    fn folder_backend_strips_leading_slash() {
        let mut files = BTreeMap::new();
        files.insert("a.txt".to_string(), _row(5, 0, "ha"));
        let fs = FolderManifestBackend::new(
            files,
            Box::new(|_, _, _| Ok(b"hello".to_vec())),
        );
        // Both /a.txt and a.txt should resolve.
        assert_eq!(fs.getattr("/a.txt").unwrap().size, 5);
        assert_eq!(fs.getattr("a.txt").unwrap().size, 5);
    }
}
