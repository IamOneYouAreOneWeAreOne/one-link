//! Real `fuser::Filesystem` adapter. Linux-only — bridges the
//! platform-agnostic [`FilesystemBackend`](crate::backend::FilesystemBackend)
//! trait to libfuse's inode-keyed callback shape.
//!
//! Compiled only when the `linux-mount` feature is enabled AND we're on
//! Linux. Other platforms get the stub mount() that returns
//! [`crate::MountError::UnsupportedPlatform`].
//!
//! ## Inode mapping
//!
//! libfuse operates on `u64` inode numbers, while
//! [`FilesystemBackend`] operates on path strings. We maintain a
//! bidirectional map: `1` is reserved for the root (per libfuse
//! convention); new entries hash their relative path to a stable
//! `u64` via BLAKE3 truncation. This keeps inodes deterministic
//! across remounts and lookups — important for client caches that
//! key on inode numbers.

#![cfg(all(target_os = "linux", feature = "linux-mount"))]

use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
    ReplyWrite, Request,
};

use crate::backend::{EntryKind, FilesystemBackend, FsError, Stat};

/// Filesystem TTL hint to the kernel — how long it may cache attrs.
/// Conservative default; the backend is the source of truth so cache
/// hits beyond this re-poll the backend.
const ATTR_TTL: Duration = Duration::from_secs(1);
/// Inode for the filesystem root, mandated by libfuse.
const ROOT_INODE: u64 = 1;
/// First inode assigned to a non-root entry.
const FIRST_DYNAMIC_INODE: u64 = 2;

/// Adapter that owns a [`FilesystemBackend`] + an inode↔path
/// mapping. Implements `fuser::Filesystem`.
pub(crate) struct FuserAdapter<B: FilesystemBackend> {
    backend: Arc<B>,
    table: Arc<Mutex<InodeTable>>,
}

#[derive(Default)]
struct InodeTable {
    by_ino: HashMap<u64, String>,
    by_path: HashMap<String, u64>,
    next: u64,
}

impl InodeTable {
    fn new() -> Self {
        Self {
            by_ino: HashMap::from([(ROOT_INODE, String::new())]),
            by_path: HashMap::from([(String::new(), ROOT_INODE)]),
            next: FIRST_DYNAMIC_INODE,
        }
    }

    fn lookup_or_assign(&mut self, path: &str) -> u64 {
        if let Some(&ino) = self.by_path.get(path) {
            return ino;
        }
        let ino = self.next;
        self.next += 1;
        self.by_ino.insert(ino, path.to_string());
        self.by_path.insert(path.to_string(), ino);
        ino
    }

    fn path_for(&self, ino: u64) -> Option<&str> {
        self.by_ino.get(&ino).map(String::as_str)
    }
}

impl<B: FilesystemBackend> FuserAdapter<B> {
    pub(crate) fn new(backend: B) -> Self {
        Self {
            backend: Arc::new(backend),
            table: Arc::new(Mutex::new(InodeTable::new())),
        }
    }

    fn fileattr_from_stat(stat: &Stat, ino: u64) -> FileAttr {
        let kind = match stat.kind {
            EntryKind::File => FileType::RegularFile,
            EntryKind::Directory => FileType::Directory,
        };
        let mtime = std::time::UNIX_EPOCH + Duration::from_millis(stat.mtime_ms);
        FileAttr {
            ino,
            size: stat.size,
            blocks: stat.size.div_ceil(512),
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: mtime,
            kind,
            perm: stat.mode,
            nlink: 1,
            // libc::getuid / getgid are unsafe to call directly,
            // which clashes with this crate's #![forbid(unsafe_code)]
            // lint. Wrap each in a SAFETY-documented block whose
            // forbid is locally lifted via #[allow(unsafe_code)].
            uid: {
                #[allow(unsafe_code)]
                unsafe {
                    libc::getuid()
                }
            },
            gid: {
                #[allow(unsafe_code)]
                unsafe {
                    libc::getgid()
                }
            },
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    fn errno(err: &FsError) -> libc::c_int {
        match err {
            FsError::NotFound => libc::ENOENT,
            FsError::NotADirectory => libc::ENOTDIR,
            FsError::IsADirectory => libc::EISDIR,
            FsError::PermissionDenied => libc::EACCES,
            FsError::NoSpace => libc::ENOSPC,
            FsError::InvalidInput(_) => libc::EINVAL,
            FsError::StateUnavailable | FsError::Io(_) => libc::EIO,
        }
    }
}

impl<B: FilesystemBackend + 'static> Filesystem for FuserAdapter<B> {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name = match name.to_str() {
            Some(n) => n,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };
        let mut table = match self.table.lock() {
            Ok(table) => table,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };
        let parent_path = match table.path_for(parent) {
            Some(p) => p.to_string(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        // Compose the absolute path the backend expects. Parent root
        // is stored as the empty string in our inode table; backend
        // paths are absolute and start with "/". So root-children
        // need a single leading slash, nested children get the
        // parent's stored path (already absolute) + "/" + name.
        let full = if parent_path.is_empty() {
            format!("/{}", name)
        } else {
            format!("{}/{}", parent_path, name)
        };
        match self.backend.getattr(&full) {
            Ok(stat) => {
                let ino = table.lookup_or_assign(&full);
                drop(table);
                let attr = Self::fileattr_from_stat(&stat, ino);
                reply.entry(&ATTR_TTL, &attr, 0);
            }
            Err(err) => reply.error(Self::errno(&err)),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let table = match self.table.lock() {
            Ok(table) => table,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };
        let path = match table.path_for(ino) {
            Some(p) => p.to_string(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        drop(table);
        let lookup_path = if path.is_empty() { "/" } else { &path };
        match self.backend.getattr(lookup_path) {
            Ok(stat) => {
                let attr = Self::fileattr_from_stat(&stat, ino);
                reply.attr(&ATTR_TTL, &attr);
            }
            Err(err) => reply.error(Self::errno(&err)),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        let table = match self.table.lock() {
            Ok(table) => table,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };
        let path = match table.path_for(ino) {
            Some(p) => p.to_string(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        drop(table);
        // Backend paths are absolute. For the root inode we stored
        // path="" — which is invalid for backend.read (root is not a
        // file). For any non-root entry the path is already
        // absolute (starts with "/").
        if path.is_empty() {
            reply.error(libc::EISDIR);
            return;
        }
        match self.backend.read(&path, offset as u64, size) {
            Ok(bytes) => reply.data(&bytes),
            Err(err) => reply.error(Self::errno(&err)),
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        let table = match self.table.lock() {
            Ok(table) => table,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };
        let path = match table.path_for(ino) {
            Some(p) => p.to_string(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        drop(table);
        match self.backend.write(&path, offset as u64, data) {
            Ok(n) => reply.written(n),
            Err(err) => reply.error(Self::errno(&err)),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        let mut table = match self.table.lock() {
            Ok(table) => table,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };
        let path = match table.path_for(ino) {
            Some(p) => p.to_string(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        let lookup_path = if path.is_empty() { "/" } else { &path };
        let entries = match self.backend.readdir(lookup_path) {
            Ok(es) => es,
            Err(err) => {
                reply.error(Self::errno(&err));
                return;
            }
        };
        // Inject "." + ".." at offsets 0 + 1 per the FUSE contract.
        let parent_ino = if path.is_empty() {
            ROOT_INODE
        } else {
            let parent_path = path.rsplit_once('/').map_or("", |(parent, _)| parent);
            table
                .by_path
                .get(parent_path)
                .copied()
                .unwrap_or(ROOT_INODE)
        };
        let synthetic = [
            (ino, FileType::Directory, "."),
            (parent_ino, FileType::Directory, ".."),
        ];
        let mut next_offset = offset;
        for (idx, (e_ino, kind, name)) in synthetic.iter().enumerate() {
            let i = idx as i64;
            if i < offset {
                continue;
            }
            if reply.add(*e_ino, i + 1, *kind, name) {
                reply.ok();
                return;
            }
            next_offset = i + 1;
        }
        for (i, entry) in entries.iter().enumerate() {
            let abs_idx = (i + synthetic.len()) as i64;
            if abs_idx < offset {
                continue;
            }
            let kind = match entry.stat.kind {
                EntryKind::File => FileType::RegularFile,
                EntryKind::Directory => FileType::Directory,
            };
            let full = if path.is_empty() {
                format!("/{}", entry.name)
            } else {
                format!("{}/{}", path, entry.name)
            };
            let child_ino = table.lookup_or_assign(&full);
            if reply.add(child_ino, abs_idx + 1, kind, &entry.name) {
                reply.ok();
                return;
            }
            next_offset = abs_idx + 1;
        }
        let _ = next_offset;
        reply.ok();
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let name = match name.to_str() {
            Some(n) => n,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };
        let table = match self.table.lock() {
            Ok(table) => table,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };
        let parent_path = match table.path_for(parent) {
            Some(p) => p.to_string(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        drop(table);
        let full = if parent_path.is_empty() {
            name.to_string()
        } else {
            format!("{}/{}", parent_path, name)
        };
        match self.backend.unlink(&full) {
            Ok(()) => reply.ok(),
            Err(err) => reply.error(Self::errno(&err)),
        }
    }
}
