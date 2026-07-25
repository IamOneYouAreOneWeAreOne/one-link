//! `ol_fuse` — bounded filesystem backend plus the Linux FUSE adapter.
//!
//! Per `FILE_ENGINE_V2_PLAN.md` Phase B item #6:
//!
//! > Filesystem surface — FUSE on Linux, Dokan/WinFSP on Windows,
//! > FSKit on macOS (NOT macFUSE — macFUSE is GPL+commercial dual-
//! > license, breaks no-monthly-bill on macOS; FSKit is Apple's
//! > modern in-userspace alternative).
//!
//! This crate ships the Linux side. The other two surfaces ship in
//! separate per-platform crates (`ol_fskit`, `ol_winfs`).
//!
//! ## Shipped scope
//!
//! Linux builds with `linux-mount` ship a real callback-backed
//! `fuser::Filesystem` and owned background mount session. The packaged Python
//! binding mounts an immutable manifest over a verified, bounded CAS reader
//! and deliberately refuses read-write operation until WAL-coupled writes are
//! implemented. This crate provides:
//!
//! 1. A platform-agnostic [`FilesystemBackend`] trait.
//! 2. Strict manifest, path, metadata, size, and bounded-read enforcement.
//! 3. A Linux [`mount`] / [`spawn_mount`] path backed by `fuser` callbacks.
//! 4. Explicit fail-closed status/errors on unsupported or disabled builds.
//! 5. A bounded [`MemoryBackend`] used by adversarial unit tests.
//!
//! macOS FSKit and Windows WinFsp/Dokan live in separate crates and remain
//! unimplemented; their presence never manufactures a successful mount.

// `deny` (not `forbid`) so the one place that calls libc::getuid /
// getgid in the FUSE adapter can locally lift it with
// #[allow(unsafe_code)]. Every other module stays unsafe-free; the
// crate-level intent (no unsafe by default) is preserved.
#![deny(unsafe_code)]
#![warn(missing_docs)]

mod backend;
mod mount;

#[cfg(all(target_os = "linux", feature = "linux-mount"))]
mod adapter;

pub use backend::{
    BlobReader, DirEntry, EntryKind, FilesystemBackend, FolderManifestBackend, FsError,
    ManifestRow, MemoryBackend, Stat, MAX_FS_IO_BYTES, MAX_FS_PATH_BYTES, MAX_MEMORY_FILES,
    MAX_MEMORY_FILE_BYTES, MAX_MEMORY_TOTAL_BYTES,
};
pub use mount::{
    mount, mount_platform_status, spawn_mount, MountError, MountOptions, MountedFilesystem,
    PlatformMountStatus,
};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
