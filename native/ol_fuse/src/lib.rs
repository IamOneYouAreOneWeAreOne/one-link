//! `ol_fuse` — FUSE filesystem surface scaffold.
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
//! ## Scope of this scaffold
//!
//! The plan calls for a full read/write FUSE binding that mounts a
//! `Folder` (the `ol_crdt` lattice + `ol_chunk_store` content-addressed
//! backing) as a regular Linux directory. The full implementation is
//! substantial (libfuse callback wiring, lookup cache, ENOENT/EAGAIN
//! semantics under churn, write-through to chunk store with WAL
//! coupling). This scaffold ships:
//!
//! 1. A platform-agnostic [`FilesystemBackend`] trait — every method a
//!    FUSE callback could call, expressed in terms the daemon already
//!    has (file_path → blob_hash, read at offset, write at offset).
//! 2. A platform-agnostic [`MountOptions`] / [`MountError`] surface so
//!    consumers can build the mount call site today.
//! 3. A [`mount`] entry point that on Linux will (eventually) call
//!    `fuser::mount2` with a wrapper that adapts [`FilesystemBackend`]
//!    to libfuse's callback shape; on every other platform it returns
//!    [`MountError::UnsupportedPlatform`] immediately.
//! 4. A trivial in-memory [`MemoryBackend`] for unit tests + the
//!    daemon's smoke tests.
//!
//! The slot in the plan ([Layer 9 in the architecture stack]) is
//! taken. When the daemon's FUSE mount endpoint goes live, the real
//! `fuser` wiring lands as a focused PR against this crate without
//! changing the surface.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod backend;
mod mount;

#[cfg(all(target_os = "linux", feature = "linux-mount"))]
mod adapter;

pub use backend::{
    DirEntry, EntryKind, FilesystemBackend, FsError, MemoryBackend, Stat,
};
pub use mount::{mount, MountError, MountOptions};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
