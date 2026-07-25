//! `ol_fskit` — macOS `FSKit` filesystem surface (Phase B layer 9).
//!
//! Per `FILE_ENGINE_V2_PLAN.md`:
//!
//! > FSKit on macOS (NOT macFUSE — macFUSE is GPL+commercial
//! > dual-license, breaks no-monthly-bill on macOS; FSKit is
//! > Apple's modern in-userspace alternative).
//!
//! ## Architectural contract
//!
//! The trait surface mirrors `ol_fuse::FilesystemBackend` exactly —
//! same trait, same `FsError` translation table, same lifecycle
//! shape. A daemon can pick a backend per platform (or share one
//! across all three) without forking the chunk-store side.
//!
//! ## Scaffold status
//!
//! `FSKit` ships through Apple's Swift / Objective-C runtime. Bridging
//! it to a Rust backend requires either:
//!
//! 1. A Swift package that links the Rust `staticlib` and forwards
//!    `FSUnaryFileSystem` / `FSFileSystem` callbacks into our trait
//!    methods, or
//! 2. `objc2-foundation` bindings (the Rust path) directly
//!    instantiating the `FSKit` `ObjC` classes.
//!
//! Both options need a macOS host to verify; the crate ships the
//! API surface today so the daemon's per-platform mount endpoint
//! can compile + dispatch correctly regardless of whether the
//! Swift adapter has landed.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::PathBuf;

use thiserror::Error;

pub use ol_fuse::{DirEntry, EntryKind, FilesystemBackend, FsError, MemoryBackend, Stat};

/// Options the daemon passes when mounting a folder as `FSKit`.
#[derive(Debug, Clone)]
pub struct MountOptions {
    /// Mountpoint directory. macOS mounts under `/Volumes/<name>`
    /// by convention; passing a custom path requires
    /// `volume_kind = .userVisibleStorage`.
    pub mountpoint: PathBuf,
    /// Volume name shown in Finder + `mount` output.
    pub volume_name: String,
    /// Read-only mount (Finder will mark the volume as locked).
    pub read_only: bool,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            mountpoint: PathBuf::new(),
            volume_name: "one_link".into(),
            read_only: false,
        }
    }
}

/// Errors `mount()` can return.
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum MountError {
    #[error("FSKit not supported on this platform (macOS 15.4+ only)")]
    UnsupportedPlatform,
    #[error("mountpoint does not exist or is not a directory: {0}")]
    InvalidMountpoint(PathBuf),
    #[error("FSKit backend error: {0}")]
    Backend(String),
}

/// Mount `backend` at `opts.mountpoint` via `FSKit`.
///
/// Behaviour:
///
/// - **macOS, with or without `macos-mount`**: returns
///   [`MountError::Backend`] stating that the app-extension adapter is
///   unimplemented. The feature is reserved and does not enable mounting.
/// - **Non-macOS**: returns [`MountError::UnsupportedPlatform`].
pub fn mount<B>(_backend: B, opts: MountOptions) -> Result<(), MountError>
where
    B: FilesystemBackend + 'static,
{
    if !opts.mountpoint.is_dir() {
        return Err(MountError::InvalidMountpoint(opts.mountpoint));
    }
    #[cfg(target_os = "macos")]
    {
        Err(MountError::Backend(
            "FSKit app-extension adapter is not implemented; the reserved macos-mount feature does not enable mounting"
                .into(),
        ))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(MountError::UnsupportedPlatform)
    }
}

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn mount_with_missing_mountpoint_errors() {
        let opts = MountOptions {
            mountpoint: PathBuf::from("/this/path/should/never/exist"),
            ..Default::default()
        };
        let backend = MemoryBackend::new();
        let err = mount(backend, opts).unwrap_err();
        assert!(matches!(err, MountError::InvalidMountpoint(_)));
    }

    #[test]
    fn mount_with_valid_mountpoint_never_claims_success() {
        let tmp = tempfile::tempdir().unwrap();
        let opts = MountOptions {
            mountpoint: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let backend = MemoryBackend::new();
        let err = mount(backend, opts).unwrap_err();
        #[cfg(target_os = "macos")]
        match err {
            MountError::Backend(message) => {
                assert!(message.contains("not implemented"));
                assert!(message.contains("does not enable mounting"));
                assert!(!message.contains("rebuild"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        #[cfg(not(target_os = "macos"))]
        {
            assert!(matches!(err, MountError::UnsupportedPlatform));
        }
    }

    #[test]
    fn default_options_volume_name() {
        let opts = MountOptions::default();
        assert_eq!(opts.volume_name, "one_link");
        assert!(!opts.read_only);
    }
}
