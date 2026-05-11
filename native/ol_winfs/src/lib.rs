//! `ol_winfs` — Windows filesystem surface (Phase B layer 9).
//!
//! Per `FILE_ENGINE_V2_PLAN.md`: Dokan / WinFSP. WinFSP is the
//! preferred backend (MIT-licensed, doesn't require a separate
//! Microsoft Store / Defender exclusion); Dokan is the fallback.
//!
//! ## Architectural contract
//!
//! Same `FilesystemBackend` trait as `ol_fuse` + `ol_fskit`. A
//! daemon can swap backends per platform without forking the chunk-
//! store side.
//!
//! ## Backend selection
//!
//! Three cargo features:
//!
//! - `winfsp` (preferred): links winfsp-rs (when it lands as a real
//!   dependency). Drive letter mount + projected file system.
//! - `dokan` (fallback): links dokan-rust. Works on Windows 7+ but
//!   has more permission edge cases.
//! - default (neither): scaffold-only; `mount()` returns
//!   [`MountError::Backend`] with a feature-required hint.
//!
//! Linux + macOS callers always get [`MountError::UnsupportedPlatform`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::PathBuf;

use thiserror::Error;

pub use ol_fuse::{
    DirEntry, EntryKind, FilesystemBackend, FsError, MemoryBackend, Stat,
};

/// Windows-specific mount options.
#[derive(Debug, Clone)]
pub struct MountOptions {
    /// Mount target. On Windows this is typically a drive letter
    /// path (`"X:\\"`) but UNC paths (`"\\\\?\\C:\\OneLink"`) work
    /// too for users who don't want a separate drive.
    pub mountpoint: PathBuf,
    /// Volume label shown in Explorer.
    pub volume_label: String,
    /// Read-only mount.
    pub read_only: bool,
    /// Whether to allow other users on the system to read the mount.
    /// Default false — single-user mount is the safest default.
    pub allow_other: bool,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            mountpoint: PathBuf::new(),
            volume_label: "OneLink".into(),
            read_only: false,
            allow_other: false,
        }
    }
}

/// Errors mount() can return.
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum MountError {
    #[error("WinFSP / Dokan not supported on this platform")]
    UnsupportedPlatform,
    #[error("mountpoint does not exist or is not a directory: {0}")]
    InvalidMountpoint(PathBuf),
    #[error("backend error: {0}")]
    Backend(String),
}

/// Mount `backend` at `opts.mountpoint` via WinFSP (preferred) or
/// Dokan (fallback).
///
/// Behaviour by platform + feature:
///
/// - **Windows + `winfsp` feature**: returns
///   [`MountError::Backend`] with "WinFSP adapter not yet wired" —
///   the C-bindings glue lands when the daemon's mount endpoint
///   ships.
/// - **Windows + `dokan` feature**: same posture as `winfsp`.
/// - **Windows without feature**: [`MountError::Backend`] with
///   rebuild hint.
/// - **Non-Windows**: [`MountError::UnsupportedPlatform`].
pub fn mount<B>(
    #[cfg(all(target_os = "windows", any(feature = "winfsp", feature = "dokan")))]
    _backend: B,
    #[cfg(not(all(target_os = "windows", any(feature = "winfsp", feature = "dokan"))))]
    _backend: B,
    opts: MountOptions,
) -> Result<(), MountError>
where
    B: FilesystemBackend + 'static,
{
    if !opts.mountpoint.is_dir() {
        return Err(MountError::InvalidMountpoint(opts.mountpoint));
    }
    #[cfg(all(target_os = "windows", feature = "winfsp"))]
    {
        Err(MountError::Backend(
            "WinFSP adapter not yet wired (Phase B daemon mount endpoint pending)".into(),
        ))
    }
    #[cfg(all(target_os = "windows", feature = "dokan", not(feature = "winfsp")))]
    {
        Err(MountError::Backend(
            "Dokan adapter not yet wired (Phase B daemon mount endpoint pending)".into(),
        ))
    }
    #[cfg(all(target_os = "windows", not(any(feature = "winfsp", feature = "dokan"))))]
    {
        Err(MountError::Backend(
            "rebuild ol_winfs with --features winfsp (preferred) or --features dokan".into(),
        ))
    }
    #[cfg(not(target_os = "windows"))]
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
            mountpoint: PathBuf::from("Z:\\never-exists\\likely"),
            ..Default::default()
        };
        let backend = MemoryBackend::new();
        let err = mount(backend, opts).unwrap_err();
        assert!(matches!(err, MountError::InvalidMountpoint(_)));
    }

    #[test]
    fn mount_with_valid_mountpoint_errors_on_scaffold() {
        let tmp = tempfile::tempdir().unwrap();
        let opts = MountOptions {
            mountpoint: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let backend = MemoryBackend::new();
        let err = mount(backend, opts).unwrap_err();
        match err {
            MountError::UnsupportedPlatform | MountError::Backend(_) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn default_options_volume_label() {
        let opts = MountOptions::default();
        assert_eq!(opts.volume_label, "OneLink");
        assert!(!opts.read_only);
        assert!(!opts.allow_other);
    }
}
