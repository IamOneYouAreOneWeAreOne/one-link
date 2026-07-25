//! `ol_winfs` — Windows filesystem surface (Phase B layer 9).
//!
//! Per `FILE_ENGINE_V2_PLAN.md`: Dokan / `WinFsp`. `WinFsp` is the
//! preferred backend. It is distributed under GPLv3 with the `WinFsp`
//! project-specific FLOSS exception and is also commercially licensed;
//! downstream packaging must verify compatibility. Dokan is the fallback.
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
//! - `winfsp` (preferred): reserved for the future `WinFsp` adapter.
//! - `dokan` (fallback): reserved for the future Dokan adapter.
//! - default (neither): scaffold-only.
//!
//! Enabling either reserved feature does not add a driver binding or
//! make mounting available.
//!
//! Linux + macOS callers always get [`MountError::UnsupportedPlatform`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::{Path, PathBuf};

use thiserror::Error;

pub use ol_fuse::{DirEntry, EntryKind, FilesystemBackend, FsError, MemoryBackend, Stat};

/// Windows-specific mount options.
#[derive(Debug, Clone)]
pub struct MountOptions {
    /// Mount target. `WinFsp` accepts an unused drive designator (`"X:"`
    /// or `"X:\\"`) that does not exist before mounting, or an existing
    /// directory mountpoint. A `\\?\` extended-length local path is not a
    /// UNC network path and must identify an existing directory.
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

/// Errors `mount()` can return.
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum MountError {
    #[error("WinFsp / Dokan not supported on this platform")]
    UnsupportedPlatform,
    #[error("mount target must be an unused drive designator or existing directory: {0}")]
    InvalidMountpoint(PathBuf),
    #[error("backend error: {0}")]
    Backend(String),
}

/// Mount `backend` at `opts.mountpoint` via `WinFsp` (preferred) or
/// Dokan (fallback).
///
/// Behaviour by platform + feature:
///
/// - **Windows, with any feature combination**: validates drive-designator
///   or directory syntax, then returns [`MountError::Backend`] stating that
///   the adapter is unimplemented.
/// - **Non-Windows**: [`MountError::UnsupportedPlatform`].
pub fn mount<B>(_backend: B, opts: MountOptions) -> Result<(), MountError>
where
    B: FilesystemBackend + 'static,
{
    if !valid_mount_target(&opts.mountpoint) {
        return Err(MountError::InvalidMountpoint(opts.mountpoint));
    }
    #[cfg(target_os = "windows")]
    {
        Err(MountError::Backend(
            "WinFsp/Dokan adapter is not implemented; reserved cargo features do not enable mounting"
                .into(),
        ))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(MountError::UnsupportedPlatform)
    }
}

fn valid_mount_target(mountpoint: &Path) -> bool {
    #[cfg(target_os = "windows")]
    if is_drive_designator(mountpoint) {
        // An unused drive does not exist until WinFsp assigns it. The future
        // adapter remains responsible for rejecting an already-assigned drive.
        return true;
    }
    mountpoint.is_dir()
}

#[cfg(any(target_os = "windows", test))]
fn is_drive_designator(mountpoint: &Path) -> bool {
    let raw = mountpoint.as_os_str().to_string_lossy();
    let bytes = raw.as_bytes();
    bytes.len() >= 2
        && bytes.len() <= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes.len() == 2 || matches!(bytes[2], b'\\' | b'/'))
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
    fn mount_with_valid_mountpoint_never_claims_success() {
        let tmp = tempfile::tempdir().unwrap();
        let opts = MountOptions {
            mountpoint: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let backend = MemoryBackend::new();
        let err = mount(backend, opts).unwrap_err();
        #[cfg(target_os = "windows")]
        match err {
            MountError::Backend(message) => {
                assert!(message.contains("not implemented"));
                assert!(message.contains("do not enable mounting"));
                assert!(!message.contains("rebuild"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        #[cfg(not(target_os = "windows"))]
        {
            assert!(matches!(err, MountError::UnsupportedPlatform));
        }
    }

    #[test]
    fn drive_designator_syntax_does_not_require_a_preexisting_path() {
        assert!(is_drive_designator(Path::new("X:")));
        assert!(is_drive_designator(Path::new("x:\\")));
        assert!(is_drive_designator(Path::new("Q:/")));
        assert!(!is_drive_designator(Path::new("1:")));
        assert!(!is_drive_designator(Path::new("XX:")));
        assert!(!is_drive_designator(Path::new("X:\\nested")));
        assert!(!is_drive_designator(Path::new("\\\\server\\share")));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn drive_designator_reaches_truthful_adapter_failure() {
        let opts = MountOptions {
            mountpoint: PathBuf::from("X:"),
            ..Default::default()
        };
        let err = mount(MemoryBackend::new(), opts).unwrap_err();
        match err {
            MountError::Backend(message) => assert!(message.contains("not implemented")),
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
