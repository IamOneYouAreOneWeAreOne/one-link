//! FUSE mount entry point. On Linux, this is where `fuser::mount2`
//! gets called (deferred until the daemon endpoint goes live). On
//! every other platform, the mount call returns
//! [`MountError::UnsupportedPlatform`] immediately so consumers can
//! fail fast without runtime panics.

use std::path::PathBuf;

use thiserror::Error;

use crate::backend::FilesystemBackend;

/// Options the daemon passes when mounting a folder as FUSE.
#[derive(Debug, Clone)]
pub struct MountOptions {
    /// Filesystem mountpoint (must be an existing empty directory).
    pub mountpoint: PathBuf,
    /// Filesystem name shown in `mount` output (e.g. `one_link_folder`).
    pub fs_name: String,
    /// Mount read-only. Default false (production folders are RW).
    pub read_only: bool,
    /// Allow non-root users to access the mount. Requires
    /// `user_allow_other` in `/etc/fuse.conf` on Linux.
    pub allow_other: bool,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            mountpoint: PathBuf::new(),
            fs_name: "one_link_folder".into(),
            read_only: false,
            allow_other: false,
        }
    }
}

/// Errors the mount entry point can return.
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum MountError {
    #[error("FUSE not supported on this platform")]
    UnsupportedPlatform,
    #[error("mountpoint does not exist or is not a directory: {0}")]
    InvalidMountpoint(PathBuf),
    #[error("fuser backend error: {0}")]
    Backend(String),
}

/// Mount `backend` at `opts.mountpoint`. On Linux: future call to
/// `fuser::mount2` (deferred — the scaffold returns
/// [`MountError::UnsupportedPlatform`] for now). On every other
/// platform: always [`MountError::UnsupportedPlatform`].
///
/// The signature is finalized — adding the real Linux wiring is a
/// drop-in change that doesn't break consumers.
pub fn mount<B>(_backend: B, opts: MountOptions) -> Result<(), MountError>
where
    B: FilesystemBackend + 'static,
{
    if !opts.mountpoint.is_dir() {
        return Err(MountError::InvalidMountpoint(opts.mountpoint));
    }
    #[cfg(target_os = "linux")]
    {
        // Real fuser wiring lands when the daemon ships its mount
        // endpoint. The scaffold reports unsupported so the failure
        // mode is honest until the wiring is real.
        Err(MountError::UnsupportedPlatform)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(MountError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemoryBackend;
    use std::path::PathBuf;

    #[test]
    fn mount_with_missing_mountpoint_errors() {
        let opts = MountOptions {
            mountpoint: PathBuf::from("/nonexistent/path/for/mount"),
            ..Default::default()
        };
        let backend = MemoryBackend::new();
        let err = mount(backend, opts).unwrap_err();
        assert!(matches!(err, MountError::InvalidMountpoint(_)));
    }

    #[test]
    fn mount_with_valid_mountpoint_returns_unsupported_on_scaffold() {
        let tmp = tempfile::tempdir().unwrap();
        let opts = MountOptions {
            mountpoint: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let backend = MemoryBackend::new();
        let err = mount(backend, opts).unwrap_err();
        // Until the Linux wiring lands the scaffold always reports
        // unsupported even on a valid mountpoint.
        assert!(matches!(err, MountError::UnsupportedPlatform));
    }

    #[test]
    fn mount_options_default_is_rw_no_allow_other() {
        let opts = MountOptions::default();
        assert!(!opts.read_only);
        assert!(!opts.allow_other);
        assert_eq!(opts.fs_name, "one_link_folder");
    }
}
