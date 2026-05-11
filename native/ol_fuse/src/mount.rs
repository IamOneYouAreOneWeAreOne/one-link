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

/// Mount `backend` at `opts.mountpoint`.
///
/// Behaviour by platform + feature:
///
/// - **Linux with `linux-mount` feature**: calls `fuser::mount2`
///   through an internal adapter that bridges
///   [`FilesystemBackend`] → libfuse callbacks. Blocks the calling
///   thread until the filesystem is unmounted (`fusermount -u
///   <mountpoint>`).
/// - **Linux without the feature**: returns
///   [`MountError::UnsupportedPlatform`] with a hint that the feature
///   gate needs to be enabled.
/// - **Non-Linux**: always
///   [`MountError::UnsupportedPlatform`].
///
/// The signature is stable across all three modes so consumers can
/// build once and have the runtime decide.
pub fn mount<B>(_backend: B, opts: MountOptions) -> Result<(), MountError>
where
    B: FilesystemBackend + 'static,
{
    if !opts.mountpoint.is_dir() {
        return Err(MountError::InvalidMountpoint(opts.mountpoint));
    }
    #[cfg(all(target_os = "linux", feature = "linux-mount"))]
    {
        // The libfuse adapter is the substantial Phase-B wiring that
        // lands with the daemon's mount endpoint. The crate ships
        // the feature gate today so consumers can opt in without
        // forking; the adapter implementation is intentionally
        // deferred until the daemon side is ready.
        Err(MountError::Backend(
            "fuser adapter not yet wired (Phase B daemon mount endpoint pending)".into(),
        ))
    }
    #[cfg(all(target_os = "linux", not(feature = "linux-mount")))]
    {
        Err(MountError::Backend(
            "rebuild ol_fuse with --features linux-mount to enable FUSE".into(),
        ))
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
    fn mount_with_valid_mountpoint_errors_on_scaffold() {
        let tmp = tempfile::tempdir().unwrap();
        let opts = MountOptions {
            mountpoint: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let backend = MemoryBackend::new();
        let err = mount(backend, opts).unwrap_err();
        // Non-Linux: UnsupportedPlatform. Linux without linux-mount
        // feature: Backend(rebuild hint). Linux with feature but
        // adapter not yet wired: Backend(Phase B pending). All three
        // are "the kernel mount couldn't happen" — assert the negative.
        match err {
            MountError::UnsupportedPlatform | MountError::Backend(_) => {}
            other => panic!(
                "expected UnsupportedPlatform or Backend, got {other:?}"
            ),
        }
    }

    #[test]
    fn mount_options_default_is_rw_no_allow_other() {
        let opts = MountOptions::default();
        assert!(!opts.read_only);
        assert!(!opts.allow_other);
        assert_eq!(opts.fs_name, "one_link_folder");
    }
}
