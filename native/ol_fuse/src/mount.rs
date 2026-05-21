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
    #[error(
        "macOS does not ship a built-in FUSE driver; install FSKit-based \
         filesystem helper (Apple-maintained, no monthly bill) or macFUSE \
         (GPL+commercial, paid). The ol_fuse crate ships scaffold only \
         for this platform."
    )]
    UnsupportedMacOS,
    #[error(
        "Windows requires WinFSP or Dokan to expose user-mode filesystems. \
         The ol_fuse crate ships scaffold only for this platform — install \
         WinFSP (free, open source) and ship the WinFSP-backed binding via \
         ol_winfs (separate crate)."
    )]
    UnsupportedWindows,
    #[error("mountpoint does not exist or is not a directory: {0}")]
    InvalidMountpoint(PathBuf),
    #[error("fuser backend error: {0}")]
    Backend(String),
}

/// D27 — Per-platform mount-support status. Returned by
/// [`mount_platform_status`] so callers can decide before they build a
/// backend whether to even attempt a mount (or whether to surface a
/// "FUSE unavailable on your platform; install WinFSP/FSKit" message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum PlatformMountStatus {
    /// libfuse-backed real mount is wired and ready to call.
    LinuxFuserReady,
    /// Running on Linux but the crate was built without the
    /// ``linux-mount`` feature. Rebuild with
    /// ``--features linux-mount`` to enable.
    LinuxFuserDisabled,
    /// macOS — needs FSKit / macFUSE; see [`MountError::UnsupportedMacOS`].
    MacOsUnsupported,
    /// Windows — needs WinFSP / Dokan; see [`MountError::UnsupportedWindows`].
    WindowsUnsupported,
    /// Any other Unix-like target — currently unsupported.
    OtherUnsupported,
}

/// Report the platform mount status of this build. Pure introspection;
/// never opens a file or touches the kernel.
#[must_use]
pub fn mount_platform_status() -> PlatformMountStatus {
    #[cfg(all(target_os = "linux", feature = "linux-mount"))]
    {
        PlatformMountStatus::LinuxFuserReady
    }
    #[cfg(all(target_os = "linux", not(feature = "linux-mount")))]
    {
        PlatformMountStatus::LinuxFuserDisabled
    }
    #[cfg(target_os = "macos")]
    {
        PlatformMountStatus::MacOsUnsupported
    }
    #[cfg(target_os = "windows")]
    {
        PlatformMountStatus::WindowsUnsupported
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        PlatformMountStatus::OtherUnsupported
    }
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
///   [`MountError::Backend`] with a hint that the feature gate needs
///   to be enabled.
/// - **Non-Linux**: always
///   [`MountError::UnsupportedPlatform`].
///
/// The signature is stable across all three modes so consumers can
/// build once and have the runtime decide.
pub fn mount<B>(
    #[cfg(all(target_os = "linux", feature = "linux-mount"))] backend: B,
    #[cfg(not(all(target_os = "linux", feature = "linux-mount")))] _backend: B,
    opts: MountOptions,
) -> Result<(), MountError>
where
    B: FilesystemBackend + 'static,
{
    if !opts.mountpoint.is_dir() {
        return Err(MountError::InvalidMountpoint(opts.mountpoint));
    }
    #[cfg(all(target_os = "linux", feature = "linux-mount"))]
    {
        use crate::adapter::FuserAdapter;
        let mut fuse_opts: Vec<fuser::MountOption> = vec![
            fuser::MountOption::FSName(opts.fs_name.clone()),
            fuser::MountOption::DefaultPermissions,
        ];
        if opts.read_only {
            fuse_opts.push(fuser::MountOption::RO);
        }
        if opts.allow_other {
            fuse_opts.push(fuser::MountOption::AllowOther);
        }
        let adapter = FuserAdapter::new(backend);
        fuser::mount2(adapter, &opts.mountpoint, &fuse_opts)
            .map_err(|e| MountError::Backend(format!("fuser::mount2: {e}")))
    }
    #[cfg(all(target_os = "linux", not(feature = "linux-mount")))]
    {
        Err(MountError::Backend(
            "rebuild ol_fuse with --features linux-mount to enable FUSE".into(),
        ))
    }
    #[cfg(target_os = "macos")]
    {
        Err(MountError::UnsupportedMacOS)
    }
    #[cfg(target_os = "windows")]
    {
        Err(MountError::UnsupportedWindows)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
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
        // Per-platform error: Linux without feature => Backend(hint);
        // Linux with feature => real fuser mount (test doesn't run);
        // macOS => UnsupportedMacOS; Windows => UnsupportedWindows;
        // exotic Unix => UnsupportedPlatform. All cases are "the
        // kernel mount couldn't happen".
        match err {
            MountError::UnsupportedPlatform
            | MountError::UnsupportedMacOS
            | MountError::UnsupportedWindows
            | MountError::Backend(_) => {}
            other => panic!(
                "expected platform-unsupported or Backend variant, got {other:?}"
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

    #[test]
    fn mount_platform_status_returns_correct_variant() {
        let s = mount_platform_status();
        #[cfg(all(target_os = "linux", feature = "linux-mount"))]
        assert_eq!(s, PlatformMountStatus::LinuxFuserReady);
        #[cfg(all(target_os = "linux", not(feature = "linux-mount")))]
        assert_eq!(s, PlatformMountStatus::LinuxFuserDisabled);
        #[cfg(target_os = "macos")]
        assert_eq!(s, PlatformMountStatus::MacOsUnsupported);
        #[cfg(target_os = "windows")]
        assert_eq!(s, PlatformMountStatus::WindowsUnsupported);
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        assert_eq!(s, PlatformMountStatus::OtherUnsupported);
    }
}
