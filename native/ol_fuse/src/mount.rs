//! FUSE mount entry point. Linux release builds call `fuser::mount2`
//! through the callback-backed adapter. Platforms without a completed
//! adapter return an explicit unsupported error so consumers fail closed
//! without manufacturing a mount-success claim.

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::backend::FilesystemBackend;

/// Options the daemon passes when mounting a folder as FUSE.
#[derive(Debug, Clone)]
pub struct MountOptions {
    /// Filesystem mountpoint (must be an existing empty directory).
    pub mountpoint: PathBuf,
    /// Filesystem name shown in `mount` output (e.g. `one_link_folder`).
    pub fs_name: String,
    /// Mount read-only. The generic crate defaults to false for backend tests,
    /// while One Link's packaged Python binding requires this to be true.
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
        "One Link's macOS FSKit filesystem adapter is not implemented; \
         installing FSKit or macFUSE support alone cannot enable this build."
    )]
    UnsupportedMacOS,
    #[error(
        "Windows requires WinFSP or Dokan to expose user-mode filesystems. \
         One Link does not yet implement its Windows filesystem adapter; \
         installing a driver alone cannot enable this build."
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
    /// `linux-mount` feature. Rebuild with
    /// `--features linux-mount` to enable.
    LinuxFuserDisabled,
    /// macOS — needs `FSKit` / `macFUSE`; see [`MountError::UnsupportedMacOS`].
    MacOsUnsupported,
    /// Windows — needs `WinFSP` / `Dokan`; see [`MountError::UnsupportedWindows`].
    WindowsUnsupported,
    /// Any other Unix-like target — currently unsupported.
    OtherUnsupported,
}

/// Owned handle for a filesystem serving requests on a background thread.
///
/// Dropping the handle unmounts the filesystem.  Consumers which need an
/// explicit lifecycle (the Python binding does) should retain the handle and
/// call [`MountedFilesystem::unmount`] when the user requests unmounting.
/// This type can only be constructed by [`spawn_mount`]; unsupported builds
/// return a [`MountError`] instead of manufacturing a non-functional handle.
pub struct MountedFilesystem {
    mountpoint: PathBuf,
    #[cfg(all(target_os = "linux", feature = "linux-mount"))]
    session: Option<fuser::BackgroundSession>,
}

impl std::fmt::Debug for MountedFilesystem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MountedFilesystem")
            .field("mountpoint", &self.mountpoint)
            .field("running", &self.is_running())
            .finish()
    }
}

impl MountedFilesystem {
    /// Canonical mountpoint supplied when the session was created.
    #[must_use]
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Whether the background FUSE service thread is still running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        #[cfg(all(target_os = "linux", feature = "linux-mount"))]
        {
            return self
                .session
                .as_ref()
                .is_some_and(|session| !session.guard.is_finished());
        }
        #[cfg(not(all(target_os = "linux", feature = "linux-mount")))]
        {
            false
        }
    }

    /// Unmount this filesystem by dropping fuser's owned kernel-mount guard.
    ///
    /// The background worker observes the closed FUSE device and exits.  The
    /// handle is consumed so an unmount cannot be repeated accidentally.
    pub fn unmount(self) -> Result<(), MountError> {
        #[cfg(all(target_os = "linux", feature = "linux-mount"))]
        {
            let mut session = self.session;
            drop(session.take());
        }
        Ok(())
    }
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
        let fuse_opts = fuser_options(&opts);
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

/// Mount `backend` and serve FUSE requests on a background thread.
///
/// Unlike [`mount`], this function returns once the kernel mount session has
/// been established.  The returned [`MountedFilesystem`] owns that session;
/// dropping or explicitly unmounting it tears the mount down.  Platform and
/// feature behavior is identical to [`mount`].
pub fn spawn_mount<B>(
    #[cfg(all(target_os = "linux", feature = "linux-mount"))] backend: B,
    #[cfg(not(all(target_os = "linux", feature = "linux-mount")))] _backend: B,
    opts: MountOptions,
) -> Result<MountedFilesystem, MountError>
where
    B: FilesystemBackend + 'static,
{
    if !opts.mountpoint.is_dir() {
        return Err(MountError::InvalidMountpoint(opts.mountpoint));
    }
    #[cfg(all(target_os = "linux", feature = "linux-mount"))]
    {
        use crate::adapter::FuserAdapter;
        let fuse_opts = fuser_options(&opts);
        let adapter = FuserAdapter::new(backend);
        let session = fuser::spawn_mount2(adapter, &opts.mountpoint, &fuse_opts)
            .map_err(|error| MountError::Backend(format!("fuser::spawn_mount2: {error}")))?;
        Ok(MountedFilesystem {
            mountpoint: opts.mountpoint,
            session: Some(session),
        })
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

#[cfg(all(target_os = "linux", feature = "linux-mount"))]
fn fuser_options(opts: &MountOptions) -> Vec<fuser::MountOption> {
    let mut fuse_opts = vec![
        fuser::MountOption::FSName(opts.fs_name.clone()),
        fuser::MountOption::DefaultPermissions,
    ];
    if opts.read_only {
        fuse_opts.push(fuser::MountOption::RO);
    }
    if opts.allow_other {
        fuse_opts.push(fuser::MountOption::AllowOther);
    }
    fuse_opts
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
    fn mount_with_valid_mountpoint_errors_without_active_backend() {
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
            other @ MountError::InvalidMountpoint(_) => {
                panic!("expected platform-unsupported or Backend variant, got {other:?}")
            }
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

    #[test]
    fn background_mount_refuses_missing_mountpoint_before_platform_dispatch() {
        let opts = MountOptions {
            mountpoint: PathBuf::from("/nonexistent/path/for/background-mount"),
            ..Default::default()
        };
        let error = spawn_mount(MemoryBackend::new(), opts).unwrap_err();
        assert!(matches!(error, MountError::InvalidMountpoint(_)));
    }
}
