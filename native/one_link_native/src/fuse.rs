//! `one_link_native.fuse` — feature-gated Linux filesystem mounting.
//!
//! This binding is deliberately read-only.  Python supplies an immutable
//! folder manifest plus a callback which reads verified slices from One
//! Link's content-addressed blob store.  The callback is retained by the
//! mounted backend and invoked with the GIL attached from FUSE worker threads.
//! Windows and macOS build the same introspection ABI, but every mount attempt
//! fails before touching a mountpoint because no `WinFsp`/`Dokan` or `FSKit` adapter
//! is implemented.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use ol_fuse::{
    mount_platform_status, spawn_mount, BlobReader, FolderManifestBackend, FsError, ManifestRow,
    MountError, MountOptions, MountedFilesystem, PlatformMountStatus, MAX_FS_PATH_BYTES,
};
use pyo3::exceptions::{
    PyFileNotFoundError, PyNotImplementedError, PyPermissionError, PyRuntimeError, PyTypeError,
    PyValueError,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Hard cap on the number of files accepted in one Python-supplied manifest.
pub const MAX_MOUNT_MANIFEST_ENTRIES: usize = 65_536;
/// Maximum byte length accepted for the name displayed by mount tools.
pub const MAX_FS_NAME_BYTES: usize = 64;

#[derive(Debug, Default)]
struct MountRegistry {
    active: BTreeMap<PathBuf, MountedFilesystem>,
    pending: BTreeSet<PathBuf>,
}

fn registry() -> &'static Mutex<MountRegistry> {
    static REGISTRY: OnceLock<Mutex<MountRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(MountRegistry::default()))
}

/// Return the authoritative compile-time platform/backend status tag.
#[pyfunction]
fn platform_status() -> &'static str {
    platform_status_tag(mount_platform_status())
}

fn platform_status_tag(status: PlatformMountStatus) -> &'static str {
    match status {
        PlatformMountStatus::LinuxFuserReady => "linux_fuser_ready",
        PlatformMountStatus::LinuxFuserDisabled => "linux_fuser_disabled",
        PlatformMountStatus::MacOsUnsupported => "macos_unsupported",
        PlatformMountStatus::WindowsUnsupported => "windows_unsupported",
        PlatformMountStatus::OtherUnsupported => "other_unsupported",
    }
}

/// Mount a read-only manifest and serve its blob data in a background thread.
///
/// `blob_reader` must be a Python callable with signature
/// `(blob_hash: str, offset: int, size: int) -> bytes`.  Production callers
/// bind this to the verified CAS reader; metadata alone is never treated as
/// file content.  Success means fuser created a live background session which
/// is retained until [`unmount`] is called or the process exits.
#[pyfunction]
#[pyo3(signature = (*, mountpoint, manifest, blob_reader, fs_name="one_link_folder", read_only=true, allow_other=false))]
fn mount_manifest(
    py: Python<'_>,
    mountpoint: &str,
    manifest: Vec<(String, u64, u64, String)>,
    blob_reader: Py<PyAny>,
    fs_name: &str,
    read_only: bool,
    allow_other: bool,
) -> PyResult<()> {
    require_mount_backend()?;
    if !read_only {
        return Err(PyPermissionError::new_err(
            "read-write filesystem mounts are not implemented; refusing an unsafe writable view",
        ));
    }
    if !blob_reader.bind(py).is_callable() {
        return Err(PyTypeError::new_err(
            "blob_reader must be callable as (blob_hash, offset, size) -> bytes",
        ));
    }
    validate_fs_name(fs_name).map_err(PyValueError::new_err)?;
    let files = validate_manifest(manifest).map_err(PyValueError::new_err)?;
    let mountpoint = validate_mountpoint(mountpoint)?;

    {
        let mut state = registry()
            .lock()
            .map_err(|_| PyRuntimeError::new_err("filesystem mount registry is unavailable"))?;
        state.active.retain(|_, session| session.is_running());
        if state.active.contains_key(&mountpoint) || !state.pending.insert(mountpoint.clone()) {
            return Err(PyRuntimeError::new_err(
                "mountpoint is already mounted or a mount is already in progress",
            ));
        }
    }

    let reader = python_blob_reader(blob_reader);
    let backend = FolderManifestBackend::new(files, reader);
    let options = MountOptions {
        mountpoint: mountpoint.clone(),
        fs_name: fs_name.to_string(),
        read_only: true,
        allow_other,
    };
    let mounted_result = py.detach(|| spawn_mount(backend, options));

    let mut state = registry()
        .lock()
        .map_err(|_| PyRuntimeError::new_err("filesystem mount registry is unavailable"))?;
    state.pending.remove(&mountpoint);
    let mounted = mounted_result.map_err(|error| mount_error_to_pyerr(&error))?;
    if !mounted.is_running() {
        drop(state);
        let _ = py.detach(|| mounted.unmount());
        return Err(PyRuntimeError::new_err(
            "FUSE session exited before the mount became available",
        ));
    }
    if state.active.insert(mountpoint, mounted).is_some() {
        return Err(PyRuntimeError::new_err(
            "mount registry collision after successful FUSE startup",
        ));
    }
    Ok(())
}

/// Unmount a filesystem previously created by [`mount_manifest`].
///
/// Arbitrary system mountpoints are never passed to an external unmount
/// command.  Only an exact path owned by this process's registry can be
/// unmounted through this API.
#[pyfunction]
fn unmount(py: Python<'_>, mountpoint: &str) -> PyResult<()> {
    require_mount_backend()?;
    let mountpoint = canonical_existing_directory(mountpoint)?;
    let mounted = {
        let mut state = registry()
            .lock()
            .map_err(|_| PyRuntimeError::new_err("filesystem mount registry is unavailable"))?;
        if state.pending.contains(&mountpoint) {
            return Err(PyRuntimeError::new_err(
                "mount is still starting; retry unmount after startup completes",
            ));
        }
        state.active.remove(&mountpoint).ok_or_else(|| {
            PyFileNotFoundError::new_err("mountpoint is not owned by this One Link process")
        })?
    };
    py.detach(|| mounted.unmount())
        .map_err(|error| mount_error_to_pyerr(&error))
}

/// Return whether this process currently owns a live mount at `mountpoint`.
#[pyfunction]
fn is_mounted(mountpoint: &str) -> bool {
    let Ok(path) = std::fs::canonicalize(mountpoint) else {
        return false;
    };
    let Ok(mut state) = registry().lock() else {
        return false;
    };
    state.active.retain(|_, session| session.is_running());
    state.active.contains_key(&path)
}

fn require_mount_backend() -> PyResult<()> {
    match mount_platform_status() {
        PlatformMountStatus::LinuxFuserReady => Ok(()),
        PlatformMountStatus::LinuxFuserDisabled => Err(PyNotImplementedError::new_err(
            "Linux filesystem mounting is disabled in this build; rebuild one_link_native with the linux-mount feature",
        )),
        PlatformMountStatus::MacOsUnsupported => Err(PyNotImplementedError::new_err(
            "the macOS FSKit adapter is not implemented in One Link",
        )),
        PlatformMountStatus::WindowsUnsupported => Err(PyNotImplementedError::new_err(
            "the Windows WinFsp/Dokan adapter is not implemented in One Link",
        )),
        PlatformMountStatus::OtherUnsupported => Err(PyNotImplementedError::new_err(
            "filesystem mounting is unsupported on this operating system",
        )),
    }
}

fn python_blob_reader(callback: Py<PyAny>) -> BlobReader {
    let callback = Arc::new(Mutex::new(callback));
    Box::new(move |blob_hash: &str, offset: u64, size: u32| {
        Python::try_attach(|py| {
            let callback = callback.lock().map_err(|_| FsError::StateUnavailable)?;
            let result = callback
                .bind(py)
                .call1((blob_hash, offset, size))
                .map_err(|_| FsError::Io("Python blob reader callback failed".into()))?;
            let bytes = result
                .cast::<PyBytes>()
                .map_err(|_| FsError::Io("Python blob reader returned a non-bytes value".into()))?;
            if bytes.as_bytes().len() > size as usize {
                return Err(FsError::Io(
                    "Python blob reader returned more bytes than requested".into(),
                ));
            }
            Ok(bytes.as_bytes().to_vec())
        })
        .unwrap_or(Err(FsError::StateUnavailable))
    })
}

fn validate_manifest(
    rows: Vec<(String, u64, u64, String)>,
) -> Result<BTreeMap<String, ManifestRow>, String> {
    if rows.len() > MAX_MOUNT_MANIFEST_ENTRIES {
        return Err(format!(
            "manifest has {} entries; maximum is {MAX_MOUNT_MANIFEST_ENTRIES}",
            rows.len()
        ));
    }
    let mut files = BTreeMap::new();
    for (path, size, mtime_ms, blob_hash) in rows {
        validate_manifest_path(&path)?;
        validate_blob_hash(&blob_hash)?;
        let row = ManifestRow {
            size,
            mtime_ms,
            blob_hash,
        };
        if files.insert(path.clone(), row).is_some() {
            return Err(format!("manifest contains duplicate path: {path}"));
        }
    }
    for path in files.keys() {
        for (index, _) in path.match_indices('/') {
            let ancestor = &path[..index];
            if files.contains_key(ancestor) {
                return Err(format!(
                    "manifest path {path} descends from file entry {ancestor}"
                ));
            }
        }
    }
    Ok(files)
}

fn validate_manifest_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("manifest path is empty".into());
    }
    if path.len() > MAX_FS_PATH_BYTES {
        return Err(format!(
            "manifest path exceeds {MAX_FS_PATH_BYTES} UTF-8 bytes"
        ));
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err("manifest paths must be canonical relative paths".into());
    }
    if path.chars().any(char::is_control) {
        return Err("manifest path contains a control character".into());
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err("manifest path contains an empty, current, or parent segment".into());
    }
    Ok(())
}

fn validate_blob_hash(blob_hash: &str) -> Result<(), String> {
    if blob_hash.len() != 64
        || !blob_hash
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(
            "blob hash must be exactly 64 canonical lowercase hexadecimal characters".into(),
        );
    }
    Ok(())
}

fn validate_fs_name(fs_name: &str) -> Result<(), String> {
    if fs_name.is_empty() || fs_name.len() > MAX_FS_NAME_BYTES {
        return Err(format!(
            "fs_name must contain 1..={MAX_FS_NAME_BYTES} UTF-8 bytes"
        ));
    }
    if !fs_name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err("fs_name may contain only ASCII letters, digits, '.', '_', and '-'".into());
    }
    Ok(())
}

fn validate_mountpoint(raw: &str) -> PyResult<PathBuf> {
    let path = canonical_existing_directory(raw)?;
    if path == Path::new("/") {
        return Err(PyPermissionError::new_err(
            "refusing to mount over the filesystem root",
        ));
    }
    let mut entries = std::fs::read_dir(&path).map_err(|error| {
        PyPermissionError::new_err(format!("cannot inspect mountpoint directory: {error}"))
    })?;
    if entries
        .next()
        .transpose()
        .map_err(|error| {
            PyPermissionError::new_err(format!("cannot inspect mountpoint directory: {error}"))
        })?
        .is_some()
    {
        return Err(PyValueError::new_err(
            "mountpoint must be empty so a mount cannot hide existing files",
        ));
    }
    Ok(path)
}

fn canonical_existing_directory(raw: &str) -> PyResult<PathBuf> {
    if raw.is_empty() || raw.as_bytes().contains(&0) {
        return Err(PyValueError::new_err("mountpoint is empty or contains NUL"));
    }
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(PyValueError::new_err("mountpoint must be an absolute path"));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        PyFileNotFoundError::new_err(format!("mountpoint is unavailable: {error}"))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(PyValueError::new_err(
            "mountpoint itself must not be a symbolic link",
        ));
    }
    if !metadata.is_dir() {
        return Err(PyValueError::new_err("mountpoint is not a directory"));
    }
    std::fs::canonicalize(path).map_err(|error| {
        PyFileNotFoundError::new_err(format!("cannot canonicalize mountpoint: {error}"))
    })
}

fn mount_error_to_pyerr(error: &MountError) -> PyErr {
    match error {
        MountError::UnsupportedPlatform
        | MountError::UnsupportedMacOS
        | MountError::UnsupportedWindows => PyNotImplementedError::new_err(error.to_string()),
        MountError::InvalidMountpoint(_) => PyValueError::new_err(error.to_string()),
        MountError::Backend(_) => PyRuntimeError::new_err(error.to_string()),
    }
}

/// Register the `one_link_native.fuse` Python submodule.
pub(crate) fn register(_py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(platform_status, module)?)?;
    module.add_function(wrap_pyfunction!(mount_manifest, module)?)?;
    module.add_function(wrap_pyfunction!(unmount, module)?)?;
    module.add_function(wrap_pyfunction!(is_mounted, module)?)?;
    module.add("MAX_MANIFEST_ENTRIES", MAX_MOUNT_MANIFEST_ENTRIES)?;
    module.add("MAX_FS_PATH_BYTES", MAX_FS_PATH_BYTES)?;
    module.add("MAX_FS_NAME_BYTES", MAX_FS_NAME_BYTES)?;
    module.add("READ_ONLY", true)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(path: &str) -> (String, u64, u64, String) {
        (path.into(), 1, 0, "ab".repeat(32))
    }

    #[test]
    fn manifest_validation_accepts_canonical_rows() {
        let files = validate_manifest(vec![row("docs/a.txt"), row("root.bin")]).unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn manifest_validation_rejects_duplicates_and_ancestor_conflicts() {
        assert!(validate_manifest(vec![row("a"), row("a")])
            .unwrap_err()
            .contains("duplicate"));
        assert!(validate_manifest(vec![row("a"), row("a/b")])
            .unwrap_err()
            .contains("descends"));
    }

    #[test]
    fn manifest_validation_rejects_traversal_controls_and_noncanonical_hashes() {
        for path in ["../escape", "a/../escape", "/absolute", "a//b", "a\nb"] {
            assert!(
                validate_manifest(vec![row(path)]).is_err(),
                "accepted {path:?}"
            );
        }
        let mut invalid = row("a");
        invalid.3 = "AB".repeat(32);
        assert!(validate_manifest(vec![invalid]).is_err());
    }

    #[test]
    fn fs_name_rejects_mount_option_injection() {
        assert!(validate_fs_name("one_link-folder.1").is_ok());
        for invalid in ["", "one,allow_other", "one link", "one\nlink"] {
            assert!(validate_fs_name(invalid).is_err());
        }
    }
}
