#!/usr/bin/env bash
# Strict FUSE mount round-trip gate for Linux/WSL.
#
# The gate builds from the reviewed workspace lock, creates a disposable
# test crate with its own deliberate lock, and fails on every mount, read,
# directory, unmount, timeout, or mount-thread error.

set -euo pipefail

readonly REQUIRED_RUST_VERSION="1.96.0"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="${ONE_LINK_REPO:-$(cd -- "${SCRIPT_DIR}/.." && pwd -P)}"
NATIVE="${REPO}/native"

die() {
    echo "FATAL: $*" >&2
    exit 1
}

if ! command -v cargo >/dev/null 2>&1 && \
   [[ -n "${HOME:-}" && -r "${HOME}/.cargo/env" ]]; then
    # Loading an existing environment is allowed. This gate never installs.
    # shellcheck source=/dev/null
    . "${HOME}/.cargo/env"
fi

[[ "$(uname -s)" == "Linux" ]] || die "this gate requires Linux/WSL"
[[ -f "$NATIVE/Cargo.toml" && -f "$NATIVE/Cargo.lock" ]] || \
    die "native Cargo workspace or lockfile is missing at $NATIVE"
[[ -d "$NATIVE/ol_fuse" ]] || die "ol_fuse crate is missing at $NATIVE/ol_fuse"
[[ -e /dev/fuse ]] || die "/dev/fuse is unavailable"
command -v cargo >/dev/null 2>&1 || \
    die "cargo is missing; provision Rust ${REQUIRED_RUST_VERSION} explicitly"
command -v rustc >/dev/null 2>&1 || \
    die "rustc is missing; provision Rust ${REQUIRED_RUST_VERSION} explicitly"
command -v timeout >/dev/null 2>&1 || die "GNU timeout is required"
[[ "$(rustc --version)" == "rustc ${REQUIRED_RUST_VERSION} "* ]] || \
    die "rustc ${REQUIRED_RUST_VERSION} is required; found $(rustc --version)"
[[ "$(cargo --version)" == "cargo ${REQUIRED_RUST_VERSION} "* ]] || \
    die "cargo ${REQUIRED_RUST_VERSION} is required; found $(cargo --version)"

if command -v fusermount3 >/dev/null 2>&1; then
    FUSERMOUNT="$(command -v fusermount3)"
elif command -v fusermount >/dev/null 2>&1; then
    FUSERMOUNT="$(command -v fusermount)"
else
    die "fusermount3/fusermount is missing; install the distro FUSE 3 prerequisites explicitly"
fi
readonly FUSERMOUNT

echo "=================================================================="
echo "  strict FUSE mount round-trip test"
echo "=================================================================="

readonly BUILD_LOG="${TMPDIR:-/tmp}/one-link-fuse-build.log"
cd -- "$NATIVE"
if cargo build --locked --release -p ol_fuse --features linux-mount \
        > "$BUILD_LOG" 2>&1; then
    echo "ol_fuse locked release build: PASS"
else
    tail -n 40 -- "$BUILD_LOG" >&2 || true
    die "ol_fuse build failed; full log: $BUILD_LOG"
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/one-link-fuse-test.XXXXXX")"
BIN_CRATE="${TEST_ROOT}/crate"
MOUNTPOINT="${TEST_ROOT}/mount"
mkdir -p -- "$BIN_CRATE/src" "$MOUNTPOINT"

cleanup() {
    local exit_code=$?
    trap - EXIT
    set +e
    "$FUSERMOUNT" -u "$MOUNTPOINT" >/dev/null 2>&1
    rm -rf -- "$TEST_ROOT"
    exit "$exit_code"
}
trap cleanup EXIT

# Link the complete reviewed native workspace, not only the member crate.
# ol_fuse deliberately inherits dependency versions from
# native/Cargo.toml; isolating the member severs that authority and makes the
# disposable lock impossible to generate. The relative dependency path still
# avoids hard-coded user paths and remains valid when the repository contains
# spaces.
ln -s -- "$NATIVE" "$BIN_CRATE/native"

cat > "$BIN_CRATE/Cargo.toml" <<'EOF'
[package]
name = "ol_fuse_mount_test"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
ol_fuse = { path = "native/ol_fuse", features = ["linux-mount"] }

[[bin]]
name = "ol_fuse_mount_test"
path = "src/main.rs"
EOF

cat > "$BIN_CRATE/src/main.rs" <<'EOF'
use ol_fuse::{mount, FilesystemBackend, MemoryBackend, MountOptions};
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

const EXPECTED: &str = "hello from MemoryBackend via FUSE";
const MOUNT_TIMEOUT: Duration = Duration::from_secs(10);

fn main() -> Result<(), Box<dyn Error>> {
    let mountpoint = PathBuf::from(env::var_os("ONE_LINK_FUSE_MOUNTPOINT").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ONE_LINK_FUSE_MOUNTPOINT is missing",
        )
    })?);
    let unmounter = env::var_os("ONE_LINK_FUSERMOUNT").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ONE_LINK_FUSERMOUNT is missing",
        )
    })?;

    let backend = MemoryBackend::new();
    let written = backend.write("/hello.txt", 0, EXPECTED.as_bytes())?;
    if written != EXPECTED.len() as u32 {
        return Err(io::Error::other(format!(
            "short seed write: expected {}, wrote {written}",
            EXPECTED.len()
        ))
        .into());
    }

    let thread_mountpoint = mountpoint.clone();
    let (mount_tx, mount_rx) = mpsc::channel();
    let mount_handle = thread::spawn(move || {
        let options = MountOptions {
            mountpoint: thread_mountpoint,
            fs_name: "ol_fuse_test".to_string(),
            read_only: true,
            allow_other: false,
        };
        let result = mount(backend, options).map_err(|error| format!("{error:?}"));
        let _send_result = mount_tx.send(result.clone());
        result
    });

    let deadline = Instant::now() + MOUNT_TIMEOUT;
    let contents = loop {
        match fs::read_to_string(mountpoint.join("hello.txt")) {
            Ok(contents) => break contents,
            Err(read_error) => {
                match mount_rx.try_recv() {
                    Ok(Ok(())) => {
                        return Err(io::Error::other(
                            "mount exited before the kernel read succeeded",
                        )
                        .into());
                    }
                    Ok(Err(error)) => {
                        return Err(io::Error::other(format!("mount failed: {error}")).into());
                    }
                    Err(TryRecvError::Disconnected) => {
                        return Err(io::Error::other("mount thread disconnected").into());
                    }
                    Err(TryRecvError::Empty) => {}
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("mount did not become readable: {read_error}"),
                    )
                    .into());
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    };

    if contents != EXPECTED {
        return Err(io::Error::other(format!(
            "content mismatch: expected {EXPECTED:?}, received {contents:?}"
        ))
        .into());
    }

    let names = fs::read_dir(&mountpoint)?
        .map(|entry| entry.map(|value| value.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, _>>()?;
    if !names.iter().any(|name| name == "hello.txt") {
        return Err(
            io::Error::other(format!("directory listing omitted hello.txt: {names:?}")).into(),
        );
    }

    let unmount_status = std::process::Command::new(unmounter)
        .arg("-u")
        .arg(&mountpoint)
        .status()?;
    if !unmount_status.success() {
        return Err(
            io::Error::other(format!("unmount command failed with {unmount_status}")).into(),
        );
    }

    let mount_result = mount_handle
        .join()
        .map_err(|_| io::Error::other("mount thread panicked"))?;
    mount_result.map_err(|error| io::Error::other(format!("mount failed: {error}")))?;

    println!("FUSE mount/read/readdir/unmount round-trip: PASS");
    Ok(())
}
EOF

cd -- "$BIN_CRATE"
readonly LOCK_LOG="${TMPDIR:-/tmp}/one-link-fuse-lock.log"
# The disposable project has no checked-in lock. Create one deliberately,
# offline, then require the build to consume it without any mutation.
if cargo generate-lockfile --offline > "$LOCK_LOG" 2>&1; then
    [[ -s Cargo.lock ]] || die "cargo reported success but did not create Cargo.lock"
else
    tail -n 40 -- "$LOCK_LOG" >&2 || true
    die "could not generate the disposable crate lockfile offline; full log: $LOCK_LOG"
fi

readonly BIN_LOG="${TMPDIR:-/tmp}/one-link-fuse-mount-binary.log"
if cargo build --locked --offline --release > "$BIN_LOG" 2>&1; then
    echo "mount-test locked offline build: PASS"
else
    tail -n 40 -- "$BIN_LOG" >&2 || true
    die "mount-test binary build failed; full log: $BIN_LOG"
fi

echo "running mount/read/readdir/unmount gate (30 second hard timeout)"
if timeout --foreground 30s env \
        ONE_LINK_FUSE_MOUNTPOINT="$MOUNTPOINT" \
        ONE_LINK_FUSERMOUNT="$FUSERMOUNT" \
        ./target/release/ol_fuse_mount_test; then
    echo "strict FUSE gate: PASS"
else
    run_exit=$?
    die "strict FUSE gate failed with exit code $run_exit"
fi
