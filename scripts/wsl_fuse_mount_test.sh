#!/usr/bin/env bash
# FUSE mount round-trip test on Linux.
#
# Build ol_fuse with --features linux-mount, write a tiny mount-and-
# verify binary inline, run it, observe actual file operations
# routed through libfuse → kernel → userspace adapter → MemoryBackend.

set -e
set -o pipefail

# shellcheck source=/dev/null
. "$HOME/.cargo/env"

NATIVE=/root/ol_native_linux
cd "$NATIVE"

echo "=================================================================="
echo "  FUSE mount round-trip test"
echo "=================================================================="
echo

# Build the crate with linux-mount.
echo "→ building ol_fuse with --features linux-mount ..."
BUILD_LOG=/tmp/ol_fuse_linux_mount.log
if cargo build --release -p ol_fuse --features linux-mount > "$BUILD_LOG" 2>&1; then
    echo "  build OK"
else
    echo "  BUILD FAILED:"
    tail -30 "$BUILD_LOG"
    exit 1
fi

# Create a tiny binary inside the crate that mounts MemoryBackend
# and verifies read/write/stat via libc.
BIN_CRATE=/root/ol_fuse_mount_test
mkdir -p "$BIN_CRATE/src"
cat > "$BIN_CRATE/Cargo.toml" <<'EOF'
[package]
name = "ol_fuse_mount_test"
version = "0.1.0"
edition = "2021"

[dependencies]
ol_fuse = { path = "/root/ol_native_linux/ol_fuse", features = ["linux-mount"] }
fuser = "0.15"
libc = "0.2"

[[bin]]
name = "ol_fuse_mount_test"
path = "src/main.rs"
EOF

cat > "$BIN_CRATE/src/main.rs" <<'EOF'
use ol_fuse::{mount, FilesystemBackend, MemoryBackend, MountOptions};
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

fn main() {
    let mountpoint = PathBuf::from("/tmp/ol_fuse_mp");
    let _ = fs::create_dir_all(&mountpoint);

    let backend = MemoryBackend::new();
    // Seed the in-memory FS with a file the kernel can later read
    // back through FUSE. write() creates the path on missing.
    let n = backend
        .write("/hello.txt", 0, b"hello from MemoryBackend via FUSE")
        .unwrap();
    println!("seeded /hello.txt with {n} bytes");

    // Mount in a background thread (fuser::mount2 blocks until
    // fusermount -u <mountpoint>).
    let mp_clone = mountpoint.clone();
    let handle = thread::spawn(move || {
        let opts = MountOptions {
            mountpoint: mp_clone,
            fs_name: "ol_fuse_test".to_string(),
            read_only: true,
            allow_other: false,
        };
        match mount(backend, opts) {
            Ok(()) => println!("mount returned cleanly"),
            Err(e) => println!("mount returned error: {e:?}"),
        }
    });

    // Wait for the mount to come up.
    thread::sleep(Duration::from_millis(500));

    // Read the file through the kernel — proves the full
    // userspace → kernel → libfuse → adapter → MemoryBackend round-trip.
    match fs::read_to_string(mountpoint.join("hello.txt")) {
        Ok(contents) => {
            println!("READ OK: {contents:?}");
            assert_eq!(contents, "hello from MemoryBackend via FUSE");
            println!("ROUND-TRIP VERIFIED");
        }
        Err(e) => {
            println!("READ FAILED: {e:?}");
        }
    }

    // List the directory.
    match fs::read_dir(&mountpoint) {
        Ok(entries) => {
            let names: Vec<String> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            println!("READDIR OK: {names:?}");
        }
        Err(e) => println!("READDIR FAILED: {e:?}"),
    }

    // Unmount cleanly.
    println!("unmounting ...");
    let status = std::process::Command::new("fusermount3")
        .args(["-u", mountpoint.to_str().unwrap()])
        .status();
    match status {
        Ok(s) if s.success() => println!("UNMOUNT OK"),
        Ok(s) => println!("fusermount3 exit {s}"),
        Err(e) => println!("fusermount3 failed: {e}"),
    }

    let _ = handle.join();
}
EOF

echo "→ building mount-test binary ..."
BIN_LOG=/tmp/ol_fuse_mount_bin.log
cd "$BIN_CRATE"
if cargo build --release > "$BIN_LOG" 2>&1; then
    echo "  binary built"
else
    echo "  binary build FAILED:"
    tail -30 "$BIN_LOG"
    exit 1
fi

echo
echo "→ running mount-and-verify ..."
echo
./target/release/ol_fuse_mount_test
