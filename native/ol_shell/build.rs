//! Compile the hash of the UI this shell is willing to render INTO the shell.
//!
//! THE TRUST PROBLEM THIS SOLVES. Everything else in the launch path can be edited by whoever can
//! write to the install directory: the Python launcher, the daemon, `index.html`. If the shell were
//! *told* which hash to expect, an attacker who edited the UI would edit the expected hash in the
//! same pass, and the check would confirm the tampering.
//!
//! So the expectation is not passed in — it is baked into the binary at build time. The shell's own
//! integrity (code signature, installer, update transaction) then roots the interface's integrity.
//! Editing `index.html` after install now requires re-signing `ol_shell.exe` as well.
//!
//! WHAT THIS DOES NOT CLAIM. It does not defend against a compromised daemon serving different
//! bytes than the file on disk — a daemon that owns the process owns everything downstream of it.
//! It defends against the realistic case: something modified the interface on disk after it shipped.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let ui = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../src/one_link/web/index.html");

    // Rebuild whenever the UI changes: a stale pin would refuse the very interface that shipped
    // beside it, which reads as "the app is broken" rather than "the pin is old".
    println!("cargo:rerun-if-changed={}", ui.display());

    let digest = match std::fs::read(&ui) {
        Ok(bytes) => sha256_hex(&bytes),
        // A build without the UI present is a build that cannot pin it. Emitting an empty pin and
        // letting the runtime decide would create exactly the silent-degradation path this whole
        // mechanism exists to remove, so the build FAILS instead.
        Err(e) => panic!(
            "ol_shell cannot pin the UI: {} could not be read ({e}). The shell refuses to build \
             without the interface it is meant to render, because a shell with no pin is a shell \
             that renders anything.",
            ui.display()
        ),
    };

    println!("cargo:rustc-env=OL_UI_SHA256={digest}");
}

/// SHA-256 without pulling a crate into the build graph.
///
/// `sha2` is a runtime dependency, not a build dependency, and adding it to `[build-dependencies]`
/// would compile it twice. Every platform this ships on has a hasher on the command line.
fn sha256_hex(bytes: &[u8]) -> String {
    // Written to a temp file rather than piped: `certutil` has no stdin mode, and the shell
    // quoting needed to pipe a 1.7 MB HTML file differs on every platform.
    let tmp = std::env::temp_dir().join(format!("ol_shell_ui_{}.bin", std::process::id()));
    std::fs::write(&tmp, bytes).expect("cannot stage the UI for hashing");

    let out = if cfg!(target_os = "windows") {
        Command::new("certutil")
            .args(["-hashfile", tmp.to_str().unwrap(), "SHA256"])
            .output()
    } else if cfg!(target_os = "macos") {
        Command::new("shasum")
            .args(["-a", "256", tmp.to_str().unwrap()])
            .output()
    } else {
        Command::new("sha256sum")
            .arg(tmp.to_str().unwrap())
            .output()
    }
    .expect("no SHA-256 tool available to pin the UI");

    let _ = std::fs::remove_file(&tmp);
    let text = String::from_utf8_lossy(&out.stdout).to_lowercase();

    // Pull the first 64-hex-character run out of whatever shape the tool prints.
    let hex: String = text
        .split_whitespace()
        .find(|w| w.len() == 64 && w.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or_else(|| {
            // certutil prints the digest with spaces between byte pairs on some locales.
            panic!("could not parse a SHA-256 out of: {text}")
        })
        .to_string();
    hex
}
