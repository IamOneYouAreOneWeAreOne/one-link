"""Build One Link's native window (`native/ol_shell`) and stage it for packaging.

    python scripts/build_native_shell.py --output-dir build/native-shell [--required]

WHY THIS IS A SEPARATE BUILD STEP. `ol_shell` is deliberately its own cargo workspace — a webview
stack is ~260 transitive crates, and the daemon's crates are the ones that touch keys, ciphertext
and the wire. `cargo build` at `native/` therefore does NOT build the shell, and packaging would
silently ship without it.

WHAT `--required` MEANS, and why the default is not required. Without the shell One Link still
opens: the launcher falls back to the browser app-mode path and says so. That is a real degradation
but not a broken product, so a developer build should not fail for want of a Rust toolchain. A
RELEASE build passes `--required`, because shipping a "native window" that is not in the bundle is
the silent-claim failure this whole line of work exists to end.

THE UI PIN IS THE REASON THIS MUST RUN AT RELEASE TIME, EVERY TIME. `build.rs` compiles
sha256(web/index.html) into the binary. A shell built before the last UI edit refuses to render the
interface that ships beside it — correctly, and confusingly. So the shell is rebuilt whenever the
interface may have moved, and `--verify-pin` re-derives the hash afterwards and refuses a mismatch
rather than letting a stale binary reach a user.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SHELL_DIR = REPO / "native" / "ol_shell"
EXE = "ol_shell.exe" if sys.platform == "win32" else "ol_shell"


def _ui_sha256() -> str:
    return hashlib.sha256((REPO / "src" / "one_link" / "web" / "index.html").read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--output-dir", required=True, help="stage the built shell here")
    ap.add_argument("--required", action="store_true",
                    help="fail the build when the shell cannot be produced (release builds)")
    ap.add_argument("--verify-pin", action="store_true", default=True,
                    help="re-derive the UI hash and refuse a shell built against a different one")
    args = ap.parse_args()

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if shutil.which("cargo") is None:
        msg = "[shell] cargo is not on PATH; cannot build One Link's native window"
        print(msg)
        if args.required:
            print("[shell] REFUSING to package a release that claims a native window it lacks")
            return 3
        print("[shell] continuing without it: the launcher falls back to the browser path")
        return 0

    # `--locked` so a release cannot silently pick up a different dependency tree than the one
    # committed in Cargo.lock. A window is not worth an unaudited crate.
    cmd = ["cargo", "build", "--release", "--locked"]
    print(f"[shell] running: {' '.join(cmd)}  (cwd {SHELL_DIR})")
    rc = subprocess.run(cmd, cwd=SHELL_DIR).returncode
    if rc != 0:
        print(f"[shell] build failed: exit {rc}")
        return rc if args.required else 0

    built = SHELL_DIR / "target" / "release" / EXE
    if not built.is_file():
        print(f"[shell] cargo reported success but {built} is missing")
        return 4 if args.required else 0

    # THE PIN CHECK. `build.rs` bakes the interface hash in; if the UI changed after the last build,
    # cargo's `rerun-if-changed` should have rebuilt it. Verifying rather than trusting, because a
    # stale pin does not fail the build -- it fails the USER, with a window that refuses to open.
    if args.verify_pin:
        expected = _ui_sha256()
        blob = built.read_bytes()
        if expected.encode("ascii") not in blob:
            print(f"[shell] the built shell does not carry the current interface hash "
                  f"({expected[:16]}). It would refuse to render the UI shipping beside it.")
            print("[shell] this means build.rs did not re-run; delete native/ol_shell/target "
                  "and rebuild.")
            return 5 if args.required else 0
        print(f"[shell] UI pin verified: {expected[:16]}")

    staged = out / EXE
    shutil.copy2(built, staged)
    digest = hashlib.sha256(staged.read_bytes()).hexdigest()
    (out / f"{EXE}.sha256").write_text(f"{digest}  {EXE}\n", encoding="utf-8", newline="\n")
    print(f"[shell] staged {staged} ({staged.stat().st_size} bytes, sha256 {digest[:16]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
