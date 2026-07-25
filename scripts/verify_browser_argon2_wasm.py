#!/usr/bin/env python3
"""Verify the shipped browser Argon2id WASM and optionally reproduce it."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
SHIPPED = ROOT / "src/one_link/web/assets/argon2id-v1.wasm"
WORKER = ROOT / "src/one_link/web/assets/argon2id-worker.js"
BUILT = NATIVE / "target/wasm32-unknown-unknown/release/ol_argon2_wasm.wasm"
EXPECTED_SHA256 = "22aab37746981785f986de39d99cf0e135218899690ce6b359c63e69e5c5d447"
PINNED_RUSTC = "1.96.0"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _remap_rustflags() -> str:
    """Build RUSTFLAGS that erase the build machine from the artifact.

    Dependency panic-location strings embed the absolute cargo registry path
    of whichever machine compiled them, which both leaks the builder's home
    directory into a shipped browser asset and makes the digest differ on
    every host. Remapping CARGO_HOME to the fixed ``/cargo`` root removes the
    machine-specific prefix on every platform.
    """
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    return f"--remap-path-prefix={cargo_home}=/cargo"


def _canonical_digest(blob: bytes) -> str:
    """Digest that is invariant to path-separator spelling in ``/cargo`` runs.

    After the CARGO_HOME remap the only remaining host difference is that a
    Windows rustc joins module paths inside a dependency with backslashes
    (``/cargo\\registry\\...\\params.rs``) where POSIX hosts use forward
    slashes. Normalizing separators inside those printable ``/cargo...`` runs
    -- bounded by the ``.rs`` suffix -- yields one digest for identical code
    on every platform. Everything outside those runs must still match
    byte-for-byte.
    """
    canonical = re.sub(
        rb"/cargo[ -~]*?\.rs",
        lambda m: m.group().replace(b"\\", b"/"),
        blob,
    )
    return hashlib.sha256(canonical).hexdigest()


def _verify_static_contract() -> None:
    blob = SHIPPED.read_bytes()
    if not blob.startswith(b"\x00asm") or not 8 <= len(blob) <= 128 * 1024:
        raise RuntimeError("shipped browser Argon2id artifact is not bounded WASM")
    actual = hashlib.sha256(blob).hexdigest()
    if actual != EXPECTED_SHA256:
        raise RuntimeError(
            f"shipped browser Argon2id digest mismatch: {actual}"
        )
    worker = WORKER.read_text(encoding="utf-8")
    matches = re.findall(r'const WASM_SHA256\s*=\s*\r?\n\s*"([0-9a-f]{64})"', worker)
    if matches != [EXPECTED_SHA256]:
        raise RuntimeError("worker does not pin the one reviewed WASM digest")


def _rebuild_and_compare() -> None:
    version = subprocess.run(
        ["rustc", "--version"],
        cwd=NATIVE,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not version.startswith(f"rustc {PINNED_RUSTC} "):
        raise RuntimeError(
            f"reproduction requires rustc {PINNED_RUSTC}; found {version!r}"
        )
    env = dict(os.environ)
    env["RUSTFLAGS"] = _remap_rustflags()
    subprocess.run(
        [
            "cargo", "build", "-p", "ol_argon2_wasm", "--target",
            "wasm32-unknown-unknown", "--release", "--locked",
        ],
        cwd=NATIVE,
        check=True,
        env=env,
    )
    built_digest = _canonical_digest(BUILT.read_bytes())
    shipped_digest = _canonical_digest(SHIPPED.read_bytes())
    if built_digest != shipped_digest:
        raise RuntimeError(
            "reproduced WASM differs from the shipped artifact "
            "(canonical path-spelling-invariant digests): "
            f"built={built_digest}, shipped={shipped_digest}, "
            f"built_raw={_digest(BUILT)}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="rebuild with pinned rustc and require byte-for-byte equality",
    )
    args = parser.parse_args(argv)
    try:
        _verify_static_contract()
        if args.rebuild:
            _rebuild_and_compare()
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"browser_argon2_wasm=FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "browser_argon2_wasm=PASS "
        f"sha256={EXPECTED_SHA256} rebuilt={str(args.rebuild).lower()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
