#!/usr/bin/env python3
"""Verify the shipped browser Ed25519 WASM and optionally reproduce it."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
SHIPPED = ROOT / "src/one_link/web/assets/ed25519-v1.wasm"
PEER_PAGE = ROOT / "src/one_link/web/peer.html"
BUILT = NATIVE / "target/wasm32-unknown-unknown/release/ol_ed25519_wasm.wasm"
EXPECTED_SHA256 = "99792408d50e1b920e99ab9e85095cf0f77f9933a30bcb81b63f7556b34f6cc0"
PINNED_RUSTC = "1.96.0"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify_static_contract() -> None:
    blob = SHIPPED.read_bytes()
    if not blob.startswith(b"\x00asm") or not 8 <= len(blob) <= 256 * 1024:
        raise RuntimeError("shipped browser Ed25519 artifact is not bounded WASM")
    actual = hashlib.sha256(blob).hexdigest()
    if actual != EXPECTED_SHA256:
        raise RuntimeError(f"shipped browser Ed25519 digest mismatch: {actual}")
    page = PEER_PAGE.read_text(encoding="utf-8")
    matches = re.findall(
        r'const ED25519_WASM_SHA256\s*=\s*\r?\n\s*"([0-9a-f]{64})"',
        page,
    )
    if matches != [EXPECTED_SHA256]:
        raise RuntimeError("peer page does not pin the one reviewed WASM digest")


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
    subprocess.run(
        [
            "cargo",
            "build",
            "-p",
            "ol_ed25519_wasm",
            "--target",
            "wasm32-unknown-unknown",
            "--release",
            "--locked",
        ],
        cwd=NATIVE,
        check=True,
    )
    built_digest = _digest(BUILT)
    shipped_digest = _digest(SHIPPED)
    if built_digest != shipped_digest:
        raise RuntimeError(
            "reproduced WASM differs from the shipped artifact: "
            f"built={built_digest}, shipped={shipped_digest}"
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
        print(f"browser_ed25519_wasm=FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "browser_ed25519_wasm=PASS "
        f"sha256={EXPECTED_SHA256} rebuilt={str(args.rebuild).lower()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
