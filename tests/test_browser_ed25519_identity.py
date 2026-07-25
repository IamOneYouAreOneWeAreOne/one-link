"""Supply-chain and fail-closed contracts for browser Ed25519 fallback."""

from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PEER = ROOT / "src/one_link/web/peer.html"
MANIFEST = ROOT / "native/ol_ed25519_wasm/Cargo.toml"
RUST = ROOT / "native/ol_ed25519_wasm/src/lib.rs"
WASM = ROOT / "src/one_link/web/assets/ed25519-v1.wasm"
DIGEST = "99792408d50e1b920e99ab9e85095cf0f77f9933a30bcb81b63f7556b34f6cc0"


def test_wasm_is_exact_integrity_pinned_first_party_artifact() -> None:
    blob = WASM.read_bytes()
    assert blob.startswith(b"\x00asm")
    assert 8 <= len(blob) <= 256 * 1024
    assert hashlib.sha256(blob).hexdigest() == DIGEST
    page = PEER.read_text(encoding="utf-8")
    assert page.count(DIGEST) == 1
    assert 'const ED25519_WASM_URL = "/browser-crypto/ed25519-v1.wasm"' in page


def test_rustcrypto_version_abi_vectors_bounds_and_zeroization_are_pinned() -> None:
    manifest = MANIFEST.read_text(encoding="utf-8")
    source = RUST.read_text(encoding="utf-8")
    lock = (ROOT / "native/Cargo.lock").read_text(encoding="utf-8")
    assert 'ed25519-dalek = { version = "=2.2.0"' in manifest
    assert 'name = "ed25519-dalek"\nversion = "2.2.0"' in lock
    for required in (
        "pub const ABI_VERSION: u32 = 1",
        "pub const MAX_MESSAGE_LEN: usize = 1024 * 1024",
        "ol_ed25519_self_test",
        "RFC 8032 test vector 1",
        "verify_strict",
        "!key.is_weak()",
        "buffer.zeroize()",
        "let mut seed = Zeroizing::new",
    ):
        assert required in source


def test_browser_loader_checks_digest_abi_exports_and_self_test_before_use() -> None:
    source = PEER.read_text(encoding="utf-8")
    loader = source[source.index("async function _loadEd25519Wasm") :]
    loader = loader[: loader.index("function _copyBoundedBytes")]
    integrity = loader.index('crypto.subtle.digest("SHA-256", bytes)')
    instantiate = loader.index("WebAssembly.instantiate(bytes, {})")
    self_test = loader.index("exports.ol_ed25519_self_test() !== 0")
    assert integrity < instantiate < self_test
    for export in (
        "ol_ed25519_abi_version",
        "ol_ed25519_zero_and_free",
        "ol_ed25519_public_from_seed",
        "ol_ed25519_validate_public",
        "ol_ed25519_sign",
        "ol_ed25519_verify",
    ):
        assert f'"{export}"' in loader


def test_native_crypto_errors_do_not_silently_downgrade_to_fallback() -> None:
    source = PEER.read_text(encoding="utf-8")
    assert 'if (!_isEd25519Unsupported(error)) throw error;' in source
    detector = source[source.index("function _isEd25519Unsupported") :]
    detector = detector[: detector.index("async function _loadEd25519Wasm")]
    assert 'error.name === "NotSupportedError"' in detector
    assert 'error.name === "OperationError"' in detector
    assert "return true" not in detector.split("if (!error", 1)[0]


def test_private_seed_and_wasm_bridge_buffers_are_wiped() -> None:
    source = PEER.read_text(encoding="utf-8")
    for required in (
        "seed.fill(0)",
        "privateSeed.fill(0)",
        "signature.fill(0)",
        "message.fill(0)",
        "exports.ol_ed25519_zero_and_free",
    ):
        assert required in source


def test_repository_wasm_verifier_passes_without_mutation() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/verify_browser_ed25519_wasm.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "browser_ed25519_wasm=PASS" in result.stdout
