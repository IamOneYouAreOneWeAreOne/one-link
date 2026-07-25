"""Supply-chain and downgrade contracts for browser identity Argon2id."""

from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PEER = ROOT / "src/one_link/web/peer.html"
WORKER = ROOT / "src/one_link/web/assets/argon2id-worker.js"
WASM = ROOT / "src/one_link/web/assets/argon2id-v1.wasm"


def test_wasm_is_exact_first_party_release_artifact() -> None:
    blob = WASM.read_bytes()
    assert blob.startswith(b"\x00asm")
    assert 8 <= len(blob) <= 128 * 1024
    digest = hashlib.sha256(blob).hexdigest()
    assert digest == "8fac36bd917280333cd7ca4bcc262b1733ed120035507008b09c0c3f1f172505"
    assert digest in WORKER.read_text(encoding="utf-8")


def test_worker_rejects_parameters_before_wasm_allocation() -> None:
    src = WORKER.read_text(encoding="utf-8")
    profile_check = src.index("if (data.abiVersion !== ABI_VERSION")
    load = src.index("exports = await loadModule()")
    allocate = src.index("passwordPtr = exports.ol_argon2id_alloc")
    assert profile_check < load < allocate
    assert "const MEMORY_KIB = 256 * 1024" in src
    assert "const TIME_COST = 3" in src
    assert "const PARALLELISM = 1" in src
    assert "const MAX_PASSWORD_BYTES = 1024" in src
    assert "exactKeys(data" in src


def test_worker_integrity_self_test_and_zeroization_are_mandatory() -> None:
    src = WORKER.read_text(encoding="utf-8")
    for required in (
        'crypto.subtle.digest("SHA-256", bytes)',
        "exports.ol_argon2id_self_test() !== 0",
        'fail("wasm_zeroization")',
        "exports.ol_argon2id_zero(outputPtr, OUTPUT_LEN)",
        "password.fill(0)",
        "salt.fill(0)",
        "exports.ol_argon2id_free",
    ):
        assert required in src


def test_v2_envelope_authenticates_public_header_as_aad() -> None:
    src = PEER.read_text(encoding="utf-8")
    aad = src[src.index("function _identityEnvelopeAad"):]
    aad = aad[: aad.index("async function _wrapIdentityV2")]
    for field in (
        "aad_v", "cipher", "created_ms", "fingerprint", "iv_b64u", "kdf",
        "kdf_memory_kib", "kdf_parallelism", "kdf_salt_b64u",
        "kdf_time_cost", "public_key_b64u", "v", "wrapped", "wrapped_ms",
    ):
        assert f"{field}: envelope.{field}" in aad
    wrap = src[src.index("async function _wrapIdentityV2"):]
    unwrap = src[src.index("async function _unwrapArgonIdentity"):]
    assert "additionalData: _identityEnvelopeAad(envelope)" in wrap[:5000]
    assert "additionalData: _identityEnvelopeAad(envelope)" in unwrap[:1800]


def test_rust_argon_profile_is_pinned_and_matrix_is_zeroized() -> None:
    manifest = (ROOT / "native/ol_argon2_wasm/Cargo.toml").read_text(
        encoding="utf-8"
    )
    source = (ROOT / "native/ol_argon2_wasm/src/lib.rs").read_text(
        encoding="utf-8"
    )
    lock = (ROOT / "native/Cargo.lock").read_text(encoding="utf-8")
    assert 'argon2 = { version = "=0.5.3"' in manifest
    assert 'name = "argon2"\nversion = "0.5.3"' in lock
    assert "Zeroizing::new(vec![Block::default(); block_count])" in source
    assert "Params::new(memory_kib, time_cost, parallelism" in source
    assert "memory_kib != MEMORY_KIB" in source
    assert "time_cost != TIME_COST" in source
    assert "parallelism != PARALLELISM" in source
    assert "ol_argon2id_self_test" in source


def test_new_identity_persistence_has_no_plaintext_downgrade() -> None:
    src = PEER.read_text(encoding="utf-8")
    write = src[src.index("async function writeIdentity(rec)"):]
    write = write[: write.index("function _sameIdentityAuthority")]
    assert "if (!isWrappedEnvelope(rec))" in write
    assert "_writeIdentityUnlocked(rec)" in write
    assert 'id="btn-remove-passphrase"' not in src
    loader = src[src.index("async function _loadOrCreateIdentity()"):]
    loader = loader[: loader.index("function _showIdentityStorageFailure")]
    assert "const rec = await generateIdentity()" in loader
    assert "_writeIdentityUnlocked(rec)" not in loader


def test_repository_wasm_verifier_passes_without_mutation() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/verify_browser_argon2_wasm.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "browser_argon2_wasm=PASS" in result.stdout
