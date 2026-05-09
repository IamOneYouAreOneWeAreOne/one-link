"""v0.20.7 audit M25: bundled native CDC binary integrity check.

Pins:
  - Correct sidecar → verify True.
  - Tampered sidecar (wrong hash) → verify False + log warning.
  - Tampered binary (sidecar matches a different hash) → verify False.
  - Missing sidecar → verify True (backward compat for older builds).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from one_link.native_cdc import _verify_bundled_library


def _write_sidecar(dll_path: Path, hex_hash: str) -> None:
    sidecar = dll_path.with_suffix(dll_path.suffix + ".sha256")
    sidecar.write_text(f"{hex_hash}  {dll_path.name}\n", encoding="ascii")


def test_verify_round_trip(tmp_path):
    dll = tmp_path / "ol_native_cdc.dll"
    payload = b"FAKE_DLL_BYTES_FOR_TEST_ONLY_NOT_A_REAL_BINARY"
    dll.write_bytes(payload)
    h = hashlib.sha256(payload).hexdigest()
    _write_sidecar(dll, h)
    assert _verify_bundled_library(dll) is True


def test_verify_tampered_sidecar_rejects(tmp_path):
    dll = tmp_path / "ol_native_cdc.dll"
    dll.write_bytes(b"PAYLOAD")
    _write_sidecar(dll, "0" * 64)
    assert _verify_bundled_library(dll) is False


def test_verify_tampered_binary_rejects(tmp_path):
    dll = tmp_path / "ol_native_cdc.dll"
    real_payload = b"PAYLOAD"
    dll.write_bytes(real_payload)
    _write_sidecar(dll, hashlib.sha256(real_payload).hexdigest())
    # Now swap the binary for a malicious one without updating the
    # sidecar. The integrity check must catch this.
    dll.write_bytes(b"MALICIOUS_REPLACEMENT_DLL_WITH_DIFFERENT_HASH")
    assert _verify_bundled_library(dll) is False


def test_verify_missing_sidecar_passes_backward_compat(tmp_path):
    """Builds older than v0.20.7 didn't ship the .sha256 sidecar.
    Treating a missing sidecar as "trust the binary" preserves
    behavior for those older bundles. New bundled releases MUST
    ship the sidecar; the build tooling is responsible for that."""
    dll = tmp_path / "ol_native_cdc.dll"
    dll.write_bytes(b"PAYLOAD")
    # No sidecar written.
    assert _verify_bundled_library(dll) is True


def test_verify_malformed_sidecar_rejects(tmp_path):
    """A sidecar that's not parseable as 64 hex chars + trailing
    name is rejected. Defends against an attacker who tries to
    blank the sidecar (write empty / write garbage)."""
    dll = tmp_path / "ol_native_cdc.dll"
    dll.write_bytes(b"PAYLOAD")
    sidecar = dll.with_suffix(dll.suffix + ".sha256")
    for malformed in ("", "   ", "not-a-hash", "abcd", "z" * 64):
        sidecar.write_text(malformed, encoding="ascii")
        assert _verify_bundled_library(dll) is False, (
            f"malformed sidecar {malformed!r} should reject"
        )


def test_bundled_dll_passes_self_check_in_repo():
    """The bundled Windows DLL shipped in this repo must verify
    against its own sidecar — pins the build pipeline to keep
    them in sync."""
    repo_root = Path(__file__).resolve().parent.parent
    dll = repo_root / "src" / "one_link" / "native" / "windows-x86_64" / "ol_native_cdc.dll"
    if not dll.is_file():
        pytest.skip("no bundled Windows DLL on this checkout")
    sidecar = dll.with_suffix(dll.suffix + ".sha256")
    assert sidecar.is_file(), (
        f"bundled DLL is missing the sha256 sidecar at {sidecar}"
    )
    assert _verify_bundled_library(dll) is True, (
        "bundled DLL doesn't match its own sha256 sidecar — "
        "build pipeline is broken"
    )
