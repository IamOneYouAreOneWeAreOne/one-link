"""v0.20.7 audit M25: bundled native CDC binary integrity check.

Pins:
  - Correct sidecar → verify True.
  - Tampered sidecar (wrong hash) → verify False + log warning.
  - Tampered binary (sidecar matches a different hash) → verify False.
  - Missing sidecar → fail closed.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import one_link.native_cdc as native_cdc
from one_link.native_cdc import (
    _compile_command,
    _verify_bundled_library,
    get_native_cdc_scanner,
    native_cdc_status,
    validate_native_cdc_library,
)


def test_windows_gnu_native_cdc_link_omits_wall_clock_timestamp(tmp_path):
    command = _compile_command(
        "gcc.exe",
        tmp_path / "scanner.c",
        tmp_path / "scanner.dll",
        target_os_name="nt",
    )
    assert "-Wl,--no-insert-timestamp" in command
    assert "-Wl,--image-base,0x180000000" in command
    assert "-fPIC" not in command


def test_windows_msvc_native_cdc_link_is_reproducible(tmp_path):
    command = _compile_command(
        "cl.exe",
        tmp_path / "scanner.c",
        tmp_path / "scanner.dll",
        target_os_name="nt",
    )
    assert command[-2:] == ["/link", "/Brepro"]


def test_windows_msvc_target_clang_uses_lld_link_switches(tmp_path, monkeypatch):
    """An msvc-triple clang drives lld-link, which parses GNU ld switches as
    input files (`could not open '0x180000000'`) — it must receive the
    /Brepro + /base equivalents instead."""
    monkeypatch.setattr(native_cdc, "_clang_targets_msvc", lambda _c: True)
    command = _compile_command(
        "clang.exe",
        tmp_path / "scanner.c",
        tmp_path / "scanner.dll",
        target_os_name="nt",
    )
    assert "-Wl,/Brepro" in command
    assert "-Wl,/base:0x180000000" in command
    assert "-Wl,--no-insert-timestamp" not in command
    assert "-Wl,--image-base,0x180000000" not in command


def test_windows_gnu_target_clang_keeps_gnu_ld_switches(tmp_path, monkeypatch):
    monkeypatch.setattr(native_cdc, "_clang_targets_msvc", lambda _c: False)
    command = _compile_command(
        "clang.exe",
        tmp_path / "scanner.c",
        tmp_path / "scanner.dll",
        target_os_name="nt",
    )
    assert "-Wl,--no-insert-timestamp" in command
    assert "-Wl,--image-base,0x180000000" in command


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


def test_verify_missing_sidecar_fails_closed(tmp_path):
    """A frozen/native payload without its binding is never trusted."""
    dll = tmp_path / "ol_native_cdc.dll"
    dll.write_bytes(b"PAYLOAD")
    # No sidecar written.
    assert _verify_bundled_library(dll) is False


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


@pytest.mark.parametrize("variant", ["single_space", "uppercase", "missing_newline"])
def test_verify_sidecar_requires_exact_canonical_format(tmp_path, variant):
    dll = tmp_path / "ol_native_cdc.dll"
    dll.write_bytes(b"PAYLOAD")
    digest = hashlib.sha256(dll.read_bytes()).hexdigest()
    if variant == "single_space":
        payload = f"{digest} {dll.name}\n"
    elif variant == "uppercase":
        payload = f"{digest.upper()}  {dll.name}\n"
    else:
        payload = f"{digest}  {dll.name}"
    dll.with_suffix(dll.suffix + ".sha256").write_text(payload, encoding="ascii")
    assert _verify_bundled_library(dll) is False


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


def test_available_native_cdc_passes_direct_abi_known_vector():
    scanner = get_native_cdc_scanner()
    if scanner is None:
        pytest.skip(f"native CDC unavailable: {native_cdc_status().reason}")
    validate_native_cdc_library(Path(scanner.library))


def test_macos_bundle_sidecar_is_resolved_from_resources(tmp_path, monkeypatch):
    app = tmp_path / "one-link.app" / "Contents"
    executable = app / "MacOS" / "one-link"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"launcher")
    platform_tag = "darwin-arm64"
    library_name = "ol_native_cdc.dylib"
    library = app / "Frameworks" / "one_link" / "native" / platform_tag / library_name
    library.parent.mkdir(parents=True)
    library.write_bytes(b"native-library")
    sidecar = (
        app
        / "Resources"
        / "one_link"
        / "native"
        / platform_tag
        / f"{library_name}.sha256"
    )
    sidecar.parent.mkdir(parents=True)
    sidecar.write_text("0" * 64 + f"  {library_name}\n", encoding="ascii")

    monkeypatch.setattr(native_cdc.sys, "executable", str(executable))
    monkeypatch.setattr(native_cdc, "native_platform_tag", lambda: platform_tag)
    monkeypatch.setattr(native_cdc, "native_library_name", lambda: library_name)

    assert native_cdc._bundled_sidecar_path(library) == sidecar
