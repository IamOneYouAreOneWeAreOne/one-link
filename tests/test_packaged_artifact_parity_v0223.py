"""Packaged artifact parity gate.

The stale-tarball failure mode is simple: source contains the fix, but
the binary/tarball people test or download was built earlier or without
dynamic modules/package data. These tests pin the release-side validator
that catches that before a public artifact goes out.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).resolve().parent.parent
    / "scripts" / "validate_packaged_artifact.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "validate_packaged_artifact", SCRIPT,
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _good_spec() -> str:
    return "\n".join([
        "datas = [('src/one_link/web', 'one_link/web'), "
        "('src/one_link/data', 'one_link/data')]",
        "hiddenimports = ['one_link.sessions', 'one_link.recovery_api']",
        "_d, _b, _h = collect_all('one_link_native')",
    ])


def test_validator_script_imports_cleanly():
    mod = _load_module()
    assert callable(mod.main)
    assert callable(mod.validate_spec)


def test_validate_spec_requires_dynamic_imports_and_package_data(tmp_path):
    mod = _load_module()
    spec = tmp_path / "one-link.spec"
    spec.write_text(_good_spec(), encoding="utf-8")
    checks = mod.validate_spec(spec)
    assert any("one_link.sessions" in c for c in checks)
    assert any("one_link/data" in c for c in checks)


def test_validate_spec_rejects_missing_recovery_api(tmp_path):
    mod = _load_module()
    spec = tmp_path / "one-link.spec"
    spec.write_text(
        _good_spec().replace(", 'one_link.recovery_api'", ""),
        encoding="utf-8",
    )
    with pytest.raises(mod.GateFailure, match="one_link.recovery_api"):
        mod.validate_spec(spec)


def test_validate_spec_rejects_missing_package_data(tmp_path):
    mod = _load_module()
    spec = tmp_path / "one-link.spec"
    spec.write_text(
        _good_spec().replace("('src/one_link/data', 'one_link/data')", ""),
        encoding="utf-8",
    )
    with pytest.raises(mod.GateFailure, match="one_link/data"):
        mod.validate_spec(spec)


def test_validate_version_rejects_stale_binary_output(tmp_path, monkeypatch):
    mod = _load_module()
    exe = tmp_path / ("one-link.exe" if sys.platform == "win32" else "one-link")
    exe.write_text("fake", encoding="utf-8")

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["one-link", "--version"],
            returncode=0,
            stdout="one-link, version 0.20.0",
            stderr="",
        )

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    with pytest.raises(mod.GateFailure, match="packaged version mismatch"):
        mod.validate_version(exe, "0.21.0-alpha")


def test_validate_version_accepts_current_binary_output(tmp_path, monkeypatch):
    mod = _load_module()
    exe = tmp_path / ("one-link.exe" if sys.platform == "win32" else "one-link")
    exe.write_text("fake", encoding="utf-8")

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["one-link", "--version"],
            returncode=0,
            stdout="one-link, version 0.21.0-alpha",
            stderr="",
        )

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    assert "0.21.0-alpha" in mod.validate_version(exe, "0.21.0-alpha")


def test_validate_peer_headers_accepts_current_phone_shell_markers(monkeypatch):
    mod = _load_module()
    body = (
        b"<title>One Link -- Peer</title>"
        b"daemon-global-search-input"
        b"setup_device_invite"
        b"cert-authed reconnect"
    )

    monkeypatch.setattr(
        mod,
        "_request",
        lambda *_a, **_kw: (
            200,
            {
                "cache-control": "no-cache, must-revalidate",
                "etag": '"abc"',
            },
            body,
        ),
    )
    assert "ETag" in mod.validate_peer_headers("https://127.0.0.1:7118", None)


def test_validate_peer_headers_rejects_stale_phone_shell(monkeypatch):
    mod = _load_module()
    monkeypatch.setattr(
        mod,
        "_request",
        lambda *_a, **_kw: (
            200,
            {
                "cache-control": "no-cache, must-revalidate",
                "etag": '"abc"',
            },
            b"<title>One Link -- Peer</title>",
        ),
    )
    with pytest.raises(mod.GateFailure, match="daemon-global-search-input"):
        mod.validate_peer_headers("https://127.0.0.1:7118", None)


def test_cli_static_gate_passes_with_skip_version(tmp_path, capsys):
    mod = _load_module()
    spec = tmp_path / "one-link.spec"
    spec.write_text(_good_spec(), encoding="utf-8")
    exe = tmp_path / ("one-link.exe" if sys.platform == "win32" else "one-link")
    exe.write_text("fake", encoding="utf-8")
    rc = mod.main([
        "--artifact", str(exe),
        "--spec", str(spec),
        "--skip-version",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "PACKAGED ARTIFACT PARITY: PASS" in out


def test_cli_fails_when_spec_missing_dynamic_import(tmp_path, capsys):
    mod = _load_module()
    spec = tmp_path / "one-link.spec"
    spec.write_text("hiddenimports = []\n", encoding="utf-8")
    exe = tmp_path / ("one-link.exe" if sys.platform == "win32" else "one-link")
    exe.write_text("fake", encoding="utf-8")
    rc = mod.main([
        "--artifact", str(exe),
        "--spec", str(spec),
        "--skip-version",
    ])
    err = capsys.readouterr().err
    assert rc == 1
    assert "one_link.sessions" in err
    assert "one_link.recovery_api" in err


def test_live_probe_functions_are_called_when_base_url_supplied(
    tmp_path, monkeypatch, capsys,
):
    mod = _load_module()
    spec = tmp_path / "one-link.spec"
    spec.write_text(_good_spec(), encoding="utf-8")
    exe = tmp_path / ("one-link.exe" if sys.platform == "win32" else "one-link")
    exe.write_text("fake", encoding="utf-8")
    called: list[str] = []

    monkeypatch.setattr(mod, "validate_peer_headers", lambda *_a: called.append("peer") or "peer ok")
    monkeypatch.setattr(mod, "validate_recovery_routes", lambda *_a: called.append("recovery") or "recovery ok")
    monkeypatch.setattr(mod, "validate_alpn", lambda *_a: called.append("alpn") or "alpn ok")
    monkeypatch.setattr(mod, "validate_cert_chain_with_openssl", lambda *_a: called.append("chain") or "chain ok")

    rc = mod.main([
        "--artifact", str(exe),
        "--spec", str(spec),
        "--skip-version",
        "--base-url", "https://127.0.0.1:7118",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert called == ["peer", "recovery", "alpn", "chain"]
    assert "chain ok" in out


def test_cert_chain_probe_falls_back_to_python_ssl(monkeypatch):
    mod = _load_module()
    called: list[tuple[str, int]] = []

    def fake_run(*_args, **_kwargs):
        raise FileNotFoundError("openssl")

    def fake_python_ssl(host, port, cacert):
        called.append((host, port))
        return "TLS serves a chain with 2 certificates"

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod, "_validate_cert_chain_with_python_ssl", fake_python_ssl)
    out = mod.validate_cert_chain_with_openssl("https://127.0.0.1:7118", None)
    assert out == "TLS serves a chain with 2 certificates"
    assert called == [("127.0.0.1", 7118)]
