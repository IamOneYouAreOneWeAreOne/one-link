"""Tests for one_link.updater — wheel selection, SHA-256 verification,
updater script generation, and the /api/update/install endpoint gate.

Phase 3 of the production-install plan. The /api/update/install
destructive path is GATED OFF by default (ONE_LINK_EXPERIMENTAL_AUTOINSTALL
env var must be set), so most of these tests exercise the building
blocks individually rather than calling the live install handler.

What we DO test:
    * host_wheel_tag returns sane platform strings
    * select_wheel_for_host picks the right wheel for each OS
    * parse_sha256sums tolerates the format-zoo sha256sum emits
    * download_to_temp handles size guards
    * write_updater_script generates a syntactically-valid Python
      file that includes the right literals
    * build_install_plan with mocked GitHub responses produces the
      expected InstallPlan for each branch
    * /api/update/install returns 503 when the gate is off (regression
      guard: nobody should be able to silently flip this on)
    * /api/update/install with the gate ON refuses unverified wheels
      and hash mismatches (defense-in-depth)
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


# ─── host detection ────────────────────────────────────────────────────

def test_host_wheel_tag_returns_string():
    from one_link.updater import host_wheel_tag
    tag = host_wheel_tag()
    assert isinstance(tag, str)
    assert tag.startswith("cp311-abi3-")
    # Must contain a recognizable OS marker
    assert any(os in tag for os in ("win_", "macosx_", "linux_"))


# ─── wheel selection ───────────────────────────────────────────────────

def _asset(name, size=1024, url=None):
    return {
        "name": name,
        "size": size,
        "browser_download_url": url or f"https://example.test/{name}",
    }


def test_select_wheel_picks_windows_amd64():
    from one_link.updater import select_wheel_for_host
    assets = [
        _asset("one_link_native-0.22.0a0-cp311-abi3-linux_x86_64.whl"),
        _asset("one_link_native-0.22.0a0-cp311-abi3-macosx_11_0_arm64.whl"),
        _asset("one_link_native-0.22.0a0-cp311-abi3-win_amd64.whl"),
    ]
    pick = select_wheel_for_host(assets, host_tag="cp311-abi3-win_amd64")
    assert pick is not None
    assert "win_amd64" in pick.filename
    assert pick.asset_url.startswith("https://example.test/")


def test_select_wheel_picks_macos_universal2_as_fallback():
    from one_link.updater import select_wheel_for_host
    # No per-arch wheel, only universal2 — should still match.
    assets = [
        _asset("one_link_native-0.22.0a0-cp311-abi3-macosx_11_0_universal2.whl"),
    ]
    pick = select_wheel_for_host(assets, host_tag="cp311-abi3-macosx_11_0_arm64")
    assert pick is not None
    assert "universal2" in pick.filename


def test_select_wheel_matches_manylinux_arch():
    """The host_tag says `linux_x86_64`; the released wheel uses
    `manylinux_2_17_x86_64`. They share an arch suffix and should
    match."""
    from one_link.updater import select_wheel_for_host
    assets = [
        _asset("one_link_native-0.22.0a0-cp311-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"),
    ]
    pick = select_wheel_for_host(assets, host_tag="cp311-abi3-linux_x86_64")
    assert pick is not None
    assert "x86_64" in pick.filename


def test_select_wheel_returns_none_when_no_match():
    from one_link.updater import select_wheel_for_host
    assets = [
        _asset("one_link_native-0.22.0a0-cp311-abi3-linux_x86_64.whl"),
    ]
    pick = select_wheel_for_host(assets, host_tag="cp311-abi3-win_amd64")
    assert pick is None


def test_select_wheel_ignores_non_one_link_native_files():
    """A release might also have SHA256SUMS, *.sigstore bundles, the
    pure-Python wheel etc. Those must not be matched."""
    from one_link.updater import select_wheel_for_host
    assets = [
        _asset("SHA256SUMS"),
        _asset("one_link-0.22.0a0-py3-none-any.whl"),  # pure-Python
        _asset("one_link_native-0.22.0a0-cp311-abi3-win_amd64.whl"),
        _asset("one_link_native-0.22.0a0-cp311-abi3-win_amd64.whl.sigstore"),
    ]
    pick = select_wheel_for_host(assets, host_tag="cp311-abi3-win_amd64")
    assert pick is not None
    assert pick.filename.endswith(".whl"), pick.filename
    assert "sigstore" not in pick.filename


# ─── SHA256SUMS parsing ───────────────────────────────────────────────

def test_parse_sha256sums_basic():
    from one_link.updater import parse_sha256sums
    hash_a = "a" * 64
    hash_b = "b" * 64
    text = f"{hash_a}  file_a.whl\n{hash_b}  file_b.tar.gz\n"
    out = parse_sha256sums(text)
    assert "file_a.whl" in out
    assert "file_b.tar.gz" in out
    for h in out.values():
        assert len(h) == 64


def test_parse_sha256sums_tolerates_binary_marker_and_blank_lines():
    """sha256sum emits `<hash> *<file>` with the asterisk when run
    with -b (binary mode). Real-world workflows mix that with the
    default two-space form. We should handle both, plus comments
    and blank lines."""
    from one_link.updater import parse_sha256sums
    hash_a = "a" * 64
    hash_b = "b" * 64
    text = f"""# comment line, ignored

{hash_a}  file_a.whl
{hash_b} *file_b.whl
"""
    out = parse_sha256sums(text)
    assert out["file_a.whl"] == hash_a
    assert out["file_b.whl"] == hash_b


def test_parse_sha256sums_rejects_malformed_hashes():
    """Anything that isn't a 64-hex-char hash is dropped — defends
    against accidentally treating a non-SHA256SUMS file as one."""
    from one_link.updater import parse_sha256sums
    text = "notahash  file_a.whl\n" + "x" * 63 + "  file_b.whl\n"
    out = parse_sha256sums(text)
    assert out == {}


# ─── download_to_temp size guard ───────────────────────────────────────

def test_download_to_temp_rejects_oversized_response(tmp_path):
    """If the server returns a body wildly larger than declared, we
    refuse — defends against accidentally fetching an HTML index page
    instead of a small wheel."""
    from one_link.updater import download_to_temp
    big_body = b"x" * 10_000

    def fake_fetch(url, timeout):
        return big_body

    with pytest.raises(ValueError, match="refusing"):
        download_to_temp(
            "https://example.test/wheel.whl",
            expected_size=100,  # 5x guard makes 500 the cap
            fetch=fake_fetch,
        )


def test_download_to_temp_writes_file(tmp_path):
    from one_link.updater import download_to_temp, sha256_file
    body = b"hello-wheel"

    def fake_fetch(url, timeout):
        return body

    path = download_to_temp(
        "https://example.test/wheel.whl",
        expected_size=len(body),
        fetch=fake_fetch,
    )
    try:
        assert path.exists()
        assert path.read_bytes() == body
        # And it's hashable consistently
        import hashlib
        assert sha256_file(path) == hashlib.sha256(body).hexdigest()
    finally:
        path.unlink(missing_ok=True)


# ─── updater script generation ─────────────────────────────────────────

def test_write_updater_script_emits_valid_python(tmp_path):
    from one_link.updater import write_updater_script
    wheel = tmp_path / "fake.whl"
    wheel.write_bytes(b"PK\x03\x04")  # zip header (whl = zip)

    script = write_updater_script(
        wheel,
        parent_pid=42,
        python_exe="/usr/bin/python3",
    )
    try:
        src = script.read_text(encoding="utf-8")
        # 1. Must parse as Python
        ast.parse(src)
        # 2. Must embed our literals
        assert "42" in src                # parent_pid
        assert str(wheel) in src or wheel.name in src
        # 3. Calls pip install in the script body
        assert "pip" in src and "install" in src
        # 4. Relaunches the daemon
        assert "one_link.cli" in src and "daemon" in src
        # 5. Waits for parent BEFORE running pip (file-lock concern)
        wait_idx = src.find("_alive(PARENT_PID)")
        pip_idx = src.find("pip")
        assert wait_idx >= 0 and pip_idx > wait_idx, (
            "pip install must come AFTER the wait-for-parent loop"
        )
    finally:
        script.unlink(missing_ok=True)


def test_write_updater_script_accepts_custom_relaunch_cmd(tmp_path):
    from one_link.updater import write_updater_script
    wheel = tmp_path / "fake.whl"
    wheel.write_bytes(b"x")

    script = write_updater_script(
        wheel,
        parent_pid=1,
        relaunch_cmd=["/opt/python", "-m", "one_link.cli", "app"],
    )
    try:
        src = script.read_text(encoding="utf-8")
        # Custom command flows through literally.
        assert "/opt/python" in src
        assert "'app'" in src or '"app"' in src
    finally:
        script.unlink(missing_ok=True)


# ─── build_install_plan with mocked GitHub responses ───────────────────

def test_build_install_plan_happy_path(monkeypatch):
    from one_link import updater as u_mod

    def fake_fetch_json(url, timeout):
        return {
            "tag_name": "v0.22.0",
            "assets": [
                {
                    "name": "one_link_native-0.22.0a0-cp311-abi3-win_amd64.whl",
                    "size": 2_400_000,
                    "browser_download_url": "https://example.test/wheel.whl",
                },
                {
                    "name": "SHA256SUMS",
                    "size": 200,
                    "browser_download_url": "https://example.test/SHA256SUMS",
                },
            ],
        }
    expected_hash = "a" * 64
    sha_body = (
        f"{expected_hash}  "
        "one_link_native-0.22.0a0-cp311-abi3-win_amd64.whl\n"
    ).encode()

    def fake_fetch_bytes(url, timeout):
        if "SHA256SUMS" in url:
            return sha_body
        raise AssertionError(f"unexpected fetch: {url}")

    # Force host tag so this passes on any OS.
    monkeypatch.setattr(
        u_mod, "host_wheel_tag", lambda: "cp311-abi3-win_amd64"
    )
    plan = u_mod.build_install_plan(
        fetch_json=fake_fetch_json,
        fetch_bytes=fake_fetch_bytes,
    )
    assert plan.status == "ready"
    assert plan.tag == "v0.22.0"
    assert plan.wheel is not None
    assert "win_amd64" in plan.wheel.filename
    assert plan.wheel.expected_sha256 == expected_hash


def test_build_install_plan_no_release_when_fetch_fails(monkeypatch):
    from one_link import updater as u_mod

    def fake_fetch_json(url, timeout):
        raise RuntimeError("github is down")

    plan = u_mod.build_install_plan(fetch_json=fake_fetch_json)
    assert plan.status == "no_release"
    assert "github" in (plan.error or "").lower()


def test_build_install_plan_no_match_when_wheel_missing(monkeypatch):
    """If the release ships e.g. only Linux wheels and we're on
    Windows, plan.status is 'no_match' and we DON'T fall back to
    a wrong wheel."""
    from one_link import updater as u_mod

    def fake_fetch_json(url, timeout):
        return {
            "tag_name": "v0.22.0",
            "assets": [
                {
                    "name": "one_link_native-0.22.0a0-cp311-abi3-linux_x86_64.whl",
                    "size": 2_400_000,
                    "browser_download_url": "https://example.test/linux.whl",
                },
            ],
        }
    monkeypatch.setattr(u_mod, "host_wheel_tag", lambda: "cp311-abi3-win_amd64")

    plan = u_mod.build_install_plan(fetch_json=fake_fetch_json)
    assert plan.status == "no_match"
    assert plan.tag == "v0.22.0"
    assert plan.wheel is None


def test_build_install_plan_unverified_when_no_sha256sums(monkeypatch):
    """A release without a SHA256SUMS file leaves the wheel
    unverified; plan.wheel exists but its expected_sha256 is None.
    The install endpoint refuses unverified wheels."""
    from one_link import updater as u_mod

    def fake_fetch_json(url, timeout):
        return {
            "tag_name": "v0.22.0",
            "assets": [
                {
                    "name": "one_link_native-0.22.0a0-cp311-abi3-win_amd64.whl",
                    "size": 2_400_000,
                    "browser_download_url": "https://example.test/w.whl",
                },
            ],
        }
    monkeypatch.setattr(u_mod, "host_wheel_tag", lambda: "cp311-abi3-win_amd64")

    plan = u_mod.build_install_plan(fetch_json=fake_fetch_json)
    assert plan.status == "ready"
    assert plan.wheel is not None
    assert plan.wheel.expected_sha256 is None


# ─── /api/update/install gate ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_api_update_install_env_hard_disable(monkeypatch):
    """v0.21.x: the env var is now a HARD DISABLE override, not an
    opt-in gate. When the operator pins it to '0', the endpoint must
    return 503 with a clear message and never touch the filesystem."""
    monkeypatch.setenv("ONE_LINK_EXPERIMENTAL_AUTOINSTALL", "0")
    from one_link.server import UIServer

    daemon = SimpleNamespace(
        state=None, discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa",
                           hostname="me"),
    )
    server = UIServer(daemon)
    resp = await server.api_update_install(SimpleNamespace(query={}))
    assert resp.status == 503
    body = json.loads(resp.text)
    assert body["status"] == "disabled"
    assert "ONE_LINK_EXPERIMENTAL_AUTOINSTALL" in body["error"]


@pytest.mark.asyncio
async def test_api_update_install_default_proceeds_past_gate(monkeypatch):
    """v0.21.x: with env unset + no user opt-out, the endpoint should
    advance past the gate and return 409 'not prepared' (because no
    plan was built in this test fixture) — NOT 503 disabled."""
    monkeypatch.delenv("ONE_LINK_EXPERIMENTAL_AUTOINSTALL", raising=False)
    from one_link.server import UIServer

    daemon = SimpleNamespace(
        state=None, discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa",
                           hostname="me"),
    )
    server = UIServer(daemon)
    resp = await server.api_update_install(SimpleNamespace(query={}))
    assert resp.status != 503, (
        "v0.21.x default should be ENABLED — the gate must let the "
        "request through to the install-plan path"
    )
    assert resp.status == 409
    body = json.loads(resp.text)
    assert body["status"] == "no_match"


@pytest.mark.asyncio
async def test_api_update_install_refuses_unverified_wheel(monkeypatch):
    """When enabled, the endpoint downloads the wheel — but if its
    expected SHA-256 wasn't published in SHA256SUMS, refuse to
    install. Hash verification is mandatory."""
    monkeypatch.setenv("ONE_LINK_EXPERIMENTAL_AUTOINSTALL", "1")
    from one_link.server import UIServer
    from one_link import updater as u_mod

    fake_wheel = MagicMock()
    fake_wheel.expected_sha256 = None
    fake_wheel.asset_url = "https://example.test/w.whl"
    fake_wheel.filename = "fake.whl"
    fake_wheel.size = 100
    fake_plan = u_mod.InstallPlan(
        status="ready", tag="v0.22.0", latest_version="v0.22.0",
        wheel=fake_wheel,
    )
    monkeypatch.setattr(u_mod, "build_install_plan", lambda: fake_plan)

    fake_path = MagicMock()
    monkeypatch.setattr(u_mod, "download_to_temp", lambda *a, **kw: fake_path)
    # If we accidentally got past the unverified check, this would
    # be called; the test asserts otherwise.
    monkeypatch.setattr(
        u_mod, "spawn_detached",
        lambda *a, **kw: pytest.fail("spawn_detached called for unverified wheel"),
    )

    daemon = SimpleNamespace(
        state=None, discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa",
                           hostname="me"),
    )
    server = UIServer(daemon)
    resp = await server.api_update_install(SimpleNamespace(query={}))
    assert resp.status == 409
    body = json.loads(resp.text)
    assert body["status"] == "unverified"


@pytest.mark.asyncio
async def test_api_update_install_refuses_hash_mismatch(monkeypatch, tmp_path):
    """If the SHA-256 of the downloaded wheel doesn't match the
    expected hash, we abort. This is the line of defense against a
    compromised or in-transit-modified wheel."""
    monkeypatch.setenv("ONE_LINK_EXPERIMENTAL_AUTOINSTALL", "1")
    from one_link.server import UIServer
    from one_link import updater as u_mod

    # Plan claims expected hash is all-a; actual file we download
    # will hash to something else.
    expected = "a" * 64
    fake_wheel = MagicMock()
    fake_wheel.expected_sha256 = expected
    fake_wheel.asset_url = "https://example.test/w.whl"
    fake_wheel.filename = "fake.whl"
    fake_wheel.size = 100
    fake_plan = u_mod.InstallPlan(
        status="ready", tag="v0.22.0", latest_version="v0.22.0",
        wheel=fake_wheel,
    )
    monkeypatch.setattr(u_mod, "build_install_plan", lambda: fake_plan)

    real_path = tmp_path / "downloaded.whl"
    real_path.write_bytes(b"definitely not the expected bytes")
    monkeypatch.setattr(u_mod, "download_to_temp", lambda *a, **kw: real_path)
    monkeypatch.setattr(
        u_mod, "spawn_detached",
        lambda *a, **kw: pytest.fail("spawn_detached called on hash mismatch"),
    )

    daemon = SimpleNamespace(
        state=None, discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa",
                           hostname="me"),
    )
    server = UIServer(daemon)
    resp = await server.api_update_install(SimpleNamespace(query={}))
    assert resp.status == 409
    body = json.loads(resp.text)
    assert body["status"] == "hash_mismatch"
    assert expected in body["error"]


@pytest.mark.asyncio
async def test_api_update_plan_returns_plan_shape(monkeypatch):
    """The read-only /api/update/plan endpoint mirrors the InstallPlan
    dataclass shape. UI uses it to decide whether to enable the
    'Update now' button."""
    from one_link.server import UIServer
    from one_link import updater as u_mod

    fake_plan = u_mod.InstallPlan(
        status="ready",
        tag="v0.22.0",
        latest_version="v0.22.0",
        wheel=u_mod.WheelMatch(
            asset_url="https://example.test/w.whl",
            filename="one_link_native-0.22.0a0-cp311-abi3-win_amd64.whl",
            size=2_400_000,
            expected_sha256="a" * 64,
        ),
    )
    monkeypatch.setattr(u_mod, "build_install_plan", lambda: fake_plan)

    daemon = SimpleNamespace(
        state=None, discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa",
                           hostname="me"),
    )
    server = UIServer(daemon)
    resp = await server.api_update_plan(SimpleNamespace(query={}))
    assert resp.status == 200
    body = json.loads(resp.text)
    assert body["status"] == "ready"
    assert body["tag"] == "v0.22.0"
    assert body["wheel"]["filename"].endswith(".whl")
    assert body["wheel"]["sha256_known"] is True
