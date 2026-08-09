"""Tests for release verification and the transactional app updater.

Legacy wheel selection remains tested as release-tooling compatibility. The
runtime install boundary is now the complete standalone bundle plus a
separately frozen, authenticated A/B replacement helper.

What we DO test:
    * host_wheel_tag returns sane platform strings
    * select_wheel_for_host picks the right wheel for each OS
    * parse_sha256sums tolerates the format-zoo sha256sum emits
    * download_to_temp handles size guards
    * updater-script generation and detached spawn fail closed
    * build_install_plan with mocked GitHub responses produces the
      expected InstallPlan for each branch
    * /api/update/install is dynamic, explicit, quiescent, and fail-closed
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest


def _next_version() -> str:
    """The version of a release that is genuinely NEWER than the one we ship.

    Hardcoding this is how these fixtures died: they said 0.22.0 when 0.22.0 was the future, and
    the day it became the present the updater short-circuited on "not_newer" before reaching the
    behaviour under test. A test that passes while testing nothing is worse than one that fails.
    """
    from packaging.version import Version

    from one_link import __version__

    v = Version(__version__)
    return f"{v.major}.{v.minor + 1}.0"


_NEXT_VERSION = _next_version()
_NEWER_TAG = f"v{_NEXT_VERSION}"



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
        _asset(f"one_link_native-{_NEXT_VERSION}-cp311-abi3-linux_x86_64.whl"),
        _asset(f"one_link_native-{_NEXT_VERSION}-cp311-abi3-macosx_11_0_arm64.whl"),
        _asset(f"one_link_native-{_NEXT_VERSION}-cp311-abi3-win_amd64.whl"),
    ]
    pick = select_wheel_for_host(assets, host_tag="cp311-abi3-win_amd64")
    assert pick is not None
    assert "win_amd64" in pick.filename
    assert pick.asset_url.startswith("https://example.test/")


def test_select_wheel_picks_macos_universal2_as_fallback():
    from one_link.updater import select_wheel_for_host
    # No per-arch wheel, only universal2 — should still match.
    assets = [
        _asset(f"one_link_native-{_NEXT_VERSION}-cp311-abi3-macosx_11_0_universal2.whl"),
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
        _asset(f"one_link_native-{_NEXT_VERSION}-cp311-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"),
    ]
    pick = select_wheel_for_host(assets, host_tag="cp311-abi3-linux_x86_64")
    assert pick is not None
    assert "x86_64" in pick.filename


def test_select_wheel_returns_none_when_no_match():
    from one_link.updater import select_wheel_for_host
    assets = [
        _asset(f"one_link_native-{_NEXT_VERSION}-cp311-abi3-linux_x86_64.whl"),
    ]
    pick = select_wheel_for_host(assets, host_tag="cp311-abi3-win_amd64")
    assert pick is None


def test_select_wheel_rejects_musllinux_for_glibc_host():
    from one_link.updater import select_wheel_for_host

    assets = [
        _asset(f"one_link_native-{_NEXT_VERSION}-cp311-abi3-musllinux_1_2_x86_64.whl"),
    ]
    assert (
        select_wheel_for_host(assets, host_tag="cp311-abi3-linux_x86_64")
        is None
    )


@pytest.mark.parametrize("python_tag", ["cp27", "cp310", "cp312", "py3"])
def test_select_wheel_rejects_wrong_python_floor(python_tag):
    from one_link.updater import select_wheel_for_host

    assets = [
        _asset(
            f"one_link_native-{_NEXT_VERSION}-{python_tag}-abi3-win_amd64.whl",
        ),
    ]
    assert (
        select_wheel_for_host(assets, host_tag="cp311-abi3-win_amd64")
        is None
    )


def test_select_wheel_ignores_non_one_link_native_files():
    """A release might also have SHA256SUMS, *.sigstore bundles, the
    pure-Python wheel etc. Those must not be matched."""
    from one_link.updater import select_wheel_for_host
    assets = [
        _asset("SHA256SUMS"),
        _asset(f"one_link-{_NEXT_VERSION}-py3-none-any.whl"),  # pure-Python
        _asset(f"one_link_native-{_NEXT_VERSION}-cp311-abi3-win_amd64.whl"),
        _asset(f"one_link_native-{_NEXT_VERSION}-cp311-abi3-win_amd64.whl.sigstore"),
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

    with pytest.raises(ValueError, match="length does not match"):
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
        from one_link.updater import remove_staged_file

        remove_staged_file(path)


def test_download_to_temp_preserves_verified_wheel_basename():
    from one_link.updater import download_to_temp, remove_staged_file

    body = b"wheel bytes"
    wheel_name = f"one_link_native-{_NEXT_VERSION}-cp311-abi3-win_amd64.whl"
    path = download_to_temp(
        "https://example.test/wheel.whl",
        expected_size=len(body),
        fetch=lambda url, timeout: body,
        artifact_filename=wheel_name,
    )
    try:
        assert path.name == wheel_name
        assert path.parent.name.startswith("ol_update_")
    finally:
        stage_dir = path.parent
        remove_staged_file(path)
        assert not stage_dir.exists()


@pytest.mark.parametrize(
    "filename",
    ["../engine.whl", "nested/engine.whl", "nested\\engine.whl", "\x00.whl"],
)
def test_download_to_temp_rejects_unsafe_artifact_filename(filename):
    from one_link.updater import download_to_temp

    with pytest.raises(ValueError, match="safe basename"):
        download_to_temp(
            "https://example.test/wheel.whl",
            expected_size=1,
            fetch=lambda url, timeout: b"x",
            artifact_filename=filename,
        )


# ─── updater script generation ─────────────────────────────────────────

def test_write_updater_script_is_fail_closed(tmp_path):
    from one_link.updater import write_updater_script
    wheel = tmp_path / "fake.whl"
    wheel.write_bytes(b"PK\x03\x04")  # zip header (whl = zip)

    with pytest.raises(RuntimeError, match="transactional full-app rollback"):
        write_updater_script(
            wheel,
            parent_pid=42,
            python_exe=sys.executable,
        )


def test_write_updater_script_rejects_custom_relaunch_cmd(tmp_path):
    from one_link.updater import write_updater_script
    wheel = tmp_path / "fake.whl"
    wheel.write_bytes(b"x")

    with pytest.raises(RuntimeError, match="transactional full-app rollback"):
        write_updater_script(
            wheel,
            parent_pid=1,
            relaunch_cmd=[sys.executable, "-m", "one_link.cli", "app"],
        )


# ─── build_install_plan with mocked GitHub responses ───────────────────

def test_build_install_plan_happy_path(monkeypatch):
    from one_link import updater as u_mod

    def fake_fetch_json(url, timeout):
        return {
            "tag_name": _NEWER_TAG,
            "assets": [
                {
                    "name": f"one_link_native-{_NEXT_VERSION}-cp311-abi3-win_amd64.whl",
                    "size": 2_400_000,
                    "browser_download_url": "https://example.test/wheel.whl",
                },
                {
                    "name": "SHA256SUMS",
                    "size": 200,
                    "browser_download_url": "https://example.test/SHA256SUMS",
                },
                {
                    "name": "SHA256SUMS.sigstore",
                    "size": 300,
                    "browser_download_url": "https://example.test/SHA256SUMS.sigstore",
                },
                {
                    "name": (
                        f"one_link_native-{_NEXT_VERSION}-cp311-abi3-win_amd64.whl"
                        ".sigstore"
                    ),
                    "size": 300,
                    "browser_download_url": "https://example.test/wheel.whl.sigstore",
                },
            ],
        }
    expected_hash = "a" * 64
    sha_body = (
        f"{expected_hash}  "
        f"one_link_native-{_NEXT_VERSION}-cp311-abi3-win_amd64.whl\n"
    ).encode()

    def fake_fetch_bytes(url, timeout):
        if "SHA256SUMS" in url:
            return sha_body
        raise AssertionError(f"unexpected fetch: {url}")

    # Force host tag so this passes on any OS.
    from packaging.tags import Tag
    monkeypatch.setattr(
        u_mod, "sys_tags", lambda: iter([Tag("cp311", "abi3", "win_amd64")]),
    )
    plan = u_mod.build_install_plan(
        fetch_json=fake_fetch_json,
        fetch_bytes=fake_fetch_bytes,
    )
    assert plan.status == "ready"
    assert plan.tag == _NEWER_TAG
    assert plan.wheel is not None
    assert "win_amd64" in plan.wheel.filename
    assert plan.wheel.expected_sha256 == expected_hash
    assert plan.wheel.has_signature_contract is True


def test_build_install_plan_no_release_when_fetch_fails(monkeypatch):
    from one_link import updater as u_mod

    def fake_fetch_json(url, timeout):
        raise RuntimeError("github is down")

    plan = u_mod.build_install_plan(fetch_json=fake_fetch_json)
    assert plan.status == "no_release"
    assert "github" in (plan.error or "").lower()


def test_build_install_plan_no_match_when_wheel_missing(monkeypatch):
    """If the release ships only wheels for a DIFFERENT platform,
    plan.status is 'no_match' and we DON'T fall back to a wrong wheel.

    Wheel selection matches against packaging's real host tag set, which no
    monkeypatch of ``host_wheel_tag`` can influence -- so hard-coding a Linux
    wheel here only produced "no match" on a Windows runner, and on Linux the
    wheel matched and a later check answered instead. Derive the foreign
    platform from the actual host so the intended condition holds everywhere.
    """
    from one_link import updater as u_mod

    foreign_platform = "linux_x86_64" if os.name == "nt" else "win_amd64"

    def fake_fetch_json(url, timeout):
        return {
            "tag_name": _NEWER_TAG,
            "assets": [
                {
                    "name": (
                        f"one_link_native-{_NEXT_VERSION}-cp311-abi3-"
                        f"{foreign_platform}.whl"
                    ),
                    "size": 2_400_000,
                    "browser_download_url": "https://example.test/foreign.whl",
                },
            ],
        }

    plan = u_mod.build_install_plan(fetch_json=fake_fetch_json)
    assert plan.status == "no_match"
    assert plan.tag == _NEWER_TAG
    assert plan.wheel is None


def test_build_install_plan_unverified_when_no_sha256sums(monkeypatch):
    """A SHA-only/signature-incomplete release is never ready to install.

    The wheel must MATCH this host for the plan to get far enough to judge
    verification, and selection uses packaging's real host tag set. A
    hard-coded win_amd64 wheel therefore stopped at 'no_match' on Linux and
    never exercised the contract, so build the name from the actual host tag.
    """
    from one_link import updater as u_mod

    host_tag = u_mod.host_wheel_tag()

    def fake_fetch_json(url, timeout):
        return {
            "tag_name": _NEWER_TAG,
            "assets": [
                {
                    "name": f"one_link_native-{_NEXT_VERSION}-{host_tag}.whl",
                    "size": 2_400_000,
                    "browser_download_url": "https://example.test/w.whl",
                },
            ],
        }

    plan = u_mod.build_install_plan(fetch_json=fake_fetch_json)
    assert plan.status == "unverified"
    assert plan.wheel is not None
    assert plan.wheel.expected_sha256 is None


def test_build_install_plan_rejects_duplicate_asset_names(monkeypatch):
    from one_link import updater as u_mod

    wheel_name = f"one_link_native-{_NEXT_VERSION}-cp311-abi3-win_amd64.whl"
    duplicate = _asset(wheel_name)
    monkeypatch.setattr(u_mod, "host_wheel_tag", lambda: "cp311-abi3-win_amd64")
    plan = u_mod.build_install_plan(
        fetch_json=lambda url, timeout: {
            "tag_name": _NEWER_TAG,
            "assets": [duplicate, dict(duplicate)],
        },
    )
    assert plan.status == "unverified"
    assert "duplicate" in (plan.error or "").lower()


def _newer_tag() -> str:
    """A tag that is genuinely NEWER than what we ship.

    This was the literal _NEWER_TAG, chosen when that was a future version. The moment the project
    reached 0.22.0 the updater short-circuited on "not_newer" and never reached the draft /
    prerelease check these cases exist for -- so they would have kept passing while testing
    nothing, which is the quietest way for a gate to die. Deriving it keeps the premise true
    across every future bump.
    """
    from packaging.version import Version

    from one_link import __version__

    v = Version(__version__)
    return f"v{v.major}.{v.minor + 1}.0"


@pytest.mark.parametrize(
    ("tag", "draft", "prerelease"),
    [
        ("../../main", False, False),
        ("v01.2.3", False, False),
        (_newer_tag(), True, False),
        (_newer_tag(), False, True),
    ],
)
def test_build_install_plan_rejects_noncanonical_release(
    tag,
    draft,
    prerelease,
):
    from one_link import updater as u_mod

    plan = u_mod.build_install_plan(
        fetch_json=lambda url, timeout: {
            "tag_name": tag,
            "draft": draft,
            "prerelease": prerelease,
            "assets": [],
        },
    )
    assert plan.status == "unverified"


def test_verify_signed_update_authenticates_manifest_then_artifact(
    monkeypatch,
    tmp_path,
):
    from one_link import updater as u_mod

    artifact = tmp_path / "engine.whl"
    artifact.write_bytes(b"authenticated wheel")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text(f"{digest}  {artifact.name}\n", encoding="utf-8")
    artifact_bundle = tmp_path / "engine.whl.sigstore"
    manifest_bundle = tmp_path / "SHA256SUMS.sigstore"
    artifact_bundle.write_bytes(b"artifact bundle")
    manifest_bundle.write_bytes(b"manifest bundle")
    calls = []

    def fake_verify(*, artifact, bundle, tag):
        calls.append((Path(artifact).name, Path(bundle).name, tag))

    monkeypatch.setattr(u_mod, "_run_sigstore_identity_verify", fake_verify)
    authenticated = u_mod.verify_signed_update(
        artifact=artifact,
        artifact_bundle=artifact_bundle,
        manifest=manifest,
        manifest_bundle=manifest_bundle,
        artifact_filename=artifact.name,
        tag=_NEWER_TAG,
    )
    assert authenticated == digest
    assert calls == [
        ("SHA256SUMS", "SHA256SUMS.sigstore", _NEWER_TAG),
        ("engine.whl", "engine.whl.sigstore", _NEWER_TAG),
    ]


def test_verify_signed_update_rejects_duplicate_manifest_entry(
    monkeypatch,
    tmp_path,
):
    from one_link import updater as u_mod

    artifact = tmp_path / "engine.whl"
    artifact.write_bytes(b"wheel")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text(
        f"{digest}  {artifact.name}\n{digest} *{artifact.name}\n",
        encoding="utf-8",
    )
    bundle = tmp_path / "bundle"
    bundle.write_bytes(b"bundle")
    monkeypatch.setattr(
        u_mod,
        "_run_sigstore_identity_verify",
        lambda **kwargs: None,
    )
    with pytest.raises(ValueError, match="exactly one"):
        u_mod.verify_signed_update(
            artifact=artifact,
            artifact_bundle=bundle,
            manifest=manifest,
            manifest_bundle=bundle,
            artifact_filename=artifact.name,
            tag=_NEWER_TAG,
        )


def test_sigstore_verifier_pins_exact_workflow_tag(monkeypatch, tmp_path):
    from one_link import updater as u_mod

    artifact = tmp_path / "engine.whl"
    bundle = tmp_path / "engine.whl.sigstore"
    artifact.write_bytes(b"wheel")
    bundle.write_bytes(b"bundle")
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(u_mod.subprocess, "run", fake_run)
    u_mod._run_sigstore_identity_verify(
        artifact=artifact,
        bundle=bundle,
        tag=_NEWER_TAG,
    )
    command = captured["command"]
    identity_index = command.index("--cert-identity") + 1
    assert command[identity_index] == (
        "https://github.com/coherence-energy-labs/one-link/"
        f".github/workflows/release.yml@refs/tags/v{_NEXT_VERSION}"
    )
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["timeout"] == u_mod.SIGSTORE_VERIFY_TIMEOUT_S


def _write_test_native_wheel(path: Path, *, root=f"one_link_native-{_NEXT_VERSION}.dist-info"):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("one_link_native/__init__.py", "VALUE = 1\n")
        archive.writestr(f"{root}/METADATA", "Name: one-link-native\n")
        archive.writestr(f"{root}/WHEEL", "Wheel-Version: 1.0\n")
        archive.writestr(f"{root}/RECORD", "")


def test_validate_native_wheel_accepts_complete_archive(tmp_path):
    from one_link.updater import validate_native_wheel

    filename = f"one_link_native-{_NEXT_VERSION}-cp311-abi3-win_amd64.whl"
    wheel = tmp_path / filename
    _write_test_native_wheel(wheel)
    validate_native_wheel(wheel, filename)


def test_validate_native_wheel_rejects_wrong_distribution(tmp_path):
    from one_link.updater import validate_native_wheel

    filename = f"one_link_native-{_NEXT_VERSION}-cp311-abi3-win_amd64.whl"
    wheel = tmp_path / filename
    _write_test_native_wheel(wheel, root="other_package-1.0.dist-info")
    with pytest.raises(ValueError, match="not one_link_native"):
        validate_native_wheel(wheel, filename)


def test_validate_native_wheel_rejects_traversal_member(tmp_path):
    from one_link.updater import validate_native_wheel

    filename = f"one_link_native-{_NEXT_VERSION}-cp311-abi3-win_amd64.whl"
    wheel = tmp_path / filename
    _write_test_native_wheel(wheel)
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr("../escape.py", "bad")
    with pytest.raises(ValueError, match="unsafe archive member"):
        validate_native_wheel(wheel, filename)


# ─── /api/update/install transactional helper gate ────────────────────


class _UpdateRequest:
    query: dict[str, str] = {}
    transport = None
    remote = "127.0.0.1"

    def __init__(self, body):
        self._body = body

    async def json(self):
        return self._body


def _update_server(*, lockbox=None):
    from one_link.server import UIServer

    state = None if lockbox is None else SimpleNamespace(_lockbox=lockbox)
    daemon = SimpleNamespace(
        state=state,
        discovery=None,
        _cap_root_key=b"c" * 32,
        _update_handoff_draining=False,
        me=SimpleNamespace(
            fingerprint="aa" * 32,
            short_id="aaaaaaaa",
            hostname="me",
        ),
    )
    return UIServer(daemon), daemon


def _available_capability(tmp_path: Path):
    from one_link.update_helper import ExternalUpdateCapability

    install = tmp_path / "installed"
    data = tmp_path / "home" / "data"
    install.mkdir(parents=True)
    data.mkdir(parents=True)
    return ExternalUpdateCapability(
        True,
        "available",
        platform="windows-x86_64",
        install_root=install.resolve(),
        data_root=data.resolve(),
        expected_executable="one-link.exe",
    )


@pytest.mark.asyncio
async def test_api_update_install_requires_exact_confirmation():
    server, _daemon = _update_server()

    missing = await server.api_update_install(_UpdateRequest({}))
    extra = await server.api_update_install(_UpdateRequest({
        "confirmed_install": True,
        "expected_tag": "v999.0.0",
    }))

    assert missing.status == 409
    assert extra.status == 409
    assert json.loads(extra.text)["code"] == "install_confirmation_required"


@pytest.mark.asyncio
async def test_api_update_install_source_runtime_fails_before_network(monkeypatch):
    from one_link import standalone_updater

    monkeypatch.setenv("ONE_LINK_EXPERIMENTAL_AUTOINSTALL", "1")
    monkeypatch.setattr(
        standalone_updater,
        "build_standalone_install_plan",
        lambda **_kwargs: pytest.fail("source runtime reached release discovery"),
    )
    server, _daemon = _update_server()

    response = await server.api_update_install(
        _UpdateRequest({"confirmed_install": True})
    )

    assert response.status == 409
    body = json.loads(response.text)
    assert body["status"] == "install_unavailable"
    assert body["reason"] == "not_frozen_standalone_bundle"


@pytest.mark.asyncio
async def test_api_update_plan_returns_standalone_plan_shape(monkeypatch, tmp_path):
    from one_link import standalone_updater
    from one_link.standalone_updater import ReleaseAsset, StandaloneInstallPlan

    server, _daemon = _update_server()
    capability = _available_capability(tmp_path)

    async def inspect(*, fresh=False):
        return capability

    server._external_update_capability = inspect
    server._update_check_policy_enabled = lambda: True
    fake_plan = StandaloneInstallPlan(
        status="ready_for_authentication",
        tag=_NEWER_TAG,
        release_id=77,
        platform=capability.platform,
        artifact=ReleaseAsset(
            "one-link-windows-x86_64.zip",
            "https://example.test/one-link-windows-x86_64.zip",
            2_400_000,
        ),
    )
    monkeypatch.setattr(
        standalone_updater,
        "build_standalone_install_plan",
        lambda **_kwargs: fake_plan,
    )

    response = await server.api_update_plan(SimpleNamespace(query={}))
    body = json.loads(response.text)

    assert response.status == 200
    assert body["status"] == "ready_for_authentication"
    assert body["tag"] == _NEWER_TAG
    assert body["release_id"] == 77
    assert body["artifact"]["filename"].endswith(".zip")
    assert body["install_available"] is True


@pytest.mark.asyncio
async def test_api_update_install_unverified_release_never_spawns(
    monkeypatch,
    tmp_path,
):
    from one_link import standalone_updater, update_helper
    from one_link.standalone_updater import StandaloneInstallPlan

    server, _daemon = _update_server()
    capability = _available_capability(tmp_path)

    async def inspect(*, fresh=False):
        return capability

    server._external_update_capability = inspect
    server._update_check_policy_enabled = lambda: True
    monkeypatch.setattr(
        standalone_updater,
        "build_standalone_install_plan",
        lambda **_kwargs: StandaloneInstallPlan(
            status="unverified",
            tag=_NEWER_TAG,
            error="missing exact-tag evidence",
        ),
    )
    monkeypatch.setattr(
        update_helper,
        "spawn_external_update_helper",
        lambda *_args, **_kwargs: pytest.fail("unverified release spawned helper"),
    )

    response = await server.api_update_install(
        _UpdateRequest({"confirmed_install": True})
    )

    assert response.status == 502
    assert json.loads(response.text)["status"] == "unverified"


@pytest.mark.asyncio
async def test_api_update_install_discovery_failure_is_bounded_and_never_spawns(
    monkeypatch,
    tmp_path,
):
    from one_link import standalone_updater, update_helper

    server, _daemon = _update_server()
    capability = _available_capability(tmp_path)

    async def inspect(*, fresh=False):
        return capability

    server._external_update_capability = inspect
    server._update_check_policy_enabled = lambda: True
    monkeypatch.setattr(
        standalone_updater,
        "build_standalone_install_plan",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("private diagnostic")),
    )
    monkeypatch.setattr(
        update_helper,
        "spawn_external_update_helper",
        lambda *_args, **_kwargs: pytest.fail("failed discovery spawned helper"),
    )

    response = await server.api_update_install(
        _UpdateRequest({"confirmed_install": True})
    )
    body = json.loads(response.text)

    assert response.status == 502
    assert body["status"] == "failed_closed"
    assert body["error"] == (
        "the authenticated release could not be discovered safely"
    )
    assert len(body["incident"]) == 12
    assert "private diagnostic" not in response.text


@pytest.mark.asyncio
async def test_api_update_install_defers_while_transfer_active(
    monkeypatch,
    tmp_path,
):
    import contextlib

    from one_link import recovery_api, standalone_updater, update_helper
    from one_link.lockbox import LockBox
    from one_link.standalone_updater import StandaloneInstallPlan

    server, daemon = _update_server(lockbox=LockBox(b"k" * 32))
    capability = _available_capability(tmp_path)

    async def inspect(*, fresh=False):
        return capability

    server._external_update_capability = inspect
    server._update_check_policy_enabled = lambda: True
    daemon.begin_update_handoff = lambda: {"active_transfers": 1}
    daemon.cancel_update_handoff = lambda: None
    monkeypatch.setattr(
        standalone_updater,
        "build_standalone_install_plan",
        lambda **_kwargs: StandaloneInstallPlan(
            status="ready_for_authentication",
            tag=_NEWER_TAG,
            release_id=77,
            platform=capability.platform,
        ),
    )

    @contextlib.contextmanager
    def guard(_root):
        yield

    monkeypatch.setattr(recovery_api, "recovery_transaction_guard", guard)
    monkeypatch.setattr(
        update_helper,
        "prepare_external_helper_launch",
        lambda **_kwargs: pytest.fail("busy daemon prepared helper"),
    )

    response = await server.api_update_install(
        _UpdateRequest({"confirmed_install": True})
    )

    assert response.status == 409
    assert json.loads(response.text)["blockers"] == {"active_transfers": 1}


@pytest.mark.asyncio
async def test_api_update_install_launches_authenticated_helper_and_shutdown(
    monkeypatch,
    tmp_path,
):
    import asyncio
    import contextlib

    from one_link import recovery_api, standalone_updater, update_helper, update_transaction
    from one_link.lockbox import LockBox
    from one_link.standalone_updater import StandaloneInstallPlan

    server, daemon = _update_server(lockbox=LockBox(b"k" * 32))
    capability = _available_capability(tmp_path)
    observed: dict[str, object] = {}

    async def inspect(*, fresh=False):
        observed.setdefault("capability_fresh", []).append(fresh)
        return capability

    async def request_shutdown(*, delay_s):
        observed["shutdown_delay"] = delay_s

    server._external_update_capability = inspect
    server._update_check_policy_enabled = lambda: True
    daemon.begin_update_handoff = lambda: {}
    daemon.cancel_update_handoff = lambda: observed.setdefault("cancelled", True)
    daemon.request_shutdown = request_shutdown
    plan = StandaloneInstallPlan(
        status="ready_for_authentication",
        tag=_NEWER_TAG,
        release_id=77,
        platform=capability.platform,
    )
    monkeypatch.setattr(
        standalone_updater,
        "build_standalone_install_plan",
        lambda **_kwargs: plan,
    )

    @contextlib.contextmanager
    def guard(root):
        observed["recovery_guard"] = root
        yield

    monkeypatch.setattr(recovery_api, "recovery_transaction_guard", guard)
    monkeypatch.setattr(
        update_transaction,
        "acquire_update_state_authority",
        lambda root, lockbox: observed.setdefault("authority", (root, lockbox)) and b"a" * 32,
    )

    launch = SimpleNamespace(handoff=SimpleNamespace())

    def prepare(**kwargs):
        observed["prepare"] = kwargs
        return launch

    monkeypatch.setattr(update_helper, "prepare_external_helper_launch", prepare)
    monkeypatch.setattr(
        update_helper,
        "spawn_external_update_helper",
        lambda received: observed.setdefault("spawn", received) and 4444,
    )

    response = await server.api_update_install(
        _UpdateRequest({"confirmed_install": True})
    )
    await asyncio.sleep(0)
    body = json.loads(response.text)

    assert response.status == 202
    assert body["status"] == "handoff_started"
    assert body["helper_pid"] == 4444
    assert observed["spawn"] is launch
    assert observed["prepare"]["expected_tag"] == _NEWER_TAG
    assert observed["prepare"]["expected_release_id"] == 77
    assert observed["prepare"]["parent_pid"] > 0
    assert observed["shutdown_delay"] == 0.75
    assert server._update_handoff_committed is True


def test_daemon_update_drain_is_atomic_and_blocks_new_local_work():
    from one_link.daemon import Daemon

    daemon = object.__new__(Daemon)
    daemon.state = SimpleNamespace(
        update_handoff_safety_counts=lambda: {"active_transfers": 0}
    )
    daemon._call_registry = SimpleNamespace(active_call_ids=lambda: [])
    daemon._incoming_files = {}
    daemon._incoming_blobs = {}
    daemon._pending_file_offers = {}
    daemon._outbound_file_gates = {}
    daemon._capsule_inbound_meta = {}
    daemon._shutdown_requested = False
    daemon._update_handoff_draining = False

    assert daemon.begin_update_handoff() == {}
    assert daemon._update_handoff_draining is True
    with pytest.raises(RuntimeError, match="authenticated update"):
        daemon._assert_update_handoff_accepting_work()
    assert daemon.begin_update_handoff() == {
        "update_handoff_already_in_progress": 1,
    }

    daemon.cancel_update_handoff()
    assert daemon._update_handoff_draining is False


def test_daemon_update_drain_defers_active_transfer():
    from one_link.daemon import Daemon

    daemon = object.__new__(Daemon)
    daemon.state = SimpleNamespace(
        update_handoff_safety_counts=lambda: {"active_transfers": 2}
    )
    daemon._call_registry = SimpleNamespace(active_call_ids=lambda: [])
    daemon._incoming_files = {}
    daemon._incoming_blobs = {}
    daemon._pending_file_offers = {}
    daemon._outbound_file_gates = {}
    daemon._capsule_inbound_meta = {}
    daemon._shutdown_requested = False
    daemon._update_handoff_draining = False

    assert daemon.begin_update_handoff() == {"active_transfers": 2}
    assert daemon._update_handoff_draining is False
