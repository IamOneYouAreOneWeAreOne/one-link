"""End-to-end integration test for authenticated update artifacts.

Phase 4 verification. The unit tests in test_updater_v0210.py mock
every external surface; this test runs against a real local HTTP
server pretending to be GitHub Releases, and exercises:

    1. build_install_plan reading the latest-release JSON
    2. download_to_temp fetching the wheel
    3. authenticate the manifest + wheel Sigstore ceremony and SHA-256
    4. executable handoff refusing to generate or spawn an installer

No in-place pip/respawn path is represented as implemented.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import socket
import sys
import threading
from pathlib import Path

import pytest
from packaging.utils import parse_wheel_filename

from one_link.safe_http import validated_urlopen


def _local_fetch_bytes(url: str, timeout: float) -> bytes:
    """Explicit test-only opt-in for the loopback release double."""
    with validated_urlopen(
        url,
        timeout=timeout,
        allow_https=False,
        allow_loopback_http=True,
    ) as response:
        return response.read()


def _local_fetch_json(url: str, timeout: float) -> dict:
    return json.loads(_local_fetch_bytes(url, timeout).decode("utf-8"))


# ─── tiny GitHub Releases mock server ──────────────────────────────────

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _ReleasesMock(http.server.BaseHTTPRequestHandler):
    """Serves the three paths the updater needs:

        GET /repos/owner/repo/releases/latest  -> release JSON
        GET /assets/<filename>                 -> wheel bytes
        GET /assets/SHA256SUMS                 -> manifest

    The wheel bytes are the actual built native wheel from
    `native/target/wheels/` so SHA-256 verification has real
    content to chew on.
    """

    # Set by the test via class attributes before the server starts.
    release_json: dict = {}
    wheel_path: Path = Path()
    sha256sums: bytes = b""
    sigstore_bundle: bytes = b"test-only bundle"

    def log_message(self, fmt, *args):  # silence
        pass

    def do_GET(self):  # noqa: N802
        if self.path.endswith("/releases/latest"):
            body = json.dumps(self.__class__.release_json).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.endswith("/SHA256SUMS"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(self.__class__.sha256sums)))
            self.end_headers()
            self.wfile.write(self.__class__.sha256sums)
            return
        if self.path.endswith(".sigstore"):
            body = self.__class__.sigstore_bundle
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.endswith(self.__class__.wheel_path.name):
            data = self.__class__.wheel_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(404)
        self.end_headers()


@pytest.fixture()
def mock_releases(tmp_path):
    """Start a real HTTP server bound to 127.0.0.1:<random>. Yields
    the base URL. Tears down after the test."""
    # Locate the prebuilt wheel from native/target/wheels/
    repo = Path(__file__).resolve().parent.parent
    wheels = list((repo / "native" / "target" / "wheels").glob("*.whl"))
    # Take a wheel this HOST can install, not merely the first one present.
    # The install plan matches against packaging's real host tag set, so a
    # leftover wheel for another platform (a Windows wheel in a checkout also
    # used from WSL, an older cross-build) made the plan answer "no_match" and
    # the test fail where it should have skipped. Ask the product's own matcher
    # so the fixture can never disagree with the code under test.
    from one_link.updater import _wheel_matches_host

    installable = [wheel for wheel in wheels if _wheel_matches_host(wheel.name)]
    if not installable:
        pytest.skip(
            "no native wheel for this host in native/target/wheels "
            f"(found {[w.name for w in wheels] or 'none'}) — run "
            "`cd native && python -m maturin build --release` first"
        )
    wheel = installable[0]

    # Compute its real SHA-256 + write a SHA256SUMS file.
    h = hashlib.sha256(wheel.read_bytes()).hexdigest()
    sums_text = f"{h}  {wheel.name}\n"
    _ReleasesMock.wheel_path = wheel
    _ReleasesMock.sha256sums = sums_text.encode("utf-8")

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    _distribution, wheel_version, _build, _tags = parse_wheel_filename(
        wheel.name,
    )
    release_tag = f"v{wheel_version}"
    _ReleasesMock.release_json = {
        "tag_name": release_tag,
        "name": "Test release",
        "html_url": f"{base}/releases/tag/v0.99.0",
        "published_at": "2026-05-12T00:00:00Z",
        "prerelease": False,
        "draft": False,
        "assets": [
            {
                "name": wheel.name,
                "size": wheel.stat().st_size,
                "browser_download_url": f"{base}/assets/{wheel.name}",
            },
            {
                "name": "SHA256SUMS",
                "size": len(sums_text),
                "browser_download_url": f"{base}/assets/SHA256SUMS",
            },
            {
                "name": "SHA256SUMS.sigstore",
                "size": len(_ReleasesMock.sigstore_bundle),
                "browser_download_url": f"{base}/assets/SHA256SUMS.sigstore",
            },
            {
                "name": f"{wheel.name}.sigstore",
                "size": len(_ReleasesMock.sigstore_bundle),
                "browser_download_url": f"{base}/assets/{wheel.name}.sigstore",
            },
        ],
    }

    srv = http.server.ThreadingHTTPServer(
        ("127.0.0.1", port), _ReleasesMock
    )
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield base, wheel, h
    finally:
        srv.shutdown()
        t.join(timeout=2.0)
        srv.server_close()


# ─── the integration test itself ───────────────────────────────────────

def test_install_path_end_to_end_against_mock_releases(mock_releases, tmp_path, monkeypatch):
    """Plan, download, and verify locally; executable handoff stays blocked."""
    base, wheel, expected_hash = mock_releases
    from one_link import updater as u_mod
    from one_link import update_check as uc_mod

    # Point the updater at the mock by overriding _build_url to
    # return our test URL. We still go through build_install_plan
    # which uses update_check's _build_url internally.
    monkeypatch.setattr(
        uc_mod,
        "_build_url",
        lambda owner, repo: f"{base}/repos/{owner}/{repo}/releases/latest",
    )
    # Force the host wheel-tag match the wheel filename's platform
    # so the test passes on any OS.
    if "win_amd64" in wheel.name:
        host_tag = "cp311-abi3-win_amd64"
    elif "macosx" in wheel.name:
        host_tag = wheel.name.split("-cp", 1)[1].rsplit("-", 1)[-1].replace(".whl", "")
        host_tag = f"cp311-abi3-{host_tag.split('-')[-1]}"
        host_tag = "cp311-abi3-macosx_11_0_arm64"  # fallback for matching
    elif "linux" in wheel.name:
        host_tag = "cp311-abi3-linux_x86_64"
    else:
        host_tag = "cp311-abi3-unknown"
    monkeypatch.setattr(u_mod, "host_wheel_tag", lambda: host_tag)

    # 1. Plan
    plan = u_mod.build_install_plan(
        current_version="0.0.0",
        fetch_json=_local_fetch_json,
        fetch_bytes=_local_fetch_bytes,
    )
    assert plan.status == "ready", f"plan failed: {plan.error}"
    assert plan.tag == _ReleasesMock.release_json["tag_name"]
    assert plan.wheel is not None
    assert plan.wheel.filename == wheel.name
    assert plan.wheel.expected_sha256 == expected_hash, (
        "SHA256SUMS lookup didn't find the wheel's hash"
    )
    assert plan.wheel.has_signature_contract is True

    # The loopback server uses inert test bundles. The verifier invocation and
    # pinned identity are covered independently; here we exercise the complete
    # network/download/cleanup/hash orchestration with that boundary stubbed.
    monkeypatch.setattr(
        u_mod,
        "_run_sigstore_identity_verify",
        lambda **kwargs: None,
    )

    def local_download(url, *, expected_size, timeout, artifact_filename):
        return u_mod.download_to_temp(
            url,
            expected_size=expected_size,
            timeout=timeout,
            fetch=_local_fetch_bytes,
            artifact_filename=artifact_filename,
        )

    prepared = u_mod.prepare_signed_update(
        plan.wheel,
        tag=plan.tag or "",
        download=local_download,
    )
    downloaded = prepared.artifact_path
    try:
        assert prepared.authenticated_sha256 == expected_hash
        assert u_mod.sha256_file(downloaded) == expected_hash
        # And the downloaded file is identical to the source wheel.
        assert downloaded.read_bytes() == wheel.read_bytes()

        with pytest.raises(RuntimeError, match="transactional full-app rollback"):
            u_mod.write_updater_script(
                downloaded,
                parent_pid=12345,
                python_exe=sys.executable,
                expected_sha256=prepared.authenticated_sha256,
            )
    finally:
        u_mod.remove_staged_file(downloaded)


def test_install_refuses_when_real_hash_disagrees(mock_releases, monkeypatch):
    """The releases mock serves the real wheel + correct hash. We
    corrupt the SHA256SUMS the server returns and verify the plan
    flags the mismatch when build_install_plan + sha256_file +
    expected_sha256 are checked together."""
    base, wheel, expected_hash = mock_releases
    from one_link import updater as u_mod
    from one_link import update_check as uc_mod

    # Swap in a WRONG hash in the SHA256SUMS response.
    bad_hash = "f" * 64
    _ReleasesMock.sha256sums = (
        f"{bad_hash}  {wheel.name}\n".encode("utf-8")
    )
    monkeypatch.setattr(
        uc_mod,
        "_build_url",
        lambda owner, repo: f"{base}/repos/{owner}/{repo}/releases/latest",
    )
    if "win_amd64" in wheel.name:
        host_tag = "cp311-abi3-win_amd64"
    elif "macosx" in wheel.name:
        host_tag = "cp311-abi3-macosx_11_0_arm64"
    else:
        host_tag = "cp311-abi3-linux_x86_64"
    monkeypatch.setattr(u_mod, "host_wheel_tag", lambda: host_tag)

    plan = u_mod.build_install_plan(
        current_version="0.0.0",
        fetch_json=_local_fetch_json,
        fetch_bytes=_local_fetch_bytes,
    )
    assert plan.status == "ready"
    assert plan.wheel is not None
    monkeypatch.setattr(
        u_mod,
        "_run_sigstore_identity_verify",
        lambda **kwargs: None,
    )

    def local_download(url, *, expected_size, timeout, artifact_filename):
        return u_mod.download_to_temp(
            url,
            expected_size=expected_size,
            timeout=timeout,
            fetch=_local_fetch_bytes,
            artifact_filename=artifact_filename,
        )

    with pytest.raises(ValueError, match="signed manifest"):
        # The signed manifest names a hash that the real wheel bytes do not
        # have. No prepared artifact is returned and all temp inputs are gone.
        u_mod.prepare_signed_update(
            plan.wheel,
            tag=plan.tag or "",
            download=local_download,
        )
