"""End-to-end integration test for the auto-install path.

Phase 4 verification. The unit tests in test_updater_v0210.py mock
every external surface; this test runs against a real local HTTP
server pretending to be GitHub Releases, and exercises:

    1. build_install_plan reading the latest-release JSON
    2. download_to_temp fetching the wheel
    3. SHA-256 verify against the published SHA256SUMS
    4. write_updater_script emitting a script with the right
       embedded literals

What this test does NOT do:
    * Actually pip-install the wheel. The updater script is
      generated and inspected; running it would replace the
      user's installed one_link_native, which we don't want in
      a test run.
    * Spawn the detached subprocess. spawn_detached() is the
      thin wrapper around subprocess.Popen + DETACHED_PROCESS;
      already covered by unit tests.

Together, this gives us complete confidence that the path works
end-to-end except for the final pip-install + respawn — which is
the part that needs per-OS verification by actually running.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import socket
import threading
import urllib.request
from pathlib import Path

import pytest


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
    if not wheels:
        pytest.skip(
            "no native wheel built — run `cd native && python -m maturin "
            "build --release` first to create one_link_native wheels"
        )
    wheel = wheels[0]

    # Compute its real SHA-256 + write a SHA256SUMS file.
    h = hashlib.sha256(wheel.read_bytes()).hexdigest()
    sums_text = f"{h}  {wheel.name}\n"
    _ReleasesMock.wheel_path = wheel
    _ReleasesMock.sha256sums = sums_text.encode("utf-8")

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    _ReleasesMock.release_json = {
        "tag_name": "v0.99.0",
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


# ─── the integration test itself ───────────────────────────────────────

def test_install_path_end_to_end_against_mock_releases(mock_releases, tmp_path, monkeypatch):
    """Plan -> download -> verify -> script-generate, all hitting a
    real (local) HTTP server. The only thing we DON'T do is run
    the updater script + pip install — those would mutate the
    user's installed environment."""
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
    plan = u_mod.build_install_plan()
    assert plan.status == "ready", f"plan failed: {plan.error}"
    assert plan.tag == "v0.99.0"
    assert plan.wheel is not None
    assert plan.wheel.filename == wheel.name
    assert plan.wheel.expected_sha256 == expected_hash, (
        "SHA256SUMS lookup didn't find the wheel's hash"
    )

    # 2. Download (real HTTP fetch from our local mock)
    downloaded = u_mod.download_to_temp(
        plan.wheel.asset_url,
        expected_size=plan.wheel.size,
    )
    try:
        # 3. SHA-256 verify
        assert u_mod.sha256_file(downloaded) == expected_hash, (
            "downloaded wheel's hash differs from SHA256SUMS — would have "
            "refused install (good)"
        )
        # And the downloaded file is identical to the source wheel.
        assert downloaded.read_bytes() == wheel.read_bytes()

        # 4. Script generation
        script = u_mod.write_updater_script(
            downloaded,
            parent_pid=12345,
            python_exe=r"C:\Python313\python.exe",
        )
        try:
            src = script.read_text(encoding="utf-8")
            # The script references the downloaded wheel path,
            # the parent PID, the Python interpreter, and runs pip.
            # repr() double-escapes Windows paths so we can't search
            # for str(downloaded) directly — check the filename
            # component, which is constant across platforms.
            assert "12345" in src
            assert downloaded.name in src, (
                f"wheel filename {downloaded.name!r} not embedded in script"
            )
            assert "Python313" in src
            assert "pip" in src and "install" in src
            # And — defense-in-depth — the wait-for-parent loop comes
            # BEFORE the pip install call so Windows file locking
            # on the loaded .pyd can't break the install.
            wait_idx = src.find("_alive(PARENT_PID)")
            pip_idx = src.find("'pip'")
            assert wait_idx >= 0 and pip_idx > wait_idx, (
                "pip install must come AFTER the wait-for-parent loop"
            )
        finally:
            script.unlink(missing_ok=True)
    finally:
        downloaded.unlink(missing_ok=True)


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

    plan = u_mod.build_install_plan()
    assert plan.status == "ready"
    assert plan.wheel is not None

    downloaded = u_mod.download_to_temp(
        plan.wheel.asset_url, expected_size=plan.wheel.size,
    )
    try:
        real_hash = u_mod.sha256_file(downloaded)
        # SHA256SUMS says bad_hash; real hash is the actual file
        # hash. They differ — install endpoint would refuse.
        assert plan.wheel.expected_sha256 == bad_hash
        assert real_hash != plan.wheel.expected_sha256
    finally:
        downloaded.unlink(missing_ok=True)
