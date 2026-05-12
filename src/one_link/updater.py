"""One-click update — wheel selection, download, verify, install, respawn.

Phase 3 of the production-install plan. Builds on update_check.py:

    Phase 1 (CI)      — release.yml ships native wheels on every v* tag
    Phase 2 (read)    — daemon polls GitHub, UI shows "Update available" banner
    Phase 3 (this)    — user clicks "Update now", daemon downloads the right
                        wheel for this OS+ABI, verifies its SHA-256 against
                        SHA256SUMS, pip-installs it, respawns. Or aborts
                        cleanly with a structured error if anything goes wrong.

Safety properties:

    * The updater never modifies the running daemon's files directly.
      pip install runs from a detached subprocess AFTER the daemon exits,
      so Windows file-locking (on the .pyd / .exe) can't break the
      install half-way.
    * SHA-256 verification is mandatory. We refuse to install a wheel
      whose hash isn't published in SHA256SUMS — defends against a
      compromised release page or a man-in-the-middle proxy.
    * Failed pip install does NOT leave you without a daemon. The
      updater script starts a fresh daemon even if pip exits non-zero,
      so the user just sees the old version still running.
    * No network calls in this module's import path. All HTTP happens
      inside the functions, so tests can monkey-patch without spinning
      up an event loop.

This module is the engine; the /api/update/install endpoint in
server.py is the thin handler that calls into it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger("one_link.updater")


# ─── data shapes ──────────────────────────────────────────────────────

@dataclass
class WheelMatch:
    """A wheel asset on a GitHub Release that matches this host's
    Python ABI + OS + arch. The updater downloads exactly this."""

    asset_url: str
    filename: str
    size: int
    expected_sha256: Optional[str] = None  # None until SHA256SUMS parsed


@dataclass
class InstallPlan:
    """Everything the install handler needs to know to make a decision:
    which wheel will be installed, where, and whether the host has
    enough info to proceed."""

    status: str       # 'ready' | 'no_match' | 'no_release' | 'error'
    tag: Optional[str] = None
    wheel: Optional[WheelMatch] = None
    error: Optional[str] = None
    # Cached so the UI can echo the version they're about to install.
    latest_version: Optional[str] = None

    def to_dict(self) -> dict:
        out = {"status": self.status}
        if self.tag:
            out["tag"] = self.tag
        if self.latest_version:
            out["latest_version"] = self.latest_version
        if self.wheel:
            out["wheel"] = {
                "filename": self.wheel.filename,
                "size": self.wheel.size,
                "sha256_known": bool(self.wheel.expected_sha256),
            }
        if self.error:
            out["error"] = self.error
        return out


# ─── host detection ───────────────────────────────────────────────────

def host_wheel_tag() -> str:
    """Return the wheel filename infix that a maturin-built abi3 wheel
    for this host would have. Example: 'cp311-abi3-win_amd64'.

    The native crate is built abi3 (Python 3.11+), so the cp311 piece
    is constant; OS + arch are the variable bits. macOS ships both
    universal2 and per-arch wheels in practice; we match either.
    """
    machine = platform.machine().lower()
    system = platform.system()
    if system == "Windows":
        arch = "amd64" if machine in ("amd64", "x86_64", "x64") else machine
        return f"cp311-abi3-win_{arch}"
    if system == "Darwin":
        # arm64 (Apple Silicon) vs x86_64 (Intel). maturin also produces
        # universal2 wheels that work on both; treat that as a fallback.
        if machine in ("arm64", "aarch64"):
            return "cp311-abi3-macosx_11_0_arm64"
        return "cp311-abi3-macosx_10_12_x86_64"
    # Linux glibc/musl distinction is handled via manylinux tags
    # (manylinux_2_17_x86_64 etc.). For matching purposes we'll
    # accept any wheel whose filename contains "linux_<arch>" or
    # "manylinux*_<arch>". `select_wheel_for_host` does the matching.
    if machine in ("x86_64", "amd64"):
        return "cp311-abi3-linux_x86_64"
    if machine in ("aarch64", "arm64"):
        return "cp311-abi3-linux_aarch64"
    return f"cp311-abi3-linux_{machine}"


def _wheel_matches_host(filename: str, host_tag: str) -> bool:
    """A wheel filename matches the host iff its OS + arch suffix
    matches OR (on macOS) it's a universal2 wheel. The cp-version
    field is checked separately to allow cp311-abi3 wheels on Py3.12+."""
    if "one_link_native-" not in filename:
        return False
    if not filename.endswith(".whl"):
        return False
    # cp311-abi3 wheels work on Python 3.11+ regardless of the
    # actual interpreter version. Some builds tag cp312/cp313 too;
    # accept any cp31x-abi3.
    if "abi3" not in filename:
        return False
    # Platform suffix match.
    suffix = filename.rsplit("-", 1)[-1].removesuffix(".whl")
    expected = host_tag.rsplit("-", 1)[-1]
    if expected in filename:
        return True
    # macOS universal2 wheels.
    if "macosx" in expected and "universal2" in filename:
        return True
    # Linux: manylinux tags share the arch suffix with the host tag
    # (e.g. host x86_64 ↔ manylinux_2_17_x86_64).
    if "linux_" in expected:
        arch = expected.rsplit("_", 1)[-1]
        if f"_{arch}" in filename or filename.endswith(f"_{arch}.whl"):
            return True
    return False


def select_wheel_for_host(
    assets: list[dict],
    host_tag: Optional[str] = None,
) -> Optional[WheelMatch]:
    """Pick the right wheel from a GitHub Release's `assets` array.
    Returns None if no asset matches this host."""
    tag = host_tag or host_wheel_tag()
    for asset in assets or []:
        name = asset.get("name", "")
        if _wheel_matches_host(name, tag):
            return WheelMatch(
                asset_url=asset.get("browser_download_url", ""),
                filename=name,
                size=int(asset.get("size") or 0),
            )
    return None


# ─── SHA256SUMS parsing ───────────────────────────────────────────────

# The release.yml workflow writes a `SHA256SUMS` file in this format:
#     <hex>  <filename>
# We download it and look up the expected hash for our chosen wheel.

def parse_sha256sums(text: str) -> dict[str, str]:
    """Return {filename: hex_hash}. Tolerant: extra whitespace, blank
    lines, and lines starting with '#' are ignored."""
    out = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        h = parts[0].lower()
        # Allow `<hash> *file.whl` (sha256sum's binary marker) as well
        # as `<hash>  file.whl`. Tolerate either form.
        name = parts[-1].lstrip("*")
        if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
            out[name] = h
    return out


# ─── network helpers (mockable) ───────────────────────────────────────

FetchFn = Callable[[str, float], bytes]


def _default_http_get_bytes(url: str, timeout: float) -> bytes:
    """Single synchronous GET, returning the response body as bytes.
    Used for downloading wheels + SHA256SUMS. Tests inject a fake."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "one-link-updater/0.21",
                 "Accept": "application/octet-stream"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        if resp.status != 200:
            raise urllib.error.HTTPError(
                url, resp.status, resp.reason, resp.headers, None
            )
        return resp.read()


def download_to_temp(
    url: str,
    *,
    expected_size: int = 0,
    timeout: float = 60.0,
    fetch: FetchFn = _default_http_get_bytes,
) -> Path:
    """Download `url` into a freshly-created temp file and return the
    path. Caller is responsible for deletion. `expected_size` is a
    soft check — we fail if the body is more than 5× the declared
    size (defends against accidentally fetching a huge index page
    instead of a 2MB wheel)."""
    body = fetch(url, timeout)
    if expected_size > 0 and len(body) > 5 * expected_size:
        raise ValueError(
            f"downloaded body {len(body):,} bytes > 5x expected "
            f"{expected_size:,}; refusing"
        )
    fd, path = tempfile.mkstemp(prefix="ol_update_", suffix=".bin")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(body)
    except Exception:
        with contextlib_suppress():
            os.unlink(path)
        raise
    return Path(path)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# Tiny stand-in for contextlib.suppress to avoid pulling in another
# import here. Keeps the module's surface narrow.
class contextlib_suppress:
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return True


# ─── plan + execute ───────────────────────────────────────────────────

def build_install_plan(
    *,
    owner: str = "Jphilbrick10",
    repo: str = "one-link",
    timeout: float = 6.0,
    fetch_json: Callable[[str, float], dict] | None = None,
    fetch_bytes: FetchFn = _default_http_get_bytes,
) -> InstallPlan:
    """Inspect the latest release, pick the wheel, look up its expected
    hash. Does NOT download the wheel or run pip. Used by both the
    /api/update/install handler and by tests to verify wheel matching."""
    from one_link.update_check import _build_url, _default_fetch
    fetch_json = fetch_json or _default_fetch
    try:
        payload = fetch_json(_build_url(owner, repo), timeout)
    except Exception as e:
        return InstallPlan(status="no_release", error=f"fetch latest: {e}")
    tag = (payload.get("tag_name") or "").strip()
    if not tag:
        return InstallPlan(status="no_release", error="no tag_name in payload")
    assets = payload.get("assets") or []
    wheel = select_wheel_for_host(assets)
    if wheel is None:
        return InstallPlan(
            status="no_match",
            tag=tag,
            latest_version=tag,
            error=f"no wheel for {host_wheel_tag()} in release {tag}",
        )
    # Try to read SHA256SUMS for hash verification. If missing,
    # we still proceed but flag the wheel as unverified — the caller
    # decides whether to refuse or fall through (default: refuse).
    for asset in assets:
        if asset.get("name") == "SHA256SUMS":
            try:
                body = fetch_bytes(asset["browser_download_url"], timeout)
                sums = parse_sha256sums(body.decode("utf-8", "replace"))
                if wheel.filename in sums:
                    wheel.expected_sha256 = sums[wheel.filename]
            except Exception as e:
                log.info("update: SHA256SUMS fetch failed: %s", e)
            break
    return InstallPlan(
        status="ready",
        tag=tag,
        latest_version=tag,
        wheel=wheel,
    )


def write_updater_script(
    wheel_path: Path,
    *,
    parent_pid: int,
    python_exe: str = sys.executable,
    relaunch_cmd: list[str] | None = None,
) -> Path:
    """Write a tiny standalone Python script that, when run, will:
        1. Wait for parent_pid to exit (so the daemon's loaded .pyd
           is no longer locked on Windows).
        2. Run `pip install --user --force-reinstall <wheel_path>`.
        3. Relaunch the daemon via `relaunch_cmd` (defaults to
           `<python_exe> -m one_link.cli daemon`).
        4. Log to ~/.one-link-update.log so the user can see what
           happened if something goes wrong.

    Returns the path to the generated script. Caller is responsible
    for running it as a detached subprocess.
    """
    relaunch = relaunch_cmd or [python_exe, "-m", "one_link.cli", "daemon"]
    # Use repr() to embed safe Python literals; the script is run
    # by the host's own Python so there's no shell-escaping concern.
    script_src = f"""# Auto-generated by one_link.updater. Do not edit.
import os, sys, time, subprocess, pathlib, logging
PARENT_PID = {parent_pid!r}
WHEEL_PATH = {str(wheel_path)!r}
PYTHON_EXE = {python_exe!r}
RELAUNCH = {relaunch!r}
LOG_PATH = pathlib.Path.home() / '.one-link-update.log'

logging.basicConfig(
    filename=str(LOG_PATH),
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
)
log = logging.getLogger('updater')

def _alive(pid):
    if pid <= 0: return False
    if os.name == 'nt':
        import ctypes
        h = ctypes.WinDLL('kernel32', use_last_error=True).OpenProcess(
            0x1000, False, pid
        )
        if not h: return False
        try:
            code = ctypes.c_ulong()
            ctypes.WinDLL('kernel32').GetExitCodeProcess(h, ctypes.byref(code))
            return code.value == 259  # STILL_ACTIVE
        finally:
            ctypes.WinDLL('kernel32').CloseHandle(h)
    try:
        os.kill(pid, 0); return True
    except (OSError, ProcessLookupError):
        return False

log.info('updater starting; waiting for daemon PID %s to exit', PARENT_PID)
deadline = time.time() + 30.0
while _alive(PARENT_PID) and time.time() < deadline:
    time.sleep(0.5)
if _alive(PARENT_PID):
    log.warning('parent did not exit within 30s; continuing anyway')
time.sleep(1.0)  # let file handles release

log.info('running pip install %s', WHEEL_PATH)
rc = subprocess.call(
    [PYTHON_EXE, '-m', 'pip', 'install', '--user',
     '--force-reinstall', '--no-deps', WHEEL_PATH]
)
if rc == 0:
    log.info('pip install succeeded')
else:
    log.error('pip install failed (exit %s); restarting OLD daemon', rc)

log.info('relaunching daemon: %s', RELAUNCH)
try:
    # On Windows we want the daemon detached + windowless so it
    # doesn't pop a console. On POSIX, plain Popen + start_new_session
    # handles the detach.
    if os.name == 'nt':
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        subprocess.Popen(
            RELAUNCH,
            creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
        )
    else:
        subprocess.Popen(RELAUNCH, start_new_session=True, close_fds=True)
    log.info('daemon relaunched')
except Exception as e:
    log.exception('daemon relaunch FAILED: %s', e)

# Clean up the wheel file so /tmp doesn't accumulate cruft.
try:
    os.unlink(WHEEL_PATH)
except OSError:
    pass
"""
    fd, path = tempfile.mkstemp(prefix="ol_updater_", suffix=".py")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(script_src)
    return Path(path)


def spawn_detached(script_path: Path, python_exe: str = sys.executable) -> int:
    """Spawn the updater script as a fully-detached subprocess.
    Returns the PID. Mocked in tests."""
    if os.name == "nt":
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        proc = subprocess.Popen(
            [python_exe, str(script_path)],
            creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    else:
        proc = subprocess.Popen(
            [python_exe, str(script_path)],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    return proc.pid
