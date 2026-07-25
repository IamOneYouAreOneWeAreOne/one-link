"""Authenticated update metadata, artifact selection, and verification.

Legacy native-wheel update substrate. Builds on update_check.py:

    Phase 1 (CI)      — release.yml ships native wheels on every v* tag
    Phase 2 (read)    — daemon polls GitHub, UI shows "Update available" banner
    Phase 3 (this)    — select and authenticate the exact native artifact.

Safety properties:

    * No production endpoint or background task performs in-place wheel
      installation.
    * Sigstore verification is mandatory for both SHA256SUMS and the wheel.
      The certificate identity is pinned to the canonical GitHub Actions
      release workflow at the exact immutable tag. SHA-256 is checked only
      after the manifest has authenticated successfully.
    * No network calls in this module's import path. All HTTP happens
      inside the functions, so tests can monkey-patch without spinning
      up an event loop.

This module remains a read-only planning and authentication substrate for the
retired wheel path. Full-application updates use ``standalone_updater`` and
the separately frozen ``update_helper``. ``server.py`` exposes that path only
as an explicit, confirmed one-shot handoff from a locally validated standalone
bundle; unattended/background installation remains disabled.
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Optional

from packaging.tags import Tag, sys_tags
from packaging.utils import (
    InvalidWheelFilename,
    canonicalize_name,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

from one_link.process_security import (
    hidden_creationflags,
    resolve_explicit_executable,
    trusted_process_env,
)
from one_link.safe_http import validated_urlopen

log = logging.getLogger("one_link.updater")

UPDATE_REPO = "IamOneYouAreOneWeAreOne/one-link"
UPDATE_WORKFLOW_PATH = ".github/workflows/release.yml"
UPDATE_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
MAX_UPDATE_METADATA_BYTES = 4 * 1024 * 1024
MAX_UPDATE_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
UPDATE_DISK_RESERVE_BYTES = 512 * 1024 * 1024
MAX_WHEEL_MEMBERS = 100_000
MAX_WHEEL_UNCOMPRESSED_BYTES = 8 * 1024 * 1024 * 1024
SIGSTORE_VERIFY_TIMEOUT_S = 180.0
_RELEASE_TAG_RE = re.compile(
    r"^v(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:(?:a|b|rc)[0-9]+|-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
    r"(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$",
)


# ─── data shapes ──────────────────────────────────────────────────────

@dataclass
class WheelMatch:
    """A wheel asset on a GitHub Release that matches this host's
    Python ABI + OS + arch. The updater downloads exactly this."""

    asset_url: str
    filename: str
    size: int
    expected_sha256: Optional[str] = None  # None until SHA256SUMS parsed
    bundle_url: Optional[str] = None
    bundle_size: int = 0
    manifest_url: Optional[str] = None
    manifest_size: int = 0
    manifest_bundle_url: Optional[str] = None
    manifest_bundle_size: int = 0

    @property
    def has_signature_contract(self) -> bool:
        return bool(
            self.expected_sha256
            and self.bundle_url
            and self.bundle_size > 0
            and self.manifest_url
            and self.manifest_size > 0
            and self.manifest_bundle_url
            and self.manifest_bundle_size > 0
        )


@dataclass
class InstallPlan:
    """Everything the install handler needs to know to make a decision:
    which wheel will be installed, where, and whether the host has
    enough info to proceed."""

    status: str  # 'ready' | 'unverified' | 'no_match' | 'no_release' | 'error'
    tag: Optional[str] = None
    wheel: Optional[WheelMatch] = None
    error: Optional[str] = None
    # Cached so the UI can echo the version they're about to install.
    latest_version: Optional[str] = None

    def to_dict(self) -> dict:
        out: dict[str, object] = {"status": self.status}
        if self.tag:
            out["tag"] = self.tag
        if self.latest_version:
            out["latest_version"] = self.latest_version
        if self.wheel:
            out["wheel"] = {
                "filename": self.wheel.filename,
                "size": self.wheel.size,
                "sha256_known": bool(self.wheel.expected_sha256),
                "sigstore_contract_known": self.wheel.has_signature_contract,
            }
        if self.error:
            out["error"] = self.error
        return out


@dataclass(frozen=True)
class PreparedUpdate:
    """A locally staged artifact whose release identity is authenticated."""

    artifact_path: Path
    authenticated_sha256: str


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


def _custom_host_tag_matches(candidate: Tag, host_tag: str) -> bool:
    """Compatibility helper for deterministic cross-platform tests.

    Production selection uses :func:`packaging.tags.sys_tags`; this helper is
    intentionally narrower and never guesses that musllinux is compatible
    with a glibc ``linux_*`` host (or vice versa).
    """

    try:
        interpreter, abi, expected_platform = host_tag.split("-", 2)
    except ValueError:
        return False
    if candidate.interpreter != interpreter or candidate.abi != abi:
        return False
    if candidate.platform == expected_platform:
        return True
    if expected_platform.startswith("linux_"):
        arch = expected_platform.removeprefix("linux_")
        return (
            candidate.platform.startswith("manylinux")
            and candidate.platform.endswith(f"_{arch}")
        )
    mac_host = re.fullmatch(r"macosx_(\d+)_(\d+)_(arm64|x86_64)", expected_platform)
    mac_wheel = re.fullmatch(r"macosx_(\d+)_(\d+)_universal2", candidate.platform)
    if mac_host and mac_wheel:
        host_floor = (int(mac_host.group(1)), int(mac_host.group(2)))
        wheel_floor = (int(mac_wheel.group(1)), int(mac_wheel.group(2)))
        return wheel_floor <= host_floor
    return False


def _wheel_matches_host(filename: str, host_tag: str | None = None) -> bool:
    """Return whether a canonical native wheel is supported by this host.

    Wheel filenames are parsed with the PyPA reference implementation. This
    prevents substring/architecture aliases from accepting the wrong libc,
    Python floor, ABI, distribution, or platform.
    """

    try:
        distribution, _version, _build, candidate_tags = parse_wheel_filename(
            filename,
        )
    except (InvalidWheelFilename, ValueError):
        return False
    if canonicalize_name(str(distribution)) != canonicalize_name("one_link_native"):
        return False
    if host_tag is not None:
        return any(
            _custom_host_tag_matches(candidate, host_tag)
            for candidate in candidate_tags
        )
    supported = set(sys_tags())
    return not candidate_tags.isdisjoint(supported)


def _resolve_target_python_executable(
    executable: str | os.PathLike[str],
) -> str:
    """Validate Python without escaping a virtual environment symlink.

    On POSIX, ``venv/bin/python`` normally points at the base interpreter.
    Resolving that symlink before invoking ``pip`` silently targets the base
    environment. Preserve the absolute venv entry point only when its
    ``pyvenv.cfg`` proves the environment boundary; otherwise retain the
    stricter canonical executable returned by the process-security layer.
    """

    path = Path(executable)
    validated_target = resolve_explicit_executable(path)
    if not path.is_absolute() or not path.is_symlink():
        return validated_target
    venv_config = path.parent.parent / "pyvenv.cfg"
    try:
        config_info = venv_config.lstat()
    except OSError:
        return validated_target
    if venv_config.is_symlink() or not stat.S_ISREG(config_info.st_mode):
        return validated_target
    return str(path.absolute())


def select_wheel_for_host(
    assets: list[dict],
    host_tag: Optional[str] = None,
) -> Optional[WheelMatch]:
    """Pick the right wheel from a GitHub Release's `assets` array.
    Returns None if no asset matches this host."""
    tag = host_tag
    for asset in assets or []:
        if not isinstance(asset, dict):
            continue
        name = asset.get("name", "")
        if not isinstance(name, str):
            continue
        if _wheel_matches_host(name, tag):
            url = asset.get("browser_download_url")
            size = asset.get("size")
            if (
                not isinstance(url, str)
                or not url
                or type(size) is not int
                or size <= 0
                or size > MAX_UPDATE_ARTIFACT_BYTES
            ):
                continue
            return WheelMatch(
                asset_url=url,
                filename=name,
                size=size,
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
    with validated_urlopen(req, timeout=timeout) as resp:
        if resp.status != 200:
            raise urllib.error.HTTPError(
                url, resp.status, resp.reason, resp.headers, None
            )
        body = resp.read(MAX_UPDATE_METADATA_BYTES + 1)
        if len(body) > MAX_UPDATE_METADATA_BYTES:
            raise ValueError("update metadata exceeds the 4 MiB hard limit")
        return body


def _safe_asset_filename(value: str | None) -> str:
    filename = value or "payload.bin"
    if (
        not isinstance(filename, str)
        or not filename
        or len(filename) > 255
        or Path(filename).name != filename
        or "/" in filename
        or "\\" in filename
        or filename in {".", ".."}
        or any(ord(character) < 32 for character in filename)
    ):
        raise ValueError("update asset filename is not a safe basename")
    return filename


def remove_staged_file(path: Path) -> None:
    """Remove a private updater asset and its now-empty staging directory."""

    candidate = Path(path)
    with contextlib_suppress():
        candidate.unlink(missing_ok=True)
    try:
        parent = candidate.parent.resolve(strict=True)
        temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
        if parent.parent == temp_root and parent.name.startswith("ol_update_"):
            parent.rmdir()
    except OSError:
        pass


def download_to_temp(
    url: str,
    *,
    expected_size: int = 0,
    timeout: float = 60.0,
    fetch: FetchFn = _default_http_get_bytes,
    artifact_filename: str | None = None,
) -> Path:
    """Download one release asset with an exact, bounded byte contract.

    GitHub's declared asset size is not an authenticity proof, but it is a
    useful pre-authentication resource bound.  The Sigstore verifier later
    establishes provenance; this helper ensures an attacker cannot make the
    daemon buffer an unbounded response before that verification occurs.
    """

    if (
        type(expected_size) is not int
        or expected_size <= 0
        or expected_size > MAX_UPDATE_ARTIFACT_BYTES
    ):
        raise ValueError("update asset has an invalid or excessive declared size")
    filename = _safe_asset_filename(artifact_filename)
    stage_dir = Path(tempfile.mkdtemp(prefix="ol_update_"))
    with contextlib_suppress():
        stage_dir.chmod(0o700)
    path = stage_dir / filename
    open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        open_flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        open_flags |= os.O_NOFOLLOW
    fd = -1
    try:
        free_bytes = shutil.disk_usage(stage_dir).free
        if free_bytes < expected_size + UPDATE_DISK_RESERVE_BYTES:
            raise OSError(
                "insufficient temporary-disk space for update staging",
            )
        fd = os.open(path, open_flags, 0o600)
        with os.fdopen(fd, "wb") as f:
            fd = -1
            if fetch is _default_http_get_bytes:
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "one-link-updater/0.21",
                        "Accept": "application/octet-stream",
                    },
                )
                with validated_urlopen(req, timeout=timeout) as response:
                    declared = response.headers.get("Content-Length")
                    if declared is not None:
                        try:
                            if int(declared) != expected_size:
                                raise ValueError(
                                    "update asset Content-Length does not match release metadata"
                                )
                        except (TypeError, ValueError) as exc:
                            raise ValueError(
                                "update asset has an invalid Content-Length"
                            ) from exc
                    remaining = expected_size
                    while remaining:
                        chunk = response.read(min(1024 * 1024, remaining + 1))
                        if not chunk:
                            break
                        if len(chunk) > remaining:
                            raise ValueError("update asset exceeded its declared size")
                        f.write(chunk)
                        remaining -= len(chunk)
                    if remaining or response.read(1):
                        raise ValueError("update asset length does not match release metadata")
            else:
                body = fetch(url, timeout)
                if len(body) != expected_size:
                    raise ValueError(
                        "update asset length does not match release metadata"
                    )
                f.write(body)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        if fd >= 0:
            with contextlib_suppress():
                os.close(fd)
        remove_staged_file(path)
        raise
    return path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_native_wheel(path: Path, expected_filename: str) -> None:
    """Validate the authenticated wheel's archive shape before pip sees it."""

    candidate = Path(path)
    if candidate.name != expected_filename or not expected_filename.endswith(".whl"):
        raise ValueError("staged wheel filename does not match release metadata")
    try:
        with zipfile.ZipFile(candidate, "r") as archive:
            members = archive.infolist()
            if not members or len(members) > MAX_WHEEL_MEMBERS:
                raise ValueError("wheel member count is empty or excessive")
            total_uncompressed = 0
            names: set[str] = set()
            dist_info_roots: set[str] = set()
            for member in members:
                name = member.filename
                posix = PurePosixPath(name)
                raw_parts = name.rstrip("/").split("/")
                mode = (int(member.external_attr) >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                if (
                    not name
                    or "\\" in name
                    or name.startswith("/")
                    or posix.is_absolute()
                    or any(part in {"", ".", ".."} for part in raw_parts)
                    or any(ord(character) < 32 for character in name)
                    or name in names
                    or member.flag_bits & 0x1
                    or member.file_size < 0
                    or member.compress_size < 0
                    or file_type not in {0, stat.S_IFREG, stat.S_IFDIR}
                ):
                    raise ValueError("wheel contains an unsafe archive member")
                names.add(name)
                total_uncompressed += int(member.file_size)
                if total_uncompressed > MAX_WHEEL_UNCOMPRESSED_BYTES:
                    raise ValueError("wheel uncompressed size is excessive")
                first = posix.parts[0]
                if first.endswith(".dist-info"):
                    dist_info_roots.add(first)
            if len(dist_info_roots) != 1:
                raise ValueError("wheel must contain exactly one dist-info directory")
            dist_info = next(iter(dist_info_roots))
            if not dist_info.lower().startswith("one_link_native-"):
                raise ValueError("wheel distribution is not one_link_native")
            required = {
                f"{dist_info}/METADATA",
                f"{dist_info}/RECORD",
                f"{dist_info}/WHEEL",
            }
            if not required.issubset(names):
                raise ValueError("wheel is missing required distribution metadata")
            corrupt_member = archive.testzip()
            if corrupt_member is not None:
                raise ValueError("wheel CRC validation failed")
    except zipfile.BadZipFile as exc:
        raise ValueError("authenticated artifact is not a valid wheel") from exc


def _valid_release_tag(tag: str) -> bool:
    return len(str(tag)) <= 128 and bool(_RELEASE_TAG_RE.fullmatch(str(tag)))


def _version_from_release_tag(tag: str) -> Version:
    if not _valid_release_tag(tag):
        raise ValueError("release tag is not canonical")
    try:
        return Version(tag.removeprefix("v"))
    except InvalidVersion as exc:
        raise ValueError("release tag version is invalid") from exc


def _wheel_version_matches_release(filename: str, tag: str) -> bool:
    try:
        distribution, wheel_version, _build, _tags = parse_wheel_filename(
            filename,
        )
        release_version = _version_from_release_tag(tag)
    except (InvalidWheelFilename, ValueError):
        return False
    return (
        canonicalize_name(str(distribution))
        == canonicalize_name("one_link_native")
        and wheel_version == release_version
    )


def _unique_asset(assets: list[dict], name: str) -> dict | None:
    matches = [asset for asset in assets if asset.get("name") == name]
    if len(matches) != 1:
        return None
    asset = matches[0]
    url = asset.get("browser_download_url")
    size = asset.get("size")
    if not isinstance(url, str) or not url:
        return None
    if type(size) is not int or size <= 0 or size > MAX_UPDATE_ARTIFACT_BYTES:
        return None
    return asset


def _exact_manifest_hash(manifest_text: str, artifact_filename: str) -> str | None:
    """Return one canonical hash entry, rejecting duplicates and aliases."""

    matches: list[str] = []
    for raw in manifest_text.splitlines():
        parts = raw.strip().split()
        if len(parts) != 2 or parts[-1].lstrip("*") != artifact_filename:
            continue
        digest = parts[0].lower()
        if len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            return None
        matches.append(digest)
    return matches[0] if len(matches) == 1 else None


def _run_sigstore_identity_verify(
    *,
    artifact: Path,
    bundle: Path,
    tag: str,
) -> None:
    """Verify one bundle against the exact release workflow/tag identity."""

    if not _valid_release_tag(tag):
        raise ValueError("release tag is not canonical")
    for path in (artifact, bundle):
        info = Path(path).lstat()
        if Path(path).is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
            raise ValueError("Sigstore input must be a non-empty regular file")
    expected_identity = (
        f"https://github.com/{UPDATE_REPO}/{UPDATE_WORKFLOW_PATH}"
        f"@refs/tags/{tag}"
    )
    python_exe = _resolve_target_python_executable(sys.executable)
    command = [
        python_exe,
        "-P",
        "-m",
        "sigstore",
        "verify",
        "identity",
        "--bundle",
        str(Path(bundle).resolve(strict=True)),
        "--cert-identity",
        expected_identity,
        "--cert-oidc-issuer",
        UPDATE_OIDC_ISSUER,
        str(Path(artifact).resolve(strict=True)),
    ]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed interpreter + argv
            command,
            shell=False,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=SIGSTORE_VERIFY_TIMEOUT_S,
            env=trusted_process_env(),
            cwd=str(Path(python_exe).resolve().parent),
            creationflags=hidden_creationflags(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"Sigstore verifier could not run: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "verification failed").strip()
        raise RuntimeError(f"Sigstore identity verification failed: {detail[:500]}")


def verify_signed_update(
    *,
    artifact: Path,
    artifact_bundle: Path,
    manifest: Path,
    manifest_bundle: Path,
    artifact_filename: str,
    tag: str,
) -> str:
    """Authenticate an update and return its signed expected SHA-256.

    The manifest signature is verified before its hash is parsed.  Exactly one
    canonical entry must name the selected artifact, and the artifact itself
    must carry a second identity-bound Sigstore bundle.
    """

    if Path(artifact_filename).name != artifact_filename or not artifact_filename:
        raise ValueError("update artifact filename is not a safe basename")
    _run_sigstore_identity_verify(
        artifact=manifest,
        bundle=manifest_bundle,
        tag=tag,
    )
    manifest_bytes = Path(manifest).read_bytes()
    if not manifest_bytes or len(manifest_bytes) > MAX_UPDATE_METADATA_BYTES:
        raise ValueError("signed SHA256SUMS is empty or oversized")
    try:
        manifest_text = manifest_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ValueError("signed SHA256SUMS is not UTF-8") from exc
    expected_hash = _exact_manifest_hash(manifest_text, artifact_filename)
    if expected_hash is None:
        raise ValueError("signed manifest must contain exactly one artifact hash")
    actual = sha256_file(Path(artifact))
    if actual != expected_hash:
        raise ValueError("update artifact does not match the signed manifest")
    _run_sigstore_identity_verify(
        artifact=artifact,
        bundle=artifact_bundle,
        tag=tag,
    )
    return expected_hash


def prepare_signed_update(
    wheel: WheelMatch,
    *,
    tag: str,
    timeout: float = 60.0,
    download: Callable[..., Path] = download_to_temp,
) -> PreparedUpdate:
    """Download and authenticate every input needed for one update.

    Only the verified wheel survives a successful call.  Bundles and the
    manifest are removed immediately; any failure removes all downloaded
    inputs so a retry cannot accidentally reuse unauthenticated bytes.
    """

    if not wheel.has_signature_contract or not _valid_release_tag(tag):
        raise ValueError("update plan lacks a complete signature contract")
    assert wheel.bundle_url is not None
    assert wheel.manifest_url is not None
    assert wheel.manifest_bundle_url is not None
    downloaded: list[Path] = []
    artifact_path: Path | None = None
    prepared = False
    try:
        artifact_path = download(
            wheel.asset_url,
            expected_size=wheel.size,
            timeout=timeout,
            artifact_filename=wheel.filename,
        )
        downloaded.append(artifact_path)
        artifact_bundle = download(
            wheel.bundle_url,
            expected_size=wheel.bundle_size,
            timeout=timeout,
            artifact_filename=f"{wheel.filename}.sigstore",
        )
        downloaded.append(artifact_bundle)
        manifest = download(
            wheel.manifest_url,
            expected_size=wheel.manifest_size,
            timeout=timeout,
            artifact_filename="SHA256SUMS",
        )
        downloaded.append(manifest)
        manifest_bundle = download(
            wheel.manifest_bundle_url,
            expected_size=wheel.manifest_bundle_size,
            timeout=timeout,
            artifact_filename="SHA256SUMS.sigstore",
        )
        downloaded.append(manifest_bundle)
        authenticated_hash = verify_signed_update(
            artifact=artifact_path,
            artifact_bundle=artifact_bundle,
            manifest=manifest,
            manifest_bundle=manifest_bundle,
            artifact_filename=wheel.filename,
            tag=tag,
        )
        validate_native_wheel(artifact_path, wheel.filename)
        prepared = True
        return PreparedUpdate(
            artifact_path=artifact_path,
            authenticated_sha256=authenticated_hash,
        )
    finally:
        for path in downloaded:
            if prepared and artifact_path is not None and path == artifact_path:
                continue
            remove_staged_file(path)


# Tiny stand-in for contextlib.suppress to avoid pulling in another
# import here. Keeps the module's surface narrow.
class contextlib_suppress:
    def __enter__(self): return self
    def __exit__(self, exc_type, exc, tb): return True


# ─── plan + execute ───────────────────────────────────────────────────

def build_install_plan(
    *,
    owner: str = "IamOneYouAreOneWeAreOne",
    repo: str = "one-link",
    timeout: float = 6.0,
    current_version: str | None = None,
    minimum_version: str | None = None,
    expected_tag: str | None = None,
    fetch_json: Callable[[str, float], dict] | None = None,
    fetch_bytes: FetchFn = _default_http_get_bytes,
) -> InstallPlan:
    """Inspect the latest stable release and build a fail-closed plan.

    ``ready`` means that the release advertises every artifact needed for the
    identity-bound Sigstore verification ceremony.  It does *not* mean the
    unsigned GitHub asset metadata has authenticated those bytes yet; the
    install endpoint downloads and verifies both bundles before it can spawn
    an updater.
    """
    from one_link.update_check import _build_url, _default_fetch
    fetch_json = fetch_json or _default_fetch
    try:
        payload = fetch_json(_build_url(owner, repo), timeout)
    except Exception as e:
        return InstallPlan(status="no_release", error=f"fetch latest: {e}")
    if not isinstance(payload, dict):
        return InstallPlan(status="no_release", error="release payload is not an object")
    tag_value = payload.get("tag_name")
    tag = tag_value.strip() if isinstance(tag_value, str) else ""
    if not _valid_release_tag(tag):
        return InstallPlan(status="unverified", error="release tag is not canonical")
    if expected_tag is not None and tag != expected_tag:
        return InstallPlan(
            status="release_changed",
            tag=tag,
            latest_version=tag,
            error="latest release changed after the update was presented",
        )
    try:
        release_version = _version_from_release_tag(tag)
        if current_version is None:
            from one_link import __version__ as current_version
        installed_version = Version(str(current_version).strip())
        version_floor = (
            Version(str(minimum_version).strip())
            if minimum_version is not None and str(minimum_version).strip()
            else None
        )
    except (InvalidVersion, ValueError) as exc:
        return InstallPlan(
            status="unverified",
            tag=tag,
            latest_version=tag,
            error=f"update version boundary is invalid: {exc}",
        )
    if release_version <= installed_version:
        return InstallPlan(
            status="not_newer",
            tag=tag,
            latest_version=tag,
            error="release is not newer than the running application",
        )
    if version_floor is not None and release_version < version_floor:
        return InstallPlan(
            status="rollback_blocked",
            tag=tag,
            latest_version=tag,
            error="release is below the authenticated update high-water mark",
        )
    if payload.get("draft") is True or payload.get("prerelease") is True:
        return InstallPlan(
            status="unverified",
            tag=tag,
            latest_version=tag,
            error="automatic installation accepts stable non-draft releases only",
        )
    assets_value = payload.get("assets")
    if not isinstance(assets_value, list) or len(assets_value) > 5_000:
        return InstallPlan(
            status="unverified",
            tag=tag,
            latest_version=tag,
            error="release asset metadata is malformed or excessive",
        )
    if any(not isinstance(asset, dict) for asset in assets_value):
        return InstallPlan(
            status="unverified",
            tag=tag,
            latest_version=tag,
            error="release contains malformed asset metadata",
        )
    assets: list[dict] = assets_value
    names = [asset.get("name") for asset in assets]
    if any(not isinstance(name, str) or not name or len(name) > 255 for name in names):
        return InstallPlan(
            status="unverified",
            tag=tag,
            latest_version=tag,
            error="release contains an invalid asset name",
        )
    if len(set(names)) != len(names):
        return InstallPlan(
            status="unverified",
            tag=tag,
            latest_version=tag,
            error="release contains duplicate asset names",
        )
    wheel = select_wheel_for_host(assets)
    if wheel is None:
        return InstallPlan(
            status="no_match",
            tag=tag,
            latest_version=tag,
            error=f"no wheel for {host_wheel_tag()} in release {tag}",
        )
    if not _wheel_version_matches_release(wheel.filename, tag):
        return InstallPlan(
            status="unverified",
            tag=tag,
            latest_version=tag,
            wheel=wheel,
            error="native wheel version does not match the immutable release tag",
        )
    wheel_asset = _unique_asset(assets, wheel.filename)
    manifest_asset = _unique_asset(assets, "SHA256SUMS")
    manifest_bundle_asset = _unique_asset(assets, "SHA256SUMS.sigstore")
    wheel_bundle_asset = _unique_asset(assets, f"{wheel.filename}.sigstore")
    if not all(
        (wheel_asset, manifest_asset, manifest_bundle_asset, wheel_bundle_asset),
    ):
        return InstallPlan(
            status="unverified",
            tag=tag,
            latest_version=tag,
            wheel=wheel,
            error=(
                "release is missing a unique wheel, SHA256SUMS, or required "
                "Sigstore bundle"
            ),
        )
    assert wheel_asset is not None
    assert manifest_asset is not None
    assert manifest_bundle_asset is not None
    assert wheel_bundle_asset is not None
    metadata_assets = (
        manifest_asset,
        manifest_bundle_asset,
        wheel_bundle_asset,
    )
    if any(
        int(asset["size"]) > MAX_UPDATE_METADATA_BYTES
        for asset in metadata_assets
    ):
        return InstallPlan(
            status="unverified",
            tag=tag,
            latest_version=tag,
            wheel=wheel,
            error="release signature metadata exceeds the 4 MiB hard limit",
        )
    wheel.asset_url = str(wheel_asset["browser_download_url"])
    wheel.size = int(wheel_asset["size"])
    wheel.bundle_url = str(wheel_bundle_asset["browser_download_url"])
    wheel.bundle_size = int(wheel_bundle_asset["size"])
    wheel.manifest_url = str(manifest_asset["browser_download_url"])
    wheel.manifest_size = int(manifest_asset["size"])
    wheel.manifest_bundle_url = str(
        manifest_bundle_asset["browser_download_url"],
    )
    wheel.manifest_bundle_size = int(manifest_bundle_asset["size"])
    try:
        manifest_body = fetch_bytes(wheel.manifest_url, timeout)
        if not manifest_body or len(manifest_body) > MAX_UPDATE_METADATA_BYTES:
            raise ValueError("SHA256SUMS is empty or oversized")
        manifest_text = manifest_body.decode("utf-8", "strict")
        wheel.expected_sha256 = _exact_manifest_hash(
            manifest_text,
            wheel.filename,
        )
    except Exception as exc:
        log.info("update: SHA256SUMS preflight failed: %s", exc)
    if not wheel.has_signature_contract:
        return InstallPlan(
            status="unverified",
            tag=tag,
            latest_version=tag,
            wheel=wheel,
            error="release manifest does not contain one canonical wheel hash",
        )
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
    expected_sha256: str | None = None,
) -> Path:
    """Refuse the retired non-transactional in-place installation handoff.

    The parameters remain for a narrow compatibility window so older callers
    fail explicitly instead of importing a missing symbol. Authenticated
    staging is read-only with respect to the running application.
    """

    raise RuntimeError(
        "in-place update handoff is disabled until transactional "
        "full-app rollback is implemented",
    )


def spawn_detached(script_path: Path, python_exe: str = sys.executable) -> int:
    """Refuse detached execution of historical updater scripts."""

    raise RuntimeError(
        "in-place update handoff is disabled until transactional "
        "full-app rollback is implemented",
    )
