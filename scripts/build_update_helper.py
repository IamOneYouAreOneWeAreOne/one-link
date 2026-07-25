"""Build the isolated one-file updater and prove its frozen dependencies.

The normal One Link onedir intentionally excludes Sigstore.  This script
creates a separate one-file executable containing only the authenticated
update path and Sigstore's full verification dependency/resource graph.  The
result is copied into the application bundle before its internal manifest and
release ZIP are generated, so the release signature covers the helper bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys


REQUIRED_IMPORTS = (
    "sigstore",
    "sigstore.hashes",
    "sigstore.models",
    "sigstore.verify.policy",
    "sigstore.verify.verifier",
    "sigstore_models.common.v1",
    "rekor_types",
    "tuf",
)

COLLECT_DATA = (
    "sigstore",
    "sigstore_models",
    "tuf",
    "securesystemslib",
)

# Verification needs Sigstore, TUF, Pydantic, cryptography, and HTTP. It does
# not need Sigstore's signing/OIDC CLI, Python build tooling, test plugins, or
# scientific/image stacks discovered by broad third-party PyInstaller hooks.
# Keeping those modules out makes the privileged replacement helper smaller
# and materially reduces its frozen import and binary attack surface.
EXCLUDED_IMPORTS = (
    "IPython",
    "PIL",
    "hypothesis",
    "jupyter",
    "keyring",
    "matplotlib",
    "mypy",
    "numpy",
    "pandas",
    "pytest",
    "pygments",
    "rich",
    "setuptools",
    "sigstore._cli",
    "sigstore.sign",
    "sympy",
    "wheel",
    "cffi._shimmed_dist_utils",
    "cffi.ffiplatform",
    "cffi.recompiler",
    "cffi.setuptools_ext",
    "cffi.verifier",
    "cffi.vengine_cpy",
    "cffi.vengine_gen",
    "pydantic.mypy",
    "pydantic.v1._hypothesis_plugin",
    "pydantic.v1.mypy",
)
WORK_ROOT_MARKER = ".one-link-update-helper-work-v1"
WORK_ROOT_MARKER_CONTENT = "one-link-update-helper-work/v1\n"


class UpdateHelperBuildError(RuntimeError):
    """The release helper could not be built or proved complete."""


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0) or 0)
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse)


def _canonical_absolute(path: Path, *, label: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute() or any(part == ".." for part in candidate.parts):
        raise UpdateHelperBuildError(f"{label} must be an absolute traversal-free path")
    normalized = Path(os.path.abspath(candidate))
    if normalized != candidate or normalized == Path(normalized.anchor):
        raise UpdateHelperBuildError(f"{label} is not a safe canonical path")
    current = Path(normalized.anchor)
    for component in normalized.parts[1:]:
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            break
        except OSError as exc:
            raise UpdateHelperBuildError(f"{label} ancestry is unreadable") from exc
        if _is_link_or_reparse(metadata):
            raise UpdateHelperBuildError(f"{label} ancestry contains a link or reparse point")
    return normalized


def _initialize_work_root(work: Path) -> None:
    try:
        work.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = os.lstat(work)
    except OSError as exc:
        raise UpdateHelperBuildError("helper work root cannot be created safely") from exc
    if _is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise UpdateHelperBuildError("helper work root is not a real directory")
    if os.name != "nt":
        work.chmod(0o700)
    marker = work / WORK_ROOT_MARKER
    try:
        marker_metadata = os.lstat(marker)
    except FileNotFoundError:
        if any(work.iterdir()):
            raise UpdateHelperBuildError(
                "helper work root is nonempty and lacks its ownership marker"
            )
        try:
            with marker.open("x", encoding="ascii", newline="") as stream:
                stream.write(WORK_ROOT_MARKER_CONTENT)
                stream.flush()
                os.fsync(stream.fileno())
            marker_metadata = os.lstat(marker)
        except OSError as exc:
            raise UpdateHelperBuildError("helper work marker cannot be published") from exc
    except OSError as exc:
        raise UpdateHelperBuildError("helper work marker cannot be inspected") from exc
    try:
        marker_content = marker.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise UpdateHelperBuildError("helper work marker is unreadable") from exc
    if (
        _is_link_or_reparse(marker_metadata)
        or not stat.S_ISREG(marker_metadata.st_mode)
        or marker_content != WORK_ROOT_MARKER_CONTENT
    ):
        raise UpdateHelperBuildError("helper work marker is invalid")


def _reset_derived_directory(directory: Path, *, work: Path) -> None:
    if directory.parent != work:
        raise UpdateHelperBuildError("derived helper directory escaped its work root")
    try:
        metadata = os.lstat(directory)
    except FileNotFoundError:
        metadata = None
    except OSError as exc:
        raise UpdateHelperBuildError("derived helper directory is unreadable") from exc
    if metadata is not None:
        if _is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise UpdateHelperBuildError("derived helper path is not a real directory")
        shutil.rmtree(directory)
    directory.mkdir(mode=0o700)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_command(
    *,
    entry: Path,
    dist_dir: Path,
    work_dir: Path,
    spec_dir: Path,
    name: str,
    icon: Path | None = None,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onefile",
        # The helper is always spawned with CREATE_NO_WINDOW/closed handles,
        # so a console never flashes in production. Keeping a real stderr
        # stream makes build-time dependency self-test failures diagnosable.
        "--console",
        "--name",
        name,
        "--distpath",
        str(dist_dir),
        "--workpath",
        str(work_dir),
        "--specpath",
        str(spec_dir),
    ]
    # Collect only non-Python trust-root/model resources. Static analysis plus
    # the exact hidden-import list below brings the verifier's executable
    # dependency closure without unnecessarily shipping Sigstore's signer,
    # interactive OIDC, test, or repository-authoring surfaces.
    for module in COLLECT_DATA:
        command.extend(("--collect-data", module))
    for module in REQUIRED_IMPORTS:
        command.extend(("--hidden-import", module))
    for module in EXCLUDED_IMPORTS:
        command.extend(("--exclude-module", module))
    if icon is not None:
        command.extend(("--icon", str(icon)))
    command.append(str(entry))
    return command


def build_update_helper(
    *,
    repo: Path,
    output: Path,
    work_root: Path,
    icon: Path | None = None,
) -> Path:
    root = Path(repo).resolve(strict=True)
    entry = root / "scripts" / "update_helper_entry.py"
    if entry.is_symlink() or not entry.is_file():
        raise UpdateHelperBuildError("update helper entry point is absent or unsafe")
    for module in REQUIRED_IMPORTS:
        try:
            importlib.import_module(module)
        except ImportError as exc:
            raise UpdateHelperBuildError(
                f"release environment lacks required helper dependency: {module}"
            ) from exc
    target = _canonical_absolute(Path(output), label="helper output")
    work = _canonical_absolute(Path(work_root), label="helper work root")
    if target == root or root in target.parents:
        # Release output lives under dist/ inside a checkout by design.  Only
        # reject source-package paths; build/dist are derived roots.
        try:
            relative = target.relative_to(root)
        except ValueError:  # pragma: no cover - guarded by condition
            relative = None
        if relative is not None and relative.parts[:1] not in {("build",), ("dist",)}:
            raise UpdateHelperBuildError("helper output would overwrite repository source")
    if target == work or work in target.parents:
        raise UpdateHelperBuildError("helper output overlaps its disposable work root")
    if work == root or root in work.parents:
        relative_work = work.relative_to(root)
        if relative_work.parts[:1] not in {("build",), ("dist",)}:
            raise UpdateHelperBuildError("helper work root overlaps repository source")
    _initialize_work_root(work)
    helper_name = "one-link-update-helper"
    built_name = helper_name + (".exe" if os.name == "nt" else "")
    dist_dir = work / "dist"
    pyinstaller_work = work / "work"
    spec_dir = work / "spec"
    for directory in (dist_dir, pyinstaller_work, spec_dir):
        _reset_derived_directory(directory, work=work)
    command = build_command(
        entry=entry,
        dist_dir=dist_dir,
        work_dir=pyinstaller_work,
        spec_dir=spec_dir,
        name=helper_name,
        icon=icon,
    )
    completed = subprocess.run(command, cwd=root, check=False)
    if completed.returncode != 0:
        raise UpdateHelperBuildError(
            f"PyInstaller update helper build failed with exit {completed.returncode}"
        )
    built = dist_dir / built_name
    if built.is_symlink() or not built.is_file() or built.stat().st_size <= 0:
        raise UpdateHelperBuildError("PyInstaller did not emit the update helper")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= int(getattr(os, "O_BINARY", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(temporary, flags, 0o700)
        with built.open("rb") as source, os.fdopen(descriptor, "wb") as destination:
            descriptor = -1
            shutil.copyfileobj(source, destination, length=1024 * 1024)
            destination.flush()
            os.fsync(destination.fileno())
        if os.name != "nt":
            temporary.chmod(0o700)
        if temporary.stat().st_size != built.stat().st_size or _sha256(temporary) != _sha256(
            built
        ):
            raise UpdateHelperBuildError("copied update helper differs from build output")
        os.replace(temporary, target)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    metadata = target.stat()
    if (
        _is_link_or_reparse(os.lstat(target))
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size != built.stat().st_size
        or _sha256(target) != _sha256(built)
    ):
        raise UpdateHelperBuildError("published update helper failed size validation")
    smoke = subprocess.run(
        [str(target), "--self-test"],
        cwd=target.parent,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
        check=False,
    )
    if (
        smoke.returncode != 0
        or smoke.stdout.strip() != "one-link-update-helper self-test ok"
        or smoke.stderr.strip()
    ):
        raise UpdateHelperBuildError(
            "frozen update helper failed its exact Sigstore dependency self-test: "
            f"{(smoke.stderr or smoke.stdout or 'no diagnostic').strip()[:500]}"
        )
    print(
        f"[update-helper] OK -> {target} "
        f"({metadata.st_size:,} bytes, sha256={_sha256(target)})"
    )
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--icon", type=Path, default=None)
    args = parser.parse_args(argv)
    repo = Path(__file__).resolve().parents[1]
    try:
        build_update_helper(
            repo=repo,
            output=args.output,
            work_root=args.work_root,
            icon=args.icon,
        )
    except (OSError, subprocess.SubprocessError, UpdateHelperBuildError) as exc:
        print(f"[update-helper] build failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
