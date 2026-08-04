"""The bundle member manifest had two producers that disagreed.

`scripts/package_standalone_bundle.py` (release.yml) writes the five-column TSV
that `one_link.update_transaction` parses. `auto_build.yml` wrote its own
inline snippet emitting classic sha256sum output -- ``"<digest>  <path>"``, two
columns, no header.

The consumer requires the header, so every bundle from the continuous/rolling
build failed `validate_installed_bundle`. Measured on the real frozen Windows
bundle from auto_build run 30874782709:

    update_install_available = False
    update_install_reason    = 'managed_bundle_validation_failed'

and on the released v0.21.0 bundle, the same check passes. Rewriting only the
manifest of the failing bundle -- changing nothing else -- flipped the live
daemon to `available = True`. Because the website's download button points at
the rolling channel, the bundle users actually install was the broken one:
their in-app updater could never activate, even once a tagged release existed.

Nothing reported it. `inspect_external_update_capability` caught every
exception and collapsed it to one opaque token, discarding the real message
("bundle member manifest has an invalid header") at that line.

These tests pin the shape of the fix: one writer, importing the format from the
parser, and a real round trip through the product's own validator.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
WRITER = REPO / "scripts" / "write_bundle_manifest.py"
AUTO_BUILD = REPO / ".github" / "workflows" / "auto_build.yml"

from one_link.update_transaction import (  # noqa: E402
    ARCHIVE_MANIFEST_HEADER,
    UpdateArchiveError,
    validate_installed_bundle,
)


def make_bundle(root: Path, *, executable: str = "one-link") -> Path:
    """A minimal but structurally real managed bundle."""
    bundle = root / "one-link"
    (bundle / "_internal").mkdir(parents=True)
    (bundle / executable).write_bytes(b"MZ fake launcher payload")
    (bundle / "BUILD_INFO.txt").write_text("commit: deadbeef\n", encoding="utf-8")
    (bundle / "_internal" / "lib.dat").write_bytes(b"\x00\x01\x02" * 100)
    if os.name != "nt":
        os.chmod(bundle / executable, 0o755)
    return bundle


def write_manifest(bundle: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(WRITER), "--bundle", str(bundle), "--root-name", "one-link"],
        capture_output=True,
        text=True,
        check=False,
    )


def test_the_writer_exists() -> None:
    assert WRITER.is_file()


def test_the_written_manifest_uses_the_parser_s_own_header(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    proc = write_manifest(bundle)
    assert proc.returncode == 0, proc.stderr
    first = (bundle / "BUNDLE_SHA256SUMS").read_text(encoding="utf-8").splitlines()[0]
    assert first == ARCHIVE_MANIFEST_HEADER


def test_a_written_bundle_passes_the_product_s_own_validator(tmp_path: Path) -> None:
    """The round trip. A header alone is not proof the bundle validates."""
    executable = "one-link.exe" if os.name == "nt" else "one-link"
    bundle = make_bundle(tmp_path, executable=executable)
    assert write_manifest(bundle).returncode == 0
    tree = validate_installed_bundle(bundle, expected_executable=executable)
    assert tree.file_count == 3, f"expected 3 members, got {tree.file_count}"
    assert tree.manifest_sha256


def test_the_old_sha256sum_format_is_still_rejected(tmp_path: Path) -> None:
    """The control, and the exact bytes that shipped.

    If the parser ever started accepting this, the gate above would pass for
    the wrong reason and the defect could return silently.
    """
    executable = "one-link.exe" if os.name == "nt" else "one-link"
    bundle = make_bundle(tmp_path, executable=executable)
    rows = []
    for path in sorted(p for p in bundle.rglob("*") if p.is_file()):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(f"{digest}  one-link/{path.relative_to(bundle).as_posix()}")
    (bundle / "BUNDLE_SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")
    with pytest.raises(UpdateArchiveError, match="invalid header"):
        validate_installed_bundle(bundle, expected_executable=executable)


def test_a_tampered_member_is_still_caught(tmp_path: Path) -> None:
    """Second control: the manifest must still be doing integrity work."""
    executable = "one-link.exe" if os.name == "nt" else "one-link"
    bundle = make_bundle(tmp_path, executable=executable)
    assert write_manifest(bundle).returncode == 0
    (bundle / "_internal" / "lib.dat").write_bytes(b"tampered")
    with pytest.raises(UpdateArchiveError):
        validate_installed_bundle(bundle, expected_executable=executable)


def test_an_extra_file_is_still_caught(tmp_path: Path) -> None:
    executable = "one-link.exe" if os.name == "nt" else "one-link"
    bundle = make_bundle(tmp_path, executable=executable)
    assert write_manifest(bundle).returncode == 0
    (bundle / "_internal" / "smuggled.dll").write_bytes(b"extra")
    with pytest.raises(UpdateArchiveError):
        validate_installed_bundle(bundle, expected_executable=executable)


def test_the_manifest_never_lists_itself(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    assert write_manifest(bundle).returncode == 0
    body = (bundle / "BUNDLE_SHA256SUMS").read_text(encoding="utf-8")
    rows = [line for line in body.splitlines()[1:] if line]
    assert not any(row.split("\t")[3].endswith("BUNDLE_SHA256SUMS") for row in rows)


def test_the_continuous_build_uses_the_single_writer() -> None:
    """auto_build.yml must not grow a second implementation again."""
    text = AUTO_BUILD.read_text(encoding="utf-8")
    assert "scripts/write_bundle_manifest.py" in text, (
        "the continuous build no longer calls the canonical manifest writer"
    )
    assert "--verify" in text, (
        "the continuous build must re-read its manifest through the product's "
        "validator; without that, a format drift ships silently again"
    )
    # The exact shape of the old inline producer.
    assert 'rows.append(f"{digest.hexdigest()}  {path.as_posix()}")' not in text, (
        "the sha256sum-format inline manifest producer is back"
    )


def test_macos_self_install_cannot_validate_in_either_channel() -> None:
    """A registered gap, asserted rather than assumed.

    validate_installed_bundle requires every manifest row to start with
    "one-link". The macOS contract puts the launcher at
    Contents/MacOS/one-link, so the install root is the .app directory, and the
    RELEASED macOS manifest is rooted at "one-link.app" (verified against
    v0.21.0's one-link-macos-arm64.zip, which carries 126 SYMLINK rows under
    that root). Those two rules cannot both hold, so macOS self-install
    validates in neither the released nor the rolling channel.

    Reconciling them changes either the manifest root convention or the
    validator, and both reach signed release artifacts -- a product decision,
    not a cleanup. This test exists so the gap cannot be forgotten: when it is
    fixed, this fails and tells you to re-enable --verify on macOS in
    auto_build.yml.
    """
    from one_link.update_metadata import PLATFORM_CONTRACTS

    macos = PLATFORM_CONTRACTS["macos-arm64"]
    assert macos.executable == "Contents/MacOS/one-link", (
        "the macOS launcher path changed; re-derive whether the install root "
        f"is still the .app: {macos.executable!r}"
    )

    source = (REPO / "src" / "one_link" / "update_transaction.py").read_text(
        encoding="utf-8"
    )
    assert 'parts[:1] != ("one-link",)' in source, (
        "validate_installed_bundle no longer hardcodes the 'one-link' manifest "
        "root. If it now accepts the .app root, macOS self-install may work -- "
        "re-enable --verify for macOS in auto_build.yml and delete this test."
    )

    workflow = AUTO_BUILD.read_text(encoding="utf-8")
    assert 'if [ "${RUNNER_OS}" = "macOS" ]' in workflow, (
        "the macOS --verify exception must stay explicit and commented, not "
        "quietly dropped"
    )


def test_the_capability_failure_is_no_longer_silent() -> None:
    source = (REPO / "src" / "one_link" / "update_helper.py").read_text(encoding="utf-8")
    marker = "managed bundle validation failed; in-app update is unavailable"
    assert marker in source, (
        "inspect_external_update_capability must log WHY it failed. Collapsing "
        "every exception to an opaque token is how this defect stayed hidden."
    )
