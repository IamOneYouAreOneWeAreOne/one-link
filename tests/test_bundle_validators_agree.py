"""Two implementations decide whether a bundle is valid. They must agree.

`scripts/package_standalone_bundle.py` validates at RELEASE time and
`one_link.update_transaction` validates at INSTALL time, and they share no code
for the manifest rules. They disagreed, and macOS was the casualty: the packager
signed and shipped a bundle the updater refused every row of, so macOS
self-install was dead in both channels and nothing reported it -- the two
validators never met.

Same class as the manifest FORMAT divergence fixed the same day (auto_build
wrote classic sha256sum output while the parser required a five-column TSV,
leaving the in-app updater dead on the bundle the website hands out). One
contract, two implementations, no conformance check.

Measured against the real v0.21.0 `one-link-macos-arm64.zip`, 701 members and
126 symlinks, it was TWO defects:

  RULE 1  root name       701/701 rows refused. The packager DERIVES the
                          archive root from the bundle directory
                          (`_archive_root_for`); the updater hardcoded
                          ("one-link",) in three places. macOS installs as
                          `one-link.app`, because its launcher is
                          Contents/MacOS/one-link and the install root is
                          therefore the .app itself.

  RULE 2  symlink targets 79/126 refused even after rule 1. PyInstaller's macOS
                          layout chains links THROUGH linked directories
                          (Python.framework/Python -> Versions/Current/Python
                          where Current -> 3.12; PIL/.dylibs -> __dot__dylibs),
                          so a resolved target is often not a literal manifest
                          entry and never can be.

Both are fixed. The root is derived, and symlink targets resolve through the
chain -- bounded against cycles, with containment enforced at EVERY hop rather
than only the first. Real bundle: 701/701 rows parsed, 126/126 symlinks
accepted.

These tests pin the agreement, and pin the properties any future change must
keep: escapes refused, later-hop escapes refused, cycles refused rather than
followed.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PACKAGER_PATH = REPO / "scripts" / "package_standalone_bundle.py"

from one_link.update_transaction import (  # noqa: E402
    UpdateArchiveError,
    validate_installed_bundle,
)


def load_packager():
    """Import the release-time packager as a module.

    It must be registered in sys.modules before exec_module or its
    @dataclass(frozen=True) fails resolving its own __module__.
    """
    spec = importlib.util.spec_from_file_location("_psb_under_test", PACKAGER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_psb_under_test"] = module
    spec.loader.exec_module(module)
    return module


def build_bundle(root: Path, name: str, executable: str) -> Path:
    bundle = root / name
    (bundle / "_internal").mkdir(parents=True)
    exe = bundle / executable
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_bytes(b"MZ launcher payload")
    (bundle / "_internal" / "lib.dat").write_bytes(b"\x01\x02\x03" * 64)
    if sys.platform != "win32":
        exe.chmod(0o755)
    return bundle


def write_installed_manifest(bundle: Path, root_name: str) -> None:
    subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts" / "write_bundle_manifest.py"),
            "--bundle", str(bundle),
            "--root-name", root_name,
        ],
        capture_output=True, text=True, check=True,
    )


def test_both_validators_are_reachable() -> None:
    # Without this, every comparison below would be vacuous.
    assert PACKAGER_PATH.is_file()
    packager = load_packager()
    assert hasattr(packager, "validate_bundle_archive")
    assert hasattr(packager, "package_bundle")


def test_they_agree_on_the_root_every_platform_actually_ships(tmp_path: Path) -> None:
    """Windows and Linux bundles are rooted 'one-link'. Both must accept."""
    executable = "one-link.exe" if sys.platform == "win32" else "one-link"
    bundle = build_bundle(tmp_path, "one-link", executable)

    packager = load_packager()
    archive = tmp_path / "out.zip"
    packager.package_bundle(bundle, archive, executable=executable, epoch=1700000000)
    # Packager accepts (it validates its own output before returning).
    packager.validate_bundle_archive(archive, expected_executable=f"one-link/{executable}")

    # Updater accepts the same tree.
    write_installed_manifest(bundle, "one-link")
    tree = validate_installed_bundle(bundle, expected_executable=executable)
    assert tree.file_count == 2, f"expected 2 members, got {tree.file_count}"


def test_both_validators_now_accept_the_app_root_macos_ships(tmp_path: Path) -> None:
    """THE DIVERGENCE, closed.

    This test used to assert the packager accepted an `.app` root the updater
    refused -- that was the bug, and it was written to go red when fixed.

    macOS ships `one-link.app`. The packager always derived the archive root
    from the bundle directory; the updater hardcoded ("one-link",) and refused
    all 701 rows of the real v0.21.0 macOS bundle. The updater now derives it
    too, so the release-time and install-time validators agree on every
    platform that ships.
    """
    executable = "Contents/MacOS/one-link"
    bundle = build_bundle(tmp_path, "one-link.app", executable)

    packager = load_packager()
    archive = tmp_path / "mac.zip"
    packager.package_bundle(bundle, archive, executable=executable, epoch=1700000000)
    with zipfile.ZipFile(archive) as z:
        roots = {n.split("/")[0] for n in z.namelist()}
    assert roots == {"one-link.app"}, f"packager did not honour the .app root: {roots}"

    # ...and the updater now accepts the very same tree.
    write_installed_manifest(bundle, "one-link.app")
    tree = validate_installed_bundle(bundle, expected_executable=executable)
    assert tree.file_count == 2, f"expected 2 members, got {tree.file_count}"


def test_a_chained_symlink_now_resolves_through_the_manifest() -> None:
    """Rule 2, closed -- and the control that it is the CHAIN being resolved.

    PyInstaller's macOS layout links THROUGH linked directories
    (Python.framework/Python -> Versions/Current/Python, where Current -> 3.12;
    PIL/.dylibs -> __dot__dylibs). Requiring a resolved target to be a literal
    manifest entry rejected 79 of the 126 symlinks in the real v0.21.0 macOS
    bundle. The resolver follows the chain, bounded, with containment checked
    at every hop.
    """
    from one_link.update_transaction import _ManifestRow, _safe_symlink_target

    rows = {
        "one-link/Frameworks/Python.framework/Versions/Current": _ManifestRow(
            digest="0" * 64, kind="SYMLINK", size=4,
            path="one-link/Frameworks/Python.framework/Versions/Current",
            target="3.12",
        ),
    }
    names = set(rows) | {
        "one-link/Frameworks/Python.framework/Versions/3.12/Python",
    }
    chained = _ManifestRow(
        digest="0" * 64, kind="SYMLINK", size=len("Versions/Current/Python"),
        path="one-link/Frameworks/Python.framework/Python",
        target="Versions/Current/Python",
    )
    _safe_symlink_target(chained, names, "one-link", rows)

    # CONTROL: the acceptance above must come from FOLLOWING the chain, not
    # from the resolver having gone permissive. Drop the intermediate link and
    # the same target no longer resolves to anything, so it must be refused.
    with pytest.raises(UpdateArchiveError, match="escapes or targets missing"):
        _safe_symlink_target(chained, names, "one-link", {})


def test_a_cyclic_symlink_chain_is_refused_not_followed_forever() -> None:
    from one_link.update_transaction import _ManifestRow, _safe_symlink_target

    rows = {
        "one-link/a": _ManifestRow(
            digest="0" * 64, kind="SYMLINK", size=6, path="one-link/a", target="b/deep",
        ),
        "one-link/b": _ManifestRow(
            digest="0" * 64, kind="SYMLINK", size=1, path="one-link/b", target="a",
        ),
    }
    with pytest.raises(UpdateArchiveError, match="too deep or cyclic"):
        _safe_symlink_target(rows["one-link/a"], set(rows), "one-link", rows)


def test_a_chain_that_escapes_on_a_LATER_hop_is_refused() -> None:
    """Containment is checked at every hop, not only the first."""
    from one_link.update_transaction import _ManifestRow, _safe_symlink_target

    rows = {
        "one-link/l1": _ManifestRow(
            digest="0" * 64, kind="SYMLINK", size=4, path="one-link/l1", target="l2/x",
        ),
        "one-link/l2": _ManifestRow(
            digest="0" * 64, kind="SYMLINK", size=12, path="one-link/l2",
            target="../../outside",
        ),
    }
    with pytest.raises(UpdateArchiveError, match="escapes the bundle root"):
        _safe_symlink_target(rows["one-link/l1"], set(rows), "one-link", rows)


def test_a_symlink_escaping_the_bundle_is_still_refused() -> None:
    """The property that must survive any future fix to rules 1 and 2."""
    from one_link.update_transaction import _ManifestRow, _safe_symlink_target

    for target in ("../../etc/passwd", "/etc/passwd", "..\\..\\windows"):
        row = _ManifestRow(
            digest="0" * 64, kind="SYMLINK", size=len(target),
            path="one-link/_internal/evil", target=target,
        )
        with pytest.raises(UpdateArchiveError):
            _safe_symlink_target(row, {"one-link/_internal/evil"})


def test_the_updater_no_longer_hardcodes_the_bundle_root() -> None:
    """A partial fix would be worse than none.

    Updating the installed-bundle path but not the archive path would let a
    macOS release verify on download and then fail to validate once installed
    -- a worse failure than the honest refusal it replaced.
    """
    source = (REPO / "src" / "one_link" / "update_transaction.py").read_text(
        encoding="utf-8"
    )
    assert '("one-link",)' not in source, (
        "a hardcoded bundle root is back; macOS bundles are rooted "
        "'one-link.app' and every row would be refused again"
    )
    assert "DEFAULT_ARCHIVE_ROOT" in source
    assert "_manifest_name_for" in source, (
        "the archive-side manifest path must be derived from the root too"
    )
