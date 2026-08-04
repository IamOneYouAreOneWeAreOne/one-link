"""Two implementations decide whether a bundle is valid, and they disagree.

`scripts/package_standalone_bundle.py` validates at RELEASE time and
`one_link.update_transaction` validates at INSTALL time. They share no code for
the manifest rules. The packager signs and ships a macOS bundle the updater
will always refuse, so macOS self-install is dead in both channels and nothing
reports it -- the two validators never meet.

This is the same class as the manifest FORMAT divergence fixed earlier the same
day (auto_build wrote classic sha256sum output while the parser required a
five-column TSV, leaving the in-app updater dead on the bundle the website
hands out). One contract, two implementations, no conformance check.

Measured against the real v0.21.0 `one-link-macos-arm64.zip`, 701 members and
126 symlinks:

  RULE 1  root name        701/701 rows rejected by the updater today.
                           0/701 rejected once the root is DERIVED from the
                           bundle directory, which is what the packager
                           already does (`_archive_root_for`, and
                           `validate_bundle_archive` discovers it from the
                           archive). The updater simply never got that
                           treatment -- it hardcodes ("one-link",) in three
                           places.

  RULE 2  symlink targets  79/126 symlinks STILL rejected after the root is
                           fixed. PyInstaller's macOS layout chains symlinks
                           THROUGH symlinked directories:
                             Python.framework/Python -> Versions/Current/Python
                             Python.framework/Versions/Current -> 3.12
                             PIL/.dylibs -> __dot__dylibs
                           The updater requires a symlink's resolved target to
                           be a LITERAL manifest entry, which a chain can never
                           satisfy. The packager instead requires lexical
                           containment plus real on-disk resolution inside the
                           bundle -- a rule that is compatible with chains and
                           has validated every shipped macOS release.

So the fix is TWO changes, not one, and rule 1 alone delivers nothing a user
can see. Rule 2 rewrites a containment check in the code that replaces the
installed application; today it fails CLOSED, and a subtly wrong change would
make it fail OPEN. That wants a macOS runner, not a Windows workstation.

These tests pin the contract so it cannot drift further, and pin the
divergence so that closing it is what turns them red.
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


def test_the_packager_accepts_an_app_root_that_the_updater_refuses(tmp_path: Path) -> None:
    """THE DIVERGENCE, pinned.

    macOS ships `one-link.app`. The packager derives the archive root from the
    bundle directory and is happy. The updater hardcodes ("one-link",) and
    refuses every row.

    When rule 1 is fixed this test FAILS, which is the point: it is the
    reminder that rule 2 must be closed in the same pass, because rule 1 alone
    changes nothing a macOS user can observe.
    """
    executable = "Contents/MacOS/one-link"
    bundle = build_bundle(tmp_path, "one-link.app", executable)

    packager = load_packager()
    archive = tmp_path / "mac.zip"
    packager.package_bundle(bundle, archive, executable=executable, epoch=1700000000)
    with zipfile.ZipFile(archive) as z:
        roots = {n.split("/")[0] for n in z.namelist()}
    assert roots == {"one-link.app"}, f"packager did not honour the .app root: {roots}"

    # ...and the updater refuses it outright.
    write_installed_manifest(bundle, "one-link.app")
    with pytest.raises(UpdateArchiveError) as excinfo:
        validate_installed_bundle(bundle, expected_executable=executable)
    assert "unsafe archive member path" in str(excinfo.value) or "bundle root" in str(
        excinfo.value
    ), f"expected a root rejection, got: {excinfo.value}"


def test_rule_two_rejects_a_chained_symlink_independently_of_the_root() -> None:
    """Rule 2 is a SECOND blocker, provable without a filesystem.

    `_safe_symlink_target` requires a symlink's resolved target to be a literal
    manifest entry. A chain through a symlinked directory -- exactly what
    Python.framework and PIL/.dylibs do on macOS -- can never satisfy that,
    whatever the root is called. 79 of 126 symlinks in the real v0.21.0 macOS
    bundle fail this way.
    """
    from one_link.update_transaction import _ManifestRow, _safe_symlink_target

    # The real shape, with the root renamed to the one the updater accepts so
    # that ONLY rule 2 can be responsible for the rejection.
    names = {
        "one-link/Frameworks/Python.framework/Versions/Current",
        "one-link/Frameworks/Python.framework/Versions/3.12/Python",
        "one-link/Frameworks/Python.framework/Python",
    }
    chained = _ManifestRow(
        digest="0" * 64,
        kind="SYMLINK",
        size=len("Versions/Current/Python"),
        path="one-link/Frameworks/Python.framework/Python",
        target="Versions/Current/Python",
    )
    with pytest.raises(UpdateArchiveError, match="escapes or targets missing content"):
        _safe_symlink_target(chained, names)

    # Control: an UNchained symlink to a real member is accepted, so the
    # rejection above is about the chain and not about symlinks in general.
    direct = _ManifestRow(
        digest="0" * 64,
        kind="SYMLINK",
        size=len("3.12/Python"),
        path="one-link/Frameworks/Python.framework/Versions/Python",
        target="3.12/Python",
    )
    _safe_symlink_target(direct, names)


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


def test_the_updater_hardcodes_the_root_in_every_place_it_checks() -> None:
    """Names the exact sites a fix has to touch, so none is missed.

    A partial fix that updates the installed-bundle path but not the archive
    path would let a macOS release verify on download and then fail to
    validate once installed -- a worse failure than the current honest refusal.
    """
    source = (REPO / "src" / "one_link" / "update_transaction.py").read_text(
        encoding="utf-8"
    )
    assert source.count('("one-link",)') == 3, (
        "the number of hardcoded bundle roots changed. The three are: "
        "_validate_archive_name (every manifest row), _safe_symlink_target "
        "(resolved link targets), and validate_installed_bundle (re-deriving "
        "relative paths). If one was parameterised, do the rest."
    )
    assert 'ARCHIVE_MANIFEST = "one-link/BUNDLE_SHA256SUMS"' in source, (
        "the archive-side manifest path is also root-dependent and must be "
        "derived in the same pass"
    )
