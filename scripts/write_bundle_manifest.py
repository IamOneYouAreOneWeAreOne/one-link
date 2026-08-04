#!/usr/bin/env python3
"""Write a managed bundle's on-disk BUNDLE_SHA256SUMS in the canonical format.

There were two producers of this file and they disagreed.

`scripts/package_standalone_bundle.py` (used by release.yml) writes the
five-column TSV that `one_link.update_transaction` parses. `auto_build.yml`
wrote its own inline snippet emitting classic `sha256sum` output --
``"<digest>  <path>"``, two columns, no header. The consumer requires the
header, so every bundle from the continuous/rolling build failed
`validate_installed_bundle`, and `inspect_external_update_capability` returned

    update_install_available = False
    update_install_reason    = 'managed_bundle_validation_failed'

on a real frozen Windows bundle. Because the website's download button points
at the rolling channel, that is the bundle users actually install: their
in-app update capability could never activate, even once a tagged release
appeared. The released v0.21.0 bundle validates; the rolling one does not.

Nothing reported this. `inspect_external_update_capability` catches every
exception and collapses it to one opaque reason, so the true error --
"bundle member manifest has an invalid header" -- never reached a log.

This script is the single writer for the on-disk form. It imports the header
and row shape from `one_link.update_transaction` rather than restating them,
so the format cannot drift here again: if the parser changes, this changes
with it or fails loudly.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from pathlib import Path, PurePosixPath

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from one_link.update_transaction import (  # noqa: E402
    ARCHIVE_MANIFEST_HEADER,
    MAX_ARCHIVE_MANIFEST_BYTES,
)

MANIFEST_NAME = "BUNDLE_SHA256SUMS"
_BLOCK = 1024 * 1024


def _digest_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(_BLOCK), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def build_rows(bundle: Path, root_name: str) -> list[str]:
    """One row per member, in the exact shape the parser accepts.

    Ordering is by POSIX path so the manifest is byte-identical across
    GNU/Linux, macOS and Windows for the same tree.
    """
    rows: list[str] = []
    entries: list[Path] = []
    for directory, directory_names, file_names in os.walk(bundle, followlinks=False):
        directory_names.sort()
        file_names.sort()
        parent = Path(directory)
        for name in directory_names:
            child = parent / name
            if child.is_symlink():
                entries.append(child)
        entries.extend(parent / name for name in file_names)

    for path in sorted(entries, key=lambda p: p.relative_to(bundle).as_posix()):
        relative = path.relative_to(bundle).as_posix()
        if relative == MANIFEST_NAME:
            # Excluded from itself: a manifest cannot contain its own digest.
            continue
        archive_name = PurePosixPath(root_name, relative).as_posix()
        if path.is_symlink():
            target = os.readlink(path)
            encoded = target.encode("utf-8")
            rows.append(
                "\t".join(
                    (
                        hashlib.sha256(encoded).hexdigest(),
                        "SYMLINK",
                        str(len(encoded)),
                        archive_name,
                        target,
                    )
                )
            )
            continue
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"refusing to manifest a special entry: {path}")
        digest, size = _digest_file(path)
        rows.append("\t".join((digest, "FILE", str(size), archive_name, "")))
    return rows


def write_manifest(bundle: Path, root_name: str | None = None) -> Path:
    bundle = bundle.resolve(strict=True)
    if not bundle.is_dir():
        raise SystemExit(f"not a directory: {bundle}")
    manifest_path = bundle / MANIFEST_NAME
    # Remove first so a stale file can never be manifested as a member.
    manifest_path.unlink(missing_ok=True)
    rows = build_rows(bundle, root_name or bundle.name)
    body = "\n".join([ARCHIVE_MANIFEST_HEADER, *rows]) + "\n"
    encoded = body.encode("utf-8")
    if len(encoded) > MAX_ARCHIVE_MANIFEST_BYTES:
        raise SystemExit(
            f"manifest is {len(encoded)} bytes, over the "
            f"{MAX_ARCHIVE_MANIFEST_BYTES} the parser accepts"
        )
    manifest_path.write_bytes(encoded)
    print(f"wrote {manifest_path} ({len(rows)} members, {len(encoded):,} bytes)")
    return manifest_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument(
        "--root-name",
        default=None,
        help=(
            "Archive-name prefix for every row. Defaults to the bundle "
            "directory name. The installed-tree validator requires 'one-link'."
        ),
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Re-read the result through the real parser before exiting.",
    )
    args = parser.parse_args(argv)
    write_manifest(args.bundle, args.root_name)
    if args.verify:
        # Proving the file we just wrote is one the PRODUCT accepts, using the
        # product's own validator rather than a restatement of it. This is the
        # check whose absence let the two formats diverge unnoticed.
        from one_link.update_transaction import validate_installed_bundle

        executable = os.environ.get("ONE_LINK_BUNDLE_EXECUTABLE")
        if not executable:
            raise SystemExit(
                "--verify needs ONE_LINK_BUNDLE_EXECUTABLE (the bundle-relative "
                "path of the launcher) so the validator can check it"
            )
        tree = validate_installed_bundle(
            args.bundle.resolve(strict=True), expected_executable=executable
        )
        print(
            f"validated: {tree.file_count} members, "
            f"{tree.payload_bytes:,} payload bytes, "
            f"manifest sha256={tree.manifest_sha256}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
