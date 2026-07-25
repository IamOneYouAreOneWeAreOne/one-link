"""Create a deterministic, integrity-indexed ZIP from a PyInstaller onedir.

One Link intentionally uses PyInstaller's onedir mode: its executable depends
on the adjacent ``_internal`` tree and runtime assets. Publishing only the
launcher produces a small, valid-looking file that cannot start. This utility
turns the complete directory into one release asset without silently dropping
dependencies, permissions, or safe in-tree symbolic links.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import posixpath
import stat
import tempfile
import unicodedata
import zipfile


class BundleError(RuntimeError):
    """The onedir tree cannot be represented as a safe release archive."""


@dataclass(frozen=True)
class Entry:
    source: Path
    archive_name: str
    mode: int
    size: int
    mtime_ns: int
    device: int
    inode: int
    symlink_target: str | None = None


_ARCHIVE_ROOT = "one-link"
_MANIFEST_NAME = "one-link/BUNDLE_SHA256SUMS"
_BLOCK_SIZE = 1024 * 1024
_MAX_MANIFEST_BYTES = 8 * 1024 * 1024
_WINDOWS_RESERVED_BASENAMES = frozenset(
    {"CLOCK$", "CON", "CONIN$", "CONOUT$", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
    | {f"COM{index}" for index in "¹²³"}
    | {f"LPT{index}" for index in "¹²³"}
)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _unsafe_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _collision_key(value: str) -> str:
    # NFC catches archives that are distinct byte strings on Linux but collapse
    # to the same pathname on normalization-insensitive extractors (notably
    # default macOS volumes); casefold covers Windows/macOS case collisions.
    normalized = unicodedata.normalize("NFC", value).replace("\\", "/")
    # Win32 strips terminal dots/spaces from every path component.  Folding
    # them here catches aliases even when validation is reused on an archive
    # produced elsewhere.
    return "/".join(part.rstrip(" .").casefold() for part in normalized.split("/"))


def _is_reparse(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & flag)


def _validate_portable_component(component: str, *, context: str) -> None:
    if (
        not component
        or component in {".", ".."}
        or _unsafe_control(component)
        or len(component.encode("utf-8", "surrogatepass")) > 255
    ):
        raise BundleError(f"unsafe portable path component in {context}: {component!r}")
    if component[-1:] in {" ", "."}:
        raise BundleError(f"Windows-truncated path component in {context}: {component!r}")
    if any(character in '<>:"/\\|?*' for character in component):
        raise BundleError(f"Windows-forbidden path character in {context}: {component!r}")
    basename = component.split(".", 1)[0].rstrip(" .").upper()
    if basename in _WINDOWS_RESERVED_BASENAMES:
        raise BundleError(f"Windows-reserved path component in {context}: {component!r}")


def _validate_portable_archive_path(value: str) -> None:
    if _unsafe_control(value) or "\\" in value or value.startswith("/"):
        raise BundleError(f"unsafe archive path: {value!r}")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or path.parts[:1] != (_ARCHIVE_ROOT,)
        # PurePosixPath collapses repeated separators, dot components, and a
        # trailing separator. Accepting a non-canonical spelling would let two
        # distinct ZIP member names extract to the same destination.
        or path.as_posix() != value
    ):
        raise BundleError(f"unsafe archive path: {value!r}")
    for component in path.parts:
        _validate_portable_component(component, context=value)


def _resolve_bundle(bundle: Path) -> Path:
    try:
        supplied_metadata = bundle.lstat()
    except OSError as exc:
        raise BundleError(f"bundle does not exist or cannot be inspected: {bundle}") from exc
    if stat.S_ISLNK(supplied_metadata.st_mode) or _is_reparse(supplied_metadata):
        raise BundleError(f"bundle root must not be a link or reparse point: {bundle}")
    try:
        root = bundle.resolve(strict=True)
    except OSError as exc:
        raise BundleError(f"bundle does not exist or cannot be resolved: {bundle}") from exc
    if not root.is_dir():
        raise BundleError(f"bundle is not a directory: {bundle}")
    return root


def _zip_timestamp(epoch: int) -> tuple[int, int, int, int, int, int]:
    # ZIP cannot represent dates before 1980 and stores seconds in two-second
    # increments. Clamping/rounding makes reruns stable and standards-compliant.
    instant = datetime.fromtimestamp(max(epoch, 315_532_800), tz=UTC)
    return (
        instant.year,
        instant.month,
        instant.day,
        instant.hour,
        instant.minute,
        instant.second - (instant.second % 2),
    )


def _collect(bundle: Path) -> list[Entry]:
    from one_link.build_identity import (
        STABLE_FROZEN_MAX_BUNDLE_BYTES,
        STABLE_FROZEN_MAX_DIRECTORIES,
        STABLE_FROZEN_MAX_ENTRIES,
        STABLE_FROZEN_MAX_FILES,
        STABLE_FROZEN_MAX_ZIP_MEMBERS,
    )

    root = _resolve_bundle(bundle)
    entries: list[Entry] = []
    discovered: list[Path] = []
    directory_count = 0
    entry_count = 0
    payload_bytes = 0

    def _walk_error(error: OSError) -> None:
        raise error

    try:
        for directory, directory_names, file_names in os.walk(
            root, followlinks=False, onerror=_walk_error
        ):
            directory_names.sort()
            file_names.sort()
            directory_count += 1
            entry_count += len(directory_names) + len(file_names)
            if directory_count > STABLE_FROZEN_MAX_DIRECTORIES:
                raise BundleError(
                    f"bundle directory budget exceeded: {directory_count} > "
                    f"{STABLE_FROZEN_MAX_DIRECTORIES}"
                )
            if entry_count + 1 > STABLE_FROZEN_MAX_ENTRIES:
                raise BundleError(
                    "bundle entry budget exceeded after reserving the manifest: "
                    f"{entry_count + 1} > {STABLE_FROZEN_MAX_ENTRIES}"
                )
            parent = Path(directory)
            for name in list(directory_names):
                child = parent / name
                metadata = child.lstat()
                if _is_reparse(metadata) and os.name == "nt":
                    raise BundleError(f"Windows reparse point in bundle: {child.relative_to(root)}")
                if stat.S_ISLNK(metadata.st_mode):
                    discovered.append(child)
                    directory_names.remove(name)
                elif not stat.S_ISDIR(metadata.st_mode):
                    raise BundleError(f"unsupported directory entry in bundle: {child}")
            discovered.extend(parent / name for name in file_names)
    except OSError as exc:
        raise BundleError(f"bundle cannot be enumerated safely: {root}: {exc}") from exc

    for source in sorted(discovered, key=lambda item: item.relative_to(root).as_posix()):
        relative = source.relative_to(root)
        archive = (
            PurePosixPath(_ARCHIVE_ROOT) / PurePosixPath(relative.as_posix())
        ).as_posix()
        _validate_portable_archive_path(archive)
        if _collision_key(archive) == _collision_key(_MANIFEST_NAME):
            raise BundleError(f"bundle collides with reserved manifest: {relative}")
        metadata = source.lstat()
        if _is_reparse(metadata) and os.name == "nt":
            raise BundleError(f"Windows reparse point in bundle: {relative}")
        if stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(source)
            if _unsafe_control(target):
                raise BundleError(f"symbolic link target contains a control character: {relative}")
            try:
                encoded_target = target.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise BundleError(f"symbolic link target is not portable UTF-8: {relative}") from exc
            windows_target = PureWindowsPath(target)
            if (
                PurePosixPath(target).is_absolute()
                or windows_target.is_absolute()
                or bool(windows_target.drive)
                or bool(windows_target.root)
            ):
                raise BundleError(f"symbolic link target is absolute: {relative} -> {target}")
            relocated = posixpath.normpath(
                str(PurePosixPath(archive).parent / PurePosixPath(target.replace("\\", "/")))
            )
            if relocated != _ARCHIVE_ROOT and not relocated.startswith(f"{_ARCHIVE_ROOT}/"):
                raise BundleError(
                    f"symbolic link escapes relocated archive: {relative} -> {target}"
                )
            try:
                resolved_target = source.resolve(strict=True)
            except OSError as exc:
                raise BundleError(
                    f"symbolic link target is missing or unreadable: {relative} -> {target}"
                ) from exc
            if not _inside(resolved_target, root):
                raise BundleError(f"symbolic link escapes bundle: {relative} -> {target}")
            payload_bytes += len(encoded_target)
            entries.append(
                Entry(
                    source,
                    archive,
                    metadata.st_mode,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    metadata.st_dev,
                    metadata.st_ino,
                    target,
                )
            )
        elif stat.S_ISREG(metadata.st_mode):
            payload_bytes += int(metadata.st_size)
            entries.append(
                Entry(
                    source,
                    archive,
                    metadata.st_mode,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    metadata.st_dev,
                    metadata.st_ino,
                )
            )
        elif stat.S_ISDIR(metadata.st_mode):
            continue
        else:
            raise BundleError(f"unsupported special file in bundle: {relative}")
        if len(entries) > STABLE_FROZEN_MAX_FILES:
            raise BundleError(
                f"bundle file budget exceeded: {len(entries)} > {STABLE_FROZEN_MAX_FILES}"
            )
        if len(entries) + 1 > STABLE_FROZEN_MAX_ZIP_MEMBERS:
            raise BundleError(
                "bundle ZIP-member budget exceeded after reserving the manifest: "
                f"{len(entries) + 1} > {STABLE_FROZEN_MAX_ZIP_MEMBERS}"
            )
        if payload_bytes > STABLE_FROZEN_MAX_BUNDLE_BYTES:
            raise BundleError(
                f"bundle byte budget exceeded: {payload_bytes} > "
                f"{STABLE_FROZEN_MAX_BUNDLE_BYTES}"
            )
    if not entries:
        raise BundleError("bundle contains no files")
    folded_names = [_collision_key(entry.archive_name) for entry in entries]
    if len(folded_names) != len(set(folded_names)):
        raise BundleError("bundle contains duplicate or case-colliding archive paths")
    return entries


def validate_bundle_archive(archive_path: Path, *, expected_executable: str) -> None:
    """Independently re-hash every ZIP member against BUNDLE_SHA256SUMS."""
    from one_link.build_identity import (
        STABLE_FROZEN_MAX_BUNDLE_BYTES,
        STABLE_FROZEN_MAX_ENTRIES,
        STABLE_FROZEN_MAX_ZIP_MEMBERS,
    )

    try:
        archive = zipfile.ZipFile(archive_path, "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise BundleError(f"standalone release ZIP is unreadable: {exc}") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > STABLE_FROZEN_MAX_ZIP_MEMBERS:
            raise BundleError(f"ZIP member budget exceeded: {len(infos)}")
        if len(infos) > STABLE_FROZEN_MAX_ENTRIES:
            raise BundleError(f"ZIP entry budget exceeded: {len(infos)}")
        total_uncompressed = sum(info.file_size for info in infos)
        if total_uncompressed > STABLE_FROZEN_MAX_BUNDLE_BYTES + _MAX_MANIFEST_BYTES:
            raise BundleError(f"ZIP uncompressed byte budget exceeded: {total_uncompressed}")
        names = [info.filename for info in infos]
        folded = [_collision_key(name) for name in names]
        if len(names) != len(set(names)) or len(folded) != len(set(folded)):
            raise BundleError("ZIP contains duplicate or portable-name-colliding members")
        for name in names:
            _validate_portable_archive_path(name)
        symlink_names = {
            info.filename for info in infos if stat.S_ISLNK(info.external_attr >> 16)
        }
        for name in names:
            parts = PurePosixPath(name).parts
            prefixes = {"/".join(parts[:index]) for index in range(1, len(parts))}
            if prefixes & symlink_names:
                raise BundleError(f"ZIP member is nested under a symlink: {name!r}")
        directory_members = [info.filename for info in infos if info.is_dir()]
        if directory_members:
            # The deterministic packager emits only files and symlinks. Empty
            # directory entries add no runtime value and are a common archive
            # bomb vector, so an independently supplied archive is rejected.
            raise BundleError(
                "ZIP contains unexpected explicit directory members: "
                + ", ".join(directory_members[:12])
            )
        if names.count(_MANIFEST_NAME) != 1:
            raise BundleError("ZIP must contain exactly one BUNDLE_SHA256SUMS")
        if names.count(expected_executable) != 1:
            raise BundleError("ZIP must contain exactly one declared bundle executable")

        with archive.open(_MANIFEST_NAME, "r") as stream:
            raw_manifest = stream.read(_MAX_MANIFEST_BYTES + 1)
        if len(raw_manifest) > _MAX_MANIFEST_BYTES:
            raise BundleError("BUNDLE_SHA256SUMS exceeds its byte budget")
        try:
            manifest_text = raw_manifest.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BundleError("BUNDLE_SHA256SUMS is not UTF-8") from exc
        lines = manifest_text.splitlines()
        if not lines or lines[0] != "# sha256\tkind\tbytes\tpath\ttarget":
            raise BundleError("BUNDLE_SHA256SUMS has an invalid header")
        rows: dict[str, tuple[str, str, int, str]] = {}
        for line in lines[1:]:
            fields = line.split("\t")
            if len(fields) != 5:
                raise BundleError("BUNDLE_SHA256SUMS has a malformed row")
            digest, kind, size_text, name, target = fields
            _validate_portable_archive_path(name)
            if name == _MANIFEST_NAME or name in rows:
                raise BundleError(f"duplicate/reserved manifest row: {name!r}")
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise BundleError(f"invalid manifest digest for {name!r}")
            try:
                size = int(size_text)
            except ValueError as exc:
                raise BundleError(f"invalid manifest byte count for {name!r}") from exc
            if size < 0 or kind not in {"FILE", "SYMLINK"}:
                raise BundleError(f"invalid manifest kind/size for {name!r}")
            rows[name] = (digest, kind, size, target)

        expected_names = set(names) - {_MANIFEST_NAME}
        if set(rows) != expected_names:
            raise BundleError(
                "BUNDLE_SHA256SUMS member set mismatch: "
                f"missing={sorted(expected_names - set(rows))!r}, "
                f"unexpected={sorted(set(rows) - expected_names)!r}"
            )
        for info in infos:
            if info.filename == _MANIFEST_NAME:
                continue
            expected_digest, kind, expected_size, target = rows[info.filename]
            mode = info.external_attr >> 16
            if kind == "SYMLINK":
                if not stat.S_ISLNK(mode):
                    raise BundleError(f"manifest marks non-symlink as symlink: {info.filename}")
            elif not stat.S_ISREG(mode):
                raise BundleError(
                    f"manifest regular file has a non-regular ZIP mode: {info.filename}"
                )
            digest = hashlib.sha256()
            actual_size = 0
            with archive.open(info, "r") as stream:
                for block in iter(lambda: stream.read(_BLOCK_SIZE), b""):
                    actual_size += len(block)
                    if actual_size > expected_size:
                        raise BundleError(f"ZIP member exceeds manifest size: {info.filename}")
                    digest.update(block)
            if actual_size != expected_size or info.file_size != expected_size:
                raise BundleError(f"ZIP member size mismatch: {info.filename}")
            if digest.hexdigest() != expected_digest:
                raise BundleError(f"ZIP member digest mismatch: {info.filename}")
            if kind == "SYMLINK":
                try:
                    decoded_target = archive.read(info).decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise BundleError(f"symlink target is not UTF-8: {info.filename}") from exc
                if decoded_target != target:
                    raise BundleError(f"symlink target mismatch: {info.filename}")
                target_path = PurePosixPath(target.replace("\\", "/"))
                windows_target = PureWindowsPath(target)
                if (
                    not target
                    or _unsafe_control(target)
                    or target_path.is_absolute()
                    or windows_target.is_absolute()
                    or windows_target.drive
                    or windows_target.root
                ):
                    raise BundleError(f"symlink target is unsafe: {info.filename}")
                relocated = PurePosixPath(
                    posixpath.normpath(
                        str(PurePosixPath(info.filename).parent / target_path)
                    )
                )
                relocated_name = relocated.as_posix()
                if (
                    relocated.parts[:1] != (_ARCHIVE_ROOT,)
                    or ".." in relocated.parts
                    or not (
                        relocated_name in names
                        or any(name.startswith(relocated_name + "/") for name in names)
                    )
                ):
                    raise BundleError(f"symlink target escapes or is absent: {info.filename}")
            elif target:
                raise BundleError(f"regular file has a symlink target: {info.filename}")
        if rows[expected_executable][1] != "FILE":
            raise BundleError("declared bundle executable must be a regular file")


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def package_bundle(
    bundle: Path,
    output: Path,
    *,
    executable: str,
    epoch: int,
) -> Path:
    if output.suffix.lower() != ".zip":
        raise BundleError("standalone release output must end in .zip")
    executable_path = PurePosixPath(executable)
    if (
        not executable
        or executable_path == PurePosixPath(".")
        or executable_path.is_absolute()
        or ".." in executable_path.parts
        or "\\" in executable
        or _unsafe_control(executable)
        or executable_path.as_posix() != executable
    ):
        raise BundleError(f"executable path must be bundle-relative: {executable!r}")

    root = _resolve_bundle(bundle)
    if _inside(output.resolve(strict=False), root):
        raise BundleError("release output must not be inside the input bundle")

    entries = _collect(bundle)
    expected_executable = (PurePosixPath(_ARCHIVE_ROOT) / executable_path).as_posix()
    executable_entries = [entry for entry in entries if entry.archive_name == expected_executable]
    if len(executable_entries) != 1 or executable_entries[0].symlink_target is not None:
        raise BundleError(f"bundle executable is missing or not a regular file: {executable}")
    executable_source = executable_entries[0].source
    if executable_source.stat().st_size <= 0:
        raise BundleError(f"bundle executable is empty: {executable}")
    if os.name != "nt" and not (executable_entries[0].mode & 0o111):
        raise BundleError(f"bundle executable lacks an execute bit: {executable}")

    timestamp = _zip_timestamp(epoch)
    output.parent.mkdir(parents=True, exist_ok=True)
    temp_handle = tempfile.NamedTemporaryFile(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent, delete=False
    )
    temporary = Path(temp_handle.name)
    temp_handle.close()
    try:
        manifest_rows = ["# sha256\tkind\tbytes\tpath\ttarget"]
        with zipfile.ZipFile(
            temporary,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            allowZip64=True,
        ) as archive:
            for entry in entries:
                info = zipfile.ZipInfo(entry.archive_name, date_time=timestamp)
                info.create_system = 3
                if entry.symlink_target is not None:
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    info.compress_type = zipfile.ZIP_STORED
                    link_payload = entry.symlink_target.encode("utf-8")
                    archive.writestr(info, link_payload)
                    manifest_rows.append(
                        "\t".join(
                            (
                                hashlib.sha256(link_payload).hexdigest(),
                                "SYMLINK",
                                str(len(link_payload)),
                                entry.archive_name,
                                entry.symlink_target,
                            )
                        )
                    )
                    continue
                info.external_attr = (entry.mode & 0xFFFF) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                try:
                    before = entry.source.lstat()
                except OSError as exc:
                    raise BundleError(
                        f"bundle file disappeared before packaging: {entry.source}"
                    ) from exc
                captured_identity = (
                    entry.mode,
                    entry.size,
                    entry.mtime_ns,
                    entry.device,
                    entry.inode,
                )
                before_identity = (
                    before.st_mode,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_dev,
                    before.st_ino,
                )
                if not stat.S_ISREG(before.st_mode) or before_identity != captured_identity:
                    raise BundleError(f"bundle file changed before packaging: {entry.source}")
                digest = hashlib.sha256()
                byte_count = 0
                try:
                    with entry.source.open("rb") as source_stream:
                        opened = os.fstat(source_stream.fileno())
                        if (
                            not stat.S_ISREG(opened.st_mode)
                            or opened.st_dev != before.st_dev
                            or opened.st_ino != before.st_ino
                        ):
                            raise BundleError(
                                f"bundle file was replaced while opening: {entry.source}"
                            )
                        with archive.open(info, mode="w", force_zip64=True) as archive_stream:
                            for block in iter(lambda: source_stream.read(_BLOCK_SIZE), b""):
                                digest.update(block)
                                byte_count += len(block)
                                archive_stream.write(block)
                except OSError as exc:
                    raise BundleError(f"bundle file cannot be read: {entry.source}") from exc
                try:
                    after = entry.source.lstat()
                except OSError as exc:
                    raise BundleError(
                        f"bundle file disappeared while packaging: {entry.source}"
                    ) from exc
                after_identity = (
                    after.st_mode,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_dev,
                    after.st_ino,
                )
                if byte_count != before.st_size or after_identity != before_identity:
                    raise BundleError(f"bundle file changed while packaging: {entry.source}")
                manifest_rows.append(
                    "\t".join(
                        (
                            digest.hexdigest(),
                            "FILE",
                            str(byte_count),
                            entry.archive_name,
                            "",
                        )
                    )
                )

            manifest_info = zipfile.ZipInfo(
                _MANIFEST_NAME, date_time=timestamp
            )
            manifest_info.create_system = 3
            manifest_info.external_attr = (stat.S_IFREG | 0o644) << 16
            manifest_info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(
                manifest_info,
                ("\n".join(manifest_rows) + "\n").encode("utf-8"),
            )

        validate_bundle_archive(temporary, expected_executable=expected_executable)
        os.replace(temporary, output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise

    print(
        f"packaged {len(entries)} bundle entries -> {output} "
        f"({output.stat().st_size:,} bytes, sha256={_digest_file(output)})"
    )
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--executable", required=True)
    parser.add_argument("--epoch", type=int, required=True)
    args = parser.parse_args(argv)
    package_bundle(
        args.bundle,
        args.output,
        executable=args.executable,
        epoch=args.epoch,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
