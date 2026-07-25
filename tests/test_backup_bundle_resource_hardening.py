"""Adversarial regressions for finite, rollback-safe `.olbak` restores."""
from __future__ import annotations

import gzip
import io
import os
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from one_link import backup_bundle


def _plaintext_archive(
    members: list[tuple[str, bytes]],
    *,
    manifest: list[tuple[str, int]] | None = None,
    extra_members: list[tarfile.TarInfo] | None = None,
) -> bytes:
    rows = manifest if manifest is not None else [
        (name, len(payload)) for name, payload in members
    ]
    manifest_payload = (
        "".join(f"{name}\t{size}\n" for name, size in rows).encode("utf-8")
    )
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            metadata = tarfile.TarInfo("MANIFEST")
            metadata.size = len(manifest_payload)
            archive.addfile(metadata, io.BytesIO(manifest_payload))
            for name, payload in members:
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            for info in extra_members or []:
                archive.addfile(info)
    return output.getvalue()


def _assert_no_restore_artifacts(target: Path) -> None:
    assert not list(target.glob(".bundle-import.*"))
    assert not list(target.glob(".bundle-rollback.*"))


def test_extract_streams_without_getmembers_readall_or_write_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plaintext = _plaintext_archive([
        ("state.db", b"s" * (2 * 1024 * 1024 + 17)),
        ("master.seed", b"m" * 32),
    ])

    def forbidden_getmembers(*_args, **_kwargs):
        raise AssertionError("restore must not materialize TarInfo.getmembers()")

    def forbidden_write_bytes(*_args, **_kwargs):
        raise AssertionError("restore must not materialize a whole file")

    real_read = tarfile.ExFileObject.read

    def bounded_read(self, size=-1):
        assert 0 <= size <= backup_bundle._ARCHIVE_COPY_CHUNK_BYTES
        return real_read(self, size)

    monkeypatch.setattr(tarfile.TarFile, "getmembers", forbidden_getmembers)
    monkeypatch.setattr(tarfile.ExFileObject, "read", bounded_read)
    monkeypatch.setattr(Path, "write_bytes", forbidden_write_bytes)
    target = tmp_path / "restore"
    written = backup_bundle.extract_bundle_to_dir(
        plaintext=plaintext,
        target_dir=target,
    )
    assert written == ["state.db", "master.seed"]
    assert (target / "state.db").stat().st_size == 2 * 1024 * 1024 + 17


def test_stream_parser_discards_stdlib_tarinfo_cache_per_member(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    member_count = 2_048
    plaintext = _plaintext_archive([
        (f"inbox/f{index:04d}.bin", b"") for index in range(member_count)
    ])
    real_next = tarfile.TarFile.next
    peak_cached_members = 0

    def tracked_next(self):
        nonlocal peak_cached_members
        member = real_next(self)
        peak_cached_members = max(peak_cached_members, len(self.members))
        return member

    monkeypatch.setattr(tarfile.TarFile, "next", tracked_next)
    names = backup_bundle.inspect_bundle_archive(plaintext=plaintext)

    assert len(names) == member_count
    assert names[0] == "inbox/f0000.bin"
    assert names[-1] == "inbox/f2047.bin"
    # TarFile.next() appends every parsed TarInfo even in r| stream mode.
    # Retaining that stdlib cache made peak RSS scale by hundreds of MiB at
    # the policy ceiling. The validator must keep only its current member.
    assert peak_cached_members <= 1


def test_member_count_limit_fails_closed_and_cleans_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plaintext = _plaintext_archive([("a", b"a"), ("b", b"b")])
    monkeypatch.setattr(backup_bundle, "MAX_ARCHIVE_MEMBERS", 2)
    target = tmp_path / "restore"
    with pytest.raises(ValueError, match="too many"):
        backup_bundle.extract_bundle_to_dir(
            plaintext=plaintext,
            target_dir=target,
        )
    assert not (target / "a").exists()
    _assert_no_restore_artifacts(target)


@pytest.mark.parametrize(
    ("constant", "value", "message"),
    [
        ("MAX_ARCHIVE_FILE_BYTES", 32, "per-file limit"),
        ("MAX_ARCHIVE_TOTAL_FILE_BYTES", 64, "aggregate file limit"),
    ],
)
def test_declared_file_budgets_are_enforced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    value: int,
    message: str,
) -> None:
    plaintext = _plaintext_archive([("state.db", b"x" * 48), ("seed", b"y" * 48)])
    monkeypatch.setattr(backup_bundle, constant, value)
    with pytest.raises(ValueError, match=message):
        backup_bundle.extract_bundle_to_dir(
            plaintext=plaintext,
            target_dir=tmp_path / "restore",
        )


def test_expansion_and_compressed_input_limits_are_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plaintext = _plaintext_archive([("state.db", b"z" * 4096)])
    monkeypatch.setattr(backup_bundle, "MIN_ARCHIVE_EXPANSION_ALLOWANCE_BYTES", 1)
    monkeypatch.setattr(backup_bundle, "MAX_ARCHIVE_EXPANSION_RATIO", 1)
    with pytest.raises(ValueError, match="expansion-ratio limit"):
        backup_bundle.inspect_bundle_archive(plaintext=plaintext)

    monkeypatch.setattr(backup_bundle, "MAX_BUNDLE_COMPRESSED_BYTES", len(plaintext) - 1)
    with pytest.raises(ValueError, match="compressed-payload limit"):
        backup_bundle.inspect_bundle_archive(plaintext=plaintext)


def test_duplicate_case_alias_and_manifest_mismatch_are_rejected(
    tmp_path: Path,
) -> None:
    duplicate = _plaintext_archive([("state.db", b"a"), ("STATE.DB", b"b")])
    with pytest.raises(ValueError, match="duplicate path"):
        backup_bundle.inspect_bundle_archive(plaintext=duplicate)

    mismatch = _plaintext_archive(
        [("state.db", b"payload")],
        manifest=[("state.db", len(b"payload") + 1)],
    )
    target = tmp_path / "restore"
    (target / "sentinel").parent.mkdir(parents=True)
    (target / "sentinel").write_text("unchanged", encoding="utf-8")
    with pytest.raises(ValueError, match="MANIFEST"):
        backup_bundle.extract_bundle_to_dir(
            plaintext=mismatch,
            target_dir=target,
        )
    assert (target / "sentinel").read_text(encoding="utf-8") == "unchanged"
    assert not (target / "state.db").exists()
    _assert_no_restore_artifacts(target)


def test_trailing_gzip_member_and_hidden_tar_payload_are_rejected() -> None:
    plaintext = _plaintext_archive([("state.db", b"ok")])
    with pytest.raises(ValueError, match="trailing or concatenated gzip"):
        backup_bundle.inspect_bundle_archive(
            plaintext=plaintext + gzip.compress(b"second-stream"),
        )

    raw_tar = gzip.decompress(plaintext)
    hidden = gzip.compress(raw_tar + b"hidden-after-tar-end")
    with pytest.raises(ValueError, match="after the tar end marker"):
        backup_bundle.inspect_bundle_archive(plaintext=hidden)


def test_oversized_pax_header_is_rejected_before_large_tar_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pax = tarfile.TarInfo("pax")
    pax.type = tarfile.XHDTYPE
    pax.size = backup_bundle.MAX_ARCHIVE_MEMBER_METADATA_BYTES + 1
    header_only = pax.tobuf(format=tarfile.USTAR_FORMAT)
    plaintext = gzip.compress(header_only)
    requested: list[int] = []
    real_read = tarfile._Stream.read

    def guarded_read(self, size):
        requested.append(size)
        assert size <= backup_bundle.MAX_ARCHIVE_MEMBER_METADATA_BYTES
        return real_read(self, size)

    monkeypatch.setattr(tarfile._Stream, "read", guarded_read)
    with pytest.raises(ValueError, match="extension metadata is too large"):
        backup_bundle.inspect_bundle_archive(plaintext=plaintext)
    assert requested and max(requested) <= 512


def test_bounded_pax_long_unicode_name_remains_restore_compatible(
    tmp_path: Path,
) -> None:
    name = "unicode-" + chr(0xE9) + "-" + "x" * 120 + ".txt"
    plaintext = _plaintext_archive([(f"inbox/{name}", b"portable")])
    target = tmp_path / "restore"
    assert backup_bundle.extract_bundle_to_dir(
        plaintext=plaintext,
        target_dir=target,
    ) == [f"inbox/{name}"]
    assert (target / "inbox" / name).read_bytes() == b"portable"


def test_disk_reserve_rejects_before_promotion_and_cleans_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plaintext = _plaintext_archive([("state.db", b"x" * 4096)])
    monkeypatch.setattr(
        backup_bundle.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(total=1024, used=0, free=1024),
    )
    target = tmp_path / "restore"
    with pytest.raises(ValueError, match="insufficient free space"):
        backup_bundle.extract_bundle_to_dir(
            plaintext=plaintext,
            target_dir=target,
        )
    _assert_no_restore_artifacts(target)


def test_mid_promotion_failure_restores_every_original(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plaintext = _plaintext_archive([
        ("master.seed", b"new-seed"),
        ("state.db", b"new-state"),
    ])
    target = tmp_path / "restore"
    target.mkdir()
    originals = {"master.seed": b"old-seed", "state.db": b"old-state"}
    for name, payload in originals.items():
        (target / name).write_bytes(payload)

    real_link = backup_bundle.os.link
    promotions = 0

    def fail_second_promotion(source, destination, **kwargs):
        nonlocal promotions
        promotions += 1
        if promotions == 2:
            raise OSError("injected second-promotion failure")
        return real_link(source, destination, **kwargs)

    monkeypatch.setattr(backup_bundle.os, "link", fail_second_promotion)
    with pytest.raises(OSError, match="injected second-promotion failure"):
        backup_bundle.extract_bundle_to_dir(
            plaintext=plaintext,
            target_dir=target,
            overwrite=True,
        )
    assert {
        name: (target / name).read_bytes() for name in originals
    } == originals
    _assert_no_restore_artifacts(target)


def test_no_overwrite_mid_promotion_failure_leaves_no_partial_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plaintext = _plaintext_archive([("first", b"one"), ("second", b"two")])
    target = tmp_path / "restore"
    real_link = backup_bundle.os.link
    links = 0

    def fail_second_link(source, destination, **kwargs):
        nonlocal links
        links += 1
        if links == 2:
            raise OSError("injected no-overwrite promotion failure")
        return real_link(source, destination, **kwargs)

    monkeypatch.setattr(backup_bundle.os, "link", fail_second_link)
    with pytest.raises(OSError, match="injected no-overwrite promotion failure"):
        backup_bundle.extract_bundle_to_dir(
            plaintext=plaintext,
            target_dir=target,
            overwrite=False,
        )
    assert not (target / "first").exists()
    assert not (target / "second").exists()
    _assert_no_restore_artifacts(target)


def test_oversized_bundle_file_is_rejected_before_open_or_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = tmp_path / "oversized.olbak"
    bundle.touch()
    with bundle.open("r+b") as handle:
        handle.truncate(
            backup_bundle.HEADER_LEN
            + backup_bundle.MAX_BUNDLE_COMPRESSED_BYTES
            + 17
        )

    def forbidden_open(*_args, **_kwargs):
        raise AssertionError("oversized bundle must be rejected from lstat")

    monkeypatch.setattr(backup_bundle.os, "open", forbidden_open)
    with pytest.raises(ValueError, match="compressed-payload limit"):
        backup_bundle.read_bundle_file_bounded(bundle)


def test_bundle_reader_requests_observed_size_not_global_ceiling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = tmp_path / "small.olbak"
    payload = b"small-bounded-read"
    bundle.write_bytes(payload)
    requested: list[int] = []
    real_fdopen = backup_bundle.os.fdopen

    class GuardedReader:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        def __enter__(self):
            self.wrapped.__enter__()
            return self

        def __exit__(self, *args):
            return self.wrapped.__exit__(*args)

        def read(self, size: int) -> bytes:
            requested.append(size)
            return self.wrapped.read(size)

    def guarded_fdopen(*args, **kwargs):
        return GuardedReader(real_fdopen(*args, **kwargs))

    monkeypatch.setattr(backup_bundle.os, "fdopen", guarded_fdopen)
    assert backup_bundle.read_bundle_file_bounded(bundle) == payload
    assert requested == [len(payload) + 1]


def test_symlink_member_and_unsafe_target_ancestor_are_rejected(
    tmp_path: Path,
) -> None:
    link = tarfile.TarInfo("linked")
    link.type = tarfile.SYMTYPE
    link.linkname = "state.db"
    special = _plaintext_archive([], extra_members=[link])
    with pytest.raises(ValueError, match="unsupported archive entry type"):
        backup_bundle.inspect_bundle_archive(plaintext=special)

    if not hasattr(os, "symlink"):
        return
    plaintext = _plaintext_archive([("nested/state.db", b"payload")])
    target = tmp_path / "restore"
    outside = tmp_path / "outside"
    target.mkdir()
    outside.mkdir()
    try:
        os.symlink(outside, target / "nested", target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this host")
    with pytest.raises(ValueError, match="unsafe restore target ancestor"):
        backup_bundle.extract_bundle_to_dir(
            plaintext=plaintext,
            target_dir=target,
        )
    assert not (outside / "state.db").exists()
    _assert_no_restore_artifacts(target)
