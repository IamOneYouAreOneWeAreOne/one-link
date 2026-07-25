from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import blake3
import pytest

import one_link.daemon as daemon_module
import one_link.namespace_durability as durability
import one_link.resume as resume_module
from one_link.resume import ResumeSidecar, load_sidecar, persist_sidecar


def _sidecar(partial: Path, *, name: str) -> ResumeSidecar:
    return ResumeSidecar(
        blob_hex="a" * 64,
        peer_fp="b" * 64,
        name=name,
        size=1,
        out_path=str(partial),
        cdc_chunks=[
            {
                "index": 0,
                "hash": "c" * 64,
                "size": 1,
                "start": 0,
                "end": 1,
            }
        ],
    )


def test_windows_replace_requests_write_through_and_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Path, Path, int]] = []

    def record(source: Path, destination: Path, flags: int) -> None:
        calls.append((Path(source), Path(destination), flags))

    monkeypatch.setattr(durability, "_IS_WINDOWS", True)
    monkeypatch.setattr(durability, "_move_file_exw", record)
    source = tmp_path / "source"
    destination = tmp_path / "destination"

    durability.replace_path(source, destination)

    assert calls == [
        (
            source,
            destination,
            durability.MOVEFILE_REPLACE_EXISTING | durability.MOVEFILE_WRITE_THROUGH,
        )
    ]


def test_windows_noreplace_publish_requests_only_write_through(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Path, Path, int]] = []

    def record(source: Path, destination: Path, flags: int) -> None:
        calls.append((Path(source), Path(destination), flags))

    monkeypatch.setattr(durability, "_IS_WINDOWS", True)
    monkeypatch.setattr(durability, "_move_file_exw", record)
    source = tmp_path / "source"
    destination = tmp_path / "destination"

    staging_remains = durability.publish_file_noreplace(source, destination)

    assert staging_remains is False
    assert calls == [
        (
            source,
            destination,
            durability.MOVEFILE_WRITE_THROUGH,
        )
    ]


def test_windows_move_failure_never_falls_back_to_non_durable_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_move(_source: Path, _destination: Path, _flags: int) -> None:
        raise PermissionError("injected write-through failure")

    def forbidden_replace(_source: Path, _destination: Path) -> None:
        raise AssertionError("non-write-through fallback was attempted")

    monkeypatch.setattr(durability, "_IS_WINDOWS", True)
    monkeypatch.setattr(durability, "_move_file_exw", fail_move)
    monkeypatch.setattr(durability.os, "replace", forbidden_replace)

    with pytest.raises(PermissionError, match="write-through failure"):
        durability.replace_path(tmp_path / "source", tmp_path / "destination")


def test_windows_extended_path_rejects_embedded_nul() -> None:
    with pytest.raises(ValueError, match="embedded NUL"):
        durability._windows_extended_path("safe\x00truncated")


@pytest.mark.skipif(os.name != "nt", reason="requires the Win32 filesystem API")
def test_real_windows_write_through_replace_and_noreplace_collision(
    tmp_path: Path,
) -> None:
    source = tmp_path / "sourcé-文件.bin"
    destination = tmp_path / "destination.bin"
    source.write_bytes(b"new")
    destination.write_bytes(b"old")

    durability.replace_path(source, destination)

    assert not source.exists()
    assert destination.read_bytes() == b"new"
    source.write_bytes(b"must-survive")
    with pytest.raises(FileExistsError):
        durability.publish_file_noreplace(source, destination)
    assert source.read_bytes() == b"must-survive"
    assert destination.read_bytes() == b"new"


def test_atomic_noreplace_publish_has_exactly_one_concurrent_winner(
    tmp_path: Path,
) -> None:
    contenders = 16
    barrier = threading.Barrier(contenders)
    destination = tmp_path / "winner.bin"
    sources = [tmp_path / f"source-{index}.bin" for index in range(contenders)]
    for index, source in enumerate(sources):
        source.write_bytes(index.to_bytes(2, "big"))

    def publish(index: int) -> tuple[int, bool]:
        barrier.wait(timeout=5)
        try:
            staging_remains = durability.publish_file_noreplace(
                sources[index],
                destination,
            )
        except FileExistsError:
            return index, False
        if staging_remains:
            sources[index].unlink()
        return index, True

    with ThreadPoolExecutor(max_workers=contenders) as pool:
        results = list(pool.map(publish, range(contenders)))

    winners = [index for index, won in results if won]
    assert len(winners) == 1
    winner = winners[0]
    assert destination.read_bytes() == winner.to_bytes(2, "big")
    assert not sources[winner].exists()
    assert all(sources[index].exists() for index in range(contenders) if index != winner)


def test_resume_sidecar_write_through_failure_preserves_old_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    partial = inbox / "partial.bin"
    partial.write_bytes(b"x")
    old = _sidecar(partial, name="old.bin")
    persist_sidecar(inbox, old)

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("injected namespace durability failure")

    monkeypatch.setattr(resume_module, "replace_path", fail_replace)
    with pytest.raises(OSError, match="namespace durability failure"):
        persist_sidecar(inbox, _sidecar(partial, name="new.bin"))

    loaded = load_sidecar(inbox, old.blob_hex)
    assert loaded is not None
    assert loaded.name == "old.bin"
    assert not list((inbox / ".resume").glob(".*.tmp"))


def test_receiver_publish_write_through_failure_keeps_verified_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"verified transfer bytes"
    staging = tmp_path / "incoming.part"
    final = tmp_path / "received.bin"
    staging.write_bytes(payload)

    def fail_publish(_staging: Path, _final: Path) -> bool:
        raise OSError("injected durable publication failure")

    monkeypatch.setattr(
        daemon_module,
        "publish_file_noreplace",
        fail_publish,
    )
    with pytest.raises(OSError, match="cannot atomically publish"):
        daemon_module._publish_verified_staging(
            staging,
            final,
            expected_blob=blake3.blake3(payload).hexdigest(),
            expected_size=len(payload),
        )

    assert staging.read_bytes() == payload
    assert not final.exists()
