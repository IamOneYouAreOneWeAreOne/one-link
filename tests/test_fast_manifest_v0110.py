from pathlib import Path

import pytest

from one_link.cdc import fixed_index_path, hash_path, index_path
from one_link.transfer_intent import (
    FileManifest,
    plan_transfer_intent_for_manifest,
)


def test_hash_path_matches_cdc_blob_without_chunking(tmp_path: Path):
    p = tmp_path / "movie.bin"
    p.write_bytes((b"frame-data-" * 4097) + b"tail")

    assert hash_path(p) == index_path(p).blob_hash


def test_fixed_index_path_is_deterministic_and_bounded(tmp_path: Path):
    p = tmp_path / "aligned.bin"
    p.write_bytes(bytes(range(251)) * 4096)

    a = fixed_index_path(p, chunk_size=8192, read_size=1024)
    b = fixed_index_path(p, chunk_size=8192, read_size=4096)

    assert a == b
    assert a.blob_hash == hash_path(p)
    assert all(0 <= c.size <= 8192 for c in a.chunks)
    assert sum(c.size for c in a.chunks) == a.size


def test_fixed_index_path_rejects_invalid_sizes(tmp_path: Path):
    p = tmp_path / "bad.bin"
    p.write_bytes(b"x")

    with pytest.raises(ValueError):
        fixed_index_path(p, chunk_size=0)
    with pytest.raises(ValueError):
        fixed_index_path(p, read_size=0)


def test_thin_manifest_plans_baseline_without_chunk_manifest(tmp_path: Path):
    p = tmp_path / "legacy-video.mp4"
    p.write_bytes(b"video" * 1024)
    manifest = FileManifest(
        name=p.name,
        size=p.stat().st_size,
        blob_hash=hash_path(p),
        chunks=(),
    )

    intent = plan_transfer_intent_for_manifest(
        manifest=manifest,
        path=p,
        peer_fp="aa" * 32,
        local_version="0.11.0",
        peer_version="0.6.0",
        peer_capabilities=["chat", "files"],
        intent_id="xfer-1",
    )

    assert intent.manifest.chunk_count == 0
    assert intent.can_offer_cdc is False
    assert intent.compatibility.transfer_mode == "baseline_file"
    assert intent.preferred_method == "file_baseline"
