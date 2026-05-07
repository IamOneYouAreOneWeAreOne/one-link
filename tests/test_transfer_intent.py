from __future__ import annotations

from pathlib import Path

from one_link.capabilities import CHAT, FILES, FILE_CDC
from one_link.transfer_intent import build_file_manifest, plan_transfer_intent


def test_file_manifest_is_content_addressed_and_chunked(tmp_path: Path):
    src = tmp_path / "dataset.bin"
    src.write_bytes((b"abc123" * 20_000) + b"tail")
    manifest = build_file_manifest(src)
    assert manifest.name == "dataset.bin"
    assert manifest.size == src.stat().st_size
    assert len(manifest.blob_hash) == 64
    assert manifest.chunk_count >= 1
    wire = manifest.to_wire()
    assert wire["blob"] == manifest.blob_hash
    assert wire["chunks"][0]["hash"] == manifest.chunks[0].hash


def test_transfer_intent_prefers_cdc_when_peer_supports_it(tmp_path: Path):
    src = tmp_path / "x.bin"
    src.write_bytes(b"x" * 200_000)
    intent = plan_transfer_intent(
        path=src,
        peer_fp="aa" * 32,
        local_version="0.8.4",
        peer_version="0.8.4",
        peer_capabilities=[CHAT, FILES, FILE_CDC],
        intent_id="intent-1",
    )
    assert intent.id == "intent-1"
    assert intent.preferred_method == "file_cdc"
    assert intent.can_offer_cdc is True
    assert intent.metadata()["manifest"]["blob"] == intent.manifest.blob_hash


def test_transfer_intent_falls_back_to_baseline_for_older_capable_peer(tmp_path: Path):
    src = tmp_path / "x.bin"
    src.write_bytes(b"x" * 200_000)
    intent = plan_transfer_intent(
        path=src,
        peer_fp="aa" * 32,
        local_version="0.8.4",
        peer_version="0.6.0",
        peer_capabilities=[CHAT, FILES],
    )
    assert intent.compatibility.compatible
    assert intent.preferred_method == "file_baseline"
    assert intent.can_offer_cdc is False


def test_transfer_intent_can_probe_unknown_legacy_peer(tmp_path: Path):
    src = tmp_path / "x.bin"
    src.write_bytes(b"x")
    intent = plan_transfer_intent(
        path=src,
        peer_fp="",
        local_version="0.8.4",
        peer_version=None,
        peer_capabilities=[],
    )
    assert intent.compatibility.mode == "legacy_unknown"
    assert intent.can_offer_cdc is True
    assert intent.preferred_method == "file_cdc_probe"
