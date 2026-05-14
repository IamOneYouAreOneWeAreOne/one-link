from __future__ import annotations

import time
import os
from pathlib import Path

import blake3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.courier_bundle import export_courier_bundle, import_courier_bundle
from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key()
    pub_bytes = pub.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk,
        public=pub,
        public_bytes=pub_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname="courier-perf",
    )


def _chunk(seed: int) -> tuple[str, bytes]:
    data = (f"chunk-{seed:04d}|".encode("ascii") * 32)[:256]
    return blake3.blake3(data).hexdigest(), data


def test_courier_bundle_1024_chunk_roundtrip_stays_interactive():
    chunks = [_chunk(i) for i in range(1024)]

    start = time.perf_counter()
    exported = export_courier_bundle(chunks, sender_fp="11" * 32, recipient_fp="22" * 32)
    imported = import_courier_bundle(
        exported.bundle,
        exported.key_token,
        expected_recipient_fp="22" * 32,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert imported.chunks == tuple(chunks)
    assert elapsed_ms < 1500


def test_courier_drop_scan_caps_and_stays_fast(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    daemon = Daemon(_identity())
    server = UIServer(daemon)
    drop = server._courier_drop_dir()
    for i in range(260):
        (drop / f"bundle-{i:03d}.olcb.json").write_text(
            '{"bundle_b64":"AA=="}',
            encoding="utf-8",
        )
    (drop / "ignored.txt").write_text("not a courier file", encoding="utf-8")

    start = time.perf_counter()
    files = server._scan_courier_files()
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert len(files) == 64
    assert all(f["name"].endswith(".olcb.json") for f in files)
    assert elapsed_ms < 500


def test_courier_drop_scan_large_directory_stays_bounded(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    daemon = Daemon(_identity())
    server = UIServer(daemon)
    drop = server._courier_drop_dir()
    for i in range(1500):
        (drop / f"bulk-{i:04d}.olcb.json").write_text(
            '{"bundle_b64":"AA=="}',
            encoding="utf-8",
        )

    start = time.perf_counter()
    files = server._scan_courier_files()
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert len(files) == 64
    assert elapsed_ms < 1500


def test_courier_drop_scan_keeps_newest_without_growing_candidate_list(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    daemon = Daemon(_identity())
    server = UIServer(daemon)
    drop = server._courier_drop_dir()
    for i in range(220):
        path = drop / f"ordered-{i:04d}.olcb.json"
        path.write_text('{"bundle_b64":"AA=="}', encoding="utf-8")
        ts = 1_700_000_000 + i
        os.utime(path, (ts, ts))

    files = server._scan_courier_files()
    names = {f["name"] for f in files}

    assert len(files) == 64
    assert "ordered-0219.olcb.json" in names
    assert "ordered-0000.olcb.json" not in names
