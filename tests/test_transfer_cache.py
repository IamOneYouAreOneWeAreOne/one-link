from __future__ import annotations

import os
import time
from pathlib import Path

import pytest


def test_385_mib_ui_pipeline_builds_field_manifest_in_one_scan(
    tmp_path,
    monkeypatch,
):
    """Admission, durable queue, and retry share one field-sized manifest."""

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))

    from one_link import daemon as daemon_module
    from one_link.capabilities import FILE_CDC_BINARY_FRAME
    from one_link.daemon import Daemon
    from one_link.identity import load_or_create
    from one_link.paths import data_dir
    from one_link.state import State

    d = Daemon(load_or_create())
    d.state = State(db_path=tmp_path / "single-scan-state.db")
    peer_fp = "ab" * 32
    d.state.upsert_peer(
        fingerprint=peer_fp,
        short_id=peer_fp[:8],
        pubkey=b"p" * 32,
    )
    d.state.set_peer_trust(peer_fp, "pinned")
    d.state.set_peer_capabilities(peer_fp, [FILE_CDC_BINARY_FRAME])
    monkeypatch.setattr(d, "cadence_for_peer", lambda _short_id: 250_000)
    upload = data_dir() / "uploads" / "ACE.zip"
    upload.parent.mkdir(parents=True, exist_ok=True)
    exact_size = 403_387_968
    with open(upload, "wb") as handle:
        handle.truncate(exact_size)

    real_fixed_index = daemon_module.fixed_index_file
    scan_stats = {"calls": 0, "bytes": 0}

    class _CountingHandle:
        def __init__(self, wrapped):
            self._wrapped = wrapped

        def read(self, size=-1):
            data = self._wrapped.read(size)
            scan_stats["bytes"] += len(data)
            return data

        def __getattr__(self, name):
            return getattr(self._wrapped, name)

    def _counted_fixed_index(handle, **kwargs):
        scan_stats["calls"] += 1
        return real_fixed_index(_CountingHandle(handle), **kwargs)

    monkeypatch.setattr(daemon_module, "fixed_index_file", _counted_fixed_index)
    try:
        # The server performs this call in asyncio.to_thread before binding its
        # durable UI delivery contract.
        admitted = d.prepare_file_for_transfer(upload, peer_fp=peer_fp)
        assert admitted.index_kind == "fixed:250000"
        assert len(admitted.file_index.chunks) == 1_614
        assert admitted.cache_hit is False

        monkeypatch.setattr(
            daemon_module,
            "_verify_staged_file",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("daemon-owned verified upload was rescanned")
            ),
        )
        queued = d.queue_file_transfer(
            peer_fp=peer_fp,
            path=upload,
            schedule_resume=False,
        )
        send_plan = d.prepare_file_for_transfer(upload, peer_fp=peer_fp)

        assert queued.blob_hash == admitted.file_index.blob_hash
        assert send_plan.cache_hit is True
        assert send_plan.file_index == admitted.file_index
        assert scan_stats == {"calls": 1, "bytes": exact_size}
        assert Path(queued.metadata["path"]) == upload
        assert queued.metadata["file_index_kind"] == "fixed"
        assert queued.metadata["file_index_mode"] == "fixed:250000"
        assert queued.metadata["fixed_chunk_size"] == 250_000
    finally:
        d.state.close()


def test_file_index_cache_rejects_same_size_timestamp_restored_replacement(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))

    from one_link.daemon import Daemon
    from one_link.identity import load_or_create
    from one_link.state import State

    d = Daemon(load_or_create())
    d.state = State(db_path=tmp_path / "identity-cache-state.db")
    source = tmp_path / "release.zip"
    source.write_bytes(b"A" * (2 * 1024 * 1024))
    first = d.prepare_file_for_transfer(source)
    first_stat = source.stat()

    replacement = tmp_path / "replacement.zip"
    replacement.write_bytes(b"B" * first.file_index.size)
    os.utime(
        replacement,
        ns=(first_stat.st_atime_ns, first_stat.st_mtime_ns),
    )
    os.replace(replacement, source)
    os.utime(source, ns=(first_stat.st_atime_ns, first_stat.st_mtime_ns))

    second_signature = d._file_cache_signature(source)
    try:
        assert any(
            first.signature[field] != second_signature[field]
            for field in ("ino", "file_id", "change_ns")
        )
        assert d._cached_file_index(second_signature) is None
        second = d.prepare_file_for_transfer(source)
        assert second.cache_hit is False
        assert second.file_index.blob_hash != first.file_index.blob_hash

        # Also cover an in-place rewrite: Windows creation time and restored
        # mtime remain unchanged, but NT ChangeTime invalidates the proof.
        before_in_place = second.signature
        time.sleep(0.01)
        source.write_bytes(b"C" * first.file_index.size)
        os.utime(source, ns=(first_stat.st_atime_ns, first_stat.st_mtime_ns))
        after_in_place = d._file_cache_signature(source)
        assert after_in_place["change_ns"] != before_in_place["change_ns"]
        assert d._cached_file_index(after_in_place) is None
    finally:
        d.state.close()


def test_outbound_source_signature_rejects_post_index_mutation(tmp_path):
    from one_link.daemon import Daemon

    daemon = Daemon.__new__(Daemon)
    source = tmp_path / "release.zip"
    source.write_bytes(b"indexed revision")
    evidence = daemon._file_cache_signature(source)

    daemon._assert_file_signature(source, evidence)
    source.write_bytes(b"different revision with a different length")

    with pytest.raises(RuntimeError, match="changed after indexing"):
        daemon._assert_file_signature(source, evidence)


def test_file_index_cache_rejects_corrupt_noncontiguous_manifest(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))

    from one_link.daemon import Daemon
    from one_link.identity import load_or_create
    from one_link.state import State

    daemon = Daemon(load_or_create())
    daemon.state = State(db_path=tmp_path / "corrupt-cache-state.db")
    source = tmp_path / "source.bin"
    source.write_bytes(b"manifest-integrity" * 8192)
    first = daemon.prepare_file_for_transfer(source)
    assert first.cache_hit is False
    daemon.state._conn.execute(
        "UPDATE file_index_cache SET chunks_json = ?",
        (
            '[{"index":0,"start":1,"end":2,"size":1,'
            '"hash":"' + ("ab" * 32) + '"}]',
        ),
    )

    assert daemon._cached_file_index(first.signature) is None
    repaired = daemon.prepare_file_for_transfer(source)
    assert repaired.cache_hit is False
    assert repaired.file_index == first.file_index
    daemon.state.close()


def test_cdc_chunk_cache_store_read_and_prune(tmp_path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))

    import blake3
    from one_link.daemon import Daemon
    from one_link.identity import load_or_create

    d = Daemon(load_or_create())
    payload = b"resume me" * 1024
    h = blake3.blake3(payload).hexdigest()

    d._store_chunk_cache(h, payload)
    assert d._read_chunk_cache(h) == payload
    stats = d._chunk_cache_stats()
    assert stats["chunks"] == 1
    assert stats["bytes"] == len(payload)

    # The chunk-cache gc protects entries newer than DEFAULT_MIN_AGE_SECONDS
    # (1 hour) to prevent racing the receive path. Age the file backwards
    # past that floor so this prune test exercises actual eviction rather
    # than the freshness guard.
    cache_path = d._chunk_cache_path(h)
    assert cache_path.is_file()
    old_ts = cache_path.stat().st_mtime - 7200  # 2 hours ago
    os.utime(cache_path, (old_ts, old_ts))

    pruned = d._prune_chunk_cache(max_bytes=0)
    assert pruned["removed"] == 1
    assert d._read_chunk_cache(h) is None


def test_prior_assist_hydrates_matching_chunks_from_existing_inbox_file(tmp_path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))

    from one_link.cdc import index_path
    from one_link.daemon import Daemon
    from one_link.identity import load_or_create
    from one_link.paths import inbox_dir
    from one_link.state import State

    d = Daemon(load_or_create())
    d.state = State(db_path=Path(tmp_path) / "s.db")
    prior = inbox_dir() / "already_here_video_fragment.bin"
    prior.write_bytes((b"scene-a" * 9000) + os.urandom(128_000) + (b"scene-b" * 9000))
    idx = index_path(prior)
    wanted = {c.hash for c in idx.chunks}

    assert all(d._read_chunk_cache(h) is None for h in wanted)
    stats = d._hydrate_chunks_from_local_prior(wanted)

    assert stats["matched"] == len(wanted)
    assert stats["matched_bytes"] == prior.stat().st_size
    assert all(d._read_chunk_cache(h) is not None for h in wanted)
    d.state.close()


def test_chunk_query_availability_uses_local_prior_before_answering(tmp_path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))

    from one_link.cdc import index_path
    from one_link.daemon import Daemon
    from one_link.identity import load_or_create
    from one_link.paths import inbox_dir
    from one_link.state import State

    d = Daemon(load_or_create())
    d.state = State(db_path=Path(tmp_path) / "s.db")
    prior = inbox_dir() / "old_cut_of_movie.bin"
    prior.write_bytes((b"shared-video-data" * 12_000) + os.urandom(96_000))
    idx = index_path(prior)
    wanted = [c.hash for c in idx.chunks]

    have = d._available_chunk_hashes(wanted)

    assert have == wanted
    assert all(d._read_chunk_cache(h) is not None for h in wanted)
    d.state.close()


def test_available_hashes_verifies_and_hydrates_durable_source_after_cache_prune(
    tmp_path, monkeypatch,
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))

    import blake3
    from one_link.daemon import Daemon
    from one_link.identity import load_or_create
    from one_link.state import State

    d = Daemon(load_or_create())
    d.state = State(db_path=Path(tmp_path) / "s.db")
    source = tmp_path / "received-large.bin"
    payload = b"durable-prior-source" * 20_000
    source.write_bytes(payload)
    h = blake3.blake3(payload).hexdigest()
    d.state.record_chunk_source(
        h,
        path=str(source),
        start=0,
        size=len(payload),
        mtime_ms=int(source.stat().st_mtime * 1000),
        file_size=source.stat().st_size,
        source="received_cdc",
    )

    assert not d._chunk_cache_path(h).is_file()
    assert d._available_chunk_hashes([h], hydrate=False) == [h]
    # Availability is a byte-level integrity claim, not an advisory DB
    # lookup.  The durable source is read, hashed, and cached before it is
    # advertised as present even when broad prior-file scanning is disabled.
    assert d._chunk_cache_path(h).is_file()
    assert d._read_chunk_cache(h) == payload
    d.state.close()


def test_available_hashes_rejects_and_repairs_corrupt_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))

    import blake3
    from one_link.daemon import Daemon
    from one_link.identity import load_or_create
    from one_link.state import State

    d = Daemon(load_or_create())
    d.state = State(db_path=Path(tmp_path) / "s.db")
    payload = b"verified-cache-payload" * 4096
    h = blake3.blake3(payload).hexdigest()
    d._store_chunk_cache(h, payload)
    d._chunk_cache_path(h).write_bytes(b"corrupt")

    assert d._available_chunk_hashes([h], hydrate=False) == []
    assert not d._chunk_cache_path(h).exists()

    # Receiving the real bytes must replace a corrupt pre-existing CAS file;
    # existence alone can never make corruption fail-sticky.
    d._chunk_cache_path(h).parent.mkdir(parents=True, exist_ok=True)
    d._chunk_cache_path(h).write_bytes(b"still-corrupt")
    d._store_chunk_cache(h, payload)
    assert d._read_chunk_cache(h) == payload
    d.state.close()


def test_available_hashes_prunes_stale_lazy_source_claim(tmp_path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))

    import blake3
    from one_link.daemon import Daemon
    from one_link.identity import load_or_create
    from one_link.state import State

    d = Daemon(load_or_create())
    d.state = State(db_path=Path(tmp_path) / "s.db")
    promised = b"original-source-bytes" * 2048
    h = blake3.blake3(promised).hexdigest()
    source = tmp_path / "source.bin"
    source.write_bytes(promised)
    st = source.stat()
    d.state.record_chunk_source(
        h,
        path=str(source),
        start=0,
        size=len(promised),
        mtime_ms=int(st.st_mtime * 1000),
        file_size=st.st_size,
        source="test",
    )
    # Preserve length and the coarse mtime evidence: only hashing can detect
    # this mutation reliably.
    source.write_bytes(b"X" * len(promised))
    os.utime(source, ns=(st.st_atime_ns, st.st_mtime_ns))

    assert d._available_chunk_hashes([h], hydrate=False) == []
    assert d.state.chunks_sourced([h]) == []
    d.state.close()


def test_prior_index_records_lazy_sources_without_copying_all_bytes(tmp_path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))

    from one_link.cdc import index_path
    from one_link.daemon import Daemon
    from one_link.identity import load_or_create
    from one_link.paths import inbox_dir
    from one_link.state import State

    d = Daemon(load_or_create())
    d.state = State(db_path=Path(tmp_path) / "s.db")
    prior = inbox_dir() / "warm_video.mov"
    prior.write_bytes((b"warm-prior" * 20_000) + os.urandom(64_000))
    idx = index_path(prior)

    stats = d._index_local_prior_sources_once()
    assert stats["indexed_files"] >= 1
    assert stats["indexed_chunks"] >= len(idx.chunks)
    assert all(not d._chunk_cache_path(c.hash).is_file() for c in idx.chunks)

    first = idx.chunks[0]
    assert d.state.chunks_sourced([first.hash]) == [first.hash]
    data = d._read_chunk_cache(first.hash)
    assert data is not None
    assert d._chunk_cache_path(first.hash).is_file()
    d.state.close()
