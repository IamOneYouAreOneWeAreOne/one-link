from __future__ import annotations

import os
from pathlib import Path


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

    pruned = d._prune_chunk_cache(max_bytes=0)
    assert pruned["removed"] == 1
    assert d._read_chunk_cache(h) is None


def test_prior_assist_hydrates_matching_chunks_from_existing_inbox_file(tmp_path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))

    from one_link.cdc import index_path
    from one_link.daemon import Daemon
    from one_link.identity import load_or_create
    from one_link.paths import inbox_dir

    d = Daemon(load_or_create())
    prior = inbox_dir() / "already_here_video_fragment.bin"
    prior.write_bytes((b"scene-a" * 9000) + os.urandom(128_000) + (b"scene-b" * 9000))
    idx = index_path(prior)
    wanted = {c.hash for c in idx.chunks}

    assert all(d._read_chunk_cache(h) is None for h in wanted)
    stats = d._hydrate_chunks_from_local_prior(wanted)

    assert stats["matched"] == len(wanted)
    assert stats["matched_bytes"] == prior.stat().st_size
    assert all(d._read_chunk_cache(h) is not None for h in wanted)


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
