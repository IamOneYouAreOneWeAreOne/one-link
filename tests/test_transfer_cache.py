from __future__ import annotations

import os


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
