"""Integration tests for the three Phase B/C wirings shipped
May 15 2026:

  1. ``one_link.durability.LocalStripeStore`` — erasure-coded local
     replication via ``ol_erasure``.
  2. ``one_link.fountain.FountainEncoder`` / ``FountainDecoder`` —
     LT-code stream encoder/decoder via ``ol_fountain``.
  3. ``GET /api/folders/{name}/tree`` — JSON file-tree endpoint
     (foundation for any future filesystem mount).
"""
from __future__ import annotations

import pathlib
import tempfile
from pathlib import Path

import pytest

from one_link import durability, fountain
from one_link import master_seed as ms
from one_link.daemon import Daemon
from one_link.identity import load_or_create as load_or_create_identity


@pytest.fixture
def daemon_with_seed(monkeypatch):
    """Daemon with a populated master seed in an isolated
    ONE_LINK_HOME (matches the fixture in test_daemon_row10_row6_wiring)."""
    td = tempfile.mkdtemp(prefix="ol_tree_test_")
    home = Path(td)
    monkeypatch.setenv("ONE_LINK_HOME", str(home))
    data_d = home / "data"
    data_d.mkdir(parents=True, exist_ok=True)
    seed, _ = ms.load_or_create_seed(data_d)
    assert len(seed) == 32
    me = load_or_create_identity(home / "config" / "identity.key")
    daemon = Daemon(me)
    yield daemon


# ── 1. durability.LocalStripeStore ────────────────────────────────


def test_durability_round_trip_with_max_loss():
    """Encode a chunk, drop M=4 shards (the maximum the STANDARD
    profile tolerates), reconstruct from the surviving k=10."""
    plaintext = b"The quick brown fox jumps over the lazy dog. " * 100
    with tempfile.TemporaryDirectory() as tmp:
        store = durability.LocalStripeStore(tmp)
        stripe_id = store.replicate_chunk_locally(plaintext, profile="standard")
        # Drop the maximum number of shards (m=4 for STANDARD).
        for pos in [0, 5, 10, 13]:
            assert store.delete_shard(stripe_id, pos) is True
        health = store.stripe_health(stripe_id)
        assert health["shards_present"] == 10
        assert health["shards_missing"] == 4
        assert health["recoverable"] is True
        recovered = store.recover_chunk_locally(stripe_id)
        assert recovered == plaintext


def test_durability_unrecoverable_when_too_many_shards_lost():
    """Drop M+1 shards — recovery must REFUSE rather than silently
    return garbage."""
    plaintext = b"X" * 4000
    with tempfile.TemporaryDirectory() as tmp:
        store = durability.LocalStripeStore(tmp)
        stripe_id = store.replicate_chunk_locally(plaintext, profile="standard")
        for pos in [0, 1, 5, 10, 13]:  # 5 shards, exceeds m=4
            store.delete_shard(stripe_id, pos)
        health = store.stripe_health(stripe_id)
        assert health["recoverable"] is False
        with pytest.raises(RuntimeError, match="cannot reconstruct"):
            store.recover_chunk_locally(stripe_id)


def test_durability_repair_rewrites_missing_shards():
    """After a partial loss, ``repair_stripe`` re-derives the
    missing shards from the survivors and re-writes them in place."""
    plaintext = b"ABCDEFGH" * 500
    with tempfile.TemporaryDirectory() as tmp:
        store = durability.LocalStripeStore(tmp)
        stripe_id = store.replicate_chunk_locally(plaintext, profile="standard")
        for pos in [0, 5, 10, 13]:
            store.delete_shard(stripe_id, pos)
        rewritten = store.repair_stripe(stripe_id)
        assert rewritten == 4
        health = store.stripe_health(stripe_id)
        assert health["shards_missing"] == 0
        # Idempotency: repair on a healthy stripe is zero-cost.
        assert store.repair_stripe(stripe_id) == 0


def test_durability_profiles():
    """Each profile produces the expected k+m shard count."""
    plaintext = b"X" * 1000
    with tempfile.TemporaryDirectory() as tmp:
        store = durability.LocalStripeStore(tmp)
        # ephemeral: k=9, m=1 → 10 shards.
        sid = store.replicate_chunk_locally(plaintext, profile="ephemeral")
        h = store.stripe_health(sid)
        assert h["manifest"]["k"] == 9
        assert h["manifest"]["m"] == 1
        # standard: k=10, m=4 → 14 shards.
        sid = store.replicate_chunk_locally(plaintext + b"!", profile="standard")
        h = store.stripe_health(sid)
        assert h["manifest"]["k"] == 10
        assert h["manifest"]["m"] == 4
        # archival: k=6, m=6 → 12 shards (2x storage overhead).
        sid = store.replicate_chunk_locally(plaintext + b"@", profile="archival")
        h = store.stripe_health(sid)
        assert h["manifest"]["k"] == 6
        assert h["manifest"]["m"] == 6


def test_durability_list_stripes():
    """``list_stripes`` enumerates everything written."""
    with tempfile.TemporaryDirectory() as tmp:
        store = durability.LocalStripeStore(tmp)
        ids = {
            store.replicate_chunk_locally(b"A" * 100 + bytes([i]))
            for i in range(5)
        }
        listed = set(store.list_stripes())
        assert ids <= listed


def test_durability_delete_stripe():
    """``delete_stripe`` drops every shard + manifest."""
    plaintext = b"Y" * 2000
    with tempfile.TemporaryDirectory() as tmp:
        store = durability.LocalStripeStore(tmp)
        sid = store.replicate_chunk_locally(plaintext)
        assert store.stripe_exists(sid)
        assert store.delete_stripe(sid) is True
        assert not store.stripe_exists(sid)
        assert store.delete_stripe(sid) is False  # idempotent


def test_durability_idempotent_replication():
    """Re-replicating the same plaintext is a no-op."""
    plaintext = b"Z" * 3000
    with tempfile.TemporaryDirectory() as tmp:
        store = durability.LocalStripeStore(tmp)
        sid_a = store.replicate_chunk_locally(plaintext)
        sid_b = store.replicate_chunk_locally(plaintext)
        assert sid_a == sid_b
        # Healthy after a second replicate.
        h = store.stripe_health(sid_a)
        assert h["shards_missing"] == 0


# ── 2. fountain.FountainEncoder / FountainDecoder ─────────────────


def test_fountain_round_trip_small():
    """Round-trip a small chunk that requires only a handful of
    LT packets. Robust Soliton at small k often needs generous
    overhead (>=2x); tested up to 3x."""
    plaintext = b"small chunk!" * 100  # 1200 bytes -> k=2
    chunk_id = b"\xa1" * 32
    recovered = fountain.round_trip_chunk(chunk_id, plaintext, overhead=3.0)
    assert recovered == plaintext


def test_fountain_round_trip_medium():
    """Mid-size chunk: ~10x symbols, overhead ~1.2."""
    plaintext = b"Hello, fountain swarm!" * 500
    chunk_id = b"\xb2" * 32
    recovered = fountain.round_trip_chunk(chunk_id, plaintext, overhead=1.5)
    assert recovered == plaintext


def test_fountain_round_trip_large():
    """Larger chunk that fits comfortably under
    ``MAX_ENCODED_PER_CHUNK``."""
    plaintext = b"A" * 100_000  # k ~ 98
    chunk_id = b"\xc3" * 32
    recovered = fountain.round_trip_chunk(chunk_id, plaintext, overhead=1.2)
    assert recovered == plaintext


def test_fountain_chunk_id_mismatch_ignored():
    """A packet whose chunk_id doesn't match the decoder is silently
    dropped — protects the decoder from cross-talk between concurrent
    transfers."""
    plaintext = b"private data" * 100
    correct_id = b"\xd4" * 32
    wrong_id = b"\xe5" * 32
    enc = fountain.FountainEncoder(correct_id, plaintext)
    dec = fountain.FountainDecoder(wrong_id, enc.k, len(plaintext))
    for symbol_id in range(20):
        assert dec.ingest(enc.encode_one(symbol_id)) is False
    assert dec.is_complete() is False


def test_fountain_encoder_rejects_oversized_chunk():
    """A chunk too big to encode within ``MAX_ENCODED_PER_CHUNK``
    raises rather than silently producing a packet stream that no
    receiver could complete."""
    huge = b"X" * (fountain.MAX_ENCODED_PER_CHUNK * fountain.SYMBOL_LEN + 1)
    with pytest.raises(ValueError, match="chunk too big"):
        fountain.FountainEncoder(b"\x00" * 32, huge)


def test_fountain_encoder_rejects_empty_input():
    """Empty plaintext → ValueError."""
    with pytest.raises(ValueError, match="non-empty"):
        fountain.FountainEncoder(b"\x00" * 32, b"")


def test_fountain_encoder_rejects_bad_chunk_id():
    """chunk_id must be exactly 32 bytes."""
    with pytest.raises(ValueError, match="32 bytes"):
        fountain.FountainEncoder(b"\x00" * 31, b"data")


def test_fountain_decoder_plaintext_before_complete_raises():
    """Calling ``plaintext()`` before the decoder is complete is
    a programmer error."""
    dec = fountain.FountainDecoder(b"\x00" * 32, k=2, source_length=2048)
    with pytest.raises(RuntimeError, match="not yet complete"):
        dec.plaintext()


def test_fountain_decoder_tolerates_duplicates():
    """Re-feeding the same packet doesn't break the decoder."""
    plaintext = b"dedup test" * 100
    chunk_id = b"\xf6" * 32
    enc = fountain.FountainEncoder(chunk_id, plaintext)
    dec = fountain.FountainDecoder(chunk_id, enc.k, len(plaintext))
    p0 = enc.encode_one(0)
    p1 = enc.encode_one(1)
    p2 = enc.encode_one(2)
    p3 = enc.encode_one(3)
    # Feed duplicates aggressively.
    for _ in range(3):
        dec.ingest(p0)
        dec.ingest(p1)
        dec.ingest(p2)
        dec.ingest(p3)
    # Add more to converge.
    for i in range(4, 50):
        if dec.ingest(enc.encode_one(i)):
            break
    if dec.is_complete():
        assert dec.plaintext() == plaintext


# ── 3. /api/folders/{name}/tree endpoint ───────────────────────────


@pytest.mark.asyncio
async def test_folder_tree_endpoint_basic(tmp_path, daemon_with_seed):
    """A folder with two manifest entries surfaces both in the
    tree response."""
    daemon = daemon_with_seed
    await daemon.start()
    try:
        # Wire a folder + drop two synthetic manifest rows directly
        # into state. This is the lightest-weight way to exercise
        # the API without spinning up a full transfer.
        folder_path = tmp_path / "test_folder"
        folder_path.mkdir()
        daemon.state.add_folder(
            name="test_folder",
            local_path=str(folder_path),
            shared_with=[],
        )
        daemon.state.upsert_manifest_entry(
            folder_name="test_folder",
            file_path="readme.txt",
            blob_hash="aa" * 32,
            size=42,
            mtime_ms=1715000000000,
            vclock={"local": 1},
        )
        daemon.state.upsert_manifest_entry(
            folder_name="test_folder",
            file_path="subdir/note.md",
            blob_hash="bb" * 32,
            size=100,
            mtime_ms=1715000000001,
            vclock={"local": 1},
        )
        # Call the server method directly.
        from aiohttp import web
        req = _mock_request(daemon, name="test_folder")
        resp = await daemon.ui_server.api_folder_tree(req)
        assert resp.status == 200
        import json
        body = json.loads(resp.text)
        assert body["folder"] == "test_folder"
        assert body["total_entries"] == 2
        assert {e["path"] for e in body["entries"]} == {"readme.txt", "subdir/note.md"}
    finally:
        await daemon.stop()


@pytest.mark.asyncio
async def test_folder_tree_endpoint_prefix_filter(tmp_path, daemon_with_seed):
    """``prefix=subdir`` scopes the listing to that subtree."""
    daemon = daemon_with_seed
    await daemon.start()
    try:
        folder_path = tmp_path / "prefix_test"
        folder_path.mkdir()
        daemon.state.add_folder(
            name="prefix_test",
            local_path=str(folder_path),
            shared_with=[],
        )
        for path in ["a.txt", "subdir/b.txt", "subdir/c.txt", "other/d.txt"]:
            daemon.state.upsert_manifest_entry(
                folder_name="prefix_test",
                file_path=path,
                blob_hash="aa" * 32,
                size=10,
                mtime_ms=1715000000000,
                vclock={"local": 1},
            )
        req = _mock_request(
            daemon,
            name="prefix_test",
            query={"prefix": "subdir"},
        )
        resp = await daemon.ui_server.api_folder_tree(req)
        import json
        body = json.loads(resp.text)
        paths = {e["path"] for e in body["entries"]}
        assert paths == {"subdir/b.txt", "subdir/c.txt"}
    finally:
        await daemon.stop()


@pytest.mark.asyncio
async def test_folder_tree_endpoint_404_for_unknown_folder(daemon_with_seed):
    """Unknown folder names return 404."""
    daemon = daemon_with_seed
    await daemon.start()
    try:
        req = _mock_request(daemon, name="never_existed")
        resp = await daemon.ui_server.api_folder_tree(req)
        assert resp.status == 404
    finally:
        await daemon.stop()


# ── helpers ────────────────────────────────────────────────────────


def _mock_request(daemon, *, name, query=None):
    """Hand-roll a minimal aiohttp Request stand-in for the
    ``api_folder_tree`` handler. Avoids spinning up the full
    aiohttp.web.Application + TCP listener for unit testing.
    """
    from unittest.mock import MagicMock
    req = MagicMock()
    req.match_info = {"name": name}
    req.query = query or {}
    return req
