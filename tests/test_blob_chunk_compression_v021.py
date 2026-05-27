"""v0.21.x BLOB_CHUNK compression on the MANIFEST_PUSH path.

When the peer advertises FILE_COMPRESSION, push_folder_to_peer
encodes each BLOB_CHUNK via _encode_payload (zlib level 1 with
early-skip for already-compressed content). The receiver's
_handle_blob_chunk reads the ``enc`` field and runs _decode_payload
with CHUNK_SIZE bound cap (zlib-bomb safe).

Coverage:
  - _encode_payload: compressible bytes → ('zlib', smaller),
    incompressible → ('raw', original)
  - _decode_payload: round-trip for zlib; raw passthrough;
    bomb cap rejection
  - _handle_blob_chunk: decodes enc=zlib correctly + writes raw
    content to blob_store
  - _handle_blob_chunk: rejects zlib-bomb (output > CHUNK_SIZE)
  - Source guard: push_folder_to_peer's chunk loop calls
    _encode_payload(...) and includes enc= in the BLOB_CHUNK frame
  - Source guard: _handle_blob_chunk calls _decode_payload(...)
"""
from __future__ import annotations

import asyncio
import base64
import inspect
import zlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.blobstore import BlobStore
from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    return Identity(
        private=sk, public=sk.public_key(), public_bytes=pub,
        fingerprint=fingerprint_of(pub), short_id=fingerprint_of(pub)[:8],
        hostname="comp-host",
    )


# ── _encode_payload / _decode_payload primitives ────────────────


def test_encode_returns_zlib_for_compressible(tmp_path: Path):
    me = _identity()
    daemon = Daemon(me)
    data = b"the quick brown fox " * 200  # ~4 KB highly repetitive
    enc, payload = daemon._encode_payload(data, allow_compress=True)
    assert enc == "zlib"
    assert len(payload) < len(data) // 2


def test_encode_returns_raw_for_already_compressed(tmp_path: Path):
    me = _identity()
    daemon = Daemon(me)
    # Pre-compressed bytes (zlib output) shouldn't compress further.
    pre = zlib.compress(b"x" * 8192, level=9)
    enc, payload = daemon._encode_payload(pre, allow_compress=True)
    assert enc == "raw"
    assert payload == pre


def test_encode_returns_raw_when_disabled(tmp_path: Path):
    me = _identity()
    daemon = Daemon(me)
    data = b"compressible" * 1000
    enc, payload = daemon._encode_payload(data, allow_compress=False)
    assert enc == "raw"


def test_decode_round_trips_zlib(tmp_path: Path):
    me = _identity()
    daemon = Daemon(me)
    plain = b"hello world\n" * 500
    enc, payload = daemon._encode_payload(plain, allow_compress=True)
    assert enc == "zlib"
    out = daemon._decode_payload(enc, payload, max_bytes=len(plain) + 64)
    assert out == plain


def test_decode_rejects_zlib_bomb(tmp_path: Path):
    me = _identity()
    daemon = Daemon(me)
    # 1 KB compressed expanding to 100 KB.
    bomb = zlib.compress(b"x" * 100_000, level=9)
    with pytest.raises(RuntimeError, match="exceeds maximum"):
        daemon._decode_payload("zlib", bomb, max_bytes=4096)


# ── _handle_blob_chunk with enc=zlib ────────────────────────────


@pytest_asyncio.fixture
async def receiver_ctx(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    blob_store = BlobStore(root=tmp_path / "blobs")
    daemon = Daemon(me)
    daemon.state = state
    daemon.blob_store = blob_store
    daemon.folder_engine = MagicMock()
    peer_fp = "aa" * 32
    state.upsert_peer(
        fingerprint=peer_fp, short_id=peer_fp[:8],
        pubkey=bytes.fromhex(peer_fp), hostname="sender",
    )
    state.set_peer_trust(peer_fp, "pinned")
    daemon._is_pinned = lambda fp: fp == peer_fp
    # Pre-arrange an incoming blob context (as if BLOB_OFFER landed).
    plain = b"compressed payload " * 256  # ~5 KB
    blob_hash_data = plain
    # Compute the BLAKE3 manually so the receiver's hash check passes.
    import blake3
    blob_hash = blake3.blake3(blob_hash_data).hexdigest()
    cm = blob_store.writer()
    writer, tmp = cm.__enter__()
    daemon._incoming_blobs = {
        blob_hash: {
            "size": len(plain), "received": 0, "next_seq": 0,
            "writer": writer, "cm": cm, "tmp_path": tmp,
        },
    }
    daemon._expected_blob_pulls = {peer_fp: {blob_hash}}
    daemon._dedupe_sites = MagicMock()
    yield {
        "daemon": daemon, "state": state, "blob_store": blob_store,
        "peer_fp": peer_fp, "blob_hash": blob_hash, "plain": plain,
    }
    state.close()


@pytest.mark.asyncio
async def test_handle_blob_chunk_decodes_zlib(receiver_ctx):
    """A BLOB_CHUNK with enc=zlib gets decompressed before write."""
    daemon = receiver_ctx["daemon"]
    plain = receiver_ctx["plain"]
    blob_hash = receiver_ctx["blob_hash"]
    peer_fp = receiver_ctx["peer_fp"]
    # Encode the plain bytes as the sender would.
    compressed = zlib.compress(plain, level=1)
    msg = {
        "t": "BLOB_CHUNK",
        "blob": blob_hash,
        "seq": 0,
        "data": base64.b64encode(compressed).decode("ascii"),
        "enc": "zlib",
        "eof": True,
    }
    chan = MagicMock()
    chan.send = AsyncMock()
    await daemon._handle_blob_chunk(chan, msg, peer_fp)
    # The blob landed in the store with the right hash.
    assert daemon.blob_store.has(blob_hash)


@pytest.mark.asyncio
async def test_handle_blob_chunk_rejects_zlib_bomb(receiver_ctx):
    """A BLOB_CHUNK whose decoded size exceeds CHUNK_SIZE must
    abort the transfer without writing."""
    daemon = receiver_ctx["daemon"]
    peer_fp = receiver_ctx["peer_fp"]
    blob_hash = receiver_ctx["blob_hash"]
    # Build a bomb: tiny zlib → huge output.
    from one_link.daemon import CHUNK_SIZE
    bomb_plain = b"x" * (CHUNK_SIZE * 4)
    bomb = zlib.compress(bomb_plain, level=9)
    msg = {
        "t": "BLOB_CHUNK", "blob": blob_hash, "seq": 0,
        "data": base64.b64encode(bomb).decode("ascii"),
        "enc": "zlib", "eof": False,
    }
    chan = MagicMock()
    chan.send = AsyncMock()
    await daemon._handle_blob_chunk(chan, msg, peer_fp)
    # Aborted: incoming entry cleared.
    assert blob_hash not in daemon._incoming_blobs


# ── source guards ────────────────────────────────────────────────


def _push_body() -> str:
    # 2026-05-27: the BLOB_CHUNK send loop (with _encode_payload +
    # enc= field) was extracted from push_folder_to_peer into the
    # shared _stream_blobs_for_wants helper so the half-duplex AND
    # full-duplex paths reuse one sender. Inspect both.
    src = inspect.getsource(Daemon.push_folder_to_peer)
    src += "\n" + inspect.getsource(Daemon._stream_blobs_for_wants)
    return inspect.cleandoc(src)


def test_push_folder_loop_calls_encode_payload():
    body = _push_body()
    assert "_encode_payload" in body, (
        "push_folder_to_peer no longer calls _encode_payload on "
        "BLOB_CHUNK data — compression regression on the MANIFEST_PUSH "
        "path; text/code folders re-uncompressed"
    )


def test_push_folder_loop_advertises_enc_field():
    body = _push_body()
    assert "enc=enc" in body or 'enc=enc,' in body or '"enc":' in body, (
        "BLOB_CHUNK frame no longer carries the enc field; receiver "
        "would default to raw and corrupt zlib-compressed chunks"
    )


def test_handle_blob_chunk_calls_decode_payload():
    src = inspect.getsource(Daemon._handle_blob_chunk)
    assert "_decode_payload" in src, (
        "_handle_blob_chunk no longer calls _decode_payload — would "
        "write zlib-compressed bytes raw to blob_store and the hash "
        "check would fail"
    )


# ── Wave 6: per-blob progress broadcast ──────────────────────────


@pytest.mark.asyncio
async def test_handle_blob_chunk_broadcasts_per_blob_progress(receiver_ctx):
    """Successful BLOB_CHUNK eof emits a folder_recv_blob_done WS
    event so the UI can show live progress during folder receive."""
    daemon = receiver_ctx["daemon"]
    daemon.ui_server = MagicMock()
    daemon.ui_server.broadcast = MagicMock()
    plain = receiver_ctx["plain"]
    blob_hash = receiver_ctx["blob_hash"]
    peer_fp = receiver_ctx["peer_fp"]
    msg = {
        "t": "BLOB_CHUNK", "blob": blob_hash, "seq": 0,
        "data": base64.b64encode(plain).decode("ascii"),
        "enc": "raw", "eof": True,
    }
    chan = MagicMock()
    chan.send = AsyncMock()
    await daemon._handle_blob_chunk(chan, msg, peer_fp)
    # Find the folder_recv_blob_done broadcast.
    calls = daemon.ui_server.broadcast.call_args_list
    payloads = [c.args[0] for c in calls if c.args]
    progress_events = [
        p for p in payloads if p.get("type") == "folder_recv_blob_done"
    ]
    assert len(progress_events) == 1
    assert progress_events[0]["blob"] == blob_hash
    assert progress_events[0]["peer_fp"] == peer_fp
    assert progress_events[0]["size"] == len(plain)
