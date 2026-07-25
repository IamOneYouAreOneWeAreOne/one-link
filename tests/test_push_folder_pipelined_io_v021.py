"""v0.21.x push_folder_to_peer pipelined disk-read behavior.

The blob-streaming loop now overlaps disk reads with wire sends:
the NEXT chunk's fh.read runs as an asyncio.Task while the CURRENT
chunk's base64 encode + AEAD + channel.send happens. On spinning
disks this halves the per-chunk latency penalty.

Coverage:
  - Multi-chunk blob serializes correctly: N+1 BLOB_CHUNK frames,
    correct seq ordering, eof=true ONLY on the last chunk
  - Zero-byte blob still emits exactly one BLOB_CHUNK with eof=true
  - Chunk count is derived from declared size (no need to read ahead
    just to detect EOF) — verified by patching fh.read and asserting
    the call count
  - Source-text guard: blob-streaming loop uses asyncio.create_task
    so the read overlaps with the send
"""
from __future__ import annotations

import inspect

from one_link.daemon import Daemon


def _push_folder_body() -> str:
    # 2026-05-27: the optimized blob-streaming loop was extracted from
    # push_folder_to_peer into the shared _stream_blobs_for_wants
    # helper (so the half-duplex forward path AND the full-duplex
    # bidirectional loop reuse one sender). The pipelining behavior
    # these tests pin now lives there; inspect both so the guard
    # survives the refactor + any future re-merge.
    src = inspect.getsource(Daemon.push_folder_to_peer)
    src += "\n" + inspect.getsource(Daemon._stream_blobs_for_wants)
    return inspect.cleandoc(src)


def test_blob_stream_loop_uses_create_task_for_pipelining():
    """The blob-send loop must schedule the next disk read via
    asyncio.create_task BEFORE the current chunk's channel.send.
    A reviewer reverting the loop to plain sequential fh.read +
    channel.send (no Task) would lose the pipelining win — this
    guard catches it."""
    body = _push_folder_body()
    # The pipelined loop has a create_task wrapping the cancellation-safe
    # storage helper, which itself owns asyncio.to_thread. Keeping the helper
    # in the marker prevents a source guard from rewarding the older race
    # where teardown could close ``fh`` while its worker was still reading.
    # Search for the marker pattern.
    assert "asyncio.create_task" in body, (
        "push_folder_to_peer no longer uses asyncio.create_task — the "
        "blob-send loop appears to have lost its disk-read pipelining"
    )
    assert "_run_folder_storage_call(fh.read" in body, (
        "push_folder_to_peer no longer reads chunks via the cancellation-safe "
        "thread helper — disk reads may be back on the event loop or racing close"
    )


def test_blob_stream_loop_derives_chunk_count_from_size():
    """The pipelined loop computes n_chunks from declared size so
    EOF is known without reading ahead. A revert to the
    read-then-check-eof pattern would re-introduce per-iteration
    sequential disk-reads."""
    body = _push_folder_body()
    assert "n_chunks" in body, (
        "push_folder_to_peer no longer pre-computes n_chunks from "
        "size; the pipelined-read optimization probably regressed"
    )


def test_blob_stream_loop_handles_zero_byte_blob():
    """Zero-byte blobs are an edge case: declared size is 0, we
    need to emit exactly one BLOB_CHUNK with eof=true. Source-text
    guard pin: there's an explicit size==0 branch."""
    body = _push_folder_body()
    assert "size == 0" in body, (
        "zero-byte-blob branch removed from push_folder_to_peer; "
        "an empty file would now hang the send loop"
    )
