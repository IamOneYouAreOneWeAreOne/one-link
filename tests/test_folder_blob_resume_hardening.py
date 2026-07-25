"""Crash-safe and adversarial coverage for resumed folder CAS blobs."""

from __future__ import annotations

import asyncio
import base64
import os
import threading
from collections import OrderedDict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import blake3
import pytest

from one_link import foldersync
from one_link.blobstore import BlobStore
from one_link.capabilities import (
    FOLDER_BLOB_RESUME_V1,
    FOLDER_SYNC_BIDI_V1,
    FOLDER_SYNC_COMMIT_V1,
    LOCAL_CAPABILITIES,
    TRANSPORT_LAYER_CAPS,
)
from one_link.daemon import (
    CHUNK_SIZE,
    FOLDER_BLOB_MAX_BYTES,
    Daemon,
)
from one_link.state import State
from one_link.storage_lifecycle import build_cas_gc_manifest
from one_link.transfer_safety import (
    InboundTransferReservationLedger,
    TransferAdmissionPolicy,
)
from one_link.wire import decode_msg, make_msg


PEER_FP = "12" * 32


def _channel(binding: str, *, resume: bool = True) -> SimpleNamespace:
    features = [FOLDER_SYNC_COMMIT_V1]
    if resume:
        features.append(FOLDER_BLOB_RESUME_V1)
    return SimpleNamespace(
        send=AsyncMock(),
        transcript_hex=binding,
        peer_caps={"features": features},
    )


def _daemon(tmp_path: Path) -> Daemon:
    daemon = Daemon.__new__(Daemon)
    daemon.me = SimpleNamespace(short_id="self")
    daemon.state = MagicMock()
    daemon.state.get_folder.return_value = {
        "name": "docs",
        "shared_with": [PEER_FP],
    }
    daemon.state.folder_peer_allows.return_value = True
    daemon.folder_engine = MagicMock()
    daemon.folder_engine.materialize_after_blob_arrived.return_value = 1
    daemon.blob_store = BlobStore(tmp_path / "blobs")
    daemon.ui_server = None
    daemon._is_pinned = MagicMock(return_value=True)
    daemon._incoming_blobs = {}
    daemon._expected_blob_pulls = {}
    daemon._expected_blob_pull_scopes = {}
    daemon._folder_sync_inbound_receipts = OrderedDict()
    daemon._folder_sync_outbound_receipts = OrderedDict()
    daemon._folder_sync_verified_inbound = OrderedDict()
    daemon._folder_sync_verified_outbound = OrderedDict()
    daemon._folder_sync_blob_progress = {}
    daemon._folder_sync_verify_semaphore = asyncio.Semaphore(1)
    daemon._cache_transfer_reservations = InboundTransferReservationLedger(
        tmp_path / "blobs",
    )
    daemon._transfer_admission_policy = TransferAdmissionPolicy(
        max_declared_bytes=FOLDER_BLOB_MAX_BYTES,
        min_free_reserve_bytes=0,
        free_reserve_ratio=0.0,
    )
    daemon._dedupe_sites = MagicMock()
    return daemon


def _entry(blob_hash: str, size: int, *, path: str = "large.bin") -> dict:
    return {
        "file_path": path,
        "blob_hash": blob_hash,
        "size": size,
        "mtime_ms": 1,
        "vclock": {PEER_FP: 1},
    }


def _register_inbound(
    daemon: Daemon,
    channel: SimpleNamespace,
    *,
    sync_id: str,
    blob_hash: str,
    size: int,
    resume_range: tuple[str, int, int, str] | None,
) -> None:
    entry = _entry(blob_hash, size)
    daemon._register_inbound_folder_sync_receipt(
        channel=channel,
        peer_fp=PEER_FP,
        sync_id=sync_id,
        folder_name="docs",
        source_root=foldersync.manifest_root_for_entries([entry]),
        manifest_digest=Daemon._folder_manifest_digest([entry]),
        entry_count=1,
        wants=(blob_hash,),
        blob_sizes=((blob_hash, size),),
        affected_paths=("large.bin",),
        source_entries=(entry,),
        resume_ranges=(() if resume_range is None else (resume_range,)),
    )


def test_resume_capability_is_transport_only() -> None:
    assert FOLDER_BLOB_RESUME_V1 in LOCAL_CAPABILITIES
    assert FOLDER_BLOB_RESUME_V1 in TRANSPORT_LAYER_CAPS


def test_partial_blob_restarts_at_exact_durable_prefix(tmp_path: Path) -> None:
    payload = os.urandom(2 * 1024 * 1024 + 37)
    blob_hash = blake3.blake3(payload).hexdigest()
    empty_digest = blake3.blake3().hexdigest()
    store = BlobStore(tmp_path / "cas")

    with store.partial_writer(
        peer_fp=PEER_FP,
        blob_hash=blob_hash,
        size=len(payload),
        expected_offset=0,
        expected_prefix_digest=empty_digest,
    ) as (writer, _path):
        writer.write(payload[: 1024 * 1024])

    restarted = BlobStore(tmp_path / "cas")
    status = restarted.partial_status(PEER_FP, blob_hash, len(payload))
    assert status is not None
    assert status.received == 1024 * 1024
    assert status.prefix_digest == blake3.blake3(
        payload[: 1024 * 1024],
    ).hexdigest()

    with restarted.partial_writer(
        peer_fp=PEER_FP,
        blob_hash=blob_hash,
        size=len(payload),
        expected_offset=status.received,
        expected_prefix_digest=status.prefix_digest,
    ) as (writer, _path):
        writer.write(payload[status.received :])
        assert writer.commit(expected_hash=blob_hash) == blob_hash

    assert restarted.read_bytes(blob_hash) == payload
    assert restarted.partial_status(PEER_FP, blob_hash, len(payload)) is None


def test_restart_truncates_bytes_beyond_last_fsynced_metadata(
    tmp_path: Path,
) -> None:
    payload = os.urandom(64 * 1024)
    blob_hash = blake3.blake3(payload).hexdigest()
    store = BlobStore(tmp_path / "cas")
    cm = store.partial_writer(
        peer_fp=PEER_FP,
        blob_hash=blob_hash,
        size=len(payload),
        expected_offset=0,
        expected_prefix_digest=blake3.blake3().hexdigest(),
    )
    writer, data_path = cm.__enter__()
    durable = 16 * 1024
    writer.write(payload[:durable])
    writer.checkpoint()
    writer.write(payload[durable : durable + 4096])
    assert writer._fh is not None  # abrupt-process-death simulation
    writer._fh.flush()
    os.fsync(writer._fh.fileno())
    writer._fh.close()
    writer._fh = None

    restarted = BlobStore(tmp_path / "cas")
    status = restarted.partial_status(PEER_FP, blob_hash, len(payload))
    assert status is not None
    assert status.received == durable
    assert data_path.stat().st_size == durable


def test_partial_prefix_corruption_is_discarded_fail_closed(tmp_path: Path) -> None:
    payload = b"durable prefix" * 4096
    blob_hash = blake3.blake3(payload).hexdigest()
    store = BlobStore(tmp_path / "cas")
    with store.partial_writer(
        peer_fp=PEER_FP,
        blob_hash=blob_hash,
        size=len(payload),
        expected_offset=0,
        expected_prefix_digest=blake3.blake3().hexdigest(),
    ) as (writer, data_path):
        writer.write(payload[:32768])

    with open(data_path, "r+b") as fh:
        fh.seek(0)
        fh.write(b"X")
        fh.flush()
        os.fsync(fh.fileno())
    assert store.partial_status(PEER_FP, blob_hash, len(payload)) is None
    assert list((store.root / "_partials").glob("*.part")) == []
    assert list((store.root / "_partials").glob("*.json")) == []


def test_blob_store_rejects_redirected_partial_staging(tmp_path: Path) -> None:
    root = tmp_path / "cas"
    target = tmp_path / "redirect-target"
    root.mkdir()
    target.mkdir()
    try:
        (root / "_partials").symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")

    with pytest.raises(OSError, match="staging root must be a real directory"):
        BlobStore(root)


def test_partial_cleanup_enforces_ttl_entry_and_byte_budgets(tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "cas")
    for index in range(2):
        payload = bytes([index]) * 4096
        blob_hash = blake3.blake3(payload).hexdigest()
        with store.partial_writer(
            peer_fp=PEER_FP,
            blob_hash=blob_hash,
            size=len(payload),
            expected_offset=0,
            expected_prefix_digest=blake3.blake3().hexdigest(),
        ) as (writer, _path):
            writer.write(payload[:2048])

    bounded = store.cleanup_partials(
        older_than_s=3600,
        max_total_bytes=4096,
        max_entries=1,
    )
    assert bounded["removed"] == 1
    assert bounded["remaining"] == 1
    expired = store.cleanup_partials(
        older_than_s=0,
        max_total_bytes=4096,
        max_entries=1,
    )
    assert expired["removed"] == 1
    assert expired["remaining"] == 0


def test_cas_lifecycle_audits_but_never_collects_valid_partials(
    tmp_path: Path,
) -> None:
    state = State(db_path=tmp_path / "state.db")
    store = BlobStore(tmp_path / "blobs")
    payload = b"not yet a complete CAS object" * 1024
    blob_hash = blake3.blake3(payload).hexdigest()
    try:
        with store.partial_writer(
            peer_fp=PEER_FP,
            blob_hash=blob_hash,
            size=len(payload),
            expected_offset=0,
            expected_prefix_digest=blake3.blake3().hexdigest(),
        ) as (writer, _path):
            writer.write(payload[:4096])

        manifest = build_cas_gc_manifest(
            state,
            store.root,
            now_ms=10_000,
            grace_ms=0,
        )
        assert manifest["safe_to_execute"] is True
        assert manifest["errors"] == []
        assert manifest["disk_count"] == 0
        assert manifest["candidates"] == []
    finally:
        state.close()


def test_cas_lifecycle_fails_closed_on_unrecognized_partial_staging(
    tmp_path: Path,
) -> None:
    state = State(db_path=tmp_path / "state.db")
    store = BlobStore(tmp_path / "blobs")
    (store.root / "_partials" / "attacker-controlled").write_bytes(b"x")
    try:
        manifest = build_cas_gc_manifest(
            state,
            store.root,
            now_ms=10_000,
            grace_ms=0,
        )
        assert manifest["safe_to_execute"] is False
        assert any(
            "unexpected partial staging entry" in error
            for error in manifest["errors"]
        )
    finally:
        state.close()


@pytest.mark.asyncio
async def test_disconnect_resumes_suffix_on_new_authenticated_channel(
    tmp_path: Path,
) -> None:
    daemon = _daemon(tmp_path)
    payload = os.urandom(CHUNK_SIZE + 257)
    blob_hash = blake3.blake3(payload).hexdigest()
    first_channel = _channel("a" * 64)
    first_sync = "b" * 32
    initial = (blob_hash, len(payload), 0, blake3.blake3().hexdigest())
    _register_inbound(
        daemon,
        first_channel,
        sync_id=first_sync,
        blob_hash=blob_hash,
        size=len(payload),
        resume_range=initial,
    )
    await daemon._handle_blob_offer(
        first_channel,
        {
            "blob": blob_hash,
            "size": len(payload),
            "folder": "docs",
            "sync_id": first_sync,
            "offset": 0,
            "prefix_digest": initial[3],
        },
        PEER_FP,
    )
    await daemon._handle_blob_chunk(
        first_channel,
        {
            "blob": blob_hash,
            "seq": 0,
            "folder": "docs",
            "sync_id": first_sync,
            "offset": 0,
            "data": base64.b64encode(payload[:CHUNK_SIZE]).decode("ascii"),
            "eof": False,
            "enc": "raw",
        },
        PEER_FP,
    )

    daemon._cleanup_folder_channel_state(first_channel, PEER_FP)
    status = daemon.blob_store.partial_status(PEER_FP, blob_hash, len(payload))
    assert status is not None
    assert status.received == CHUNK_SIZE
    assert daemon._cache_transfer_reservations.snapshot() == ()

    second_channel = _channel("c" * 64)
    second_sync = "d" * 32
    claims = await daemon._folder_blob_resume_claims(
        peer_fp=PEER_FP,
        wants_data=({"blob_hash": blob_hash, "size": len(payload)},),
    )
    assert claims == ((
        blob_hash,
        len(payload),
        CHUNK_SIZE,
        blake3.blake3(payload[:CHUNK_SIZE]).hexdigest(),
    ),)
    _register_inbound(
        daemon,
        second_channel,
        sync_id=second_sync,
        blob_hash=blob_hash,
        size=len(payload),
        resume_range=claims[0],
    )
    await daemon._handle_blob_offer(
        second_channel,
        {
            "blob": blob_hash,
            "size": len(payload),
            "folder": "docs",
            "sync_id": second_sync,
            "offset": CHUNK_SIZE,
            "prefix_digest": claims[0][3],
        },
        PEER_FP,
    )
    await daemon._handle_blob_chunk(
        second_channel,
        {
            "blob": blob_hash,
            "seq": 0,
            "folder": "docs",
            "sync_id": second_sync,
            "offset": CHUNK_SIZE,
            "data": base64.b64encode(payload[CHUNK_SIZE:]).decode("ascii"),
            "eof": True,
            "enc": "raw",
        },
        PEER_FP,
    )

    assert daemon.blob_store.read_bytes(blob_hash) == payload
    assert daemon.blob_store.partial_status(PEER_FP, blob_hash, len(payload)) is None
    daemon.folder_engine.materialize_after_blob_arrived.assert_called_once_with(
        blob_hash=blob_hash,
    )


@pytest.mark.asyncio
async def test_manifest_wants_binds_durable_resume_claim_to_receipt(
    tmp_path: Path,
) -> None:
    daemon = _daemon(tmp_path)
    payload = os.urandom(CHUNK_SIZE + 31)
    blob_hash = blake3.blake3(payload).hexdigest()
    with daemon.blob_store.partial_writer(
        peer_fp=PEER_FP,
        blob_hash=blob_hash,
        size=len(payload),
        expected_offset=0,
        expected_prefix_digest=blake3.blake3().hexdigest(),
    ) as (writer, _path):
        writer.write(payload[:CHUNK_SIZE])
    entry = _entry(blob_hash, len(payload))
    root = foldersync.manifest_root_for_entries([entry])
    daemon.state.list_manifest.return_value = []
    daemon.state.get_manifest_entry.return_value = None
    daemon.folder_engine.manifest_root.return_value = "a" * 64
    daemon.folder_engine.manifest_for.return_value = []
    daemon.folder_engine.receive_remote_manifest.return_value = [entry]
    daemon._sandbox_filter_manifest_entries = MagicMock(return_value=[entry])
    channel = _channel("0" * 64)
    push = make_msg(
        "MANIFEST_PUSH",
        "peer",
        folder="docs",
        entries=[entry],
        merkle_root=root,
        manifest_digest=Daemon._folder_manifest_digest([entry]),
        entry_count=1,
    )

    await daemon._handle_manifest_push(channel, push, PEER_FP)

    response = decode_msg(channel.send.await_args_list[0].args[0])
    expected_digest = blake3.blake3(payload[:CHUNK_SIZE]).hexdigest()
    assert response["resume"] == [{
        "blob": blob_hash,
        "size": len(payload),
        "offset": CHUNK_SIZE,
        "prefix_digest": expected_digest,
    }]
    receipt = daemon._folder_sync_inbound_receipts[
        (PEER_FP, channel.transcript_hex, push["id"])
    ]
    assert receipt.resume_ranges == ((
        blob_hash,
        len(payload),
        CHUNK_SIZE,
        expected_digest,
    ),)


@pytest.mark.asyncio
async def test_resume_capable_pending_response_releases_offer_without_resume_fields(
    tmp_path: Path,
) -> None:
    daemon = _daemon(tmp_path)
    entry = _entry("a" * 64, 1)
    channel = _channel("b" * 64)
    sync_id = "c" * 32
    daemon._register_outbound_folder_sync_offer(
        channel=channel,
        peer_fp=PEER_FP,
        sync_id=sync_id,
        folder_name="docs",
        source_root=foldersync.manifest_root_for_entries([entry]),
        manifest_digest=Daemon._folder_manifest_digest([entry]),
        entries=[entry],
    )
    response = make_msg(
        "MANIFEST_WANTS",
        "peer",
        folder="docs",
        wants=[],
        of=sync_id,
        sync_id=sync_id,
        pending_offer=True,
    )

    await daemon._handle_manifest_wants(channel, response, PEER_FP)

    key = (PEER_FP, channel.transcript_hex, sync_id)
    assert key not in daemon._folder_sync_outbound_receipts
    channel.send.assert_not_awaited()


@pytest.mark.asyncio
async def test_resumed_writer_rehash_does_not_block_event_loop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon = _daemon(tmp_path)
    payload = os.urandom(CHUNK_SIZE + 1)
    blob_hash = blake3.blake3(payload).hexdigest()
    channel = _channel("d" * 64)
    sync_id = "e" * 32
    claim = (blob_hash, len(payload), 0, blake3.blake3().hexdigest())
    _register_inbound(
        daemon,
        channel,
        sync_id=sync_id,
        blob_hash=blob_hash,
        size=len(payload),
        resume_range=claim,
    )
    original_status = daemon.blob_store.partial_status
    started = threading.Event()
    release = threading.Event()

    def _slow_status(*args: object):
        started.set()
        assert release.wait(timeout=5)
        return original_status(*args)

    monkeypatch.setattr(daemon.blob_store, "partial_status", _slow_status)
    opening = asyncio.create_task(daemon._handle_blob_offer(
        channel,
        {
            "blob": blob_hash,
            "size": len(payload),
            "folder": "docs",
            "sync_id": sync_id,
            "offset": 0,
            "prefix_digest": claim[3],
        },
        PEER_FP,
    ))
    assert await asyncio.to_thread(started.wait, 2)
    loop_tick = asyncio.Event()
    asyncio.get_running_loop().call_soon(loop_tick.set)
    await asyncio.wait_for(loop_tick.wait(), timeout=0.5)
    assert not opening.done()
    release.set()
    await asyncio.wait_for(opening, timeout=2)
    assert len(daemon._incoming_blobs) == 1
    daemon._cleanup_folder_channel_state(channel, PEER_FP)


@pytest.mark.asyncio
async def test_resume_offer_and_chunk_offsets_are_exact_and_fail_closed(
    tmp_path: Path,
) -> None:
    daemon = _daemon(tmp_path)
    payload = os.urandom(CHUNK_SIZE + 5)
    blob_hash = blake3.blake3(payload).hexdigest()
    channel = _channel("e" * 64)
    sync_id = "f" * 32
    claim = (blob_hash, len(payload), 0, blake3.blake3().hexdigest())
    _register_inbound(
        daemon,
        channel,
        sync_id=sync_id,
        blob_hash=blob_hash,
        size=len(payload),
        resume_range=claim,
    )

    await daemon._handle_blob_offer(
        channel,
        {
            "blob": blob_hash,
            "size": len(payload),
            "folder": "docs",
            "sync_id": sync_id,
            "offset": 1,
            "prefix_digest": claim[3],
        },
        PEER_FP,
    )
    assert daemon._incoming_blobs == {}
    assert daemon._cache_transfer_reservations.snapshot() == ()

    await daemon._handle_blob_offer(
        channel,
        {
            "blob": blob_hash,
            "size": len(payload),
            "folder": "docs",
            "sync_id": sync_id,
            "offset": 0,
            "prefix_digest": claim[3],
        },
        PEER_FP,
    )
    assert len(daemon._incoming_blobs) == 1
    await daemon._handle_blob_chunk(
        channel,
        {
            "blob": blob_hash,
            "seq": 0,
            "folder": "docs",
            "sync_id": sync_id,
            "offset": 1,
            "data": base64.b64encode(payload[:CHUNK_SIZE]).decode("ascii"),
            "eof": False,
            "enc": "raw",
        },
        PEER_FP,
    )
    assert daemon._incoming_blobs == {}
    assert daemon.blob_store.partial_status(PEER_FP, blob_hash, len(payload)) is None


@pytest.mark.asyncio
async def test_sender_rejects_forged_resume_prefix_before_streaming(
    tmp_path: Path,
) -> None:
    daemon = _daemon(tmp_path)
    payload = os.urandom(CHUNK_SIZE + 11)
    blob_hash = daemon.blob_store.put_bytes(payload)
    entry = _entry(blob_hash, len(payload))
    channel = _channel("1" * 64)
    sync_id = "2" * 32
    daemon._register_outbound_folder_sync_offer(
        channel=channel,
        peer_fp=PEER_FP,
        sync_id=sync_id,
        folder_name="docs",
        source_root=foldersync.manifest_root_for_entries([entry]),
        manifest_digest=Daemon._folder_manifest_digest([entry]),
        entries=[entry],
    )
    request = make_msg(
        "MANIFEST_WANTS",
        "peer",
        folder="docs",
        wants=[blob_hash],
        of=sync_id,
        sync_id=sync_id,
        resume=[{
            "blob": blob_hash,
            "size": len(payload),
            "offset": CHUNK_SIZE,
            "prefix_digest": "f" * 64,
        }],
    )

    with pytest.raises(RuntimeError, match="prefix proof mismatch"):
        await daemon._handle_manifest_wants(channel, request, PEER_FP)
    channel.send.assert_not_awaited()


@pytest.mark.asyncio
async def test_sender_streams_only_proven_suffix_with_absolute_offsets(
    tmp_path: Path,
) -> None:
    daemon = _daemon(tmp_path)
    daemon._update_transfer = MagicMock()
    daemon._throttle_chunk = AsyncMock()
    payload = os.urandom(CHUNK_SIZE + 99)
    blob_hash = daemon.blob_store.put_bytes(payload)
    channel = _channel("3" * 64)
    prefix_digest = blake3.blake3(payload[:CHUNK_SIZE]).hexdigest()

    blobs_sent, bytes_sent = await daemon._stream_blobs_for_wants(
        channel=channel,
        folder_name="docs",
        wants=[blob_hash],
        peer_fp=PEER_FP,
        peer_short_id="peer",
        transfer_id="transfer",
        total_bytes=len(payload),
        entries_count=1,
        merkle_root="4" * 64,
        sync_id="5" * 32,
        expected_sizes={blob_hash: len(payload)},
        resume_requests={blob_hash: (CHUNK_SIZE, prefix_digest)},
    )

    frames = [decode_msg(call.args[0]) for call in channel.send.await_args_list]
    assert (blobs_sent, bytes_sent) == (1, 99)
    assert frames[0]["t"] == "BLOB_OFFER"
    assert frames[0]["offset"] == CHUNK_SIZE
    assert frames[0]["prefix_digest"] == prefix_digest
    assert frames[1]["t"] == "BLOB_CHUNK"
    assert frames[1]["seq"] == 0
    assert frames[1]["offset"] == CHUNK_SIZE
    assert frames[1]["eof"] is True
    assert base64.b64decode(frames[1]["data"]) == payload[CHUNK_SIZE:]


@pytest.mark.asyncio
async def test_sender_cancellation_waits_for_disk_read_before_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon = _daemon(tmp_path)
    daemon._update_transfer = MagicMock()
    daemon._throttle_chunk = AsyncMock()
    payload = b"cancellation-safe disk reader"
    blob_hash = daemon.blob_store.put_bytes(payload)
    channel = _channel("4" * 64, resume=False)
    started = threading.Event()
    release = threading.Event()
    read_active = threading.Event()
    closed = threading.Event()

    class _SlowReader:
        def seek(self, offset: int) -> int:
            assert offset == 0
            return 0

        def read(self, size: int) -> bytes:
            assert size == CHUNK_SIZE
            read_active.set()
            started.set()
            assert release.wait(timeout=5)
            read_active.clear()
            return payload

        def close(self) -> None:
            assert not read_active.is_set()
            closed.set()

    async def _open(_blob_hash: str) -> _SlowReader:
        assert _blob_hash == blob_hash
        return _SlowReader()

    monkeypatch.setattr(daemon, "_open_folder_blob_read", _open)
    streaming = asyncio.create_task(daemon._stream_blobs_for_wants(
        channel=channel,
        folder_name="docs",
        wants=[blob_hash],
        peer_fp=PEER_FP,
        peer_short_id="peer",
        transfer_id="transfer",
        total_bytes=len(payload),
        entries_count=1,
        merkle_root="5" * 64,
        sync_id="6" * 32,
        expected_sizes={blob_hash: len(payload)},
    ))
    assert await asyncio.to_thread(started.wait, 2)
    streaming.cancel()
    await asyncio.sleep(0)
    assert not streaming.done()
    assert not closed.is_set()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(streaming, timeout=2)
    assert closed.is_set()


@pytest.mark.asyncio
async def test_materialization_runs_off_loop_after_durable_commit(
    tmp_path: Path,
) -> None:
    daemon = _daemon(tmp_path)
    payload = b"off-loop materialization"
    blob_hash = blake3.blake3(payload).hexdigest()
    channel = _channel("6" * 64, resume=False)
    sync_id = "7" * 32
    _register_inbound(
        daemon,
        channel,
        sync_id=sync_id,
        blob_hash=blob_hash,
        size=len(payload),
        resume_range=None,
    )
    await daemon._handle_blob_offer(
        channel,
        {
            "blob": blob_hash,
            "size": len(payload),
            "folder": "docs",
            "sync_id": sync_id,
        },
        PEER_FP,
    )
    started = threading.Event()
    release = threading.Event()

    def _slow_materialize(*, blob_hash: str) -> int:
        del blob_hash
        started.set()
        assert release.wait(timeout=5)
        return 1

    daemon.folder_engine.materialize_after_blob_arrived.side_effect = _slow_materialize
    receive = asyncio.create_task(daemon._handle_blob_chunk(
        channel,
        {
            "blob": blob_hash,
            "seq": 0,
            "folder": "docs",
            "sync_id": sync_id,
            "data": base64.b64encode(payload).decode("ascii"),
            "eof": True,
            "enc": "raw",
        },
        PEER_FP,
    ))
    assert await asyncio.to_thread(started.wait, 2)
    loop_tick = asyncio.Event()
    asyncio.get_running_loop().call_soon(loop_tick.set)
    await asyncio.wait_for(loop_tick.wait(), timeout=0.5)
    assert not receive.done()
    release.set()
    await asyncio.wait_for(receive, timeout=2)


@pytest.mark.asyncio
async def test_large_manifest_progress_is_incremental_not_quadratic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon = _daemon(tmp_path)
    daemon.ui_server = SimpleNamespace(broadcast=MagicMock())
    payload = b"one completed blob"
    blob_hash = blake3.blake3(payload).hexdigest()
    other_hashes = [blake3.blake3(f"other-{i}".encode()).hexdigest() for i in range(300)]
    wants = (blob_hash, *other_hashes)
    entries = tuple(
        _entry(value, len(payload) if value == blob_hash else 1, path=f"p/{i}.bin")
        for i, value in enumerate(wants)
    )
    channel = _channel("8" * 64, resume=False)
    sync_id = "9" * 32
    daemon._register_inbound_folder_sync_receipt(
        channel=channel,
        peer_fp=PEER_FP,
        sync_id=sync_id,
        folder_name="docs",
        source_root="a" * 64,
        manifest_digest="b" * 64,
        entry_count=len(entries),
        wants=wants,
        blob_sizes=(
            (value, len(payload) if value == blob_hash else 1)
            for value in wants
        ),
        affected_paths=tuple(entry["file_path"] for entry in entries),
        source_entries=entries,
    )
    await daemon._handle_blob_offer(
        channel,
        {
            "blob": blob_hash,
            "size": len(payload),
            "folder": "docs",
            "sync_id": sync_id,
        },
        PEER_FP,
    )
    original_has = daemon.blob_store.has
    has_calls = 0

    def _counted_has(value: str) -> bool:
        nonlocal has_calls
        has_calls += 1
        return original_has(value)

    monkeypatch.setattr(daemon.blob_store, "has", _counted_has)
    await daemon._handle_blob_chunk(
        channel,
        {
            "blob": blob_hash,
            "seq": 0,
            "folder": "docs",
            "sync_id": sync_id,
            "data": base64.b64encode(payload).decode("ascii"),
            "eof": True,
            "enc": "raw",
        },
        PEER_FP,
    )

    assert has_calls < 10
    progress_events = [
        call.args[0]
        for call in daemon.ui_server.broadcast.call_args_list
        if call.args[0].get("type") == "folder_recv_blob_done"
    ]
    assert progress_events[-1]["remaining"] == len(wants) - 1


def test_manifest_depth_and_total_verification_bounds() -> None:
    daemon = Daemon.__new__(Daemon)
    blob_hash = "c" * 64
    depth_64 = "/".join(f"d{i}" for i in range(63)) + "/file.bin"
    depth_65 = "/".join(f"d{i}" for i in range(64)) + "/file.bin"
    daemon._validate_folder_manifest_entries([
        _entry(blob_hash, FOLDER_BLOB_MAX_BYTES, path=depth_64),
    ])
    with pytest.raises(RuntimeError, match="unsafe path"):
        daemon._validate_folder_manifest_entries([
            _entry(blob_hash, 1, path=depth_65),
        ])
    with pytest.raises(RuntimeError, match="verification byte limit"):
        daemon._validate_folder_manifest_entries([
            _entry("d" * 64, FOLDER_BLOB_MAX_BYTES, path="a.bin"),
            _entry("e" * 64, 1, path="b.bin"),
        ])


@pytest.mark.asyncio
async def test_unshared_folder_is_rejected_before_manifest_work(
    tmp_path: Path,
) -> None:
    daemon = _daemon(tmp_path)
    daemon.state.get_folder.return_value = {
        "name": "docs",
        "shared_with": [],
    }
    daemon._validate_folder_manifest_entries = MagicMock(
        side_effect=AssertionError("expensive validation must not run"),
    )
    channel = _channel("d" * 64)
    message = make_msg(
        "MANIFEST_PUSH",
        "peer",
        folder="docs",
        entries=[{"attacker": "controlled"}],
        merkle_root="e" * 64,
        manifest_digest="f" * 64,
        entry_count=1,
    )

    await daemon._handle_manifest_push(channel, message, PEER_FP)

    daemon._validate_folder_manifest_entries.assert_not_called()
    daemon.folder_engine.receive_remote_manifest.assert_not_called()
    channel.send.assert_not_awaited()


@pytest.mark.asyncio
async def test_equal_content_root_with_new_metadata_is_merged(
    tmp_path: Path,
) -> None:
    daemon = _daemon(tmp_path)
    blob_hash = "1" * 64
    local = _entry(blob_hash, 7, path="same.bin")
    remote = {
        **local,
        "mtime_ms": 2,
        "vclock": {PEER_FP: 2},
    }
    root = foldersync.manifest_root_for_entries([remote])
    assert root == foldersync.manifest_root_for_entries([local])
    daemon.state.list_manifest.return_value = [local]
    daemon.state.get_manifest_entry.return_value = local
    daemon.folder_engine.manifest_root.return_value = root
    daemon.folder_engine.manifest_for.return_value = [local]
    daemon.folder_engine.receive_remote_manifest.return_value = []
    daemon._sandbox_filter_manifest_entries = MagicMock(return_value=[remote])
    channel = _channel("2" * 64, resume=False)
    message = make_msg(
        "MANIFEST_PUSH",
        "peer",
        folder="docs",
        entries=[remote],
        merkle_root=root,
        manifest_digest=Daemon._folder_manifest_digest([remote]),
        entry_count=1,
    )

    await daemon._handle_manifest_push(channel, message, PEER_FP)

    daemon.folder_engine.receive_remote_manifest.assert_called_once_with(
        folder_name="docs",
        entries=[remote],
        peer_fp=PEER_FP,
    )
    response = decode_msg(channel.send.await_args_list[0].args[0])
    assert response["t"] == "MANIFEST_WANTS"
    assert response.get("already_in_sync") is not True


@pytest.mark.asyncio
async def test_equal_manifest_still_honors_bidirectional_reverse_request(
    tmp_path: Path,
) -> None:
    daemon = _daemon(tmp_path)
    entry = _entry("3" * 64, 9, path="same.bin")
    root = foldersync.manifest_root_for_entries([entry])
    daemon.state.list_manifest.return_value = [entry]
    daemon.state.get_manifest_entry.return_value = entry
    daemon.folder_engine.manifest_root.return_value = root
    daemon.folder_engine.manifest_for.return_value = [entry]
    daemon._send_local_manifest_in_channel = AsyncMock(return_value="4" * 32)
    channel = _channel("5" * 64, resume=False)
    channel.peer_caps["features"].append(FOLDER_SYNC_BIDI_V1)
    message = make_msg(
        "MANIFEST_PUSH",
        "peer",
        folder="docs",
        entries=[entry],
        merkle_root=root,
        manifest_digest=Daemon._folder_manifest_digest([entry]),
        entry_count=1,
        request_reverse=True,
    )

    await daemon._handle_manifest_push(channel, message, PEER_FP)

    daemon.folder_engine.receive_remote_manifest.assert_not_called()
    daemon._send_local_manifest_in_channel.assert_awaited_once_with(
        channel=channel,
        folder_name="docs",
        peer_fp=PEER_FP,
    )


@pytest.mark.asyncio
async def test_equal_manifest_with_missing_cas_requests_durable_partial_suffix(
    tmp_path: Path,
) -> None:
    daemon = _daemon(tmp_path)
    payload = os.urandom(CHUNK_SIZE + 17)
    blob_hash = blake3.blake3(payload).hexdigest()
    entry = _entry(blob_hash, len(payload), path="same.bin")
    root = foldersync.manifest_root_for_entries([entry])
    with daemon.blob_store.partial_writer(
        peer_fp=PEER_FP,
        blob_hash=blob_hash,
        size=len(payload),
        expected_offset=0,
        expected_prefix_digest=blake3.blake3().hexdigest(),
    ) as (writer, _path):
        writer.write(payload[:CHUNK_SIZE])
    daemon.state.list_manifest.return_value = [entry]
    daemon.state.get_manifest_entry.return_value = entry
    daemon.folder_engine.manifest_root.return_value = root
    daemon.folder_engine.manifest_for.return_value = [entry]
    channel = _channel("6" * 64)
    message = make_msg(
        "MANIFEST_PUSH",
        "peer",
        folder="docs",
        entries=[entry],
        merkle_root=root,
        manifest_digest=Daemon._folder_manifest_digest([entry]),
        entry_count=1,
    )

    await daemon._handle_manifest_push(channel, message, PEER_FP)

    daemon.folder_engine.receive_remote_manifest.assert_not_called()
    response = decode_msg(channel.send.await_args_list[0].args[0])
    assert response["already_in_sync"] is False
    assert response["manifest_already_merged"] is True
    assert response["wants"] == [blob_hash]
    assert response["resume"] == [{
        "blob": blob_hash,
        "size": len(payload),
        "offset": CHUNK_SIZE,
        "prefix_digest": blake3.blake3(payload[:CHUNK_SIZE]).hexdigest(),
    }]
