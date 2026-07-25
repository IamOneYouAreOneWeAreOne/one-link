"""Adversarial coverage for exact, channel-bound folder-sync receipts."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import blake3
import pytest

from one_link import foldersync
from one_link.blobstore import BlobStore
from one_link.capabilities import FOLDER_SYNC_COMMIT_V1
from one_link.daemon import Daemon
from one_link.foldersync import FolderEngine
from one_link.state import State
from one_link.transfer_safety import (
    InboundTransferReservationLedger,
    TransferAdmissionPolicy,
)
from one_link.wire import decode_msg, make_msg


PEER_FP = "12" * 32


def _channel(binding: str) -> SimpleNamespace:
    return SimpleNamespace(
        send=AsyncMock(),
        transcript_hex=binding,
        peer_caps={"features": [FOLDER_SYNC_COMMIT_V1]},
    )


def _protocol_daemon(tmp_path: Path) -> Daemon:
    """Build only the daemon state used by folder receipt handlers."""

    daemon = Daemon.__new__(Daemon)
    daemon.me = SimpleNamespace(short_id="self")
    daemon.state = MagicMock()
    daemon.state.get_folder.return_value = {
        "name": "docs",
        "shared_with": [PEER_FP],
    }
    daemon.state.folder_peer_allows.return_value = True
    daemon.folder_engine = MagicMock()
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
    daemon._folder_sync_verify_semaphore = asyncio.Semaphore(1)
    daemon._cache_transfer_reservations = InboundTransferReservationLedger(
        tmp_path / "blobs",
    )
    daemon._transfer_admission_policy = TransferAdmissionPolicy(
        min_free_reserve_bytes=0,
        free_reserve_ratio=0.0,
    )
    daemon._dedupe_sites = MagicMock()
    return daemon


def _empty_offer_contract() -> tuple[list[dict], str, str]:
    entries: list[dict] = []
    root = foldersync.manifest_root_for_entries(entries)
    digest = Daemon._folder_manifest_digest(entries)
    return entries, root, digest


def test_blob_writer_expected_hash_mismatch_preserves_existing_cas(
    tmp_path: Path,
) -> None:
    store = BlobStore(tmp_path / "cas")
    legitimate = b"already durable and unrelated"
    legitimate_hash = store.put_bytes(legitimate)
    claimed_hash = blake3.blake3(b"different content address").hexdigest()

    with store.writer() as (writer, staged_path):
        writer.write(legitimate)
        with pytest.raises(ValueError, match="expected hash"):
            writer.commit(expected_hash=claimed_hash)

        assert staged_path.exists()
        assert store.has(legitimate_hash)
        assert store.path(legitimate_hash).read_bytes() == legitimate

    assert not staged_path.exists()
    assert store.has(legitimate_hash)
    assert store.path(legitimate_hash).read_bytes() == legitimate


@pytest.mark.asyncio
async def test_wants_and_commit_are_channel_bound_and_one_shot(
    tmp_path: Path,
) -> None:
    daemon = _protocol_daemon(tmp_path)
    offered_channel = _channel("a" * 64)
    crossed_channel = _channel("b" * 64)
    entries, source_root, manifest_digest = _empty_offer_contract()
    sync_id = "c" * 32
    daemon._register_outbound_folder_sync_offer(
        channel=offered_channel,
        peer_fp=PEER_FP,
        sync_id=sync_id,
        folder_name="docs",
        source_root=source_root,
        manifest_digest=manifest_digest,
        entries=entries,
    )
    wants = make_msg(
        "MANIFEST_WANTS",
        "peer",
        folder="docs",
        wants=[],
        of=sync_id,
        sync_id=sync_id,
    )

    with pytest.raises(RuntimeError, match="active manifest offer"):
        await daemon._handle_manifest_wants(crossed_channel, wants, PEER_FP)

    await daemon._handle_manifest_wants(offered_channel, wants, PEER_FP)
    verify = decode_msg(offered_channel.send.await_args_list[-1].args[0])
    assert verify["t"] == "FOLDER_SYNC_VERIFY"
    frames_after_first_wants = offered_channel.send.await_count
    with pytest.raises(RuntimeError, match="active manifest offer"):
        await daemon._handle_manifest_wants(offered_channel, wants, PEER_FP)
    assert offered_channel.send.await_count == frames_after_first_wants
    commit = make_msg(
        "FOLDER_SYNC_COMMIT",
        "peer",
        of=verify["id"],
        sync_id=sync_id,
        folder="docs",
        source_root=source_root,
        manifest_digest=manifest_digest,
        applied_root=source_root,
        entry_count=0,
        wanted_count=0,
        paths_verified=0,
        source_outcome="exact",
        conflict_count=0,
        ok=True,
        durable=True,
        reason="",
    )

    with pytest.raises(RuntimeError, match="no active proof context"):
        await daemon._handle_folder_sync_commit(
            crossed_channel,
            commit,
            PEER_FP,
        )

    await daemon._handle_folder_sync_commit(offered_channel, commit, PEER_FP)
    with pytest.raises(RuntimeError, match="no active proof context"):
        await daemon._handle_folder_sync_commit(offered_channel, commit, PEER_FP)
    with pytest.raises(RuntimeError, match="active manifest offer"):
        await daemon._handle_manifest_wants(offered_channel, wants, PEER_FP)

    unsolicited = dict(wants, id="d" * 32, of="e" * 32, sync_id="e" * 32)
    with pytest.raises(RuntimeError, match="active manifest offer"):
        await daemon._handle_manifest_wants(
            offered_channel,
            unsolicited,
            PEER_FP,
        )


@pytest.mark.asyncio
async def test_verify_consumes_context_before_replay_can_repeat_disk_proof(
    tmp_path: Path,
) -> None:
    daemon = _protocol_daemon(tmp_path)
    channel = _channel("f" * 64)
    sync_id = "0" * 32
    entries, source_root, manifest_digest = _empty_offer_contract()
    daemon.folder_engine.verify_materialized_paths.return_value = (
        True,
        "",
        source_root,
    )
    daemon._register_inbound_folder_sync_receipt(
        channel=channel,
        peer_fp=PEER_FP,
        sync_id=sync_id,
        folder_name="docs",
        source_root=source_root,
        manifest_digest=manifest_digest,
        entry_count=len(entries),
        wants=(),
        blob_sizes=(),
        affected_paths=(),
        source_entries=entries,
    )
    verify = make_msg(
        "FOLDER_SYNC_VERIFY",
        "peer",
        sync_id=sync_id,
        folder="docs",
        source_root=source_root,
        manifest_digest=manifest_digest,
        entry_count=0,
        wants=[],
    )

    await daemon._handle_folder_sync_verify(channel, verify, PEER_FP)

    assert daemon.folder_engine.verify_materialized_paths.call_count == 1
    assert channel.send.await_count == 1
    with pytest.raises(RuntimeError, match="no active proof context"):
        await daemon._handle_folder_sync_verify(channel, verify, PEER_FP)
    assert daemon.folder_engine.verify_materialized_paths.call_count == 1
    assert channel.send.await_count == 1


@pytest.mark.asyncio
async def test_negative_commit_preserves_receiver_failure_reason(
    tmp_path: Path,
) -> None:
    daemon = _protocol_daemon(tmp_path)
    channel = _channel("e" * 64)
    entries, source_root, manifest_digest = _empty_offer_contract()
    sync_id = "1" * 32
    daemon._register_outbound_folder_sync_offer(
        channel=channel,
        peer_fp=PEER_FP,
        sync_id=sync_id,
        folder_name="docs",
        source_root=source_root,
        manifest_digest=manifest_digest,
        entries=entries,
    )
    verify_id = await daemon._send_folder_sync_verify(
        channel=channel,
        peer_fp=PEER_FP,
        sync_id=sync_id,
        folder_name="docs",
        source_root=source_root,
        manifest_digest=manifest_digest,
        entry_count=0,
        wants=(),
    )
    negative = make_msg(
        "FOLDER_SYNC_COMMIT",
        "peer",
        of=verify_id,
        sync_id=sync_id,
        folder="docs",
        source_root=source_root,
        manifest_digest=manifest_digest,
        applied_root="",
        entry_count=0,
        wanted_count=0,
        paths_verified=0,
        source_outcome="unverified",
        conflict_count=0,
        ok=False,
        durable=False,
        reason="requested_blob_not_durable",
    )

    with pytest.raises(
        RuntimeError,
        match="receiver could not commit folder sync: requested_blob_not_durable",
    ):
        daemon._accept_folder_sync_commit(
            channel=channel,
            msg=negative,
            peer_fp=PEER_FP,
        )


@pytest.mark.asyncio
async def test_commit_distinguishes_exact_projection_from_reconciled_conflict(
    tmp_path: Path,
) -> None:
    daemon = _protocol_daemon(tmp_path)
    channel = _channel("9" * 64)
    sync_id = "8" * 32
    source_hash = "a" * 64
    winning_hash = "b" * 64
    source_entries = ({
        "file_path": "conflict.txt",
        "blob_hash": source_hash,
        "size": 1,
        "mtime_ms": 1,
        "vclock": {PEER_FP: 1},
    },)
    daemon._register_inbound_folder_sync_receipt(
        channel=channel,
        peer_fp=PEER_FP,
        sync_id=sync_id,
        folder_name="docs",
        source_root="c" * 64,
        manifest_digest="d" * 64,
        entry_count=1,
        wants=(),
        blob_sizes=(),
        affected_paths=("conflict.txt",),
        source_entries=source_entries,
    )
    daemon.state.get_manifest_entry.return_value = {
        "file_path": "conflict.txt",
        "blob_hash": winning_hash,
        "size": 1,
        "mtime_ms": 2,
        "vclock": {PEER_FP: 1, "34" * 32: 1},
    }
    daemon.folder_engine.verify_materialized_paths.return_value = (
        True,
        "",
        "e" * 64,
    )
    verify = make_msg(
        "FOLDER_SYNC_VERIFY",
        "peer",
        sync_id=sync_id,
        folder="docs",
        source_root="c" * 64,
        manifest_digest="d" * 64,
        entry_count=1,
        wants=[],
    )

    await daemon._handle_folder_sync_verify(channel, verify, PEER_FP)

    commit = decode_msg(channel.send.await_args.args[0])
    assert commit["ok"] is True
    assert commit["durable"] is True
    assert commit["source_outcome"] == "reconciled_conflict"
    assert commit["conflict_count"] == 1


@pytest.mark.asyncio
async def test_blob_offer_rejects_hash_and_size_outside_receipt_contract(
    tmp_path: Path,
) -> None:
    daemon = _protocol_daemon(tmp_path)
    channel = _channel("1" * 64)
    sync_id = "2" * 32
    wanted_hash = blake3.blake3(b"wanted bytes").hexdigest()
    other_hash = blake3.blake3(b"not requested").hexdigest()
    daemon._register_inbound_folder_sync_receipt(
        channel=channel,
        peer_fp=PEER_FP,
        sync_id=sync_id,
        folder_name="docs",
        source_root="3" * 64,
        manifest_digest="4" * 64,
        entry_count=1,
        wants=(wanted_hash,),
        blob_sizes=((wanted_hash, 12),),
        affected_paths=("wanted.bin",),
        source_entries=({
            "file_path": "wanted.bin",
            "blob_hash": wanted_hash,
            "size": 12,
            "mtime_ms": 1,
            "vclock": {PEER_FP: 1},
        },),
    )

    await daemon._handle_blob_offer(
        channel,
        {
            "blob": wanted_hash,
            "size": 13,
            "folder": "docs",
            "sync_id": sync_id,
        },
        PEER_FP,
    )
    await daemon._handle_blob_offer(
        channel,
        {
            "blob": other_hash,
            "size": 12,
            "folder": "docs",
            "sync_id": sync_id,
        },
        PEER_FP,
    )

    assert daemon._incoming_blobs == {}
    assert daemon._cache_transfer_reservations.snapshot() == ()
    assert list((tmp_path / "blobs" / "_tmp").iterdir()) == []


@pytest.mark.asyncio
async def test_channel_cleanup_releases_receipts_writer_and_disk_reservation(
    tmp_path: Path,
) -> None:
    daemon = _protocol_daemon(tmp_path)
    channel = _channel("5" * 64)
    inbound_sync_id = "6" * 32
    outbound_sync_id = "7" * 32
    payload = b"pending blob"
    blob_hash = blake3.blake3(payload).hexdigest()
    daemon._register_inbound_folder_sync_receipt(
        channel=channel,
        peer_fp=PEER_FP,
        sync_id=inbound_sync_id,
        folder_name="docs",
        source_root="8" * 64,
        manifest_digest="9" * 64,
        entry_count=1,
        wants=(blob_hash,),
        blob_sizes=((blob_hash, len(payload)),),
        affected_paths=("pending.bin",),
        source_entries=({
            "file_path": "pending.bin",
            "blob_hash": blob_hash,
            "size": len(payload),
            "mtime_ms": 1,
            "vclock": {PEER_FP: 1},
        },),
    )
    entries, source_root, manifest_digest = _empty_offer_contract()
    daemon._register_outbound_folder_sync_offer(
        channel=channel,
        peer_fp=PEER_FP,
        sync_id=outbound_sync_id,
        folder_name="docs",
        source_root=source_root,
        manifest_digest=manifest_digest,
        entries=entries,
    )
    binding = channel.transcript_hex
    daemon._folder_sync_verified_inbound[
        (PEER_FP, binding, "a" * 32)
    ] = 1.0
    daemon._folder_sync_verified_outbound[
        (PEER_FP, binding, "b" * 32)
    ] = 1.0
    await daemon._handle_blob_offer(
        channel,
        {
            "blob": blob_hash,
            "size": len(payload),
            "folder": "docs",
            "sync_id": inbound_sync_id,
        },
        PEER_FP,
    )

    assert len(daemon._incoming_blobs) == 1
    staged_path = next(iter(daemon._incoming_blobs.values()))["tmp_path"]
    assert staged_path.exists()
    assert len(daemon._cache_transfer_reservations.snapshot()) == 1

    daemon._cleanup_folder_channel_state(channel, PEER_FP)

    assert daemon._incoming_blobs == {}
    assert daemon._cache_transfer_reservations.snapshot() == ()
    assert not staged_path.exists()
    for mapping in (
        daemon._folder_sync_inbound_receipts,
        daemon._folder_sync_outbound_receipts,
        daemon._folder_sync_verified_inbound,
        daemon._folder_sync_verified_outbound,
    ):
        assert not any(
            key[0] == PEER_FP and key[1] == binding for key in mapping
        )


def test_verify_materialized_paths_repairs_blob_index_and_returns_exact_root(
    tmp_path: Path,
) -> None:
    state = State(db_path=tmp_path / "state.db")
    blobs = BlobStore(tmp_path / "cas")
    loop = asyncio.new_event_loop()
    engine = FolderEngine(
        state=state,
        blob_store=blobs,
        my_fingerprint="ab" * 32,
        loop=loop,
    )
    try:
        root = tmp_path / "sync"
        root.mkdir()
        (root / "nested").mkdir()
        payload = b"durable materialized content"
        blob_hash = blobs.put_bytes(payload)
        (root / "nested" / "proof.bin").write_bytes(payload)
        state.add_folder(name="docs", local_path=str(root), shared_with=[])
        state.upsert_manifest_entry(
            folder_name="docs",
            file_path="nested/proof.bin",
            blob_hash=blob_hash,
            size=len(payload),
            mtime_ms=1,
            vclock={"ab" * 32: 1},
        )
        expected_root = foldersync.manifest_root_for_entries(
            state.list_manifest("docs"),
        )
        assert not state.has_blob(blob_hash)

        ok, reason, applied_root = engine.verify_materialized_paths(
            folder_name="docs",
            paths=("nested/proof.bin",),
        )

        assert (ok, reason, applied_root) == (True, "", expected_root)
        assert state.has_blob(blob_hash)
    finally:
        state.close()
        loop.close()


@pytest.mark.asyncio
async def test_policy_rejected_manifest_returns_correlated_negative_response(
    tmp_path: Path,
) -> None:
    daemon = _protocol_daemon(tmp_path)
    state = State(db_path=tmp_path / "state.db")
    root = tmp_path / "sync"
    root.mkdir()
    state.add_folder(
        name="docs",
        local_path=str(root),
        shared_with=[PEER_FP],
        ignored_patterns=["*.secret"],
    )
    daemon.state = state
    daemon.folder_engine = MagicMock()
    daemon.folder_engine.manifest_for.return_value = []
    daemon.folder_engine.manifest_root.return_value = (
        foldersync.manifest_root_for_entries([])
    )
    channel = _channel("d" * 64)
    entries = [
        {
            "file_path": "blocked.secret",
            "blob_hash": "e" * 64,
            "size": 9,
            "mtime_ms": 1,
            "vclock": {PEER_FP: 1},
        },
    ]
    message = make_msg(
        "MANIFEST_PUSH",
        "peer",
        folder="docs",
        entries=entries,
        merkle_root=foldersync.manifest_root_for_entries(entries),
        manifest_digest=Daemon._folder_manifest_digest(entries),
        entry_count=len(entries),
    )
    try:
        await daemon._handle_manifest_push(channel, message, PEER_FP)

        channel.send.assert_awaited_once()
        response = decode_msg(channel.send.await_args.args[0])
        assert response == {
            "t": "MANIFEST_WANTS",
            "id": response["id"],
            "ts": response["ts"],
            "from": "self",
            "folder": "docs",
            "wants": [],
            "of": message["id"],
            "sync_id": message["id"],
            "accepted": False,
            "reason": "manifest_policy_rejected",
        }
        assert state.list_manifest("docs") == []
        assert daemon._folder_sync_inbound_receipts == OrderedDict()
        daemon.folder_engine.receive_remote_manifest.assert_not_called()
    finally:
        state.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "folder_name",
    ["../escape", "nested/folder", r"nested\folder", "CON", "C:escape"],
)
async def test_self_mesh_auto_accept_rejects_unsafe_folder_leaf(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    folder_name: str,
) -> None:
    daemon = _protocol_daemon(tmp_path)
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    monkeypatch.setattr("one_link.paths.inbox_dir", lambda: inbox)

    await daemon._auto_accept_self_mesh_folder_offer(
        offer_id=1,
        peer_fp=PEER_FP,
        folder_name=folder_name,
    )

    daemon.folder_engine.add_folder.assert_not_called()
    daemon.state.mark_folder_offer_accepted.assert_not_called()
    assert not (tmp_path / "escape").exists()
