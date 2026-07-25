"""D18 — Tests for bidirectional folder sync.

Exercises:
  - FOLDER_SYNC_BIDI_V1 capability is exposed in LOCAL_CAPABILITIES
  - _send_local_manifest_in_channel sends the right frame shape
  - _send_local_manifest_in_channel gates on pre-conditions (peer
    pinned, folder shared, capability allows push)
  - _handle_manifest_push triggers the reverse push iff:
      - request_reverse=True is set on the inbound frame
      - peer advertises FOLDER_SYNC_BIDI_V1
  - push_folder_to_peer adds request_reverse=True only when
    bidirectional=True AND peer advertises the cap
  - legacy peers (no cap) get unchanged behavior

No live socket pair is spun up; we mock the channel + folder_engine +
state and assert on the message bytes that would have been emitted.
"""

from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from one_link import daemon as daemon_module, foldersync
from one_link.capabilities import (
    FOLDER_SYNC,
    FOLDER_SYNC_BIDI_V1,
    FOLDER_SYNC_COMMIT_V1,
    LOCAL_CAPABILITIES,
)
from one_link.discovery import Peer
from one_link.daemon import TransferLedgerUnavailableError
from one_link.wire import decode_msg, encode_msg, make_msg


def _bare_daemon():
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d.folder_engine = MagicMock()
    d.blob_store = MagicMock()
    d.blob_store.has.return_value = True
    d.me = MagicMock()
    d.me.short_id = "selfid"
    # Folder-sync unit tests isolate manifest dispatch.  Fresh-channel CAPS
    # negotiation and cryptographic peer verification have their own live and
    # adversarial coverage; model their successful post-condition here.
    d._verify_channel_peer = MagicMock(return_value="peer_fp_abc")
    d._negotiate_outbound_caps = AsyncMock()
    # Make _is_pinned return True by default.
    d._is_pinned = MagicMock(return_value=True)
    # Standard folder mock.
    d.state.get_folder.return_value = {"shared_with": ["peer_fp_abc"]}
    d.state.folder_peer_allows.return_value = True
    # Folder engine returns a tiny manifest.
    d.folder_engine.manifest_for.return_value = [
        {"file_path": "x.txt", "blob_hash": "a" * 64,
         "size": 10, "mtime_ms": 0, "vclock": {}},
    ]
    d.folder_engine.manifest_root.return_value = foldersync.manifest_root_for_entries(
        d.folder_engine.manifest_for.return_value,
    )
    d.state.get_manifest_entry.return_value = None
    return d


def _channel(*, bidi: bool = False) -> MagicMock:
    channel = MagicMock()
    channel.send = AsyncMock()
    channel.transcript_hex = "c" * 64
    features = [FOLDER_SYNC, FOLDER_SYNC_COMMIT_V1]
    if bidi:
        features.append(FOLDER_SYNC_BIDI_V1)
    channel.peer_caps = {"features": features}
    return channel


def _empty_manifest(*, request_reverse: bool = False) -> dict:
    entries: list[dict] = []
    payload = {
        "folder": "myfolder",
        "entries": entries,
        "merkle_root": foldersync.manifest_root_for_entries(entries),
        "manifest_digest": daemon_module.Daemon._folder_manifest_digest(entries),
        "entry_count": 0,
    }
    if request_reverse:
        payload["request_reverse"] = True
    return make_msg("MANIFEST_PUSH", "peer1", **payload)


# ---------- capability surface ----------


def test_folder_sync_bidi_in_local_capabilities() -> None:
    assert FOLDER_SYNC_BIDI_V1 in LOCAL_CAPABILITIES


def test_folder_sync_bidi_string_value() -> None:
    # Wire stability: don't accidentally rename the cap string.
    assert FOLDER_SYNC_BIDI_V1 == "folder_sync_bidi_v1"


# ---------- _send_local_manifest_in_channel ----------


@pytest.mark.asyncio
async def test_send_local_manifest_emits_manifest_push() -> None:
    d = _bare_daemon()
    channel = _channel()
    await d._send_local_manifest_in_channel(
        channel=channel, folder_name="myfolder", peer_fp="peer_fp_abc",
    )
    channel.send.assert_called_once()
    raw = channel.send.call_args[0][0]
    frame = decode_msg(raw)
    assert frame["t"] == "MANIFEST_PUSH"
    assert frame["folder"] == "myfolder"
    assert frame["entry_count"] == 1
    assert frame["merkle_root"] == d.folder_engine.manifest_root.return_value
    assert frame["manifest_digest"] == d._folder_manifest_digest(frame["entries"])
    # No request_reverse when not asked for.
    assert "request_reverse" not in frame


@pytest.mark.asyncio
async def test_send_local_manifest_can_request_reverse() -> None:
    d = _bare_daemon()
    channel = _channel()
    await d._send_local_manifest_in_channel(
        channel=channel, folder_name="myfolder", peer_fp="peer_fp_abc",
        request_reverse=True,
    )
    frame = decode_msg(channel.send.call_args[0][0])
    assert frame["request_reverse"] is True


@pytest.mark.asyncio
async def test_send_local_manifest_fails_when_peer_not_pinned() -> None:
    d = _bare_daemon()
    d._is_pinned = MagicMock(return_value=False)
    channel = MagicMock()
    channel.send = AsyncMock()
    with pytest.raises(RuntimeError, match="not initialized or pinned"):
        await d._send_local_manifest_in_channel(
            channel=channel, folder_name="myfolder", peer_fp="peer_fp_abc",
        )
    channel.send.assert_not_called()


@pytest.mark.asyncio
async def test_send_local_manifest_fails_when_folder_not_shared() -> None:
    d = _bare_daemon()
    d.state.get_folder.return_value = {"shared_with": ["other_peer"]}
    channel = MagicMock()
    channel.send = AsyncMock()
    with pytest.raises(RuntimeError, match="not shared"):
        await d._send_local_manifest_in_channel(
            channel=channel, folder_name="myfolder", peer_fp="peer_fp_abc",
        )
    channel.send.assert_not_called()


@pytest.mark.asyncio
async def test_send_local_manifest_fails_when_cap_denies_push() -> None:
    d = _bare_daemon()
    d.state.folder_peer_allows.return_value = False
    channel = MagicMock()
    channel.send = AsyncMock()
    with pytest.raises(RuntimeError, match="forbids reverse push"):
        await d._send_local_manifest_in_channel(
            channel=channel, folder_name="myfolder", peer_fp="peer_fp_abc",
        )
    channel.send.assert_not_called()


@pytest.mark.asyncio
async def test_send_local_manifest_propagates_engine_failure() -> None:
    d = _bare_daemon()
    d.folder_engine.manifest_for.side_effect = RuntimeError("simulated")
    channel = MagicMock()
    channel.send = AsyncMock()
    with pytest.raises(RuntimeError, match="simulated"):
        await d._send_local_manifest_in_channel(
            channel=channel, folder_name="myfolder", peer_fp="peer_fp_abc",
        )
    channel.send.assert_not_called()


# ---------- _handle_manifest_push reverse-push trigger ----------


@pytest.mark.asyncio
async def test_handle_manifest_push_triggers_reverse_when_flag_and_cap() -> None:
    d = _bare_daemon()
    # Mock receive_remote_manifest to return no wants.
    d.folder_engine.receive_remote_manifest.return_value = []
    # Mock sandbox filter pass-through.
    d._sandbox_filter_manifest_entries = MagicMock(side_effect=lambda *a, **k: k["entries"])
    d._expected_blob_pulls = {}
    # Capture _send_local_manifest_in_channel calls.
    d._send_local_manifest_in_channel = AsyncMock()
    channel = _channel(bidi=True)
    msg = _empty_manifest(request_reverse=True)
    await d._handle_manifest_push(channel, msg, "peer_fp_abc")
    # Reverse push fired.
    d._send_local_manifest_in_channel.assert_awaited_once()
    call_kwargs = d._send_local_manifest_in_channel.await_args.kwargs
    assert call_kwargs["folder_name"] == "myfolder"
    assert call_kwargs["peer_fp"] == "peer_fp_abc"


@pytest.mark.asyncio
async def test_handle_manifest_push_no_reverse_when_flag_missing() -> None:
    d = _bare_daemon()
    d.folder_engine.receive_remote_manifest.return_value = []
    d._sandbox_filter_manifest_entries = MagicMock(side_effect=lambda *a, **k: k["entries"])
    d._expected_blob_pulls = {}
    d._send_local_manifest_in_channel = AsyncMock()
    channel = _channel(bidi=True)
    msg = _empty_manifest()
    await d._handle_manifest_push(channel, msg, "peer_fp_abc")
    d._send_local_manifest_in_channel.assert_not_called()


@pytest.mark.asyncio
async def test_nonempty_equal_manifest_uses_no_merge_fast_path() -> None:
    d = _bare_daemon()
    entries = d.folder_engine.manifest_for.return_value
    d.folder_engine.manifest_root.return_value = (
        foldersync.manifest_root_for_entries(entries)
    )
    d.state.list_manifest.return_value = list(entries)
    d._sandbox_filter_manifest_entries = MagicMock()
    channel = _channel()
    msg = make_msg(
        "MANIFEST_PUSH",
        "peer1",
        folder="myfolder",
        entries=entries,
        merkle_root=foldersync.manifest_root_for_entries(entries),
        manifest_digest=d._folder_manifest_digest(entries),
        entry_count=len(entries),
    )

    await d._handle_manifest_push(channel, msg, "peer_fp_abc")

    d.folder_engine.receive_remote_manifest.assert_not_called()
    d._sandbox_filter_manifest_entries.assert_not_called()
    response = decode_msg(channel.send.await_args.args[0])
    assert response["t"] == "MANIFEST_WANTS"
    assert response["already_in_sync"] is True
    assert response["wants"] == []
    context = next(iter(d._folder_sync_inbound_receipts.values()))
    assert context.affected_paths == ("x.txt",)


@pytest.mark.asyncio
async def test_handle_manifest_push_refuses_legacy_peer_without_receipts() -> None:
    d = _bare_daemon()
    d.folder_engine.receive_remote_manifest.return_value = []
    d._sandbox_filter_manifest_entries = MagicMock(side_effect=lambda *a, **k: k["entries"])
    d._expected_blob_pulls = {}
    d._send_local_manifest_in_channel = AsyncMock()
    channel = _channel()
    # Peer asks for reverse but doesn't advertise the cap.
    channel.peer_caps = {"features": [FOLDER_SYNC]}  # legacy peer
    msg = _empty_manifest(request_reverse=True)
    with pytest.raises(RuntimeError, match="durable folder sync receipts"):
        await d._handle_manifest_push(channel, msg, "peer_fp_abc")
    d._send_local_manifest_in_channel.assert_not_called()
    d.folder_engine.receive_remote_manifest.assert_not_called()


@pytest.mark.asyncio
async def test_push_folder_bidi_streams_without_blocking_reverse_receive(monkeypatch) -> None:
    """The initiator must keep receiving while its outbound blob stream is
    active. Otherwise two large opposite-direction syncs can both fill their
    send buffers and deadlock."""
    d = _bare_daemon()
    d.blob_store = object()
    d._check_outbound_trust = MagicMock(return_value=None)
    d._peer_fp_from_peer = MagicMock(return_value="peer_fp_abc")
    d._capability_allowed = MagicMock(return_value=True)
    d._dial_peer = AsyncMock(return_value=(object(), object()))
    d._upsert_transfer = MagicMock()
    d._update_transfer = MagicMock()
    d._throttle_chunk = AsyncMock()
    d.state.set_peer_capabilities = MagicMock()

    reverse_seen = asyncio.Event()

    async def fake_stream(**_kwargs):
        await reverse_seen.wait()
        return (1, 10)

    async def fake_handle_manifest_push(_channel, msg, peer_fp):
        assert msg["t"] == "MANIFEST_PUSH"
        assert peer_fp == "peer_fp_abc"
        d._prune_folder_sync_receipt_contexts()
        key = (
            peer_fp,
            d._folder_channel_binding(_channel),
            str(msg["id"]),
        )
        d._folder_sync_verified_inbound[key] = time.monotonic()
        reverse_seen.set()

    d._stream_blobs_for_wants = fake_stream
    d._handle_manifest_push = fake_handle_manifest_push
    d._handle_blob_offer = AsyncMock()
    d._handle_blob_chunk = AsyncMock()

    class FakeChannel:
        def __init__(self) -> None:
            self.peer_short_id = "peer1"
            self.peer_caps = {"features": [
                FOLDER_SYNC,
                FOLDER_SYNC_BIDI_V1,
                FOLDER_SYNC_COMMIT_V1,
            ]}
            self.transcript_hex = "d" * 64
            self.sent = []
            self._stage = 0

        async def send(self, payload: bytes) -> None:
            self.sent.append(decode_msg(payload))

        async def recv(self) -> bytes:
            await asyncio.sleep(0)
            manifest = next(
                frame for frame in self.sent if frame["t"] == "MANIFEST_PUSH"
            )
            if self._stage == 0:
                self._stage = 1
                return encode_msg(make_msg(
                    "MANIFEST_WANTS",
                    "peer1",
                    folder="myfolder",
                    wants=["a" * 64],
                    of=manifest["id"],
                    sync_id=manifest["id"],
                ))
            if self._stage == 1:
                self._stage = 2
                return encode_msg(_empty_manifest())
            verify = next(
                (frame for frame in self.sent if frame["t"] == "FOLDER_SYNC_VERIFY"),
                None,
            )
            if verify is not None and self._stage == 2:
                self._stage = 3
                return encode_msg(make_msg(
                    "FOLDER_SYNC_COMMIT",
                    "peer1",
                    of=verify["id"],
                    sync_id=manifest["id"],
                    folder="myfolder",
                    source_root=manifest["merkle_root"],
                    manifest_digest=manifest["manifest_digest"],
                    applied_root="e" * 64,
                    entry_count=manifest["entry_count"],
                    wanted_count=1,
                    paths_verified=1,
                    source_outcome="exact",
                    conflict_count=0,
                    ok=True,
                    durable=True,
                    reason="",
                ))
            raise asyncio.TimeoutError

        async def close(self) -> None:
            pass

        def note_caps_sent(self) -> None:
            pass

        def maybe_activate_ratchet(self) -> None:
            pass

    channel = FakeChannel()

    async def fake_initiate(*_args, **_kwargs):
        return channel

    monkeypatch.setattr(daemon_module.ch, "initiate", fake_initiate)
    peer = Peer(
        short_id="peer1",
        hostname="peer-host",
        address="127.0.0.1",
        port=9,
        ed_pub_hex="00" * 32,
    )

    result = await asyncio.wait_for(
        d.push_folder_to_peer(peer, "myfolder", bidirectional=True),
        timeout=1.0,
    )
    assert result["ok"] is True
    assert reverse_seen.is_set()
    assert result["blobs_sent"] == 1
    assert any(
        frame["t"] == "MANIFEST_PUSH" and frame.get("request_reverse") is True
        for frame in channel.sent
    )


@pytest.mark.asyncio
async def test_push_folder_refuses_before_dial_when_ledger_is_unavailable() -> None:
    d = _bare_daemon()
    d.blob_store = object()
    d._check_outbound_trust = MagicMock(return_value=None)
    d._peer_fp_from_peer = MagicMock(return_value="peer_fp_abc")
    d._capability_allowed = MagicMock(return_value=True)
    d._upsert_transfer = MagicMock(return_value=None)
    d._dial_peer = AsyncMock()
    peer = Peer(
        short_id="peer1",
        hostname="peer-host",
        address="127.0.0.1",
        port=9,
        ed_pub_hex="00" * 32,
    )

    with pytest.raises(TransferLedgerUnavailableError):
        await d.push_folder_to_peer(peer, "myfolder")

    d._dial_peer.assert_not_awaited()


class _EmptyWantsChannel:
    """Minimal channel for one half-duplex manifest reconciliation."""

    def __init__(self, *, wants: list[str] | None = None) -> None:
        self.peer_short_id = "peer1"
        self.peer_caps = {"features": [FOLDER_SYNC, FOLDER_SYNC_COMMIT_V1]}
        self.transcript_hex = "f" * 64
        self._wants = list(wants or [])
        self.sent: list[dict] = []
        self.closed = False
        self._wants_sent = False
        self._commit_sent = False

    async def send(self, payload: bytes) -> None:
        self.sent.append(decode_msg(payload))

    async def recv(self) -> bytes:
        manifest = next(
            frame for frame in self.sent if frame["t"] == "MANIFEST_PUSH"
        )
        if not self._wants_sent:
            self._wants_sent = True
            return encode_msg(make_msg(
                "MANIFEST_WANTS",
                "peer1",
                folder="myfolder",
                wants=self._wants,
                of=manifest["id"],
                sync_id=manifest["id"],
            ))
        verify = next(
            (frame for frame in self.sent if frame["t"] == "FOLDER_SYNC_VERIFY"),
            None,
        )
        if verify is not None and not self._commit_sent:
            self._commit_sent = True
            return encode_msg(make_msg(
                "FOLDER_SYNC_COMMIT",
                "peer1",
                of=verify["id"],
                sync_id=manifest["id"],
                folder="myfolder",
                source_root=manifest["merkle_root"],
                manifest_digest=manifest["manifest_digest"],
                applied_root="b" * 64,
                entry_count=manifest["entry_count"],
                wanted_count=len(self._wants),
                paths_verified=1,
                source_outcome="exact",
                conflict_count=0,
                ok=True,
                durable=True,
                reason="",
            ))
        raise asyncio.TimeoutError

    async def close(self) -> None:
        self.closed = True

    def note_caps_sent(self) -> None:
        pass

    def maybe_activate_ratchet(self) -> None:
        pass


def _background_push_daemon() -> daemon_module.Daemon:
    d = _bare_daemon()
    d.blob_store = object()
    d.ui_server = None
    d._check_outbound_trust = MagicMock(return_value=None)
    d._sync_paused_or_quiet = MagicMock(return_value=(False, ""))
    d._peer_fp_from_peer = MagicMock(return_value="peer_fp_abc")
    d._capability_allowed = MagicMock(return_value=True)
    d._dial_peer = AsyncMock(return_value=(object(), object()))
    d._require_upsert_transfer = MagicMock()
    d._update_transfer = MagicMock()
    d._stream_blobs_for_wants = AsyncMock(return_value=(0, 0))
    d._build_my_caps_for_channel = MagicMock(return_value=make_msg(
        "CAPS", "selfid", features=[FOLDER_SYNC, FOLDER_SYNC_COMMIT_V1],
    ))
    return d


def _peer() -> Peer:
    return Peer(
        short_id="peer1",
        hostname="peer-host",
        address="127.0.0.1",
        port=9,
        ed_pub_hex="00" * 32,
    )


@pytest.mark.asyncio
async def test_background_equal_manifest_uses_bounded_checkpoint_not_transfer_row(
    monkeypatch,
) -> None:
    """A 30-second equality probe must not append Activity history.

    The production database had accumulated 21,651 folder rows, including
    20,028 zero-want probes for one folder.  One durable settings checkpoint
    per (folder, peer) preserves crash truth without unbounded row growth.
    """

    d = _background_push_daemon()
    channel = _EmptyWantsChannel()

    async def fake_initiate(*_args, **_kwargs):
        return channel

    monkeypatch.setattr(daemon_module.ch, "initiate", fake_initiate)
    result = await d.push_folder_to_peer(
        _peer(), "myfolder", background=True,
    )

    assert result["ok"] is True
    assert result["wants"] == 0
    assert result["activity_recorded"] is False
    d._require_upsert_transfer.assert_not_called()
    d._update_transfer.assert_not_called()
    assert d.state.set_setting.call_count == 2
    first_key, first_value = d.state.set_setting.call_args_list[0].args
    second_key, second_value = d.state.set_setting.call_args_list[1].args
    assert first_key == second_key
    assert first_key.startswith("folder_sync_checkpoint:")
    assert len(first_key.removeprefix("folder_sync_checkpoint:")) == 64
    assert json.loads(first_value)["status"] == "active"
    assert json.loads(second_value)["status"] == "complete"
    assert channel.closed is True


@pytest.mark.asyncio
async def test_repeated_background_equality_probes_never_append_transfer_rows(
    monkeypatch,
) -> None:
    d = _background_push_daemon()
    channels: list[_EmptyWantsChannel] = []

    async def fake_initiate(*_args, **_kwargs):
        channel = _EmptyWantsChannel()
        channels.append(channel)
        return channel

    monkeypatch.setattr(daemon_module.ch, "initiate", fake_initiate)

    for _ in range(100):
        result = await d.push_folder_to_peer(
            _peer(), "myfolder", background=True,
        )
        assert result["activity_recorded"] is False

    d._require_upsert_transfer.assert_not_called()
    d._update_transfer.assert_not_called()
    keys = {call.args[0] for call in d.state.set_setting.call_args_list}
    assert len(keys) == 1
    assert len(channels) == 100
    assert all(channel.closed for channel in channels)


@pytest.mark.asyncio
async def test_background_requested_blobs_promote_before_first_blob(
    monkeypatch,
) -> None:
    d = _background_push_daemon()
    channel = _EmptyWantsChannel(wants=["a" * 64])
    events: list[str] = []

    def set_checkpoint(_key: str, value: str) -> None:
        events.append(f"checkpoint:{json.loads(value)['status']}")

    def record_transfer(**_kwargs) -> None:
        events.append("transfer")

    async def stream(**_kwargs):
        events.append("blob")
        return (1, 10)

    d.state.set_setting.side_effect = set_checkpoint
    d._require_upsert_transfer.side_effect = record_transfer
    d._stream_blobs_for_wants.side_effect = stream

    async def fake_initiate(*_args, **_kwargs):
        return channel

    monkeypatch.setattr(daemon_module.ch, "initiate", fake_initiate)
    result = await d.push_folder_to_peer(
        _peer(), "myfolder", background=True,
    )

    assert result["ok"] is True
    assert result["activity_recorded"] is True
    assert events == [
        "checkpoint:active",
        "transfer",
        "blob",
        "checkpoint:complete",
    ]
    d._update_transfer.assert_called()
    assert d._update_transfer.call_args.kwargs["status"] == "complete"


@pytest.mark.asyncio
async def test_background_checkpoint_failure_refuses_before_dial() -> None:
    d = _background_push_daemon()
    d.state.set_setting.side_effect = OSError("disk full")

    with pytest.raises(OSError, match="disk full"):
        await d.push_folder_to_peer(
            _peer(), "myfolder", background=True,
        )

    d._dial_peer.assert_not_awaited()
    d._require_upsert_transfer.assert_not_called()


@pytest.mark.asyncio
async def test_manual_folder_dial_failure_closes_active_ledger_row() -> None:
    d = _background_push_daemon()
    d._dial_peer.side_effect = ConnectionError("offline")

    result = await d.push_folder_to_peer(_peer(), "myfolder")

    assert result["ok"] is False
    assert "offline" in result["error"]
    d._require_upsert_transfer.assert_called_once()
    d._update_transfer.assert_called_once()
    assert d._update_transfer.call_args.kwargs["status"] == "failed"


@pytest.mark.asyncio
async def test_manual_folder_cancellation_pauses_ledger_and_propagates() -> None:
    d = _background_push_daemon()
    d._dial_peer.side_effect = asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await d.push_folder_to_peer(_peer(), "myfolder")

    d._require_upsert_transfer.assert_called_once()
    d._update_transfer.assert_called_once()
    assert d._update_transfer.call_args.kwargs["status"] == "paused"


@pytest.mark.asyncio
async def test_periodic_cycle_marks_push_as_background() -> None:
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    peer = _peer()
    d.folder_engine = object()
    d.state = MagicMock()
    d.state.list_folders.return_value = [{
        "name": "myfolder",
        "shared_with": ["peer_fp_abc"],
    }]
    d.discovery = MagicMock()
    d.discovery.registry.list.return_value = [peer]
    d._is_pinned = MagicMock(return_value=True)
    d._peer_fp_from_peer = MagicMock(return_value="peer_fp_abc")
    d.push_folder_to_peer = AsyncMock(return_value={"ok": True})

    await d._run_one_folder_sync_cycle()

    d.push_folder_to_peer.assert_awaited_once_with(
        peer,
        "myfolder",
        bidirectional=True,
        background=True,
    )
