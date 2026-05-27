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
from unittest.mock import AsyncMock, MagicMock

import pytest

from one_link import daemon as daemon_module
from one_link.capabilities import (
    FOLDER_SYNC,
    FOLDER_SYNC_BIDI_V1,
    LOCAL_CAPABILITIES,
)
from one_link.discovery import Peer
from one_link.wire import decode_msg, encode_msg, make_msg


def _bare_daemon():
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d.folder_engine = MagicMock()
    d.me = MagicMock()
    d.me.short_id = "selfid"
    # Make _is_pinned return True by default.
    d._is_pinned = MagicMock(return_value=True)
    # Standard folder mock.
    d.state.get_folder.return_value = {"shared_with": ["peer_fp_abc"]}
    d.state.folder_peer_allows.return_value = True
    # Folder engine returns a tiny manifest.
    d.folder_engine.manifest_for.return_value = [
        {"file_path": "x.txt", "blob_hash": "h" * 64,
         "size": 10, "mtime_ms": 0, "vclock": {}},
    ]
    d.folder_engine.manifest_root.return_value = "root_hex"
    return d


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
    channel = MagicMock()
    channel.send = AsyncMock()
    await d._send_local_manifest_in_channel(
        channel=channel, folder_name="myfolder", peer_fp="peer_fp_abc",
    )
    channel.send.assert_called_once()
    raw = channel.send.call_args[0][0]
    frame = decode_msg(raw)
    assert frame["t"] == "MANIFEST_PUSH"
    assert frame["folder"] == "myfolder"
    assert frame["entry_count"] == 1
    assert frame["merkle_root"] == "root_hex"
    # No request_reverse when not asked for.
    assert "request_reverse" not in frame


@pytest.mark.asyncio
async def test_send_local_manifest_can_request_reverse() -> None:
    d = _bare_daemon()
    channel = MagicMock()
    channel.send = AsyncMock()
    await d._send_local_manifest_in_channel(
        channel=channel, folder_name="myfolder", peer_fp="peer_fp_abc",
        request_reverse=True,
    )
    frame = decode_msg(channel.send.call_args[0][0])
    assert frame["request_reverse"] is True


@pytest.mark.asyncio
async def test_send_local_manifest_silent_when_peer_not_pinned() -> None:
    d = _bare_daemon()
    d._is_pinned = MagicMock(return_value=False)
    channel = MagicMock()
    channel.send = AsyncMock()
    await d._send_local_manifest_in_channel(
        channel=channel, folder_name="myfolder", peer_fp="peer_fp_abc",
    )
    channel.send.assert_not_called()


@pytest.mark.asyncio
async def test_send_local_manifest_silent_when_folder_not_shared() -> None:
    d = _bare_daemon()
    d.state.get_folder.return_value = {"shared_with": ["other_peer"]}
    channel = MagicMock()
    channel.send = AsyncMock()
    await d._send_local_manifest_in_channel(
        channel=channel, folder_name="myfolder", peer_fp="peer_fp_abc",
    )
    channel.send.assert_not_called()


@pytest.mark.asyncio
async def test_send_local_manifest_silent_when_cap_denies_push() -> None:
    d = _bare_daemon()
    d.state.folder_peer_allows.return_value = False
    channel = MagicMock()
    channel.send = AsyncMock()
    await d._send_local_manifest_in_channel(
        channel=channel, folder_name="myfolder", peer_fp="peer_fp_abc",
    )
    channel.send.assert_not_called()


@pytest.mark.asyncio
async def test_send_local_manifest_silent_when_engine_raises() -> None:
    d = _bare_daemon()
    d.folder_engine.manifest_for.side_effect = RuntimeError("simulated")
    channel = MagicMock()
    channel.send = AsyncMock()
    # Must not raise.
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
    channel = MagicMock()
    channel.send = AsyncMock()
    channel.peer_caps = {"features": [FOLDER_SYNC, FOLDER_SYNC_BIDI_V1]}
    msg = {
        "t": "MANIFEST_PUSH",
        "folder": "myfolder",
        "entries": [],
        "merkle_root": "remote_root",
        "entry_count": 0,
        "request_reverse": True,
    }
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
    channel = MagicMock()
    channel.send = AsyncMock()
    channel.peer_caps = {"features": [FOLDER_SYNC, FOLDER_SYNC_BIDI_V1]}
    msg = {
        "t": "MANIFEST_PUSH",
        "folder": "myfolder",
        "entries": [],
        "merkle_root": "remote_root",
        "entry_count": 0,
        # request_reverse omitted -> reverse path must NOT fire.
    }
    await d._handle_manifest_push(channel, msg, "peer_fp_abc")
    d._send_local_manifest_in_channel.assert_not_called()


@pytest.mark.asyncio
async def test_handle_manifest_push_no_reverse_when_cap_missing() -> None:
    d = _bare_daemon()
    d.folder_engine.receive_remote_manifest.return_value = []
    d._sandbox_filter_manifest_entries = MagicMock(side_effect=lambda *a, **k: k["entries"])
    d._expected_blob_pulls = {}
    d._send_local_manifest_in_channel = AsyncMock()
    channel = MagicMock()
    channel.send = AsyncMock()
    # Peer asks for reverse but doesn't advertise the cap.
    channel.peer_caps = {"features": [FOLDER_SYNC]}  # legacy peer
    msg = {
        "t": "MANIFEST_PUSH",
        "folder": "myfolder",
        "entries": [],
        "merkle_root": "remote_root",
        "entry_count": 0,
        "request_reverse": True,
    }
    await d._handle_manifest_push(channel, msg, "peer_fp_abc")
    d._send_local_manifest_in_channel.assert_not_called()


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
        reverse_seen.set()

    d._stream_blobs_for_wants = fake_stream
    d._handle_manifest_push = fake_handle_manifest_push
    d._handle_blob_offer = AsyncMock()
    d._handle_blob_chunk = AsyncMock()

    class FakeChannel:
        def __init__(self) -> None:
            self.peer_short_id = "peer1"
            self.peer_caps = {"features": [FOLDER_SYNC, FOLDER_SYNC_BIDI_V1]}
            self.sent = []

        async def send(self, payload: bytes) -> None:
            self.sent.append(decode_msg(payload))

        async def recv(self) -> bytes:
            if not hasattr(self, "_frames"):
                self._frames = [
                    make_msg(
                        "MANIFEST_WANTS",
                        "peer1",
                        folder="myfolder",
                        wants=["a" * 64],
                    ),
                    make_msg(
                        "MANIFEST_PUSH",
                        "peer1",
                        folder="myfolder",
                        entries=[],
                        merkle_root="remote",
                        entry_count=0,
                    ),
                ]
            if self._frames:
                await asyncio.sleep(0)
                return encode_msg(self._frames.pop(0))
            await asyncio.sleep(0)
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
