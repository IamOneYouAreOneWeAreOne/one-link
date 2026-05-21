"""D17 wire-up — Tests for receiver-pulled BLOB_REQUEST surface.

Exercises:
  - BLOB_REQUEST_V1 capability is advertised
  - _handle_blob_request gates on (a) peer pinned, (b) we have the
    blob, (c) folder share-list / FILES cap
  - _handle_blob_request emits BLOB_OFFER + BLOB_CHUNKs on success
  - find_alternate_sources_for_blob filters by cap + pinned state
  - request_blob_from_peer returns the right status code in every
    failure path (not_pinned, no_cap, no_session, send_failed,
    requested-on-happy-path)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from one_link import daemon as daemon_module
from one_link.capabilities import (
    BLOB_REQUEST_V1,
    FILES,
    FOLDER_SYNC,
    LOCAL_CAPABILITIES,
)
from one_link.wire import decode_msg


def _bare_daemon():
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d.blob_store = MagicMock()
    d.me = MagicMock()
    d.me.short_id = "selfid"
    d._is_pinned = MagicMock(return_value=True)
    d._expected_blob_pulls = {}
    # Defaults — overridden by individual tests.
    d.blob_store.has.return_value = True
    d.blob_store.size.return_value = 5
    # open_read returns a context manager yielding a file-like with
    # .read() that returns bytes then empty.
    file_mock = MagicMock()
    file_mock.read.side_effect = [b"hello", b""]
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=file_mock)
    cm.__exit__ = MagicMock(return_value=False)
    d.blob_store.open_read.return_value = cm
    return d


# ---------- capability surface ----------


def test_blob_request_cap_is_local() -> None:
    assert BLOB_REQUEST_V1 in LOCAL_CAPABILITIES


def test_blob_request_cap_string_value() -> None:
    assert BLOB_REQUEST_V1 == "blob_request_v1"


# ---------- _handle_blob_request handler ----------


@pytest.mark.asyncio
async def test_handle_blob_request_silent_when_peer_not_pinned() -> None:
    d = _bare_daemon()
    d._is_pinned = MagicMock(return_value=False)
    channel = MagicMock()
    channel.send = AsyncMock()
    await d._handle_blob_request(
        channel, {"blob": "a" * 64}, "peer_fp_abc",
    )
    channel.send.assert_not_called()


@pytest.mark.asyncio
async def test_handle_blob_request_silent_when_blob_missing() -> None:
    d = _bare_daemon()
    d.blob_store.has.return_value = False
    channel = MagicMock()
    channel.send = AsyncMock()
    await d._handle_blob_request(
        channel, {"blob": "a" * 64}, "peer_fp_abc",
    )
    channel.send.assert_not_called()


@pytest.mark.asyncio
async def test_handle_blob_request_silent_on_bad_hash() -> None:
    d = _bare_daemon()
    channel = MagicMock()
    channel.send = AsyncMock()
    await d._handle_blob_request(
        channel, {"blob": "not-hex"}, "peer_fp_abc",
    )
    channel.send.assert_not_called()


@pytest.mark.asyncio
async def test_handle_blob_request_with_folder_gates_on_share_list() -> None:
    d = _bare_daemon()
    d.state.get_folder.return_value = {"shared_with": ["other"]}
    channel = MagicMock()
    channel.send = AsyncMock()
    await d._handle_blob_request(
        channel,
        {"blob": "a" * 64, "folder": "myfolder"},
        "peer_fp_abc",
    )
    channel.send.assert_not_called()


@pytest.mark.asyncio
async def test_handle_blob_request_with_folder_gates_on_push_perm() -> None:
    d = _bare_daemon()
    d.state.get_folder.return_value = {"shared_with": ["peer_fp_abc"]}
    d.state.folder_peer_allows.return_value = False
    channel = MagicMock()
    channel.send = AsyncMock()
    await d._handle_blob_request(
        channel,
        {"blob": "a" * 64, "folder": "myfolder"},
        "peer_fp_abc",
    )
    channel.send.assert_not_called()


@pytest.mark.asyncio
async def test_handle_blob_request_without_folder_gates_on_files_cap() -> None:
    d = _bare_daemon()
    # No folder context, no FILES cap -> reject.
    d._capability_allowed = MagicMock(return_value=False)
    channel = MagicMock()
    channel.send = AsyncMock()
    await d._handle_blob_request(
        channel, {"blob": "a" * 64}, "peer_fp_abc",
    )
    channel.send.assert_not_called()
    d._capability_allowed.assert_called_once()
    assert d._capability_allowed.call_args[0][1] == FILES


@pytest.mark.asyncio
async def test_handle_blob_request_happy_path_with_folder() -> None:
    d = _bare_daemon()
    d.state.get_folder.return_value = {"shared_with": ["peer_fp_abc"]}
    d.state.folder_peer_allows.return_value = True
    channel = MagicMock()
    channel.send = AsyncMock()
    await d._handle_blob_request(
        channel,
        {"blob": "a" * 64, "folder": "myfolder"},
        "peer_fp_abc",
    )
    # Should have sent BLOB_OFFER + at least one BLOB_CHUNK.
    assert channel.send.call_count >= 2
    sent = [decode_msg(c[0][0]) for c in channel.send.call_args_list]
    assert sent[0]["t"] == "BLOB_OFFER"
    assert sent[0]["blob"] == "a" * 64
    assert sent[0]["size"] == 5
    # Following frames are BLOB_CHUNKs.
    for frame in sent[1:]:
        assert frame["t"] == "BLOB_CHUNK"


@pytest.mark.asyncio
async def test_handle_blob_request_happy_path_without_folder_with_files_cap() -> None:
    d = _bare_daemon()
    d._capability_allowed = MagicMock(return_value=True)
    channel = MagicMock()
    channel.send = AsyncMock()
    await d._handle_blob_request(
        channel, {"blob": "a" * 64}, "peer_fp_abc",
    )
    assert channel.send.call_count >= 2


@pytest.mark.asyncio
async def test_handle_blob_request_preregisters_expected_pull() -> None:
    """The replied-BLOB_OFFER lands on the peer's side via their normal
    _handle_blob_offer path, which gates on the expected-pull set —
    so we must preregister our reply or the peer drops it."""
    d = _bare_daemon()
    d._capability_allowed = MagicMock(return_value=True)
    channel = MagicMock()
    channel.send = AsyncMock()
    await d._handle_blob_request(
        channel, {"blob": "a" * 64}, "peer_fp_abc",
    )
    expected = d._expected_blob_pulls.get("peer_fp_abc", set())
    assert "a" * 64 in expected


# ---------- find_alternate_sources_for_blob ----------


def test_find_alternate_sources_filters_by_cap() -> None:
    d = _bare_daemon()
    # Two peers in dedupe index; only one advertises BLOB_REQUEST_V1.
    from one_link.dedupe_sites import DedupeSiteIndex
    d._dedupe_sites = DedupeSiteIndex()
    d._dedupe_sites.record_have("hashX", "peerA")
    d._dedupe_sites.record_have("hashX", "peerB")
    cap_map = {
        "peerA": [FOLDER_SYNC, BLOB_REQUEST_V1],
        "peerB": [FOLDER_SYNC],  # no BLOB_REQUEST_V1
    }
    d.state.get_peer_capabilities = lambda fp: cap_map.get(fp, [])
    out = d.find_alternate_sources_for_blob("hashX")
    assert out == ("peerA",)


def test_find_alternate_sources_skip_unpinned() -> None:
    d = _bare_daemon()
    from one_link.dedupe_sites import DedupeSiteIndex
    d._dedupe_sites = DedupeSiteIndex()
    d._dedupe_sites.record_have("hashX", "peerA")
    d._dedupe_sites.record_have("hashX", "peerB")
    d._is_pinned = lambda fp: fp == "peerA"
    d.state.get_peer_capabilities = lambda fp: [BLOB_REQUEST_V1]
    out = d.find_alternate_sources_for_blob("hashX")
    assert out == ("peerA",)


def test_find_alternate_sources_excludes_listed() -> None:
    d = _bare_daemon()
    from one_link.dedupe_sites import DedupeSiteIndex
    d._dedupe_sites = DedupeSiteIndex()
    d._dedupe_sites.record_have("hashX", "peerA")
    d._dedupe_sites.record_have("hashX", "peerB")
    d.state.get_peer_capabilities = lambda fp: [BLOB_REQUEST_V1]
    out = d.find_alternate_sources_for_blob("hashX", exclude=["peerA"])
    assert out == ("peerB",)


def test_find_alternate_sources_no_cap_filter_when_disabled() -> None:
    d = _bare_daemon()
    from one_link.dedupe_sites import DedupeSiteIndex
    d._dedupe_sites = DedupeSiteIndex()
    d._dedupe_sites.record_have("hashX", "peerA")
    out = d.find_alternate_sources_for_blob(
        "hashX", require_blob_request_cap=False,
    )
    assert "peerA" in out


def test_find_alternate_sources_empty_when_no_claims() -> None:
    d = _bare_daemon()
    from one_link.dedupe_sites import DedupeSiteIndex
    d._dedupe_sites = DedupeSiteIndex()
    assert d.find_alternate_sources_for_blob("hashGhost") == ()


# ---------- request_blob_from_peer ----------


@pytest.mark.asyncio
async def test_request_blob_returns_not_pinned() -> None:
    d = _bare_daemon()
    d._is_pinned = lambda fp: False
    out = await d.request_blob_from_peer("peerX", "h" * 64)
    assert out["status"] == "not_pinned"


@pytest.mark.asyncio
async def test_request_blob_returns_no_cap() -> None:
    d = _bare_daemon()
    d.state.get_peer_capabilities = lambda fp: []
    out = await d.request_blob_from_peer("peerX", "h" * 64)
    assert out["status"] == "no_cap"


@pytest.mark.asyncio
async def test_request_blob_returns_no_session_when_no_outbound() -> None:
    d = _bare_daemon()
    d.state.get_peer_capabilities = lambda fp: [BLOB_REQUEST_V1]
    rec = MagicMock()
    d.state.get_peer.return_value = rec
    d._outbound_sessions = {}  # empty
    out = await d.request_blob_from_peer("peerX", "h" * 64)
    assert out["status"] == "no_session"


@pytest.mark.asyncio
async def test_request_blob_returns_requested_on_happy_path() -> None:
    d = _bare_daemon()
    d.state.get_peer_capabilities = lambda fp: [BLOB_REQUEST_V1]
    rec = MagicMock()
    d.state.get_peer.return_value = rec
    channel = MagicMock()
    channel.send = AsyncMock()
    sess = MagicMock()
    sess.channel = channel
    d._outbound_sessions = {"peerX": sess}
    out = await d.request_blob_from_peer(
        "peerX", "h" * 64, folder_name="myfolder",
    )
    assert out["status"] == "requested"
    # Frame shape on the wire.
    frame = decode_msg(channel.send.call_args[0][0])
    assert frame["t"] == "BLOB_REQUEST"
    assert frame["blob"] == "h" * 64
    assert frame["folder"] == "myfolder"


@pytest.mark.asyncio
async def test_request_blob_returns_send_failed_on_exception() -> None:
    d = _bare_daemon()
    d.state.get_peer_capabilities = lambda fp: [BLOB_REQUEST_V1]
    rec = MagicMock()
    d.state.get_peer.return_value = rec
    channel = MagicMock()
    channel.send = AsyncMock(side_effect=RuntimeError("simulated"))
    sess = MagicMock()
    sess.channel = channel
    d._outbound_sessions = {"peerX": sess}
    out = await d.request_blob_from_peer("peerX", "h" * 64)
    assert out["status"] == "send_failed"
    assert "simulated" in out["detail"]
