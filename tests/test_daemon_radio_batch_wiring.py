"""Tests for Phase G radio-batcher enqueue path in
``broadcast_endpoint_to_paired``.

Verifies:
  - When ONE_LINK_RADIO_BATCHER is OFF, behavior is unchanged
    (no enqueue calls).
  - When enabled, paired peers' announcements are enqueued instead
    of sent inline.
  - The dispatch handler decodes payload + schedules an async send.
  - Decode errors are swallowed.
  - Non-running event loop is tolerated.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from one_link import daemon as daemon_module


def _make_daemon(batcher_enabled: bool = False):
    """A Daemon-like object with the minimum surface to exercise
    _enqueue_endpoint_broadcasts / _dispatch_endpoint_broadcast /
    _send_batched_endpoint."""
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.me = MagicMock()
    d.me.short_id = "ME"
    d.me.fingerprint = "fp_me"
    d._radio_batcher_enabled = batcher_enabled
    d._radio_batcher = MagicMock() if batcher_enabled else None
    d._quic_local_port = None
    d._user_mode_value = "normal"
    return d


def _peer(fp: str, trust: str = "pinned"):
    p = MagicMock()
    p.fingerprint = fp
    p.trust = trust
    p.short_id = fp[:4]
    return p


# ---------- _enqueue_endpoint_broadcasts ----------


def test_enqueue_skips_when_no_batcher() -> None:
    d = _make_daemon(batcher_enabled=False)
    d._radio_batcher = None
    peers = [_peer("fp1"), _peer("fp2")]
    n = d._enqueue_endpoint_broadcasts(peers, [{"host": "1.2.3.4", "port": 80}])
    assert n == 0


def test_enqueue_loops_paired_peers() -> None:
    d = _make_daemon(batcher_enabled=True)
    peers = [_peer("fp1"), _peer("fp2"), _peer("fp3")]
    n = d._enqueue_endpoint_broadcasts(peers, [{"host": "1.2.3.4", "port": 80}])
    assert n == 3
    assert d._radio_batcher.enqueue.call_count == 3


def test_enqueue_skips_non_pinned() -> None:
    d = _make_daemon(batcher_enabled=True)
    peers = [_peer("fp1"), _peer("fp2", trust="pending"), _peer("fp3", trust="rejected")]
    n = d._enqueue_endpoint_broadcasts(peers, [{"host": "1.2.3.4", "port": 80}])
    assert n == 1
    d._radio_batcher.enqueue.assert_called_once()


def test_enqueue_skips_self() -> None:
    d = _make_daemon(batcher_enabled=True)
    peers = [_peer("fp1"), _peer("fp_me")]  # second is self
    n = d._enqueue_endpoint_broadcasts(peers, [{"host": "1.2.3.4", "port": 80}])
    assert n == 1


def test_enqueue_includes_quic_port_when_active() -> None:
    d = _make_daemon(batcher_enabled=True)
    d._quic_local_port = 8443
    peers = [_peer("fp1")]
    d._enqueue_endpoint_broadcasts(peers, [{"host": "1.2.3.4", "port": 80}])
    # Inspect the payload that was enqueued.
    call_args = d._radio_batcher.enqueue.call_args
    payload_bytes = call_args[0][1]
    payload = json.loads(payload_bytes.decode("utf-8"))
    assert payload.get("quic_port") == 8443


def test_enqueue_survives_batcher_error() -> None:
    d = _make_daemon(batcher_enabled=True)
    d._radio_batcher.enqueue.side_effect = ValueError("queue_full")
    peers = [_peer("fp1"), _peer("fp2")]
    # Must not raise; count successful enqueues.
    n = d._enqueue_endpoint_broadcasts(peers, [{"host": "1.2.3.4", "port": 80}])
    assert n == 0  # all attempts failed


def test_enqueue_registers_dispatch_handler() -> None:
    d = _make_daemon(batcher_enabled=True)
    assert getattr(d, "_radio_batcher_dispatch", None) is None
    d._enqueue_endpoint_broadcasts([_peer("fp1")], [{"host": "1.2.3.4", "port": 80}])
    assert callable(d._radio_batcher_dispatch)


# ---------- _dispatch_endpoint_broadcast ----------


def test_dispatch_decodes_payload() -> None:
    d = _make_daemon()
    d._send_batched_endpoint = AsyncMock()
    outer = {"type": "ENDPOINT_UPDATE", "endpoints": []}
    payload = json.dumps(outer).encode("utf-8")
    # asyncio.get_running_loop() raises outside a running loop;
    # the method swallows that gracefully.
    d._dispatch_endpoint_broadcast("fp1", payload)
    # Without a running loop the async helper is NOT awaited.
    d._send_batched_endpoint.assert_not_called()


def test_dispatch_survives_bad_json() -> None:
    d = _make_daemon()
    d._send_batched_endpoint = AsyncMock()
    # Must not raise.
    d._dispatch_endpoint_broadcast("fp1", b"\x00\x01\x02not_json")
    d._send_batched_endpoint.assert_not_called()


@pytest.mark.asyncio
async def test_dispatch_scheduled_in_running_loop() -> None:
    """When a loop IS running, dispatch schedules the async send."""
    d = _make_daemon()
    sends: list = []

    async def fake_send(fp, outer):
        sends.append((fp, outer))

    d._send_batched_endpoint = fake_send

    d._dispatch_endpoint_broadcast(
        "fp1",
        json.dumps({"type": "ENDPOINT_UPDATE", "endpoints": []}).encode("utf-8"),
    )
    # Yield so the scheduled task runs.
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert len(sends) == 1
    assert sends[0][0] == "fp1"


# ---------- _send_batched_endpoint ----------


@pytest.mark.asyncio
async def test_send_batched_skips_unresolvable_peer() -> None:
    d = _make_daemon()
    d.resolve_for_send = AsyncMock(return_value=None)
    d.send_to = AsyncMock()
    await d._send_batched_endpoint("fp1", {"type": "ENDPOINT_UPDATE"})
    d.send_to.assert_not_called()


@pytest.mark.asyncio
async def test_send_batched_sends_when_resolvable() -> None:
    d = _make_daemon()
    peer_obj = MagicMock()
    d.resolve_for_send = AsyncMock(return_value=peer_obj)
    d.send_to = AsyncMock()
    await d._send_batched_endpoint("fp1", {"type": "ENDPOINT_UPDATE"})
    d.send_to.assert_called_once_with(peer_obj, [{"type": "ENDPOINT_UPDATE"}])


@pytest.mark.asyncio
async def test_send_batched_swallows_send_error() -> None:
    d = _make_daemon()
    peer_obj = MagicMock()
    d.resolve_for_send = AsyncMock(return_value=peer_obj)
    d.send_to = AsyncMock(side_effect=RuntimeError("network gone"))
    # Must not raise.
    await d._send_batched_endpoint("fp1", {"type": "ENDPOINT_UPDATE"})
