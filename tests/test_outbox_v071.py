"""v0.7.1 store-and-forward outbox tests.

Pin the contract:
  - State helpers: enqueue, list (filterable), mark delivered,
    record attempt, cancel, clear-by-peer, prune.
  - Enqueue is idempotent on (peer_fp, msg_id).
  - Daemon enqueue requires a pinned peer fp; persists into
    messages + broadcasts an `outbox_enqueued` WS event.
  - Daemon flush walks pending in enqueued-order; on success
    marks delivered + broadcasts `outbox_delivered`.
  - Flush short-circuits on first error (don't burn through the
    queue stamping every row with the same transient error).
  - Per-peer flush lock prevents concurrent flushes from racing.
  - revoke_peer hooks into clear_outbox_for_peer.
  - Server endpoints: list, cancel, flush.
  - api_send queues on offline-pinned peer instead of 404.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.discovery import Peer
from one_link.identity import Identity, fingerprint_of
from one_link.state import OutboxEntry, State


def _new_identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="x",
    )


# ─── State helpers ─────────────────────────────────────────────────

def test_enqueue_and_list_outbox(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    fp = "aa" * 32
    entry_id = state.enqueue_outbox(
        peer_fp=fp, msg_id="m1",
        msg_body={"t": "TEXT", "id": "m1", "body": "hi"},
    )
    assert entry_id > 0
    rows = state.list_outbox(peer_fp=fp)
    assert len(rows) == 1
    assert rows[0].msg_id == "m1"
    assert rows[0].msg_body == {"t": "TEXT", "id": "m1", "body": "hi"}
    assert rows[0].delivered is False
    state.close()


def test_enqueue_outbox_idempotent_on_same_msg_id(tmp_path: Path):
    """The same (peer_fp, msg_id) should never duplicate in the outbox.
    Idempotent enqueue is what makes a UI retry safe."""
    state = State(db_path=tmp_path / "s.db")
    fp = "aa" * 32
    eid1 = state.enqueue_outbox(
        peer_fp=fp, msg_id="m1",
        msg_body={"t": "TEXT", "body": "hi"},
    )
    eid2 = state.enqueue_outbox(
        peer_fp=fp, msg_id="m1",
        msg_body={"t": "TEXT", "body": "different"},  # ignored
    )
    assert eid1 == eid2
    rows = state.list_outbox(peer_fp=fp)
    assert len(rows) == 1
    # Original body preserved.
    assert rows[0].msg_body["body"] == "hi"
    state.close()


def test_list_outbox_filters_pending_only_by_default(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    fp = "aa" * 32
    eid = state.enqueue_outbox(
        peer_fp=fp, msg_id="m1", msg_body={"t": "TEXT"},
    )
    state.mark_outbox_delivered(eid)

    state.enqueue_outbox(
        peer_fp=fp, msg_id="m2", msg_body={"t": "TEXT"},
    )
    pending = state.list_outbox(peer_fp=fp, pending_only=True)
    assert [r.msg_id for r in pending] == ["m2"]

    all_rows = state.list_outbox(peer_fp=fp, pending_only=False)
    assert {r.msg_id for r in all_rows} == {"m1", "m2"}
    state.close()


def test_list_outbox_orders_by_enqueued_ms_ascending(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    fp = "aa" * 32
    state.enqueue_outbox(peer_fp=fp, msg_id="m1", msg_body={})
    time.sleep(0.005)
    state.enqueue_outbox(peer_fp=fp, msg_id="m2", msg_body={})
    time.sleep(0.005)
    state.enqueue_outbox(peer_fp=fp, msg_id="m3", msg_body={})

    rows = state.list_outbox(peer_fp=fp)
    assert [r.msg_id for r in rows] == ["m1", "m2", "m3"]
    state.close()


def test_mark_outbox_delivered_idempotent(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    fp = "aa" * 32
    eid = state.enqueue_outbox(peer_fp=fp, msg_id="m1", msg_body={})
    assert state.mark_outbox_delivered(eid) is True
    assert state.mark_outbox_delivered(eid) is False  # already delivered
    state.close()


def test_record_outbox_attempt_increments(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    fp = "aa" * 32
    eid = state.enqueue_outbox(peer_fp=fp, msg_id="m1", msg_body={})

    state.record_outbox_attempt(eid, error="timeout")
    state.record_outbox_attempt(eid, error="handshake")
    rows = state.list_outbox(peer_fp=fp)
    assert rows[0].attempts == 2
    assert rows[0].last_error == "handshake"
    assert rows[0].last_attempt_ms is not None
    state.close()


def test_cancel_outbox_removes_pending(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    fp = "aa" * 32
    eid = state.enqueue_outbox(peer_fp=fp, msg_id="m1", msg_body={})
    assert state.cancel_outbox(eid) is True
    assert state.list_outbox(peer_fp=fp) == []
    state.close()


def test_cancel_outbox_refuses_delivered(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    fp = "aa" * 32
    eid = state.enqueue_outbox(peer_fp=fp, msg_id="m1", msg_body={})
    state.mark_outbox_delivered(eid)
    assert state.cancel_outbox(eid) is False
    # Row still exists (just marked delivered).
    assert len(state.list_outbox(peer_fp=fp, pending_only=False)) == 1
    state.close()


def test_clear_outbox_for_peer_drops_all(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    fp_a = "aa" * 32
    fp_b = "bb" * 32
    state.enqueue_outbox(peer_fp=fp_a, msg_id="m1", msg_body={})
    state.enqueue_outbox(peer_fp=fp_a, msg_id="m2", msg_body={})
    state.enqueue_outbox(peer_fp=fp_b, msg_id="m3", msg_body={})

    removed = state.clear_outbox_for_peer(fp_a)
    assert removed == 2
    assert state.list_outbox(peer_fp=fp_a, pending_only=False) == []
    # Other peer untouched.
    assert len(state.list_outbox(peer_fp=fp_b, pending_only=False)) == 1
    state.close()


def test_prune_outbox_drops_delivered_only(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    fp = "aa" * 32
    eid_old = state.enqueue_outbox(peer_fp=fp, msg_id="m1", msg_body={})
    state.mark_outbox_delivered(eid_old)
    state.enqueue_outbox(peer_fp=fp, msg_id="m2", msg_body={})

    removed = state.prune_outbox(delivered_only=True)
    assert removed == 1
    rows = state.list_outbox(peer_fp=fp, pending_only=False)
    assert [r.msg_id for r in rows] == ["m2"]
    state.close()


# ─── Daemon enqueue ────────────────────────────────────────────────

def test_enqueue_text_outbox_requires_pinned(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    # Default trust is 'pending'.
    with pytest.raises(RuntimeError, match="pinned"):
        daemon.enqueue_text_outbox(them.fingerprint, "hi")
    state.close()


def test_enqueue_text_outbox_persists_msg_and_broadcasts(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    events: list[dict] = []
    daemon.ui_server = SimpleNamespace(broadcast=lambda evt: events.append(evt))

    result = daemon.enqueue_text_outbox(them.fingerprint, "hello sleeping peer")
    assert result["ok"] is True
    assert result["outbox_id"] > 0
    assert result["msg"]["t"] == "TEXT"
    assert result["msg"]["body"] == "hello sleeping peer"

    # Outbox row is queryable.
    rows = state.list_outbox(peer_fp=them.fingerprint)
    assert [r.msg_id for r in rows] == [result["msg"]["id"]]

    # WS event broadcast.
    enq = [e for e in events if e.get("type") == "outbox_enqueued"]
    assert enq, f"no outbox_enqueued event; events={events}"
    assert enq[0]["fingerprint"] == them.fingerprint
    assert enq[0]["msg_id"] == result["msg"]["id"]
    state.close()


def test_enqueue_text_outbox_no_state_raises():
    me = _new_identity()
    daemon = Daemon(me)
    daemon.state = None
    with pytest.raises(RuntimeError, match="state"):
        daemon.enqueue_text_outbox("aa" * 32, "x")


# ─── Daemon flush ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_flush_outbox_no_peer_returns_offline(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    state.enqueue_outbox(peer_fp=them.fingerprint, msg_id="m1", msg_body={})

    # No discovery → resolve_for_send returns None.
    result = await daemon.flush_outbox_for(them.fingerprint)
    assert result["ok"] is False
    assert result["error"] == "peer offline"
    assert result["delivered"] == 0
    state.close()


@pytest.mark.asyncio
async def test_flush_outbox_unknown_peer_handled(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state

    result = await daemon.flush_outbox_for("zz" * 32)
    assert result["ok"] is False
    assert result["error"] == "unknown peer"
    state.close()


@pytest.mark.asyncio
async def test_flush_outbox_delivers_pending_in_order(tmp_path: Path, monkeypatch):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    # Enqueue three messages.
    for i in range(3):
        state.enqueue_outbox(
            peer_fp=them.fingerprint, msg_id=f"m{i}",
            msg_body={"t": "TEXT", "id": f"m{i}", "body": f"hi-{i}"},
        )

    # Stub resolve_for_send to return a dummy Peer.
    fake_peer = Peer(
        short_id=them.short_id, hostname="them",
        address="127.0.0.1", port=12345,
        ed_pub_hex=them.public_bytes.hex(),
    )

    async def _fake_resolve(needle):
        return fake_peer

    daemon.resolve_for_send = _fake_resolve  # type: ignore[method-assign]

    sent: list[list[dict]] = []

    async def _fake_send_to(peer, msgs):
        sent.append(list(msgs))
        return [{"t": "ACK"} for _ in msgs]

    daemon.send_to = _fake_send_to  # type: ignore[method-assign]

    events: list[dict] = []
    daemon.ui_server = SimpleNamespace(broadcast=lambda evt: events.append(evt))

    result = await daemon.flush_outbox_for(them.fingerprint)
    assert result["ok"] is True
    assert result["delivered"] == 3
    assert result["errors"] == 0
    # All three actually shipped.
    flat = [m for batch in sent for m in batch]
    assert [m["id"] for m in flat] == ["m0", "m1", "m2"]
    # All three persisted as delivered.
    pending = state.list_outbox(peer_fp=them.fingerprint, pending_only=True)
    assert pending == []
    # 3 outbox_delivered events fired.
    delivered = [e for e in events if e.get("type") == "outbox_delivered"]
    assert len(delivered) == 3
    state.close()


@pytest.mark.asyncio
async def test_flush_outbox_short_circuits_on_first_error(
    tmp_path: Path, monkeypatch,
):
    """If the first row fails, don't burn through the rest stamping
    them with the same error. Stop, surface the error, retry on
    next session-up."""
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    for i in range(3):
        state.enqueue_outbox(
            peer_fp=them.fingerprint, msg_id=f"m{i}",
            msg_body={"t": "TEXT", "body": f"x{i}"},
        )

    fake_peer = Peer(
        short_id=them.short_id, hostname="them", address="127.0.0.1",
        port=12345, ed_pub_hex=them.public_bytes.hex(),
    )

    async def _fake_resolve(needle):
        return fake_peer
    daemon.resolve_for_send = _fake_resolve  # type: ignore[method-assign]

    call_count = 0

    async def _fake_send_to(peer, msgs):
        nonlocal call_count
        call_count += 1
        raise RuntimeError("simulated network error")

    daemon.send_to = _fake_send_to  # type: ignore[method-assign]

    result = await daemon.flush_outbox_for(them.fingerprint)
    assert result["delivered"] == 0
    assert result["errors"] == 1
    # send_to was only called once — short-circuited.
    assert call_count == 1
    # All three rows still pending.
    pending = state.list_outbox(peer_fp=them.fingerprint, pending_only=True)
    assert len(pending) == 3
    # First row's last_error was stamped.
    assert pending[0].last_error is not None
    assert "simulated" in pending[0].last_error
    assert pending[0].attempts == 1
    state.close()


@pytest.mark.asyncio
async def test_flush_outbox_concurrent_calls_are_serialized(tmp_path: Path):
    """Two simultaneous flush calls for the same peer don't both
    try to ship the queue. Second call is a no-op."""
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    state.enqueue_outbox(
        peer_fp=them.fingerprint, msg_id="m1",
        msg_body={"t": "TEXT", "body": "x"},
    )

    fake_peer = Peer(
        short_id=them.short_id, hostname="them", address="127.0.0.1",
        port=12345, ed_pub_hex=them.public_bytes.hex(),
    )

    async def _fake_resolve(needle):
        return fake_peer
    daemon.resolve_for_send = _fake_resolve  # type: ignore[method-assign]

    send_event = asyncio.Event()
    started = asyncio.Event()

    async def _slow_send_to(peer, msgs):
        started.set()
        await send_event.wait()
        return [{"t": "ACK"}]

    daemon.send_to = _slow_send_to  # type: ignore[method-assign]

    # Kick off a flush; it parks waiting for send_event.
    flush1 = asyncio.create_task(daemon.flush_outbox_for(them.fingerprint))
    await started.wait()
    # Second flush should bail because the lock is held.
    result2 = await daemon.flush_outbox_for(them.fingerprint)
    assert result2.get("skipped_concurrent") is True

    # Let the first one finish.
    send_event.set()
    result1 = await flush1
    assert result1["delivered"] == 1
    state.close()


# ─── revoke_peer drops outbox ──────────────────────────────────────

@pytest.mark.asyncio
async def test_revoke_peer_clears_outbox(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    state.enqueue_outbox(
        peer_fp=them.fingerprint, msg_id="m1", msg_body={"t": "TEXT"},
    )
    state.enqueue_outbox(
        peer_fp=them.fingerprint, msg_id="m2", msg_body={"t": "TEXT"},
    )

    daemon.ui_server = SimpleNamespace(broadcast=lambda evt: None)
    await daemon.revoke_peer(them.fingerprint, actor="test")

    assert state.list_outbox(
        peer_fp=them.fingerprint, pending_only=False,
    ) == []
    state.close()


# ─── Server endpoints ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_api_list_outbox(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    fp = "cc" * 32
    state.enqueue_outbox(peer_fp=fp, msg_id="m1", msg_body={"t": "TEXT", "body": "x"})

    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)

    class _Req:
        query: dict = {}
        match_info: dict = {}

    resp = await server.api_list_outbox(_Req())
    body = json.loads(resp.text)
    assert len(body["entries"]) == 1
    assert body["entries"][0]["msg_id"] == "m1"
    assert body["entries"][0]["delivered"] is False
    state.close()


@pytest.mark.asyncio
async def test_api_cancel_outbox(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    fp = "cc" * 32
    eid = state.enqueue_outbox(
        peer_fp=fp, msg_id="m1", msg_body={"t": "TEXT"},
    )

    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"id": str(eid)}
        async def json(self):
            return {}

    resp = await server.api_cancel_outbox(_Req())
    body = json.loads(resp.text)
    assert body["removed"] is True
    assert state.list_outbox(peer_fp=fp) == []
    state.close()


@pytest.mark.asyncio
async def test_api_cancel_outbox_404_unknown(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"id": "999999"}
        async def json(self):
            return {}

    resp = await server.api_cancel_outbox(_Req())
    assert resp.status == 404
    state.close()


@pytest.mark.asyncio
async def test_api_cancel_outbox_409_when_delivered(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    fp = "cc" * 32
    eid = state.enqueue_outbox(
        peer_fp=fp, msg_id="m1", msg_body={"t": "TEXT"},
    )
    state.mark_outbox_delivered(eid)

    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"id": str(eid)}
        async def json(self):
            return {}

    resp = await server.api_cancel_outbox(_Req())
    assert resp.status == 409
    state.close()


# ─── api_send queues on offline pinned peer ────────────────────────

@pytest.mark.asyncio
async def test_api_send_queues_on_offline_pinned_peer(tmp_path: Path):
    """The flagship UX: user sends to a sleeping paired device,
    the message queues instead of erroring."""
    from one_link.server import UIServer

    me_fp = "aa" * 32
    them_fp = "bb" * 32

    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint=them_fp, short_id="bbbbbbbb",
        pubkey=bytes.fromhex(them_fp),
    )
    state.set_peer_trust(them_fp, "pinned")

    enqueued: list[tuple[str, str]] = []

    def _enqueue(fp, body, *, client_msg_id=None):
        enqueued.append((fp, body, client_msg_id))
        return {
            "ok": True, "outbox_id": 7,
            "msg": {"t": "TEXT", "id": client_msg_id or "abc", "body": body},
        }

    daemon = SimpleNamespace(
        state=state,
        resolve_for_send=lambda needle: _async_returns(None),
        enqueue_text_outbox=_enqueue,
    )
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        async def json(self):
            return {"peer": "bbbbbbbb", "body": "hello sleeper"}

    resp = await server.api_send(_Req())
    body = json.loads(resp.text)
    assert resp.status == 202
    assert body["ok"] is True
    assert body["queued"] is True
    assert body["outbox_id"] == 7
    assert body["reason"] == "peer_offline"
    assert enqueued == [(them_fp, "hello sleeper", None)]
    state.close()


@pytest.mark.asyncio
async def test_api_send_unknown_peer_still_404s(tmp_path: Path):
    """If the needle doesn't match any pinned peer, the 404 stays.
    Don't queue messages addressed to strangers."""
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(
        state=state,
        resolve_for_send=lambda n: _async_returns(None),
        enqueue_text_outbox=lambda fp, body, *, client_msg_id=None: None,
    )
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        async def json(self):
            return {"peer": "ghost", "body": "x"}

    resp = await server.api_send(_Req())
    assert resp.status == 404
    state.close()


@pytest.mark.asyncio
async def test_api_send_queue_on_failure_opt_out(tmp_path: Path):
    """When queue_on_failure=False is set, offline peer gets the
    legacy 404 (used by control plane / CLI sync sends)."""
    from one_link.server import UIServer

    them_fp = "bb" * 32
    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint=them_fp, short_id="bbbbbbbb",
        pubkey=bytes.fromhex(them_fp),
    )
    state.set_peer_trust(them_fp, "pinned")

    daemon = SimpleNamespace(
        state=state,
        resolve_for_send=lambda n: _async_returns(None),
        enqueue_text_outbox=lambda fp, body, *, client_msg_id=None: pytest.fail("should not enqueue"),
    )
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        async def json(self):
            return {"peer": "bbbbbbbb", "body": "x", "queue_on_failure": False}

    resp = await server.api_send(_Req())
    assert resp.status == 404
    state.close()


# ─── helpers ───────────────────────────────────────────────────────

def _async_returns(v):
    async def _co():
        return v
    return _co()
