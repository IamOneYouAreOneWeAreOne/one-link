"""v0.7.4 resume-on-reconnect tests.

Pin the contract:
  - send_file's exception path classifies via _is_transient_send_error:
    transient (OSError family, timeout, "handshake timed out", etc) →
    status='paused'; permanent (capability_disabled, rejected, decrypt
    fail) → status='failed'.
  - resume_paused_transfers_for(peer_fp) re-runs send_file for each
    paused outbound row. Per-peer asyncio lock prevents duplicate
    resumes.
  - Source-file-gone case: paused row → failed (can't resume what
    we don't have).
  - Peer offline: returns ok=False without touching paused rows.
  - api_cancel_transfer marks paused → failed with "cancelled by user".
  - api_resume_peer_transfers triggers the orchestrator manually.
  - statusLabel + statusKind + paused badge surface in the UI.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon, _is_transient_send_error
from one_link.discovery import Discovery, Peer
from one_link.identity import Identity, fingerprint_of
from one_link.state import State


def _new_identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="x",
    )


# ─── _is_transient_send_error classifier ───────────────────────────

def test_oserror_is_transient():
    assert _is_transient_send_error(OSError("ECONNREFUSED")) is True


def test_connection_aborted_is_transient():
    assert _is_transient_send_error(ConnectionAbortedError("WinError 10053")) is True


def test_connection_reset_is_transient():
    assert _is_transient_send_error(ConnectionResetError("reset by peer")) is True


def test_asyncio_timeout_is_transient():
    assert _is_transient_send_error(asyncio.TimeoutError()) is True


def test_runtimeerror_handshake_timeout_is_transient():
    e = RuntimeError("file send to abc: handshake timed out after 8.0s")
    assert _is_transient_send_error(e) is True


def test_runtimeerror_no_ack_is_transient():
    e = RuntimeError("file send to abc: peer did not ACK within 30s")
    assert _is_transient_send_error(e) is True


def test_capability_disabled_is_permanent():
    e = RuntimeError("files capability disabled for peer abc")
    assert _is_transient_send_error(e) is False


def test_rejected_is_permanent():
    e = RuntimeError("peer rejected: blocked")
    assert _is_transient_send_error(e) is False


def test_decrypt_failure_is_permanent():
    e = RuntimeError("decrypt failed: invalidtag")
    assert _is_transient_send_error(e) is False


def test_unknown_runtimeerror_is_permanent():
    """When in doubt, FAIL — don't loop forever on a truly broken
    peer. Only known-transient markers flip the bit."""
    e = RuntimeError("something obscure happened")
    assert _is_transient_send_error(e) is False


# ─── resume_paused_transfers_for orchestrator ─────────────────────

@pytest.mark.asyncio
async def test_resume_offline_peer_returns_offline(tmp_path: Path):
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
    # Paused row exists but peer is unreachable.
    state.upsert_transfer(
        id="t-1", direction="out", peer_fp=them.fingerprint,
        kind="file", name="a.bin", size=10, status="paused",
        progress_bytes=5, total_bytes=10,
        chunks_done=1, chunks_total=2,
        metadata={"path": str(tmp_path / "a.bin")},
    )
    (tmp_path / "a.bin").write_bytes(b"hi")
    before = int(__import__("time").time() * 1000)
    result = await daemon.resume_paused_transfers_for(them.fingerprint)
    assert result["ok"] is False
    assert result["error"] == "peer offline"
    row = state.get_transfer("t-1")
    assert row.status == "paused"
    assert row.metadata["delivery_state"] == "waiting_for_device"
    assert row.metadata["error_class"] == "PeerOffline"
    assert row.metadata["next_retry_ms"] > before
    state.close()


@pytest.mark.asyncio
async def test_resume_unknown_peer(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    result = await daemon.resume_paused_transfers_for("zz" * 32)
    assert result["ok"] is False
    state.close()


@pytest.mark.asyncio
async def test_resume_marks_failed_when_source_gone(tmp_path: Path):
    """Paused with original file deleted → mark failed, don't try
    to resend something we can't read."""
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
    state.upsert_transfer(
        id="t-gone", direction="out", peer_fp=them.fingerprint,
        kind="file", name="ghost.bin", size=10, status="paused",
        progress_bytes=0, total_bytes=10,
        chunks_done=0, chunks_total=1,
        metadata={"path": str(tmp_path / "definitely-not-there.bin")},
    )

    # Stub resolve_for_send so the orchestrator gets past the
    # peer-offline check. We don't actually send.
    fake_peer = Peer(
        short_id=them.short_id, hostname="them",
        address="127.0.0.1", port=12345,
        ed_pub_hex=them.public_bytes.hex(),
    )

    async def _fake_resolve(needle):
        return fake_peer
    daemon.resolve_for_send = _fake_resolve  # type: ignore[method-assign]

    result = await daemon.resume_paused_transfers_for(them.fingerprint)
    assert result["ok"] is True
    assert result["errors"] == 1
    rec = state.get_transfer("t-gone")
    assert rec.status == "failed"
    assert "no longer exists" in (rec.metadata or {}).get("error", "")
    state.close()


@pytest.mark.asyncio
async def test_resume_walks_only_paused_outbound(tmp_path: Path):
    """Inbound paused rows + outbound completed rows are skipped."""
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
    # Paused-inbound — orchestrator must NOT touch.
    state.upsert_transfer(
        id="t-in", direction="in", peer_fp=them.fingerprint,
        kind="file", name="a.bin", size=10, status="paused",
        progress_bytes=5, total_bytes=10,
        chunks_done=1, chunks_total=2,
    )
    # Complete-outbound — orchestrator must NOT touch.
    state.upsert_transfer(
        id="t-done", direction="out", peer_fp=them.fingerprint,
        kind="file", name="b.bin", size=10, status="complete",
        progress_bytes=10, total_bytes=10,
        chunks_done=2, chunks_total=2,
    )

    fake_peer = Peer(
        short_id=them.short_id, hostname="them",
        address="127.0.0.1", port=12345,
        ed_pub_hex=them.public_bytes.hex(),
    )
    sends = []

    async def _fake_send_file(peer, path, *, transfer_id=None):
        sends.append(path)
        return {}

    async def _fake_resolve(needle):
        return fake_peer
    daemon.resolve_for_send = _fake_resolve  # type: ignore[method-assign]
    daemon.send_file = _fake_send_file  # type: ignore[method-assign]

    result = await daemon.resume_paused_transfers_for(them.fingerprint)
    assert result["resumed"] == 0
    assert sends == []
    # Inbound paused row was not touched.
    assert state.get_transfer("t-in").status == "paused"
    assert state.get_transfer("t-done").status == "complete"
    state.close()


@pytest.mark.asyncio
async def test_resume_respects_retry_backoff(tmp_path: Path):
    """Paused rows with a future retry time stay quiet until due."""
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
    src = tmp_path / "later.bin"
    src.write_bytes(b"not yet")
    state.upsert_transfer(
        id="t-later", direction="out", peer_fp=them.fingerprint,
        kind="file", name="later.bin", size=7, status="paused",
        progress_bytes=0, total_bytes=7,
        chunks_done=0, chunks_total=1,
        metadata={
            "path": str(src),
            "next_retry_ms": 9_999_999_999_999,
            "delivery_state": "waiting_for_device",
        },
    )

    fake_peer = Peer(
        short_id=them.short_id, hostname="them",
        address="127.0.0.1", port=12345,
        ed_pub_hex=them.public_bytes.hex(),
    )
    sends = []

    async def _fake_resolve(needle):
        return fake_peer

    async def _fake_send_file(peer, path, *, transfer_id=None):
        sends.append((path, transfer_id))
        return {}

    daemon.resolve_for_send = _fake_resolve  # type: ignore[method-assign]
    daemon.send_file = _fake_send_file  # type: ignore[method-assign]

    result = await daemon.resume_paused_transfers_for(them.fingerprint)
    assert result["resumed"] == 0
    assert sends == []
    state.close()


def test_retry_pump_waits_for_live_discovered_peer(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = Discovery(
        short_id=me.short_id,
        hostname="me",
        port=1,
        ed_pub_hex=me.public_bytes.hex(),
    )
    scheduled: list[str] = []
    daemon._schedule_resume_paused = scheduled.append  # type: ignore[method-assign]
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    src = tmp_path / "wait.bin"
    src.write_bytes(b"wait")
    state.upsert_transfer(
        id="t-wait",
        direction="out",
        peer_fp=them.fingerprint,
        kind="file",
        name="wait.bin",
        size=4,
        status="paused",
        progress_bytes=0,
        total_bytes=4,
        chunks_done=0,
        chunks_total=1,
        metadata={"path": str(src), "next_retry_ms": 0},
    )

    assert daemon._schedule_due_transfer_retries() == 0
    assert scheduled == []

    daemon.discovery.registry.upsert(Peer(
        short_id=them.short_id,
        hostname="them",
        address="127.0.0.1",
        port=12345,
        ed_pub_hex=them.public_bytes.hex(),
    ))

    assert daemon._schedule_due_transfer_retries() == 1
    assert scheduled == [them.fingerprint]
    state.close()


def test_retry_pump_does_not_resume_in_flight_planning_row(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = Discovery(
        short_id=me.short_id,
        hostname="me",
        port=1,
        ed_pub_hex=me.public_bytes.hex(),
    )
    scheduled: list[str] = []
    daemon._schedule_resume_paused = scheduled.append  # type: ignore[method-assign]
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    src = tmp_path / "new-send.bin"
    src.write_bytes(b"new send")
    state.upsert_transfer(
        id="planning-current-send",
        direction="out",
        peer_fp=them.fingerprint,
        kind="file",
        name=src.name,
        size=src.stat().st_size,
        status="queued",
        progress_bytes=0,
        total_bytes=src.stat().st_size,
        chunks_done=0,
        chunks_total=1,
        metadata={
            "mode": "planning",
            "path": str(src),
            "next_retry_ms": 0,
        },
    )
    daemon.discovery.registry.upsert(Peer(
        short_id=them.short_id,
        hostname="them",
        address="127.0.0.1",
        port=12345,
        ed_pub_hex=them.public_bytes.hex(),
    ))

    assert daemon._schedule_due_transfer_retries() == 0
    assert scheduled == []
    state.close()


def test_control_resolves_pinned_peer_when_offline(tmp_path: Path):
    """Durable queued sends must work even when discovery has not found
    the device yet. Users should be able to send to the trusted device name;
    One Link waits quietly and drains it when the route appears.
    """
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
        hostname="Computer 2",
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    assert daemon._resolve_pinned_peer_fp(them.short_id) == them.fingerprint
    assert daemon._resolve_pinned_peer_fp("computer") == them.fingerprint
    assert daemon._resolve_pinned_peer_fp(them.fingerprint) == them.fingerprint
    state.close()


@pytest.mark.asyncio
async def test_control_queue_file_transfer_creates_auto_resume_intent(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
        hostname="Computer 2",
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    src = tmp_path / "queued.bin"
    src.write_bytes(b"queued durable intent")
    scheduled: list[str] = []
    daemon._schedule_resume_paused = scheduled.append  # type: ignore[method-assign]

    reader = asyncio.StreamReader()
    reader.feed_data(json.dumps({
        "cmd": "queue_file_transfer",
        "peer": "Computer 2",
        "path": str(src),
    }).encode("utf-8") + b"\n")
    reader.feed_eof()

    class _Writer:
        def __init__(self):
            self.buf = b""
            self.closed = False

        def write(self, data):
            self.buf += data

        async def drain(self):
            return None

        def close(self):
            self.closed = True

        async def wait_closed(self):
            return None

    writer = _Writer()
    await daemon._handle_control(reader, writer)  # type: ignore[arg-type]
    payload = json.loads(writer.buf.decode("utf-8"))

    assert payload["ok"] is True
    assert payload["transfer"]["status"] == "paused"
    assert payload["transfer"]["metadata"]["delivery_state"] == "waiting_for_device"
    assert scheduled == [them.fingerprint]
    rows = state.list_transfers(peer_fp=them.fingerprint, limit=10)
    assert len(rows) == 1
    assert rows[0].metadata["path"] == str(src)
    state.close()


@pytest.mark.asyncio
async def test_resume_reuses_existing_transfer_id(tmp_path: Path):
    """A resumed transfer updates the durable intent row instead of
    creating a second ghost row beside it.
    """
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
    src = tmp_path / "same.bin"
    src.write_bytes(b"again")
    state.upsert_transfer(
        id="t-same", direction="out", peer_fp=them.fingerprint,
        kind="file", name="same.bin", size=5, status="paused",
        progress_bytes=0, total_bytes=5,
        chunks_done=0, chunks_total=1,
        metadata={"path": str(src), "next_retry_ms": 0},
    )
    fake_peer = Peer(
        short_id=them.short_id, hostname="them",
        address="127.0.0.1", port=12345,
        ed_pub_hex=them.public_bytes.hex(),
    )
    seen: list[str | None] = []

    async def _fake_resolve(needle):
        return fake_peer

    async def _fake_send_file(peer, path, *, transfer_id=None):
        seen.append(transfer_id)
        state.update_transfer("t-same", status="complete")
        return {}

    daemon.resolve_for_send = _fake_resolve  # type: ignore[method-assign]
    daemon.send_file = _fake_send_file  # type: ignore[method-assign]

    result = await daemon.resume_paused_transfers_for(them.fingerprint)
    assert result["resumed"] == 1
    assert seen == ["t-same"]
    assert [r.id for r in state.list_transfers(limit=10)] == ["t-same"]
    state.close()


@pytest.mark.asyncio
async def test_resume_concurrent_calls_are_serialized(tmp_path: Path):
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
    src = tmp_path / "x.bin"
    src.write_bytes(b"hi")
    state.upsert_transfer(
        id="t-1", direction="out", peer_fp=them.fingerprint,
        kind="file", name="x.bin", size=2, status="paused",
        progress_bytes=0, total_bytes=2,
        chunks_done=0, chunks_total=1,
        metadata={"path": str(src)},
    )

    fake_peer = Peer(
        short_id=them.short_id, hostname="them",
        address="127.0.0.1", port=12345,
        ed_pub_hex=them.public_bytes.hex(),
    )

    async def _fake_resolve(needle):
        return fake_peer
    daemon.resolve_for_send = _fake_resolve  # type: ignore[method-assign]

    started = asyncio.Event()
    release = asyncio.Event()

    async def _slow_send_file(peer, path, *, transfer_id=None):
        started.set()
        await release.wait()
        return {}

    daemon.send_file = _slow_send_file  # type: ignore[method-assign]

    task1 = asyncio.create_task(
        daemon.resume_paused_transfers_for(them.fingerprint)
    )
    await started.wait()
    # Second call hits the lock and returns skipped_concurrent.
    r2 = await daemon.resume_paused_transfers_for(them.fingerprint)
    assert r2.get("skipped_concurrent") is True

    release.set()
    r1 = await task1
    assert r1["resumed"] == 1
    state.close()


# ─── api_cancel_transfer ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_api_cancel_paused_transfer(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    state.upsert_transfer(
        id="t-paused", direction="out", peer_fp="aa" * 32,
        kind="file", name="x.bin", size=10, status="paused",
        progress_bytes=0, total_bytes=10,
        chunks_done=0, chunks_total=1,
    )
    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"transfer_id": "t-paused"}

    resp = await server.api_cancel_transfer(_Req())
    body = json.loads(resp.text)
    assert body["ok"] is True
    rec = state.get_transfer("t-paused")
    assert rec.status == "failed"
    assert rec.metadata.get("error") == "cancelled by user"
    state.close()


@pytest.mark.asyncio
async def test_api_cancel_complete_is_idempotent(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    state.upsert_transfer(
        id="t-done", direction="out", peer_fp="aa" * 32,
        kind="file", name="x.bin", size=10, status="complete",
        progress_bytes=10, total_bytes=10,
        chunks_done=1, chunks_total=1,
    )
    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"transfer_id": "t-done"}

    resp = await server.api_cancel_transfer(_Req())
    body = json.loads(resp.text)
    assert body["ok"] is True
    assert body.get("already_terminal") is True
    rec = state.get_transfer("t-done")
    assert rec.status == "complete"
    state.close()


@pytest.mark.asyncio
async def test_api_cancel_unknown_is_ok(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"transfer_id": "no-such-id"}

    resp = await server.api_cancel_transfer(_Req())
    body = json.loads(resp.text)
    assert body["ok"] is True
    assert body.get("removed") is False
    state.close()


# ─── HTML structural pin ───────────────────────────────────────────

def test_index_html_has_paused_status_renderer():
    p = Path(__file__).resolve().parent.parent / "src" / "one_link" / "web" / "index.html"
    text = p.read_text(encoding="utf-8")
    assert '"paused"' in text or "'paused'" in text
    assert "Waiting for device" in text  # human-readable retry label
    assert ".badge.paused" in text  # CSS pill style
