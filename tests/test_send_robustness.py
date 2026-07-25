"""v0.6.3 robustness tests.

These pin behaviors the user audit surfaced as broken:
  - File-send no longer hangs forever when the receiver is silent
    (handshake timeout, per-chunk ACK timeout).
  - The transfer ledger reaper fails any transfer stuck for too long
    so the UI never shows "sending..." indefinitely.
  - The paste-image handler in the UI markup is wired via the JS
    contract that's checked by the existing UI smoke test
    (test_ui_markup.py).
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

import blake3
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import (
    Daemon,
    FILE_ACK_DEADLINE_S,
    HANDSHAKE_DEADLINE_OUTBOUND_S,
    IncomingFile,
    OutboundSession,
    TransferPausedError,
    _is_transient_send_error,
)
from one_link.discovery import Peer
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


async def _close_silent_server(
    server: asyncio.AbstractServer,
    writers: list[asyncio.StreamWriter],
    handler_tasks: set[asyncio.Task[None]],
) -> None:
    """Close a synthetic peer and every accepted-side handler it owns."""
    server.close()
    for task in handler_tasks:
        if not task.done():
            task.cancel()
    await asyncio.gather(*handler_tasks, return_exceptions=True)
    for writer in writers:
        writer.close()
    try:
        await asyncio.wait_for(
            asyncio.gather(
                *(writer.wait_closed() for writer in writers),
                return_exceptions=True,
            ),
            timeout=2.0,
        )
    except TimeoutError:
        for writer in writers:
            transport = writer.transport
            transport.abort()
        await asyncio.sleep(0)
    await asyncio.wait_for(server.wait_closed(), timeout=2.0)


def test_timeout_errors_are_transient_send_errors() -> None:
    assert _is_transient_send_error(asyncio.TimeoutError())


@pytest.mark.asyncio
async def test_fire_and_forget_retry_tasks_are_owned_and_drained_by_stop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon = Daemon(_new_identity())
    daemon.state = State(db_path=tmp_path / "state.db")
    peer_fp = "ab" * 32
    started = asyncio.Event()
    cancelled: set[str] = set()

    async def _hold_resume(_peer_fp: str, *, force: bool = False) -> None:
        del force
        started.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            cancelled.add("resume")
            raise

    async def _hold_outbox(_peer_fp: str) -> None:
        started.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            cancelled.add("outbox")
            raise

    monkeypatch.setattr(daemon, "_resume_paused_swallow", _hold_resume)
    monkeypatch.setattr(daemon, "_flush_outbox_swallow", _hold_outbox)

    daemon._schedule_resume_paused(peer_fp)
    daemon._schedule_outbox_flush(peer_fp)
    await asyncio.wait_for(started.wait(), timeout=1.0)
    await asyncio.sleep(0)
    assert len(daemon._background_tasks) == 2

    await daemon.stop()

    assert cancelled == {"resume", "outbox"}
    assert not daemon._background_tasks


class _DesyncedChannel:
    async def send(self, payload: bytes) -> None:
        return None

    async def recv(self) -> bytes:
        raise ValueError("unsupported ratchet header version: 152")

    async def close(self) -> None:
        return None


# ─── handshake-timeout protection ─────────────────────────────────

@pytest.mark.asyncio
async def test_send_text_retries_same_message_id_after_transient_read_drop(
    tmp_path: Path,
    monkeypatch,
):
    me = _new_identity()
    them = _new_identity()
    daemon = Daemon(me)
    daemon.state = State(db_path=tmp_path / "state.db")
    daemon.state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    daemon.state.set_peer_trust(them.fingerprint, "pinned")
    peer = Peer(
        short_id=them.short_id,
        hostname="peer",
        address="127.0.0.1",
        port=1,
        ed_pub_hex=them.public_bytes.hex(),
    )
    sent_ids: list[str] = []

    async def fake_send_to(_peer, msgs):
        sent_ids.append(str(msgs[0]["id"]))
        if len(sent_ids) == 1:
            raise asyncio.IncompleteReadError(partial=b"", expected=4)
        return [{"t": "ACK", "of": msgs[0]["id"]}]

    monkeypatch.setattr(daemon, "send_to", fake_send_to)
    result = await daemon.send_text(peer, "hello")

    assert result["ack"]["of"] == result["sent"]["id"]
    assert len(sent_ids) == 2
    assert sent_ids[0] == sent_ids[1] == result["sent"]["id"]


@pytest.mark.asyncio
async def test_send_file_aborts_when_receiver_doesnt_speak_protocol(
    tmp_path: Path,
    monkeypatch,
):
    """Stand up a TCP listener that ACCEPTS connections but never
    sends the handshake REPLY frame. send_file should time out within
    the handshake deadline rather than hang forever."""
    me_a = _new_identity()
    me_b = _new_identity()

    state_a = State(db_path=tmp_path / "state.db")
    state_a.upsert_peer(
        fingerprint=me_b.fingerprint, short_id=me_b.short_id,
        pubkey=me_b.public_bytes,
    )
    state_a.set_peer_trust(me_b.fingerprint, "pinned")

    daemon_a = Daemon(me_a)
    daemon_a.state = state_a
    daemon_a.discovery = None

    # Silent listener: accept and hold; never reply.
    accepted_writers: list[asyncio.StreamWriter] = []
    handler_tasks: set[asyncio.Task[None]] = set()

    async def _silent(reader, writer):
        task = asyncio.current_task()
        if task is not None:
            handler_tasks.add(task)
        accepted_writers.append(writer)
        try:
            await asyncio.sleep(60.0)
        except asyncio.CancelledError:
            pass

    server = await asyncio.start_server(_silent, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]

    f = tmp_path / "small.txt"
    f.write_bytes(b"X" * 15_000)

    peer_b = Peer(
        short_id=me_b.short_id, hostname="b",
        address="127.0.0.1", port=port,
        ed_pub_hex=me_b.public_bytes.hex(),
    )

    # Compress the deadline so the test runs in seconds, not 8s.
    monkeypatch.setattr(
        "one_link.daemon.HANDSHAKE_DEADLINE_OUTBOUND_S", 1.0,
    )

    started = time.monotonic()
    try:
        with pytest.raises(RuntimeError, match="handshake timed out"):
            await daemon_a.send_file(peer_b, f)
    finally:
        elapsed = time.monotonic() - started
        # Must abort within the tight window, NOT hang forever.
        assert elapsed < 5.0, f"send_file took {elapsed:.1f}s — did the timeout fire?"
        await _close_silent_server(server, accepted_writers, handler_tasks)
        await daemon_a.stop()


@pytest.mark.asyncio
async def test_send_file_marks_transfer_paused_with_reason(
    tmp_path: Path, monkeypatch,
):
    """When send_file aborts on a transient timeout, the transfer-ledger
    row must be 'paused' with a human-readable reason in metadata.
    The UI/API can then show "will resume" instead of a 500 or spinner."""
    me_a = _new_identity()
    me_b = _new_identity()
    state_a = State(db_path=tmp_path / "state.db")
    state_a.upsert_peer(
        fingerprint=me_b.fingerprint, short_id=me_b.short_id,
        pubkey=me_b.public_bytes,
    )
    state_a.set_peer_trust(me_b.fingerprint, "pinned")
    daemon_a = Daemon(me_a)
    daemon_a.state = state_a
    daemon_a.discovery = None

    accepted_writers: list[asyncio.StreamWriter] = []
    handler_tasks: set[asyncio.Task[None]] = set()

    async def _silent(reader, writer):
        task = asyncio.current_task()
        if task is not None:
            handler_tasks.add(task)
        accepted_writers.append(writer)
        try:
            await asyncio.sleep(30.0)
        except asyncio.CancelledError:
            pass
    server = await asyncio.start_server(_silent, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]
    f = tmp_path / "x.txt"
    f.write_bytes(b"hi")
    peer_b = Peer(
        short_id=me_b.short_id, hostname="b",
        address="127.0.0.1", port=port,
        ed_pub_hex=me_b.public_bytes.hex(),
    )
    monkeypatch.setattr(
        "one_link.daemon.HANDSHAKE_DEADLINE_OUTBOUND_S", 0.5,
    )
    try:
        with pytest.raises(TransferPausedError):
            await daemon_a.send_file(peer_b, f)
        # The ledger row should now be 'paused' with our reason.
        rows = state_a.list_transfers(limit=10)
        assert rows, "no transfer recorded"
        rec = rows[0]
        assert rec.status == "paused"
        # Reason populated.
        assert "error" in rec.metadata
        assert "timed out" in rec.metadata["error"].lower()
        assert rec.metadata.get("transient") is True
    finally:
        await _close_silent_server(server, accepted_writers, handler_tasks)
        await daemon_a.stop()


@pytest.mark.asyncio
async def test_resume_retry_preserves_existing_progress_on_handshake_timeout(
    tmp_path: Path,
):
    """A retry attempt must not reset a durable transfer row back to 0%
    before the peer answers. Crash/restart recovery depends on the ledger
    staying truthful while One Link waits for the device again."""
    me_a = _new_identity()
    me_b = _new_identity()
    state_a = State(db_path=tmp_path / "state.db")
    state_a.upsert_peer(
        fingerprint=me_b.fingerprint,
        short_id=me_b.short_id,
        pubkey=me_b.public_bytes,
    )
    state_a.set_peer_trust(me_b.fingerprint, "pinned")
    daemon_a = Daemon(me_a)
    daemon_a.state = state_a
    src = tmp_path / "resume.bin"
    src.write_bytes(b"x" * 1024 * 1024)
    transfer_id = "resume-progress-row"
    state_a.upsert_transfer(
        id=transfer_id,
        direction="out",
        peer_fp=me_b.fingerprint,
        kind="file",
        name=src.name,
        size=src.stat().st_size,
        status="paused",
        progress_bytes=256 * 1024,
        total_bytes=src.stat().st_size,
        chunks_done=1,
        chunks_total=4,
        metadata={"path": str(src), "next_retry_ms": 0},
    )
    peer_b = Peer(
        short_id=me_b.short_id,
        hostname="b",
        address="127.0.0.1",
        port=9,
        ed_pub_hex=me_b.public_bytes.hex(),
    )

    async def _timeout(*_args, **_kwargs):
        raise asyncio.TimeoutError()

    daemon_a._get_outbound_session = _timeout  # type: ignore[method-assign]

    with pytest.raises(TransferPausedError):
        await daemon_a.send_file(peer_b, src, transfer_id=transfer_id)

    rec = state_a.get_transfer(transfer_id)
    assert rec.status == "paused"
    assert rec.progress_bytes == 256 * 1024
    assert rec.chunks_done == 1
    assert rec.chunks_total >= 4
    assert rec.metadata["delivery_state"] == "waiting_for_device"
    await daemon_a.stop()


def test_ratchet_header_mismatch_is_transient():
    assert _is_transient_send_error(
        ValueError("unsupported ratchet header version: 152")
    )


@pytest.mark.asyncio
async def test_send_file_pauses_and_preserves_on_ratchet_desync(tmp_path: Path):
    """If an existing secure session is desynced, files must pause for
    automatic retry instead of being marked permanently failed."""
    me_a = _new_identity()
    me_b = _new_identity()
    state_a = State(db_path=tmp_path / "state.db")
    state_a.upsert_peer(
        fingerprint=me_b.fingerprint,
        short_id=me_b.short_id,
        pubkey=me_b.public_bytes,
    )
    state_a.set_peer_trust(me_b.fingerprint, "pinned")
    daemon_a = Daemon(me_a)
    daemon_a.state = state_a
    peer_b = Peer(
        short_id=me_b.short_id,
        hostname="b",
        address="127.0.0.1",
        port=9,
        ed_pub_hex=me_b.public_bytes.hex(),
    )
    sess = OutboundSession(
        peer_fp=me_b.fingerprint,
        peer=peer_b,
        channel=_DesyncedChannel(),  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    daemon_a._outbound_sessions[me_b.fingerprint] = sess
    src = tmp_path / "movie.mp4"
    src.write_bytes(b"video-bytes" * 4096)

    with pytest.raises(TransferPausedError) as ei:
        await daemon_a.send_file(peer_b, src)
    assert ei.value.path == src
    assert src.is_file()
    row = state_a.list_transfers(limit=1)[0]
    assert row.status == "paused"
    assert row.metadata["transient"] is True
    assert "ratchet header version" in row.metadata["error"]
    assert me_b.fingerprint not in daemon_a._outbound_sessions
    await daemon_a.stop()


# ─── transfer-ledger watchdog ──────────────────────────────────────

def test_reap_stuck_transfers_marks_old_offered_as_waiting(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state

    # Stuck transfer: offered status, last update > deadline ago.
    long_ago = int(time.time() * 1000) - (10 * 60 * 1000)  # 10 min ago
    state.upsert_transfer(
        id="stuck1",
        direction="out",
        peer_fp="aa" * 32,
        kind="file",
        name="big.bin",
        size=1_000_000,
        status="offered",
        progress_bytes=0,
        total_bytes=1_000_000,
        chunks_done=0,
        chunks_total=10,
    )
    # Force the updated_ms field backward via direct UPDATE (the
    # upsert helper stamps it to now).
    with state._write_lock:
        state._conn.execute(
            "UPDATE transfers SET updated_ms = ? WHERE id = ?",
            (long_ago, "stuck1"),
        )
    # Healthy transfer: also offered but recent.
    state.upsert_transfer(
        id="fresh1",
        direction="out",
        peer_fp="bb" * 32,
        kind="file",
        name="ok.bin",
        size=1_000,
        status="offered",
        progress_bytes=0,
        total_bytes=1_000,
        chunks_done=0,
        chunks_total=1,
    )

    reaped = daemon._reap_stuck_transfers()
    assert reaped == 1

    # Stuck row is now retryable, not dead.
    rows = {r.id: r for r in state.list_transfers(limit=10)}
    assert rows["stuck1"].status == "paused"
    assert rows["stuck1"].metadata.get("transient") is True
    assert rows["stuck1"].metadata.get("delivery_state") == "waiting_for_device"
    assert rows["stuck1"].metadata.get("next_retry_ms")
    assert rows["stuck1"].metadata.get("reaped") is True
    assert rows["stuck1"].metadata.get("reaped_reason") == "no_progress_within_deadline"
    # Fresh row still 'offered'.
    assert rows["fresh1"].status == "offered"
    state.close()


def test_reaper_preserves_inbound_offer_waiting_for_acceptance(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    old = int(time.time() * 1000) - (10 * 60 * 1000)
    state.upsert_transfer(
        id="in:held", direction="in", peer_fp="aa" * 32, kind="file",
        name="ACE.zip", size=100, status="offered", progress_bytes=40,
        total_bytes=100, chunks_done=4, chunks_total=10,
        metadata={"needs_accept": True, "delivery_state": "awaiting_acceptance"},
    )
    with state._write_lock:
        state._conn.execute(
            "UPDATE transfers SET updated_ms = ? WHERE id = ?", (old, "in:held"),
        )

    assert daemon._reap_stuck_transfers() == 0
    row = state.get_transfer("in:held")
    assert row.status == "offered"
    assert row.progress_bytes == 40
    assert row.metadata["delivery_state"] == "awaiting_acceptance"
    state.close()


def test_reaper_labels_stale_inbound_as_waiting_for_sender(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    old = int(time.time() * 1000) - (10 * 60 * 1000)
    state.upsert_transfer(
        id="in:stalled", direction="in", peer_fp="bb" * 32, kind="file",
        name="ACE.zip", size=100, status="active", progress_bytes=40,
        total_bytes=100, chunks_done=4, chunks_total=10,
        metadata={"delivery_state": "receiving"},
    )
    with state._write_lock:
        state._conn.execute(
            "UPDATE transfers SET updated_ms = ? WHERE id = ?", (old, "in:stalled"),
        )

    assert daemon._reap_stuck_transfers() == 1
    row = state.get_transfer("in:stalled")
    assert row.status == "paused"
    assert row.progress_bytes == 40
    assert row.metadata["delivery_state"] == "waiting_for_sender"
    assert "next_retry_ms" not in row.metadata
    state.close()


def test_reaper_parks_cdc_partial_and_releases_capacity(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _new_identity()
    peer_fp = "bb" * 32
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    payload = b"park resumable progress"
    blob = blake3.blake3(payload).hexdigest()
    out_path = tmp_path / "data" / "inbox" / "park.partial"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(out_path, "x+b")
    handle.write(payload)
    chunks = [{
        "index": 0,
        "start": 0,
        "end": len(payload),
        "size": len(payload),
        "hash": blob,
    }]
    transfer_id = f"in:{blob}"
    incoming = IncomingFile(
        name="park.bin",
        size=len(payload),
        blob_hex=blob,
        out_path=out_path,
        handle=handle,
        hasher=blake3.blake3(payload),
        cdc_chunks=chunks,
        cdc_missing=set(),
        cdc_parts={},
        cdc_streamed={0},
        transfer_id=transfer_id,
        acceptance_granted=True,
        peer_fp=peer_fp,
        reservation_id=transfer_id,
        cache_reservation_id=transfer_id,
    )
    daemon._incoming_files[blob] = incoming
    admission = daemon._transfer_reservation_ledger().reserve(
        reservation_id=transfer_id,
        name="park.bin",
        size=len(payload),
        peer_fp=peer_fp,
        policy=daemon._transfer_admission_policy.__class__(
            min_free_reserve_bytes=0,
            free_reserve_ratio=0,
        ),
    )
    assert admission.ok
    state.upsert_transfer(
        id=transfer_id,
        direction="in",
        peer_fp=peer_fp,
        kind="file",
        name="park.bin",
        size=len(payload),
        blob_hash=blob,
        status="active",
        progress_bytes=len(payload),
        total_bytes=len(payload),
        chunks_done=1,
        chunks_total=1,
        metadata={"delivery_state": "receiving"},
    )
    old = int(time.time() * 1000) - (10 * 60 * 1000)
    with state._write_lock:
        state._conn.execute(
            "UPDATE transfers SET updated_ms = ? WHERE id = ?",
            (old, transfer_id),
        )

    incoming.finalizing = True
    assert daemon._reap_stuck_transfers() == 0
    assert daemon._incoming_files[blob] is incoming
    assert state.get_transfer(transfer_id).status == "active"

    incoming.finalizing = False
    with state._write_lock:
        state._conn.execute(
            "UPDATE transfers SET status = ?, updated_ms = ? WHERE id = ?",
            ("paused", old, transfer_id),
        )
    assert daemon._reap_stuck_transfers() == 1
    assert blob not in daemon._incoming_files
    assert incoming.handle.closed
    assert out_path.is_file()
    assert daemon._transfer_reservation_ledger().snapshot() == ()
    assert (peer_fp, blob) in set(daemon._resume_registry.keys())
    row = state.get_transfer(transfer_id)
    assert row is not None and row.status == "paused"
    state.close()


def test_resume_selects_partial_with_verified_bytes_across_manifest_change(
    tmp_path: Path, monkeypatch,
):
    """A zero-byte retry duplicate must not replace a useful old partial."""
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    daemon = Daemon(_new_identity())
    inbox = tmp_path / "data" / "inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    payload = b"abcdefgh"
    blob = blake3.blake3(payload).hexdigest()
    canonical = inbox / f"{blob[:8]}_ACE.zip"
    canonical.write_bytes(payload)
    preferred = inbox / f"{blob[:8]}_staged_ACE.zip"
    preferred.write_bytes(b"")
    chunks = [
        {
            "index": 0, "start": 0, "end": 4, "size": 4,
            "hash": blake3.blake3(payload[:4]).hexdigest(),
        },
        {
            "index": 1, "start": 4, "end": 8, "size": 4,
            "hash": blake3.blake3(payload[4:]).hexdigest(),
        },
    ]

    selected, handle, valid = daemon._open_best_resume_partial(
        blob=blob, size=len(payload), cdc_chunks=chunks,
        preferred_path=preferred, canonical_name="ACE.zip",
    )
    try:
        assert selected == canonical.resolve()
        assert valid == {0, 1}
        assert handle.read() == payload
    finally:
        handle.close()


def test_reap_stuck_transfers_marks_old_planning_queue_as_waiting(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state

    src = tmp_path / "huge-video.bin"
    src.write_bytes(b"x" * 1024)
    long_ago = int(time.time() * 1000) - (10 * 60 * 1000)
    state.upsert_transfer(
        id="planning1",
        direction="out",
        peer_fp="aa" * 32,
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
            "delivery_state": "queued",
        },
    )
    with state._write_lock:
        state._conn.execute(
            "UPDATE transfers SET updated_ms = ? WHERE id = ?",
            (long_ago, "planning1"),
        )

    reaped = daemon._reap_stuck_transfers()
    assert reaped == 1
    row = state.get_transfer("planning1")
    assert row is not None
    assert row.status == "paused"
    assert row.metadata.get("transient") is True
    assert row.metadata.get("delivery_state") == "waiting_for_device"
    assert row.metadata.get("error_class") == "PlanningInterrupted"
    assert row.metadata.get("reaped_reason") == "stale_planning_row"
    state.close()


def test_reap_stuck_transfers_ignores_complete_and_failed(tmp_path: Path):
    """Don't churn rows that are already in a terminal state."""
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state

    long_ago = int(time.time() * 1000) - (10 * 60 * 1000)
    for status in ("complete", "failed"):
        state.upsert_transfer(
            id=f"old-{status}",
            direction="in",
            peer_fp="aa" * 32,
            kind="file",
            name="x.bin",
            size=1,
            status=status,
            progress_bytes=1,
            total_bytes=1,
            chunks_done=1,
            chunks_total=1,
        )
        with state._write_lock:
            state._conn.execute(
                "UPDATE transfers SET updated_ms = ? WHERE id = ?",
                (long_ago, f"old-{status}"),
            )

    reaped = daemon._reap_stuck_transfers()
    assert reaped == 0
    rows = {r.id: r for r in state.list_transfers(limit=10)}
    assert rows["old-complete"].status == "complete"
    assert rows["old-failed"].status == "failed"
    state.close()


# ─── startup reconciliation of transfers orphaned by a restart ─────


def test_boot_reconcile_marks_prior_active_transfers_waiting(tmp_path: Path):
    """A daemon that boots with 'active'/'offered' rows left over from
    a killed run must flip them to retryable immediately — not wait out
    the 5-min no-progress reaper. This is the root-cause fix for the
    "said Sending for 2 minutes and nothing moved" report after a
    'kill all daemons / open new tab'."""
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state

    # Two orphans from the PRIOR run: one outbound, one inbound. Both
    # were last touched before this process booted.
    prior = int(time.time() * 1000) - (90 * 1000)  # 90s ago (< 5min!)
    for tid, direction, name in (
        ("out:orphan", "out", "explainer.coherence"),
        ("in:orphan", "in", "diagnostics.json"),
    ):
        state.upsert_transfer(
            id=tid,
            direction=direction,
            peer_fp="aa" * 32,
            kind="file",
            name=name,
            size=960,
            status="active",
            progress_bytes=0,
            total_bytes=960,
            chunks_done=0,
            chunks_total=1,
        )
        with state._write_lock:
            state._conn.execute(
                "UPDATE transfers SET updated_ms = ? WHERE id = ?",
                (prior, tid),
            )

    # Boot instant is AFTER those rows were last touched.
    daemon._boot_wall_ms = int(time.time() * 1000)
    reconciled = daemon._reconcile_orphaned_transfers_on_boot()
    assert reconciled == 2

    rows = {r.id: r for r in state.list_transfers(limit=10)}
    for tid in ("out:orphan", "in:orphan"):
        assert rows[tid].status == "paused"
        assert rows[tid].metadata.get("transient") is True
        assert rows[tid].metadata.get("reaped_reason") == "orphaned_by_restart"
        assert rows[tid].metadata.get("error_class") == "DaemonRestarted"
    assert rows["out:orphan"].metadata.get("next_retry_ms")
    assert rows["out:orphan"].metadata.get("delivery_state") == "waiting_for_device"
    assert "next_retry_ms" not in rows["in:orphan"].metadata
    assert rows["in:orphan"].metadata.get("delivery_state") == "waiting_for_sender"
    assert "doctor" not in rows["in:orphan"].metadata
    # Direction is preserved on the row (the receiver still reads
    # "Receiving"/"Paused", the sender still retries).
    assert rows["out:orphan"].direction == "out"
    assert rows["in:orphan"].direction == "in"
    assert rows["out:orphan"].metadata.get("orphaned_direction") == "out"
    assert rows["in:orphan"].metadata.get("orphaned_direction") == "in"
    state.close()


def test_boot_reconcile_never_touches_transfers_from_this_run(tmp_path: Path):
    """The boot instant anchors the reconciliation: a transfer this
    process started (updated_ms >= boot) must be left alone, so there's
    no race where a just-started send gets wrongly paused."""
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state

    # Boot FIRST, then start a transfer (updated_ms stamped to now,
    # which is after boot).
    daemon._boot_wall_ms = int(time.time() * 1000) - 5
    state.upsert_transfer(
        id="this-run",
        direction="out",
        peer_fp="aa" * 32,
        kind="file",
        name="live.bin",
        size=1000,
        status="active",
        progress_bytes=128,
        total_bytes=1000,
        chunks_done=1,
        chunks_total=8,
    )

    reconciled = daemon._reconcile_orphaned_transfers_on_boot()
    assert reconciled == 0
    assert state.get_transfer("this-run").status == "active"
    state.close()


def test_boot_reconcile_ignores_terminal_rows(tmp_path: Path):
    """complete/failed rows from a prior run stay terminal."""
    me = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state

    prior = int(time.time() * 1000) - (90 * 1000)
    for status in ("complete", "failed"):
        state.upsert_transfer(
            id=f"old-{status}",
            direction="in",
            peer_fp="aa" * 32,
            kind="file",
            name="x.bin",
            size=1,
            status=status,
            progress_bytes=1,
            total_bytes=1,
            chunks_done=1,
            chunks_total=1,
        )
        with state._write_lock:
            state._conn.execute(
                "UPDATE transfers SET updated_ms = ? WHERE id = ?",
                (prior, f"old-{status}"),
            )

    daemon._boot_wall_ms = int(time.time() * 1000)
    reconciled = daemon._reconcile_orphaned_transfers_on_boot()
    assert reconciled == 0
    rows = {r.id: r for r in state.list_transfers(limit=10)}
    assert rows["old-complete"].status == "complete"
    assert rows["old-failed"].status == "failed"
    state.close()


# ─── UI markup contract for paste-image ────────────────────────────

def test_paste_image_handler_is_bound(tmp_path):
    """The HTML smoke test (test_ui_markup.py) covers the structural
    contract; this is the targeted feature check — ensures the paste
    handler wiring exists."""
    p = Path(__file__).parent.parent / "src" / "one_link" / "web" / "index.html"
    text = p.read_text(encoding="utf-8")
    # The function exists.
    assert "function handlePasteImage(" in text
    # It's bound on the chat input.
    assert '$("#input").addEventListener("paste"' in text
    # AND on the document so paste-with-no-focus also lands.
    assert 'document.addEventListener("paste"' in text


def test_upload_failure_uses_server_reason_in_toast(tmp_path):
    """Pin the contract that uploadFile shows the server's error
    string, not a generic 'send failed'. Post-ac3d63f the failure
    path routes through `errorToastBody(e)` — a server-error
    translator that maps codes/messages to human language. We
    assert the helper is invoked rather than asserting on a fixed
    string, since the wording is allowed to evolve."""
    p = Path(__file__).parent.parent / "src" / "one_link" / "web" / "index.html"
    text = p.read_text(encoding="utf-8")
    # The success path removes the sticky "sending" toast.
    assert "sendingToast?.remove" in text
    # The failure path translates the server reason via errorToastBody.
    assert "errorToastBody" in text


def test_every_direct_upload_coalesces_one_stable_file_intent(tmp_path):
    p = Path(__file__).parent.parent / "src" / "one_link" / "web" / "index.html"
    text = p.read_text(encoding="utf-8")
    idx = text.find("function _uploadIntentEntry(")
    assert idx > 0
    upload_idx = text.find("async upload(peer, file, opts = {})", idx)
    upload_end = text.find("\n    folders()", upload_idx)
    assert idx < upload_idx < upload_end
    helper = text[idx:upload_idx]
    snippet = text[upload_idx:upload_end]
    assert "const _implicitUploadIntents = new WeakMap()" in text
    assert "clientDeliveryId: opts.clientDeliveryId || _newClientMsgId()" in helper
    assert "if (intent.inFlight) return await intent.inFlight" in snippet
    assert 'fd.append("client_delivery_id", intent.clientDeliveryId)' in snippet
    assert "intent.inFlight = operation" in snippet
    key_pos = snippet.find('fd.append("client_delivery_id"')
    size_pos = snippet.find('fd.append("file_size"')
    complete_pos = snippet.find('fd.append("intent_metadata_complete"')
    file_pos = snippet.find('fd.append("file", file, file.name)')
    assert 0 < key_pos < size_pos < complete_pos < file_pos


# ─── deadline constants exposed for tests ──────────────────────────

def test_handshake_outbound_deadline_constant_exists():
    assert HANDSHAKE_DEADLINE_OUTBOUND_S > 0
    assert HANDSHAKE_DEADLINE_OUTBOUND_S < 60  # not absurdly long


def test_file_ack_deadline_constant_exists():
    assert FILE_ACK_DEADLINE_S > 0
    assert FILE_ACK_DEADLINE_S < 600  # not absurdly long
