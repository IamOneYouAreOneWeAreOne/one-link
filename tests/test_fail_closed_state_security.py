from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import master_seed
from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


def _identity() -> Identity:
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    public_bytes = public.public_bytes_raw()
    fingerprint = fingerprint_of(public_bytes)
    return Identity(
        private=private,
        public=public,
        public_bytes=public_bytes,
        fingerprint=fingerprint,
        short_id=fingerprint[:8],
        hostname="fail-closed-test",
    )


class _DaemonForServer:
    def __init__(self, state: State) -> None:
        self.state = state
        self.me = _identity()
        self.discovery = None
        self._outbound_sessions: dict[str, object] = {}
        self._inbound_regime: dict[str, object] = {}
        self.folder_engine = None


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _seed_trace_rows(state: State, *, peer_fp: str, folder_path: Path) -> None:
    state.upsert_peer(
        fingerprint=peer_fp,
        short_id=peer_fp[:8],
        pubkey=b"\x01" * 32,
        hostname="alice",
    )
    state.record_message(
        id="must-survive-failed-wipe",
        ts_ms=1,
        direction="in",
        peer_fp=peer_fp,
        msg_type="file",
        body="evidence.bin",
    )
    state.upsert_transfer(
        id="must-survive-failed-wipe",
        direction="in",
        peer_fp=peer_fp,
        kind="file",
        name="evidence.bin",
        size=8,
        status="complete",
        progress_bytes=8,
    )
    state.add_folder(name="Evidence", local_path=str(folder_path), shared_with=[])
    state.set_setting("chatpref:peer:alice:color", "violet")


def _install_late_wipe_failure(state: State) -> None:
    # This is deliberately the final DELETE in clear_all_app_traces().  Every
    # preceding table has already been mutated when SQLite raises, making it a
    # regression test for real partial-commit behavior rather than an early
    # validation failure.
    state._conn.execute(
        """
        CREATE TRIGGER inject_late_trace_wipe_failure
        BEFORE DELETE ON settings
        WHEN OLD.key LIKE 'chatpref:%'
        BEGIN
            SELECT RAISE(ABORT, 'injected late trace wipe failure');
        END
        """
    )


def test_seed_verifier_failure_propagates_and_capability_gate_denies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon = Daemon.__new__(Daemon)
    daemon._seed_file_fingerprint_at_boot = (123, 32)
    denial_recorder = MagicMock()
    monkeypatch.setattr(daemon, "_record_capability_denial", denial_recorder)

    def _verification_failure(_data_dir: Path):
        raise PermissionError("injected seed fingerprint read failure")

    monkeypatch.setattr(master_seed, "seed_file_fingerprint", _verification_failure)

    with pytest.raises(
        PermissionError,
        match="injected seed fingerprint read failure",
    ):
        daemon.detect_seed_file_tamper()

    assert daemon._capability_allowed("aa" * 32, "files:read") is False
    denial_recorder.assert_called_once_with(
        reason="seed_tamper_check_failed",
        capability="files:read",
    )


def test_late_trace_wipe_failure_rolls_back_every_prior_delete(
    tmp_path: Path,
) -> None:
    state = State(db_path=tmp_path / "state.db")
    peer_fp = "aa" * 32
    folder_path = tmp_path / "evidence"
    folder_path.mkdir()
    try:
        _seed_trace_rows(state, peer_fp=peer_fp, folder_path=folder_path)
        _install_late_wipe_failure(state)

        with pytest.raises(sqlite3.IntegrityError, match="injected late"):
            state.clear_all_app_traces()

        assert [m.id for m in state.recent_messages(peer_fp=peer_fp)] == [
            "must-survive-failed-wipe"
        ]
        assert [t.id for t in state.list_transfers()] == [
            "must-survive-failed-wipe"
        ]
        assert [folder["name"] for folder in state.list_folders()] == ["Evidence"]
        assert state.get_setting("chatpref:peer:alice:color") == "violet"
        assert state.get_setting("activity_cleared_before_ms") is None
        assert state._conn.in_transaction is False
    finally:
        state.close()


@pytest_asyncio.fixture
async def failed_wipe_http(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    peer_fp = "bb" * 32
    folder_path = tmp_path / "evidence"
    folder_path.mkdir()
    _seed_trace_rows(state, peer_fp=peer_fp, folder_path=folder_path)
    _install_late_wipe_failure(state)
    server = UIServer(_DaemonForServer(state))  # type: ignore[arg-type]
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client, state, server.token, peer_fp
    finally:
        await client.close()
        state.close()


@pytest.mark.asyncio
async def test_wipe_handler_returns_500_and_preserves_rows_on_sqlite_failure(
    failed_wipe_http,
) -> None:
    client, state, token, peer_fp = failed_wipe_http

    response = await client.post(
        "/api/traces/wipe",
        headers=_auth(token),
        json={"confirm": "wipe local traces"},
    )

    assert response.status == 500
    body = await response.json()
    assert body.get("ok") is not True
    assert body["error"] == "internal server error"
    assert [m.id for m in state.recent_messages(peer_fp=peer_fp)] == [
        "must-survive-failed-wipe"
    ]
    assert [t.id for t in state.list_transfers()] == [
        "must-survive-failed-wipe"
    ]
    assert [folder["name"] for folder in state.list_folders()] == ["Evidence"]
    assert state.get_setting("chatpref:peer:alice:color") == "violet"
    assert state.get_setting("activity_cleared_before_ms") is None
    assert state._conn.in_transaction is False
