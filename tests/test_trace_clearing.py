from __future__ import annotations

import json
from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.identity import Identity, fingerprint_of
from one_link.paths import inbox_dir
from one_link.server import UIServer
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key()
    pub_bytes = pub.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk,
        public=pub,
        public_bytes=pub_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname="trace-test",
    )


class _Daemon:
    def __init__(self, state: State) -> None:
        self.state = state
        self.me = _identity()
        self.discovery = None
        self._outbound_sessions: dict[str, object] = {}
        self._inbound_regime: dict[str, object] = {}
        self.folder_engine = None


@pytest_asyncio.fixture
async def http(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    peer_fp = "aa" * 32
    state.upsert_peer(
        fingerprint=peer_fp,
        short_id=peer_fp[:8],
        pubkey=b"\x01" * 32,
        hostname="alice",
    )
    server = UIServer(_Daemon(state))  # type: ignore[arg-type]
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client, state, server.token, peer_fp, tmp_path
    finally:
        await client.close()
        state.close()


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _seed_file_trace_state(state: State, peer_fp: str) -> None:
    state.record_message(
        id="file-msg",
        ts_ms=1,
        direction="in",
        peer_fp=peer_fp,
        msg_type="file",
        body="report.pdf",
    )
    state.upsert_transfer(
        id="t-file",
        direction="in",
        peer_fp=peer_fp,
        kind="file",
        name="report.pdf",
        size=123,
        status="complete",
        progress_bytes=123,
    )


@pytest.mark.asyncio
async def test_clear_file_traces_hides_inbox_without_deleting_file(http) -> None:
    client, state, token, peer_fp, _ = http
    _seed_file_trace_state(state, peer_fp)
    inbox = inbox_dir()
    path = inbox / "report.pdf"
    path.write_bytes(b"still here")

    before = await (await client.get("/api/files", headers=_h(token))).json()
    assert [f["name"] for f in before["files"]] == ["report.pdf"]

    resp = await client.delete("/api/traces/files", headers=_h(token))
    assert resp.status == 200
    body = await resp.json()
    assert body["counts"]["transfers"] == 1
    assert body["counts"]["file_messages"] == 1
    assert body["counts"]["inbox_files_hidden"] == 1
    assert path.exists()
    assert state.list_transfers() == []
    assert state.recent_messages(peer_fp=peer_fp) == []

    after = await (await client.get("/api/files", headers=_h(token))).json()
    assert after["files"] == []


@pytest.mark.asyncio
async def test_clear_folder_traces_preserves_real_folder(http) -> None:
    client, state, token, _, tmp_path = http
    real_folder = tmp_path / "real-folder"
    real_folder.mkdir()
    (real_folder / "keep.txt").write_text("do not delete", encoding="utf-8")
    state.add_folder(name="Docs", local_path=str(real_folder), shared_with=[])

    resp = await client.delete("/api/traces/folders", headers=_h(token))
    assert resp.status == 200
    body = await resp.json()
    assert body["counts"]["folders"] == 1
    assert state.list_folders() == []
    assert (real_folder / "keep.txt").read_text(encoding="utf-8") == "do not delete"


@pytest.mark.asyncio
async def test_clear_activity_traces_hides_existing_peer_activity(http) -> None:
    client, _, token, _, _ = http
    before = await (await client.get("/api/activity", headers=_h(token))).json()
    assert any(e["kind"] == "peer" for e in before["events"])

    resp = await client.delete("/api/traces/activity", headers=_h(token))
    assert resp.status == 200
    after = await (await client.get("/api/activity", headers=_h(token))).json()
    assert after["events"] == []


@pytest.mark.asyncio
async def test_wipe_local_traces_requires_phrase_and_preserves_files(http) -> None:
    client, state, token, peer_fp, tmp_path = http
    _seed_file_trace_state(state, peer_fp)
    folder = tmp_path / "watched"
    folder.mkdir()
    (folder / "keep.txt").write_text("safe", encoding="utf-8")
    state.add_folder(name="Watched", local_path=str(folder), shared_with=[])
    inbox_file = inbox_dir() / "inbox.bin"
    inbox_file.write_bytes(b"safe")

    bad = await client.post(
        "/api/traces/wipe",
        headers=_h(token),
        json={"confirm": "wipe everything"},
    )
    assert bad.status == 400

    ok = await client.post(
        "/api/traces/wipe",
        headers=_h(token),
        json={"confirm": "wipe local traces"},
    )
    assert ok.status == 200
    body = json.loads(await ok.text())
    assert body["ok"] is True
    assert state.recent_messages(peer_fp=peer_fp) == []
    assert state.list_transfers() == []
    assert state.list_folders() == []
    assert inbox_file.exists()
    assert (folder / "keep.txt").exists()
