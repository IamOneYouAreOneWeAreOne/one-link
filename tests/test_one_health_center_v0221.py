"""One Health Center.

This pins the product layer that turns One Link's many subsystems into a
plain-language readiness center: health score, lost-device safety, people,
calls, recovery, and trust timeline.
"""

from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


ROOT = Path(__file__).resolve().parents[1]


def _server_src() -> str:
    return (ROOT / "src" / "one_link" / "server.py").read_text(encoding="utf-8")


def _index_html() -> str:
    return (ROOT / "src" / "one_link" / "web" / "index.html").read_text(encoding="utf-8")


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk,
        public=pub_obj,
        public_bytes=pub_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname="health-host",
    )


@pytest_asyncio.fixture
async def http(tmp_path: Path):
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client, state, server.token
    finally:
        await client.close()
        state.close()


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_one_health_api_route_and_snapshot_contract() -> None:
    src = _server_src()
    assert 'r.add_get("/api/one-health", self._guarded(self.api_one_health))' in src
    idx = src.find("async def api_one_health(")
    assert idx > 0
    snippet = src[idx:idx + 14000]
    for marker in (
        '"score": overall',
        '"scores": score_rows',
        '"lost_device": {',
        '"calls": {',
        '"timeline": timeline',
        '"people": people_rows',
        '"setup": {',
        '"finish_setup"',
        '"add_device"',
        '"set_recovery"',
        '"review_lost_device"',
        '"view_privacy_proof"',
    ):
        assert marker in snippet


def test_one_health_ui_surface_exists_and_is_actionable() -> None:
    html = _index_html()
    for marker in (
        'id="one-health"',
        'id="one-health-score"',
        'id="one-health-grid"',
        'id="one-health-actions"',
        'id="one-health-people"',
        'id="one-health-timeline"',
        "People, calls, lost-device safety, and trust timeline",
        "oneHealth() { return this.get(\"/api/one-health\"); }",
        "function renderOneHealth()",
        "async function refreshOneHealth()",
        "function runOneHealthAction(id)",
        "data-one-health-action",
    ):
        assert marker in html


def test_one_health_refreshes_on_startup_poll_and_mesh_events() -> None:
    html = _index_html()
    init_idx = html.find("async function init()")
    init = html[init_idx:init_idx + 5000]
    assert "await refreshOneHealth()" in init
    assert "setInterval(refreshOneHealth, 15000)" in init
    ws_idx = html.find('m.type === "self_mesh_changed"')
    ws = html[ws_idx:ws_idx + 300]
    assert "refreshOneHealth()" in ws


@pytest.mark.asyncio
async def test_one_health_endpoint_returns_plain_language_status(http) -> None:
    client, state, token = http
    state.set_setting("one_setup_privacy_proof_viewed_at_ms", "1")
    resp = await client.get("/api/one-health", headers=_h(token))
    assert resp.status == 200
    body = await resp.json()
    assert body["ok"] is True
    assert isinstance(body["score"], int)
    assert body["headline"]
    assert {row["id"] for row in body["scores"]} == {
        "protection", "speed", "recovery", "devices", "people",
    }
    assert "lost_device" in body
    assert "calls" in body
    assert isinstance(body["actions"], list)
