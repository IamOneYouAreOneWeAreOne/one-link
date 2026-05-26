"""v0.21.x Ship 4 behavioral tests — selective sync (ignored_patterns
+ max_file_bytes + conflict_policy) live round-trip via the
settings endpoint, plus the daemon-side filter that enforces them.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    return Identity(
        private=sk, public=sk.public_key(), public_bytes=pub,
        fingerprint=fingerprint_of(pub), short_id=fingerprint_of(pub)[:8],
        hostname="ship4-host",
    )


@pytest_asyncio.fixture
async def http_ctx(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    monkeypatch.setenv("ONE_LINK_DISABLE_NATIVE_PICKER", "1")
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    # api_set_folder_policy gates on folder_engine being non-None
    # (sentinel guard, not actual use). A MagicMock satisfies that
    # without spinning up a real engine.
    from unittest.mock import MagicMock
    daemon.folder_engine = MagicMock()
    state.add_folder(
        name="my-folder", local_path=str(tmp_path / "my-folder"),
        shared_with=[], max_file_bytes=None, ignored_patterns=[],
        conflict_policy="latest-wins",
    )
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client, state, server.token
    finally:
        await client.close()
        state.close()


def _h(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


@pytest.mark.asyncio
async def test_list_folders_surfaces_policy_defaults(http_ctx):
    """A freshly added folder's GET response must include all three
    policy fields so the Settings modal can pre-fill correctly."""
    client, state, token = http_ctx
    r = await client.get("/api/folders", headers=_h(token))
    assert r.status == 200
    body = await r.json()
    folder = body["folders"][0]
    assert folder["ignored_patterns"] == []
    assert folder["max_file_bytes"] is None
    assert folder["conflict_policy"] == "latest-wins"


@pytest.mark.asyncio
async def test_set_policy_persists_ignored_patterns(http_ctx):
    """POST policy → GET folder echoes the new ignored_patterns."""
    client, state, token = http_ctx
    patterns = ["node_modules/", "*.log", ".DS_Store"]
    r = await client.post(
        "/api/folders/my-folder/policy",
        headers=_h(token),
        json={"ignored_patterns": patterns},
    )
    assert r.status == 200
    r = await client.get("/api/folders", headers=_h(token))
    folder = (await r.json())["folders"][0]
    assert folder["ignored_patterns"] == patterns


@pytest.mark.asyncio
async def test_set_policy_persists_max_file_bytes(http_ctx):
    client, state, token = http_ctx
    r = await client.post(
        "/api/folders/my-folder/policy",
        headers=_h(token),
        json={"max_file_bytes": 5 * 1024 * 1024},
    )
    assert r.status == 200
    folder = (await (await client.get(
        "/api/folders", headers=_h(token),
    )).json())["folders"][0]
    assert folder["max_file_bytes"] == 5 * 1024 * 1024


@pytest.mark.asyncio
async def test_set_policy_validates_conflict_policy(http_ctx):
    """Invalid conflict_policy must be rejected with 400, not
    silently coerced to a random value."""
    client, state, token = http_ctx
    r = await client.post(
        "/api/folders/my-folder/policy",
        headers=_h(token),
        json={"conflict_policy": "make-stuff-up"},
    )
    assert r.status == 400


@pytest.mark.asyncio
async def test_set_policy_validates_ignored_pattern_type(http_ctx):
    """ignored_patterns must be a list — not a string. Reject."""
    client, state, token = http_ctx
    r = await client.post(
        "/api/folders/my-folder/policy",
        headers=_h(token),
        json={"ignored_patterns": "node_modules/"},
    )
    assert r.status == 400


# ── filter logic enforcement ────────────────────────────────────────


def test_path_matches_ignored_handles_dir_patterns():
    """node_modules/ pattern matches files INSIDE node_modules at
    any depth, not just literal 'node_modules' files."""
    matches = State.folder_path_matches_ignored
    assert matches("node_modules/react/index.js", ["node_modules/*"]) is True
    assert matches("src/main.py", ["node_modules/*"]) is False


def test_path_matches_ignored_handles_glob_extensions():
    matches = State.folder_path_matches_ignored
    assert matches("daemon.log", ["*.log"]) is True
    assert matches("src/debug.log", ["*.log"]) is True
    assert matches("config.yaml", ["*.log"]) is False


def test_path_matches_ignored_empty_patterns_never_match():
    matches = State.folder_path_matches_ignored
    assert matches("anything", []) is False
    assert matches("", []) is False


def test_path_matches_ignored_handles_os_junk():
    matches = State.folder_path_matches_ignored
    patterns = [".DS_Store", "Thumbs.db", "desktop.ini"]
    assert matches(".DS_Store", patterns) is True
    assert matches("subdir/.DS_Store", patterns) is True
    assert matches("Thumbs.db", patterns) is True
    assert matches("normal.txt", patterns) is False
