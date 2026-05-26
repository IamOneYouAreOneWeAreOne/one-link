"""v0.21.x test-only /api/peers/{fp}/_test_force_dial endpoint.

Pins the surface that lets integration tests skip the slow mDNS
rediscovery window after a daemon restart. The endpoint MUST:

  1. Return 404 when ONE_LINK_ENABLE_TEST_API is unset (default).
     A production daemon must NOT expose this surface, even with a
     valid bearer token — it bypasses the discovery pipeline.

  2. Return 200 with {ok: true} when the env gate is on and the
     peer fingerprint is known to the daemon's state.

  3. Return 401 without an Authorization header (defense in depth —
     even when the env gate is on, no anonymous force-dial).

  4. Return 404 when the peer fingerprint is unknown.

The endpoint itself calls _dial_peer which is fully tested elsewhere;
this file just guards the routing + gating logic.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.blobstore import BlobStore
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
        hostname="force-dial-host",
    )


def _h(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


@pytest_asyncio.fixture
async def daemon_ctx(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    blob_store = BlobStore(root=tmp_path / "blobs")
    daemon = Daemon(me)
    daemon.state = state
    daemon.blob_store = blob_store
    daemon.folder_engine = MagicMock()
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    # Pin a fake peer in state. _peer_from_fp resolves via discovery
    # not state, so we ALSO put a matching peer in a fake discovery
    # registry so the endpoint can find it.
    peer_fp = "aa" * 32
    state.upsert_peer(
        fingerprint=peer_fp, short_id=peer_fp[:8],
        pubkey=bytes.fromhex(peer_fp), hostname="paired-peer",
    )
    state.set_peer_trust(peer_fp, "pinned")
    # Stub _peer_from_fp directly to return a fake Peer for our fp.
    fake_peer = MagicMock()
    fake_peer.ed_pub_hex = peer_fp
    fake_peer.short_id = peer_fp[:8]

    def _peer_from_fp(fp: str):
        return fake_peer if fp == peer_fp else None
    daemon._peer_from_fp = _peer_from_fp
    daemon.discovery = None
    # Stub _dial_peer so we don't actually open a socket — the test
    # is about the endpoint surface, not the dial itself.
    daemon._dial_peer = AsyncMock(return_value=(None, None))
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield {
            "client": client, "daemon": daemon, "state": state,
            "token": server.token, "peer_fp": peer_fp,
        }
    finally:
        await client.close()
        state.close()


# ── env gate ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_force_dial_returns_404_without_env_gate(
    daemon_ctx, monkeypatch,
):
    """Default (env unset) — endpoint must be invisible (404)."""
    monkeypatch.delenv("ONE_LINK_ENABLE_TEST_API", raising=False)
    r = await daemon_ctx["client"].post(
        f"/api/peers/{daemon_ctx['peer_fp']}/_test_force_dial",
        headers=_h(daemon_ctx["token"]),
    )
    assert r.status == 404, await r.text()


@pytest.mark.asyncio
async def test_force_dial_returns_404_when_env_explicit_off(
    daemon_ctx, monkeypatch,
):
    """Env set to anything other than '1' — still invisible."""
    monkeypatch.setenv("ONE_LINK_ENABLE_TEST_API", "0")
    r = await daemon_ctx["client"].post(
        f"/api/peers/{daemon_ctx['peer_fp']}/_test_force_dial",
        headers=_h(daemon_ctx["token"]),
    )
    assert r.status == 404


# ── auth (defense in depth) ──────────────────────────────────────


@pytest.mark.asyncio
async def test_force_dial_requires_auth_when_enabled(
    daemon_ctx, monkeypatch,
):
    """Even with the env gate on, missing token MUST return 401.
    A production-disabled test surface must not become an auth bypass
    when somebody flips the env flag for diagnostics."""
    monkeypatch.setenv("ONE_LINK_ENABLE_TEST_API", "1")
    r = await daemon_ctx["client"].post(
        f"/api/peers/{daemon_ctx['peer_fp']}/_test_force_dial",
    )
    assert r.status == 401


# ── happy path ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_force_dial_returns_ok_for_known_peer(
    daemon_ctx, monkeypatch,
):
    """Env on + token + known peer → 200 {ok: true, fingerprint: fp}.
    _dial_peer was called exactly once."""
    monkeypatch.setenv("ONE_LINK_ENABLE_TEST_API", "1")
    r = await daemon_ctx["client"].post(
        f"/api/peers/{daemon_ctx['peer_fp']}/_test_force_dial",
        headers=_h(daemon_ctx["token"]),
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body == {"ok": True, "fingerprint": daemon_ctx["peer_fp"]}
    daemon_ctx["daemon"]._dial_peer.assert_awaited_once()


@pytest.mark.asyncio
async def test_force_dial_returns_404_for_unknown_peer(
    daemon_ctx, monkeypatch,
):
    """Unknown fingerprint → 404 with a structured error body, not a
    silent dial-attempt against nothing."""
    monkeypatch.setenv("ONE_LINK_ENABLE_TEST_API", "1")
    unknown_fp = "ff" * 32
    r = await daemon_ctx["client"].post(
        f"/api/peers/{unknown_fp}/_test_force_dial",
        headers=_h(daemon_ctx["token"]),
    )
    assert r.status == 404
    body = await r.json()
    assert body.get("error") == "unknown peer"
    assert body.get("fingerprint") == unknown_fp
    daemon_ctx["daemon"]._dial_peer.assert_not_awaited()
