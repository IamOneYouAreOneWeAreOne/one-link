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

The endpoint establishes a complete authenticated session and probes it;
this file guards that lifecycle plus the routing and gating logic.
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
    # Pin a real identity and durable endpoint.  Discovery is deliberately
    # absent: post-restart reconnect must use the authenticated state fallback
    # while mDNS is still converging.
    peer_identity = _identity()
    peer_fp = peer_identity.fingerprint
    state.upsert_peer(
        fingerprint=peer_fp, short_id=peer_fp[:8],
        pubkey=peer_identity.public_bytes, hostname="paired-peer",
        address="127.0.0.1", port=45678,
    )
    state.set_peer_trust(peer_fp, "pinned")
    daemon.discovery = None
    # Stub session establishment so we don't actually open a socket. The
    # endpoint must still require a completed authenticated probe rather than
    # treating a bare TCP connect as success.
    session = MagicMock()
    daemon._get_outbound_session = AsyncMock(return_value=session)
    daemon._probe_outbound_session = AsyncMock(return_value=True)
    daemon._drop_outbound_session = AsyncMock()
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
    Session establishment and its authenticated probe each run once."""
    monkeypatch.setenv("ONE_LINK_ENABLE_TEST_API", "1")
    r = await daemon_ctx["client"].post(
        f"/api/peers/{daemon_ctx['peer_fp']}/_test_force_dial",
        headers=_h(daemon_ctx["token"]),
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body == {"ok": True, "fingerprint": daemon_ctx["peer_fp"]}
    daemon_ctx["daemon"]._get_outbound_session.assert_awaited_once()
    resolved = daemon_ctx["daemon"]._get_outbound_session.await_args.args[0]
    assert resolved.address == "127.0.0.1"
    assert resolved.port == 45678
    assert fingerprint_of(bytes.fromhex(resolved.ed_pub_hex)) == daemon_ctx["peer_fp"]
    daemon_ctx["daemon"]._probe_outbound_session.assert_awaited_once_with(
        daemon_ctx["daemon"]._get_outbound_session.return_value,
    )


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
    daemon_ctx["daemon"]._get_outbound_session.assert_not_awaited()


@pytest.mark.asyncio
async def test_force_dial_fails_when_authenticated_probe_fails(
    daemon_ctx, monkeypatch,
):
    monkeypatch.setenv("ONE_LINK_ENABLE_TEST_API", "1")
    daemon_ctx["daemon"]._probe_outbound_session.return_value = False
    r = await daemon_ctx["client"].post(
        f"/api/peers/{daemon_ctx['peer_fp']}/_test_force_dial",
        headers=_h(daemon_ctx["token"]),
    )
    assert r.status == 502
    assert await r.json() == {
        "ok": False,
        "error": "authenticated probe failed",
    }
    daemon_ctx["daemon"]._drop_outbound_session.assert_awaited_once_with(
        daemon_ctx["peer_fp"],
    )


def test_durable_endpoint_fallback_rejects_unpinned_peer(
    daemon_ctx,
):
    state = daemon_ctx["state"]
    fp = daemon_ctx["peer_fp"]
    state.set_peer_trust(fp, "pending")
    assert daemon_ctx["daemon"]._peer_from_fp(fp) is None


def test_durable_endpoint_fallback_rejects_fingerprint_key_mismatch(
    daemon_ctx,
):
    state = daemon_ctx["state"]
    fp = daemon_ctx["peer_fp"]
    other = _identity()
    state.upsert_peer(
        fingerprint=fp,
        short_id=fp[:8],
        pubkey=other.public_bytes,
        hostname="tampered",
        address="127.0.0.1",
        port=45678,
    )
    assert daemon_ctx["daemon"]._peer_from_fp(fp) is None
