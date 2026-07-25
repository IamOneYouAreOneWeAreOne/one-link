"""End-to-end HTTP bridge coverage for browser-created async capsules."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

from aiohttp.test_utils import TestClient, TestServer
import blake3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
import pytest_asyncio

from one_link.call_manager import ManagerEvent, ManagerEventKind
from one_link.call_signaling import CallPhase
from one_link.daemon import Daemon
from one_link.identity import Identity
from one_link.server import UIServer


def _identity(name: str) -> Identity:
    seed = blake3.blake3(name.encode("utf-8")).digest()[:32]
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key()
    public_bytes = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fingerprint = blake3.blake3(public_bytes).hexdigest()
    return Identity(
        private=private,
        public=public,
        public_bytes=public_bytes,
        fingerprint=fingerprint,
        short_id=fingerprint[:8],
        hostname=name,
    )


@pytest_asyncio.fixture
async def capsule_http(tmp_path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity("capsule-browser-owner")
    peer = _identity("capsule-browser-peer")
    daemon = Daemon(me=me)
    monkeypatch.setattr(
        UIServer,
        "_load_or_create_token",
        MagicMock(return_value="capsule-test-token-abcdefghijklmnopqrstuvwxyz"),
    )
    server = UIServer(daemon)
    daemon._flush_manager_output = AsyncMock()  # type: ignore[method-assign]
    now_ms = int(time.time() * 1000)
    manager = daemon._call_registry.open(
        call_id="call-capsule-browser-1",
        peer_master_vk_hex=peer.fingerprint,
        local_role="originator",
        local_master_vk_hex=me.fingerprint,
        started_at_ms=now_ms,
    )
    manager.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, now_ms))
    manager.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, now_ms + 1))
    manager.handle(ManagerEvent(ManagerEventKind.IMMUNE_CONVERT_TO_ASYNC, now_ms + 2))
    client = TestClient(TestServer(server.app))
    await client.start_server()
    try:
        yield {
            "client": client,
            "daemon": daemon,
            "manager": manager,
            "me": me,
            "token": server.token,
            "call_id": manager.call_id,
        }
    finally:
        await client.close()


def _auth(ctx) -> dict[str, str]:
    return {"Authorization": f"Bearer {ctx['token']}"}


def _chunk_headers(ctx, sequence: str, content_type: str = "audio/webm") -> dict[str, str]:
    return {
        **_auth(ctx),
        "Content-Type": content_type,
        "X-One-Link-Capsule-Sequence": sequence,
    }


@pytest.mark.asyncio
async def test_capsule_binary_route_requires_owner_auth(capsule_http) -> None:
    ctx = capsule_http
    response = await ctx["client"].post(
        f"/api/v1/calls/{ctx['call_id']}/capsule/chunk",
        data=b"opaque-opus-fragment",
        headers={
            "Content-Type": "audio/webm",
            "X-One-Link-Capsule-Sequence": "0",
        },
    )
    assert response.status == 401
    assert ctx["manager"].state.capsule_builder.total_bytes() == 0


@pytest.mark.asyncio
async def test_capsule_chunks_are_ordered_idempotent_signed_and_finalized(
    capsule_http,
) -> None:
    ctx = capsule_http
    path = f"/api/v1/calls/{ctx['call_id']}/capsule/chunk"
    first = b"webm-opus-fragment-0"
    second = b"webm-opus-fragment-1"

    response = await ctx["client"].post(
        path,
        data=first,
        headers=_chunk_headers(ctx, "0"),
    )
    assert response.status == 200
    body = await response.json()
    assert body["duplicate"] is False
    assert body["next_sequence"] == 1
    assert body["total_bytes"] == len(first)
    assert response.headers["Cache-Control"] == "no-store"

    duplicate = await ctx["client"].post(
        path,
        data=first,
        headers=_chunk_headers(ctx, "0"),
    )
    assert duplicate.status == 200
    assert (await duplicate.json())["duplicate"] is True
    assert ctx["manager"].state.capsule_builder.total_bytes() == len(first)

    conflict = await ctx["client"].post(
        path,
        data=b"same-sequence-different-content",
        headers=_chunk_headers(ctx, "0"),
    )
    assert conflict.status == 409
    assert (await conflict.json())["expected_sequence"] == 1

    gap = await ctx["client"].post(
        path,
        data=second,
        headers=_chunk_headers(ctx, "2"),
    )
    assert gap.status == 409
    assert (await gap.json())["expected_sequence"] == 1

    response = await ctx["client"].post(
        path,
        data=second,
        headers=_chunk_headers(ctx, "1"),
    )
    assert response.status == 200

    finish_path = f"/api/v1/calls/{ctx['call_id']}/capsule/finalize"
    finish_body = {
        "expected_chunks": 2,
        "expected_bytes": len(first) + len(second),
    }
    finalized = await ctx["client"].post(
        finish_path,
        json=finish_body,
        headers=_auth(ctx),
    )
    assert finalized.status == 200
    finalized_body = await finalized.json()
    assert finalized_body["ok"] is True
    assert finalized_body["duplicate"] is False
    assert finalized_body["size_bytes"] == len(first) + len(second)
    assert ctx["manager"].phase == CallPhase.RESUMABLE
    capsule = ctx["manager"].state.finalized_capsule
    assert capsule is not None
    assert capsule.audio_payload == first + second
    assert capsule.audio_codec == "webm-opus"
    assert len(capsule.provenance_chain) == 2
    assert capsule.all_frames_verified_by(ctx["me"].public_bytes)
    ctx["daemon"]._flush_manager_output.assert_awaited_once()

    retried = await ctx["client"].post(
        finish_path,
        json=finish_body,
        headers=_auth(ctx),
    )
    assert retried.status == 200
    assert (await retried.json())["duplicate"] is True
    ctx["daemon"]._flush_manager_output.assert_awaited_once()


@pytest.mark.asyncio
async def test_capsule_chunked_body_and_completion_contract_are_bounded(
    capsule_http,
    monkeypatch,
) -> None:
    from one_link import server as server_module

    ctx = capsule_http
    monkeypatch.setattr(server_module, "CAPSULE_CAPTURE_CHUNK_MAX_BYTES", 8)
    path = f"/api/v1/calls/{ctx['call_id']}/capsule/chunk"

    async def oversized_chunks():
        yield b"12345"
        yield b"67890"

    oversized = await ctx["client"].post(
        path,
        data=oversized_chunks(),
        headers=_chunk_headers(ctx, "0"),
    )
    assert oversized.status == 413
    assert ctx["manager"].state.capsule_builder.total_bytes() == 0

    accepted = await ctx["client"].post(
        path,
        data=b"12345678",
        headers=_chunk_headers(ctx, "0"),
    )
    assert accepted.status == 200

    changed_codec = await ctx["client"].post(
        path,
        data=b"a",
        headers=_chunk_headers(ctx, "1", "audio/ogg"),
    )
    assert changed_codec.status == 409

    noncanonical_sequence = await ctx["client"].post(
        path,
        data=b"a",
        headers=_chunk_headers(ctx, "01"),
    )
    assert noncanonical_sequence.status == 400

    mismatched_finish = await ctx["client"].post(
        f"/api/v1/calls/{ctx['call_id']}/capsule/finalize",
        json={"expected_chunks": 2, "expected_bytes": 8},
        headers=_auth(ctx),
    )
    assert mismatched_finish.status == 409
    mismatch = await mismatched_finish.json()
    assert mismatch["expected_sequence"] == 1
    assert ctx["manager"].phase == CallPhase.ASYNC_CAPTURE


def test_browser_capsule_bridge_uses_raw_ordered_retryable_uploads() -> None:
    from one_link.server import WEB_DIR

    html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
    assert "function beginCapsuleCapture" in html
    assert "async function finishCapsuleCapture" in html
    assert "X-One-Link-Capsule-Sequence" in html
    assert "/capsule/chunk" in html
    assert "/capsule/finalize" in html
    assert "CAPSULE_CAPTURE_MAX_BYTES" in html
    assert "enqueueCapsuleBlob(ev.data)" in html
    assert 'action: "convert_to_async"' in html
    assert "JSON.stringify(blob)" not in html
