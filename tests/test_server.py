"""HTTP + WebSocket UI server tests.

Spins up a real daemon (which auto-starts the UI server alongside) and
hits the API surface with `aiohttp` (already a project dep). Verifies
auth, peer list, send, file upload, file list, file download, and the
WS event stream.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import socket
import time
from pathlib import Path

import aiohttp
import pytest

from tests.harness import daemon_pair


pytestmark = pytest.mark.timeout(120)


def _read(home: Path, name: str) -> str:
    return (home / "data" / name).read_text(encoding="utf-8").strip()


def _server_addr(home: Path) -> tuple[str, str]:
    port = _read(home, "server.port")
    token = _read(home, "ui.token")
    return f"http://127.0.0.1:{port}", token


# ─── helpers ──────────────────────────────────────────────────────────

async def _get(session, url, *, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with session.get(url, headers=headers) as r:
        return r.status, await r.text()


async def _get_json(session, url, *, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with session.get(url, headers=headers) as r:
        return r.status, await r.json()


async def _post_json(session, url, payload, *, token=None):
    headers = {"Authorization": f"Bearer {token}"}
    async with session.post(url, json=payload, headers=headers) as r:
        return r.status, await r.json()


# ─── tests ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_server_unauth_returns_401():
    with daemon_pair() as p:
        base, _token = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, _ = await _get(s, f"{base}/api/me")
            assert status == 401


@pytest.mark.asyncio
async def test_server_index_serves_html_and_sets_cookie():
    with daemon_pair() as p:
        base, _ = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{base}/") as r:
                assert r.status == 200
                txt = await r.text()
                assert "<!doctype html>" in txt.lower() or "<html" in txt.lower()
                assert any(c.key == "ol_ui" for c in r.cookies.values())


@pytest.mark.asyncio
async def test_api_me_returns_identity():
    with daemon_pair() as p:
        base, token = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _get_json(s, f"{base}/api/me", token=token)
            assert status == 200
            assert j["short_id"] == p.a.short_id
            assert "fingerprint" in j
            assert "hostname" in j


@pytest.mark.asyncio
async def test_api_peers_lists_other_peer():
    with daemon_pair() as p:
        base, token = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _get_json(s, f"{base}/api/peers", token=token)
            assert status == 200
            short_ids = {pp["short_id"] for pp in j["peers"]}
            assert p.b.short_id in short_ids


@pytest.mark.asyncio
async def test_api_send_text_round_trip():
    with daemon_pair() as p:
        base_a, tok_a = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _post_json(
                s,
                f"{base_a}/api/send",
                {"peer": p.b.short_id, "body": "hi via api"},
                token=tok_a,
            )
            assert status == 200, j
            assert j["ok"] is True

        # Verify B received it (give the daemon a moment)
        await asyncio.sleep(0.5)
        from tests.harness import message_log
        bodies = [
            m.get("body")
            for m in message_log(p.b.home)
            if m.get("t") == "TEXT" and m.get("dir") == "in"
        ]
        assert "hi via api" in bodies, bodies


@pytest.mark.asyncio
async def test_api_send_to_unknown_peer_404():
    with daemon_pair() as p:
        base_a, tok_a = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _post_json(
                s, f"{base_a}/api/send",
                {"peer": "zzzzzzzz", "body": "hi"},
                token=tok_a,
            )
            assert status == 404
            assert "no peer" in j["error"].lower()


@pytest.mark.asyncio
async def test_api_send_missing_fields_400():
    with daemon_pair() as p:
        base_a, tok_a = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _post_json(s, f"{base_a}/api/send", {}, token=tok_a)
            assert status == 400


@pytest.mark.asyncio
async def test_api_send_file_round_trip(tmp_path: Path):
    with daemon_pair() as p:
        base_a, tok_a = _server_addr(p.a.home)
        # Build a real uploaded file
        sample = tmp_path / "via_api.bin"
        payload = os.urandom(123_456)
        sample.write_bytes(payload)

        form = aiohttp.FormData()
        form.add_field("peer", p.b.short_id)
        form.add_field(
            "file", payload, filename="via_api.bin",
            content_type="application/octet-stream",
        )
        async with aiohttp.ClientSession() as s:
            async with s.post(
                f"{base_a}/api/send-file", data=form,
                headers={"Authorization": f"Bearer {tok_a}"},
            ) as r:
                assert r.status == 200, await r.text()
                j = await r.json()
                assert j["ok"] is True

        await asyncio.sleep(1.0)
        inbox = list((p.b.home / "data" / "inbox").iterdir())
        match = [f for f in inbox if "via_api.bin" in f.name]
        assert match, f"file not in B inbox: {inbox}"
        assert match[0].read_bytes() == payload


@pytest.mark.asyncio
async def test_api_files_lists_and_downloads():
    with daemon_pair() as p:
        # Send a file from A to B first so B has something in inbox
        from tests.harness import request as ctrl_request
        src = p.tmp / "for_listing.bin"
        src.write_bytes(b"hello world")
        ctrl_request(p.a.control_port, cmd="send_file", peer=p.b.short_id, path=str(src))
        await asyncio.sleep(0.6)

        base_b, tok_b = _server_addr(p.b.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _get_json(s, f"{base_b}/api/files", token=tok_b)
            assert status == 200
            names = [f["name"] for f in j["files"]]
            assert any("for_listing.bin" in n for n in names), names

            target = next(n for n in names if "for_listing.bin" in n)
            async with s.get(
                f"{base_b}/api/files/{target}",
                headers={"Authorization": f"Bearer {tok_b}"},
            ) as r:
                assert r.status == 200
                data = await r.read()
                assert data == b"hello world"


@pytest.mark.asyncio
async def test_api_file_download_blocks_path_traversal():
    """Defense in depth: even if a client crafts a URL that bypasses
    aiohttp's path normalization, the handler must refuse."""
    with daemon_pair() as p:
        base_b, tok_b = _server_addr(p.b.home)
        async with aiohttp.ClientSession() as s:
            # These get normalized client-side; they should at minimum NOT
            # return 200 with file content.
            for evil in ["../../etc/passwd", "..\\..\\foo", "../bar"]:
                status, _ = await _get(
                    s, f"{base_b}/api/files/{evil}", token=tok_b
                )
                assert status != 200, f"path-traversal returned 200: {evil!r}"

        # Send a raw HTTP request that DOESN'T normalize, to hit the handler.
        port = int(_read(p.b.home, "server.port"))
        for raw_evil in ["..%2F..%2Fetc%2Fpasswd", "..", "subdir/x", "x/../y"]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(("127.0.0.1", port))
            try:
                req = (
                    f"GET /api/files/{raw_evil} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1\r\n"
                    f"Authorization: Bearer {tok_b}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
                sock.sendall(req)
                buf = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                first_line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                # Must NOT be 200 OK
                assert "200" not in first_line, (
                    f"raw path-traversal got {first_line!r} for {raw_evil!r}"
                )
            finally:
                sock.close()


@pytest.mark.asyncio
async def test_api_messages_returns_list():
    with daemon_pair() as p:
        # Generate some traffic
        from tests.harness import request as ctrl_request
        ctrl_request(p.a.control_port, cmd="send", peer=p.b.short_id, body="m1")
        ctrl_request(p.a.control_port, cmd="send", peer=p.b.short_id, body="m2")
        await asyncio.sleep(0.6)

        base_a, tok_a = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _get_json(
                s, f"{base_a}/api/messages?limit=50", token=tok_a
            )
            assert status == 200
            bodies = [m.get("body") for m in j["messages"] if m.get("t") == "TEXT"]
            assert "m1" in bodies and "m2" in bodies


@pytest.mark.asyncio
async def test_websocket_event_stream_pushes_messages():
    with daemon_pair() as p:
        base_b, tok_b = _server_addr(p.b.home)
        ws_url = base_b.replace("http://", "ws://") + f"/api/events?t={tok_b}"
        async with aiohttp.ClientSession() as s:
            async with s.ws_connect(ws_url) as ws:
                # First frame should be the hello with our identity
                msg = await asyncio.wait_for(ws.receive(), timeout=5)
                assert msg.type == aiohttp.WSMsgType.TEXT
                hello = json.loads(msg.data)
                assert hello["type"] == "hello"
                assert hello["me"]["short_id"] == p.b.short_id

                # Now have A send a message; B's WS should see it
                from tests.harness import request as ctrl_request
                ctrl_request(p.a.control_port, cmd="send", peer=p.b.short_id, body="ws-test")

                # Drain events until we see the one we want, with a timeout.
                deadline = time.time() + 8.0
                got = False
                while time.time() < deadline:
                    msg = await asyncio.wait_for(ws.receive(), timeout=2.0)
                    if msg.type != aiohttp.WSMsgType.TEXT:
                        continue
                    obj = json.loads(msg.data)
                    if obj.get("type") == "msg" and obj.get("msg", {}).get("body") == "ws-test":
                        got = True
                        break
                assert got, "WS never delivered the inbound TEXT"


@pytest.mark.asyncio
async def test_api_search_finds_message_by_word():
    with daemon_pair() as p:
        from tests.harness import request as ctrl_request
        ctrl_request(p.a.control_port, cmd="send", peer=p.b.short_id, body="the quick brown fox")
        ctrl_request(p.a.control_port, cmd="send", peer=p.b.short_id, body="lazy dog")
        await asyncio.sleep(0.6)

        base_b, tok_b = _server_addr(p.b.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _get_json(
                s, f"{base_b}/api/search?q=quick", token=tok_b
            )
            assert status == 200
            bodies = [m.get("body") for m in j["messages"]]
            assert "the quick brown fox" in bodies


@pytest.mark.asyncio
async def test_api_search_q_required():
    with daemon_pair() as p:
        base_a, tok_a = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, _ = await _get_json(s, f"{base_a}/api/search", token=tok_a)
            assert status == 400


@pytest.mark.asyncio
async def test_api_audit_describes_surface():
    with daemon_pair() as p:
        base_a, tok_a = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _get_json(s, f"{base_a}/api/audit", token=tok_a)
            assert status == 200
            assert j["ui_bind"].startswith("127.0.0.1")
            assert j["no_external_telemetry"] is True
            assert "TEXT" in j["peer_protocol"]["message_types"]
            assert any("mdns" in d["kind"] for d in j["outbound_destinations"])


@pytest.mark.asyncio
async def test_api_set_trust_round_trip():
    with daemon_pair() as p:
        # First, drive A to send to B so B records A in its peer DB
        from tests.harness import request as ctrl_request
        ctrl_request(p.a.control_port, cmd="send", peer=p.b.short_id, body="trust-test")
        await asyncio.sleep(0.6)

        # B's view: list peers, find A by short_id, get fingerprint
        base_b, tok_b = _server_addr(p.b.home)
        async with aiohttp.ClientSession() as s:
            _, j = await _get_json(s, f"{base_b}/api/peers", token=tok_b)
            target = next(
                (pp for pp in j["peers"] if pp["short_id"] == p.a.short_id),
                None,
            )
            assert target is not None and target.get("fingerprint")
            fp = target["fingerprint"]
            assert target["trust"] in ("pending", "pinned")

            # Set rejected
            status, j2 = await _post_json(
                s, f"{base_b}/api/peers/{fp}/trust",
                {"trust": "rejected"}, token=tok_b,
            )
            assert status == 200
            assert j2["trust"] == "rejected"

            # Verify it stuck
            _, j3 = await _get_json(s, f"{base_b}/api/peers", token=tok_b)
            target3 = next(pp for pp in j3["peers"] if pp["fingerprint"] == fp)
            assert target3["trust"] == "rejected"

            # Bad trust value
            status_bad, _ = await _post_json(
                s, f"{base_b}/api/peers/{fp}/trust",
                {"trust": "yolo"}, token=tok_b,
            )
            assert status_bad == 400

            # Unknown peer
            status_404, _ = await _post_json(
                s, f"{base_b}/api/peers/{'00' * 32}/trust",
                {"trust": "pinned"}, token=tok_b,
            )
            assert status_404 == 404


@pytest.mark.asyncio
async def test_set_trust_auto_seeds_from_mdns_for_unmessaged_peer():
    """User clicks Accept/Block on a peer they've only seen via mDNS, never
    actually messaged. The endpoint must auto-populate the peer DB from the
    discovery record rather than rejecting with 'unknown peer'."""
    with daemon_pair() as p:
        # B has seen A via mDNS but they have NOT exchanged messages yet,
        # so B's peer DB likely doesn't have an A record.
        # Find A in B's discovery view.
        base_b, tok_b = _server_addr(p.b.home)
        async with aiohttp.ClientSession() as s:
            _, j = await _get_json(s, f"{base_b}/api/peers", token=tok_b)
            target = next(pp for pp in j["peers"] if pp["short_id"] == p.a.short_id)
            fp = target["fingerprint"]

            # Pin them — should succeed even if state.get_peer(fp) returns None
            status, j2 = await _post_json(
                s, f"{base_b}/api/peers/{fp}/trust",
                {"trust": "pinned"}, token=tok_b,
            )
            assert status == 200, j2
            assert j2["trust"] == "pinned"

            # Now confirmed in DB
            _, j3 = await _get_json(s, f"{base_b}/api/peers", token=tok_b)
            after = next(pp for pp in j3["peers"] if pp["fingerprint"] == fp)
            assert after["trust"] == "pinned"


@pytest.mark.asyncio
async def test_set_trust_for_truly_unknown_peer_returns_404():
    """If a fingerprint isn't in the DB and isn't visible via mDNS either,
    the endpoint should still 404 (genuine unknown)."""
    with daemon_pair() as p:
        base_a, tok_a = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _post_json(
                s, f"{base_a}/api/peers/{'00' * 32}/trust",
                {"trust": "pinned"}, token=tok_a,
            )
            assert status == 404


@pytest.mark.asyncio
async def test_outbound_blocked_for_rejected_peer():
    """If we mark a peer 'rejected', outbound sends to them must error."""
    with daemon_pair() as p:
        # Seed: A sends to B so B has A's fingerprint pinned-trust.
        # Then B marks A rejected. Subsequent B → A sends must fail.
        from tests.harness import request as ctrl_request

        ctrl_request(p.a.control_port, cmd="send", peer=p.b.short_id, body="seed")
        await asyncio.sleep(0.6)

        base_b, tok_b = _server_addr(p.b.home)
        async with aiohttp.ClientSession() as s:
            _, j = await _get_json(s, f"{base_b}/api/peers", token=tok_b)
            target = next(pp for pp in j["peers"] if pp["short_id"] == p.a.short_id)
            fp = target["fingerprint"]

            # B rejects A
            await _post_json(
                s, f"{base_b}/api/peers/{fp}/trust",
                {"trust": "rejected"}, token=tok_b,
            )

            # B tries to send to A → must error
            status, j2 = await _post_json(
                s, f"{base_b}/api/send",
                {"peer": p.a.short_id, "body": "hi"},
                token=tok_b,
            )
            assert status >= 400
            assert "rejected" in j2["error"].lower()


@pytest.mark.asyncio
async def test_websocket_unauthorized_closes():
    with daemon_pair() as p:
        base_b, _ = _server_addr(p.b.home)
        ws_url = base_b.replace("http://", "ws://") + "/api/events"  # no token
        async with aiohttp.ClientSession() as s:
            async with s.ws_connect(ws_url) as ws:
                # Server should close immediately. receive() returns CLOSE.
                msg = await asyncio.wait_for(ws.receive(), timeout=5)
                assert msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.CLOSING,
                )


@pytest.mark.asyncio
async def test_settings_round_trip():
    with daemon_pair() as p:
        base_a, tok_a = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            # Default
            status, j = await _get_json(s, f"{base_a}/api/settings", token=tok_a)
            assert status == 200
            assert j["display_name"] is None
            assert j["auto_accept_lan"] is False

            # Set
            status, _ = await _post_json(
                s, f"{base_a}/api/settings",
                {"display_name": "Alex's Studio", "auto_accept_lan": True},
                token=tok_a,
            )
            assert status == 200

            # Read back
            _, j2 = await _get_json(s, f"{base_a}/api/settings", token=tok_a)
            assert j2["display_name"] == "Alex's Studio"
            assert j2["auto_accept_lan"] is True

            # /api/me reflects the override
            _, me = await _get_json(s, f"{base_a}/api/me", token=tok_a)
            assert me["display_name"] == "Alex's Studio"

            # Clear display_name (empty / null)
            await _post_json(
                s, f"{base_a}/api/settings",
                {"display_name": None}, token=tok_a,
            )
            _, j3 = await _get_json(s, f"{base_a}/api/settings", token=tok_a)
            assert j3["display_name"] is None
            _, me2 = await _get_json(s, f"{base_a}/api/me", token=tok_a)
            assert me2["display_name"] == me2["hostname"]
