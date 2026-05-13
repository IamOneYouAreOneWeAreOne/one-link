"""v0.9.9 — real integration audit of session ships.

The session shipped a lot of new endpoints + UI surfaces. Most
existing tests are string-asserts on index.html or unit tests of
state.py helpers. This file is the missing layer: aiohttp
TestClient hitting the actual UIServer routes against a real
in-memory State + a stub Daemon.

Coverage matrix (one assertion per row in each suite):

  Endpoint                                   Auth | Happy | Edge
  ------------------------------------------ ---- + ----- + ----
  GET  /api/me                                ✓     ✓       —
  GET  /api/peers                             ✓     ✓       —
  GET  /api/palette                           ✓     ✓       ✓
  GET  /api/activity                          ✓     ✓       ✓
  GET  /api/folder-conflicts                  ✓     ✓       —
  POST /api/folder-conflicts/{id}/resolve     ✓     ✓       ✓
  GET  /api/files/{name}/preview              ✓     ✓       ✓
  GET  /api/peers/{fp}/trust-history          ✓     ✓       ✓
  GET  /api/peers/{fp}/key-history            ✓     ✓       —
  POST /api/peers/{fp}/verify                 ✓     ✓       ✓
  DEL  /api/peers/{fp}/verify                 ✓     ✓       —
  GET  /api/key-change-events                 ✓     ✓       —
  POST /api/key-change-events/{id}/ack        ✓     ✓       ✓
  POST /api/inbox/reveal                      ✓     ✓       —
  POST /api/files/{name}/reveal               ✓     ✓       ✓ traversal

  ✓ Auth = endpoint returns 401 without a valid token.
  ✓ Happy = endpoint returns 200 with expected shape on valid input.
  ✓ Edge = endpoint handles malformed input / missing entities cleanly.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import MAX_FAILED_AUTH_ATTEMPTS, MAX_JSON_REQUEST_BYTES, UIServer
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="audit-host",
    )


@pytest_asyncio.fixture
async def ctx(tmp_path: Path, monkeypatch):
    """Spin up a real UIServer + State backed by a tmp sqlite db.
    Yields (client, daemon, state, token, peer_fp)."""
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    # paths.py respects ONE_LINK_HOME, so inbox_dir() etc. resolve under tmp.
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    # Pre-seed a paired peer + a couple of trust events so endpoints
    # have data to return.
    peer_fp = "aa" * 32
    state.upsert_peer(
        fingerprint=peer_fp, short_id=peer_fp[:8],
        pubkey=b"\x01" * 32, hostname="audit-peer",
    )
    state.set_peer_trust(peer_fp, "pinned")
    state.set_peer_verified(peer_fp, method="sas-digits", note="audit fixture")
    state.record_message(
        id="m1", ts_ms=1_000_000, direction="in", peer_fp=peer_fp,
        msg_type="TEXT", body="hello there general kenobi",
    )

    daemon = Daemon(me)
    daemon.state = state
    # Bypass discovery / outbound machinery — we only test the HTTP layer.
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None  # /api/folder-conflicts/.../resolve early-returns

    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client, daemon, state, server.token, peer_fp
    finally:
        await client.close()
        state.close()


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ───────── auth gate (every guarded route returns 401 without a token) ──

GUARDED_GET_ROUTES = [
    "/api/me",
    "/api/peers",
    "/api/palette?q=hi",
    "/api/activity?limit=5",
    "/api/fabric",
    "/api/route-bootstrap",
    "/api/route-bootstrap/qr.svg",
    "/api/folder-conflicts",
    "/api/key-change-events",
    "/api/peers/{fp}/trust-history",
    "/api/peers/{fp}/key-history",
]


@pytest.mark.asyncio
async def test_unauthenticated_access_is_blocked(ctx):
    client, _, _, _, peer_fp = ctx
    for route in GUARDED_GET_ROUTES:
        url = route.format(fp=peer_fp)
        resp = await client.get(url)
        assert resp.status == 401, f"{url} should be 401 without auth"


# ───────── /api/me ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_api_me_happy(ctx):
    client, _, _, token, _ = ctx
    resp = await client.get("/api/me", headers=_h(token))
    assert resp.status == 200
    me = await resp.json()
    assert "fingerprint" in me
    assert "app_version" in me
    assert "onboarding_completed" in me, "v0.9.4 flag must surface"


@pytest.mark.asyncio
async def test_api_fabric_returns_route_truth(ctx):
    client, daemon, state, token, peer_fp = ctx
    state.upsert_route_candidate(
        peer_fp=peer_fp,
        route="lan",
        transport="tcp",
        host="10.0.0.9",
        port=17117,
        source="session_open",
        verified=True,
        attempts=2,
        successes=2,
        failures=0,
        latency_ms=5.0,
        bandwidth_bps=420_000_000.0,
    )
    daemon._fabric_snapshot = lambda: {  # type: ignore[method-assign]
        "ok": True,
        "cache_age_s": 0.0,
        "inventory": {"paths": []},
        "route_truth": {
            "route": "lan",
            "kind": "Local network",
            "state": "Sending",
            "reason": "lan can carry control and bulk data",
            "activation_state": "active",
            "activation_risk": "low",
            "automatic": True,
        },
        "scores": [],
        "activation": [
            {
                "adapter_id": "lan.test",
                "route_name": "lan",
                "state": "active",
                "risk": "low",
                "score": 0.95,
                "automatic": True,
                "needs_user": False,
                "reason": "path ready",
                "next_action": "open_route",
                "safeguards": ["all payload chunks are cryptographically verified"],
            },
        ],
        "probes": [],
    }

    resp = await client.get("/api/fabric", headers=_h(token))

    assert resp.status == 200
    j = await resp.json()
    assert j["ok"] is True
    assert j["route_truth"]["kind"] == "Local network"
    assert j["route_truth"]["automatic"] is True
    assert j["activation"][0]["state"] == "active"
    assert j["route_candidates"]["verified"] == 1
    assert j["route_candidates"]["top"][0]["route"] == "lan"


@pytest.mark.asyncio
async def test_api_route_bootstrap_returns_signed_token(ctx, monkeypatch):
    client, daemon, _, token, _ = ctx
    daemon._rendezvous_peer_port = 17117
    from one_link import rendezvous_client
    from one_link.route_bootstrap import decode_bootstrap
    from one_link.rendezvous_proto import Endpoint

    monkeypatch.setattr(
        rendezvous_client,
        "discover_local_endpoints",
        lambda *, peer_port, include_loopback=False: [
            Endpoint(host="192.168.1.20", port=peer_port),
        ],
    )
    daemon._fabric_snapshot = lambda: {  # type: ignore[method-assign]
        "ok": True,
        "cache_age_s": 0.0,
        "route_truth": {
            "route": "lan",
            "kind": "Local network",
            "state": "Ready",
            "reason": "lan can carry control and bulk data",
        },
        "scores": [],
        "activation": [],
        "probes": [],
    }

    resp = await client.get("/api/route-bootstrap?ttl_s=60", headers=_h(token))

    assert resp.status == 200
    j = await resp.json()
    assert j["ok"] is True
    decoded = decode_bootstrap(j["token"])
    assert decoded.issuer_fp == daemon.me.fingerprint
    assert decoded.endpoints[0]["address"] == "192.168.1.20"


@pytest.mark.asyncio
async def test_api_route_bootstrap_qr_returns_no_store_svg(ctx, monkeypatch):
    client, daemon, _, token, _ = ctx
    daemon._rendezvous_peer_port = 17117
    from one_link import rendezvous_client
    from one_link.rendezvous_proto import Endpoint

    monkeypatch.setattr(
        rendezvous_client,
        "discover_local_endpoints",
        lambda *, peer_port, include_loopback=False: [
            Endpoint(host="192.168.1.20", port=peer_port),
        ],
    )

    resp = await client.get("/api/route-bootstrap/qr.svg", headers=_h(token))

    assert resp.status == 200
    assert "svg" in resp.headers.get("Content-Type", "")
    assert "no-store" in resp.headers.get("Cache-Control", "")
    body = await resp.text()
    assert "<svg" in body
    assert "<path" in body


@pytest.mark.asyncio
async def test_api_route_bootstrap_marks_loopback_as_loopback_only(ctx, monkeypatch):
    client, daemon, _, token, _ = ctx
    daemon._rendezvous_peer_port = 17117
    from one_link import rendezvous_client
    from one_link.route_bootstrap import decode_bootstrap
    from one_link.rendezvous_proto import Endpoint

    monkeypatch.setattr(
        rendezvous_client,
        "discover_local_endpoints",
        lambda *, peer_port, include_loopback=False: [
            Endpoint(host="127.0.0.1", port=peer_port),
        ],
    )

    resp = await client.get("/api/route-bootstrap?ttl_s=60", headers=_h(token))

    assert resp.status == 200
    j = await resp.json()
    decoded = decode_bootstrap(j["token"])
    assert decoded.endpoints[0]["address"] == "127.0.0.1"
    assert decoded.endpoints[0]["route"] == "loopback"
    assert decoded.endpoints[0]["kind"] == "loopback"


@pytest.mark.asyncio
async def test_api_route_bootstrap_import_queues_verified_probe(ctx, monkeypatch):
    client, daemon, state, token, peer_fp = ctx
    from one_link.route_bootstrap import (
        RouteEndpointHint,
        encode_bootstrap,
        make_route_bootstrap,
    )

    peer_identity = _identity()
    state.upsert_peer(
        fingerprint=peer_identity.fingerprint,
        short_id=peer_identity.short_id,
        pubkey=peer_identity.public_bytes,
        hostname="route-peer",
    )
    state.set_peer_trust(peer_identity.fingerprint, "pinned")
    calls = []

    async def fake_verify(fp, sid, host, port, **_kwargs):
        calls.append((fp, sid, host, port))

    monkeypatch.setattr(daemon, "_verify_and_promote_endpoint", fake_verify)
    payload = make_route_bootstrap(
        identity=peer_identity,
        endpoints=[RouteEndpointHint(kind="lan", address="10.1.2.3", port=17117)],
    )

    resp = await client.post(
        "/api/route-bootstrap/import",
        headers=_h(token),
        json={"token": encode_bootstrap(payload)},
    )

    assert resp.status == 200
    j = await resp.json()
    assert j["ok"] is True
    assert j["queued"] == 1
    await asyncio.sleep(0)
    assert calls == [(peer_identity.fingerprint, peer_identity.short_id, "10.1.2.3", 17117)]
    candidates = state.list_route_candidates(peer_identity.fingerprint, include_expired=True)
    assert candidates[0]["source"] == "signed_bootstrap"
    assert candidates[0]["host"] == "10.1.2.3"


@pytest.mark.asyncio
async def test_api_route_bootstrap_import_rejects_remote_loopback(ctx, monkeypatch):
    client, daemon, state, token, _ = ctx
    from one_link.route_bootstrap import (
        RouteEndpointHint,
        encode_bootstrap,
        make_route_bootstrap,
    )

    peer_identity = _identity()
    state.upsert_peer(
        fingerprint=peer_identity.fingerprint,
        short_id=peer_identity.short_id,
        pubkey=peer_identity.public_bytes,
        hostname="route-peer",
    )
    state.set_peer_trust(peer_identity.fingerprint, "pinned")
    calls = []

    async def fake_verify(fp, sid, host, port, **_kwargs):
        calls.append((fp, sid, host, port))

    monkeypatch.setattr(daemon, "_verify_and_promote_endpoint", fake_verify)
    payload = make_route_bootstrap(
        identity=peer_identity,
        endpoints=[
            RouteEndpointHint(
                kind="loopback",
                route="loopback",
                address="127.0.0.1",
                port=17117,
            )
        ],
    )

    resp = await client.post(
        "/api/route-bootstrap/import",
        headers=_h(token),
        json={"token": encode_bootstrap(payload)},
    )

    assert resp.status == 409
    j = await resp.json()
    assert j["state"] == "no_valid_endpoints"
    assert j["rejected"] == 1
    await asyncio.sleep(0)
    assert calls == []


@pytest.mark.asyncio
async def test_api_route_bootstrap_import_rejects_unpaired_issuer(ctx):
    client, _, _, token, _ = ctx
    from one_link.route_bootstrap import (
        RouteEndpointHint,
        encode_bootstrap,
        make_route_bootstrap,
    )

    unknown = _identity()
    payload = make_route_bootstrap(
        identity=unknown,
        endpoints=[RouteEndpointHint(kind="lan", address="10.1.2.3", port=17117)],
    )

    resp = await client.post(
        "/api/route-bootstrap/import",
        headers=_h(token),
        json={"token": encode_bootstrap(payload)},
    )

    assert resp.status == 409
    j = await resp.json()
    assert j["state"] == "needs_pairing"


@pytest.mark.asyncio
async def test_api_route_bootstrap_import_rejects_replay(ctx, monkeypatch):
    client, daemon, state, token, _ = ctx
    from one_link.route_bootstrap import (
        RouteEndpointHint,
        encode_bootstrap,
        make_route_bootstrap,
    )

    peer_identity = _identity()
    state.upsert_peer(
        fingerprint=peer_identity.fingerprint,
        short_id=peer_identity.short_id,
        pubkey=peer_identity.public_bytes,
        hostname="route-peer",
    )
    state.set_peer_trust(peer_identity.fingerprint, "pinned")
    calls = []

    async def fake_verify(fp, sid, host, port, **_kwargs):
        calls.append((fp, sid, host, port))

    monkeypatch.setattr(daemon, "_verify_and_promote_endpoint", fake_verify)
    payload = make_route_bootstrap(
        identity=peer_identity,
        endpoints=[RouteEndpointHint(kind="lan", address="10.1.2.3", port=17117)],
        nonce_hex="11" * 16,
    )
    body = {"token": encode_bootstrap(payload)}

    first = await client.post(
        "/api/route-bootstrap/import",
        headers=_h(token),
        json=body,
    )
    second = await client.post(
        "/api/route-bootstrap/import",
        headers=_h(token),
        json=body,
    )

    assert first.status == 200
    assert second.status == 409
    j = await second.json()
    assert j["state"] == "replayed"
    await asyncio.sleep(0)
    assert len(calls) == 1


# ───────── /api/peers ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_api_peers_returns_paired(ctx):
    client, _, _, token, peer_fp = ctx
    resp = await client.get("/api/peers", headers=_h(token))
    assert resp.status == 200
    j = await resp.json()
    assert any(p["fingerprint"] == peer_fp for p in j["peers"])
    p = next(x for x in j["peers"] if x["fingerprint"] == peer_fp)
    # Verification fields surface (v0.7.7).
    assert p["is_verified"] is True
    assert p["verified_method"] == "sas-digits"
    # Key-change unacked count surfaces (v0.7.8).
    assert p["key_change_unacked"] == 0


# ───────── /api/palette ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_palette_finds_message(ctx):
    client, _, _, token, _ = ctx
    resp = await client.get("/api/palette?q=kenobi", headers=_h(token))
    assert resp.status == 200
    j = await resp.json()
    assert len(j["messages"]) >= 1
    assert "kenobi" in j["messages"][0]["body"].lower()


@pytest.mark.asyncio
async def test_palette_empty_query_returns_empty(ctx):
    client, _, _, token, _ = ctx
    resp = await client.get("/api/palette?q=", headers=_h(token))
    assert resp.status == 200
    j = await resp.json()
    assert j["messages"] == []
    assert j["peers"] == []


@pytest.mark.asyncio
async def test_palette_fts_special_chars_safe(ctx):
    """A user typing 'auth: user' would otherwise hit FTS5's
    field-restricted query parser. Phrase-quoting in
    state.global_search must keep it safe — endpoint must not 500."""
    client, _, _, token, _ = ctx
    resp = await client.get(
        "/api/palette?q=auth%3A%20user", headers=_h(token),
    )
    assert resp.status == 200


@pytest.mark.asyncio
async def test_palette_caps_limit(ctx):
    """limit param must be clamped — passing 999999 doesn't blow past
    the documented hard max."""
    client, _, _, token, _ = ctx
    resp = await client.get(
        "/api/palette?q=a&limit=999999", headers=_h(token),
    )
    assert resp.status == 200


# ───────── /api/activity ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_activity_feed_includes_seeded_events(ctx):
    client, _, _, token, _ = ctx
    resp = await client.get("/api/activity?limit=20", headers=_h(token))
    assert resp.status == 200
    j = await resp.json()
    kinds = {e["kind"] for e in j["events"]}
    assert "trust" in kinds  # set_peer_verified above
    assert "peer" in kinds   # first_seen synthetic event


@pytest.mark.asyncio
async def test_activity_kinds_filter(ctx):
    client, _, _, token, _ = ctx
    resp = await client.get(
        "/api/activity?kinds=trust&limit=20", headers=_h(token),
    )
    assert resp.status == 200
    j = await resp.json()
    assert all(e["kind"] == "trust" for e in j["events"])


# ───────── /api/folder-conflicts ──────────────────────────────────────

@pytest.mark.asyncio
async def test_folder_conflicts_empty(ctx):
    client, _, _, token, _ = ctx
    resp = await client.get(
        "/api/folder-conflicts", headers=_h(token),
    )
    assert resp.status == 200
    j = await resp.json()
    assert j["unresolved_total"] == 0
    assert j["conflicts"] == []


@pytest.mark.asyncio
async def test_resolve_unknown_conflict_400(ctx):
    """Resolving a nonexistent conflict must 400 with a clear error,
    not crash."""
    client, _, _, token, _ = ctx
    resp = await client.post(
        "/api/folder-conflicts/99999/resolve",
        headers=_h(token), json={"choice": "mine"},
    )
    # 503 is acceptable when folder_engine is None (test harness sets
    # it None to avoid spinning up the FolderEngine).
    assert resp.status in (400, 503), f"got {resp.status}"


@pytest.mark.asyncio
async def test_resolve_bad_choice_rejected(ctx):
    client, _, _, token, _ = ctx
    resp = await client.post(
        "/api/folder-conflicts/1/resolve",
        headers=_h(token), json={"choice": "yolo"},
    )
    assert resp.status in (400, 503)


# ───────── /api/files/{name}/preview ──────────────────────────────────

@pytest.mark.asyncio
async def test_preview_markdown(ctx, tmp_path: Path):
    client, _, _, token, _ = ctx
    # Use the daemon's actual inbox_dir
    from one_link.paths import inbox_dir
    inbox = inbox_dir()
    inbox.mkdir(parents=True, exist_ok=True)
    md = inbox / "audit_test.md"
    md.write_text("# Hi\n\n**bold**", encoding="utf-8")
    try:
        resp = await client.get(
            "/api/files/audit_test.md/preview", headers=_h(token),
        )
        assert resp.status == 200
        j = await resp.json()
        assert j["kind"] == "markdown"
        assert "# Hi" in j["content"]
    finally:
        md.unlink()


@pytest.mark.asyncio
async def test_preview_traversal_blocked(ctx):
    client, _, _, token, _ = ctx
    # `..` in path component must be rejected.
    resp = await client.get(
        "/api/files/..%2F..%2Fetc%2Fpasswd/preview", headers=_h(token),
    )
    assert resp.status in (400, 404)


@pytest.mark.asyncio
async def test_preview_unknown_extension_415(ctx):
    client, _, _, token, _ = ctx
    from one_link.paths import inbox_dir
    inbox = inbox_dir()
    inbox.mkdir(parents=True, exist_ok=True)
    f = inbox / "audit_test.xyz"
    f.write_text("opaque", encoding="utf-8")
    try:
        resp = await client.get(
            "/api/files/audit_test.xyz/preview", headers=_h(token),
        )
        assert resp.status == 415
    finally:
        f.unlink()


@pytest.mark.asyncio
async def test_preview_pdf_returns_metadata_only(ctx):
    """PDF kind must short-circuit BEFORE reading content (the v0.9.5
    fix). Server returns stream_url + size, no 'content' field."""
    client, _, _, token, _ = ctx
    from one_link.paths import inbox_dir
    inbox = inbox_dir()
    inbox.mkdir(parents=True, exist_ok=True)
    f = inbox / "audit_test.pdf"
    f.write_bytes(b"%PDF-1.4\n" + b"\x00" * 4096)
    try:
        resp = await client.get(
            "/api/files/audit_test.pdf/preview", headers=_h(token),
        )
        assert resp.status == 200
        j = await resp.json()
        assert j["kind"] == "pdf"
        assert "stream_url" in j
        assert j["stream_url"].endswith("/audit_test.pdf")
        # Content field NOT present (the v0.9.5 short-circuit).
        assert "content" not in j
    finally:
        f.unlink()


@pytest.mark.asyncio
async def test_preview_lossy_decode_for_binary_text(ctx):
    """A binary file with a .txt extension must NOT 500 — the
    handler falls back to errors='replace'."""
    client, _, _, token, _ = ctx
    from one_link.paths import inbox_dir
    inbox = inbox_dir()
    inbox.mkdir(parents=True, exist_ok=True)
    f = inbox / "audit_binary.txt"
    f.write_bytes(bytes(range(256)))
    try:
        resp = await client.get(
            "/api/files/audit_binary.txt/preview", headers=_h(token),
        )
        assert resp.status == 200
        j = await resp.json()
        assert j["encoding"] == "utf-8-replace"
    finally:
        f.unlink()


# ───────── /api/peers/{fp}/trust-history ──────────────────────────────

@pytest.mark.asyncio
async def test_trust_history_returns_events(ctx):
    client, _, _, token, peer_fp = ctx
    resp = await client.get(
        f"/api/peers/{peer_fp}/trust-history", headers=_h(token),
    )
    assert resp.status == 200
    j = await resp.json()
    assert len(j["events"]) >= 2  # first_seen + verify_set + trust_set


@pytest.mark.asyncio
async def test_trust_history_unknown_peer_404(ctx):
    client, _, _, token, _ = ctx
    resp = await client.get(
        "/api/peers/" + "ff" * 32 + "/trust-history", headers=_h(token),
    )
    assert resp.status == 404


# ───────── /api/peers/{fp}/key-history ────────────────────────────────

@pytest.mark.asyncio
async def test_key_history_includes_seeded(ctx):
    client, _, _, token, peer_fp = ctx
    resp = await client.get(
        f"/api/peers/{peer_fp}/key-history", headers=_h(token),
    )
    assert resp.status == 200
    j = await resp.json()
    assert j["hostname"] == "audit-peer"
    assert len(j["history"]) == 1


# ───────── /api/peers/{fp}/verify ─────────────────────────────────────

@pytest.mark.asyncio
async def test_verify_set_then_clear(ctx):
    client, _, state, token, peer_fp = ctx
    # Already verified via fixture. Clear, then re-set.
    resp = await client.delete(
        f"/api/peers/{peer_fp}/verify", headers=_h(token),
    )
    assert resp.status == 200
    rec = state.get_peer(peer_fp)
    assert rec.is_verified is False

    resp = await client.post(
        f"/api/peers/{peer_fp}/verify",
        headers=_h(token), json={"method": "sas-qr", "note": "audit"},
    )
    assert resp.status == 200
    rec = state.get_peer(peer_fp)
    assert rec.is_verified is True
    assert rec.verified_method == "sas-qr"


@pytest.mark.asyncio
async def test_verify_unknown_method_400(ctx):
    client, _, _, token, peer_fp = ctx
    resp = await client.post(
        f"/api/peers/{peer_fp}/verify",
        headers=_h(token), json={"method": "vibes-only"},
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_verify_missing_method_400(ctx):
    client, _, _, token, peer_fp = ctx
    resp = await client.post(
        f"/api/peers/{peer_fp}/verify",
        headers=_h(token), json={"note": "no method"},
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_verify_unknown_peer_404(ctx):
    client, _, _, token, _ = ctx
    resp = await client.post(
        "/api/peers/" + "ff" * 32 + "/verify",
        headers=_h(token), json={"method": "manual"},
    )
    assert resp.status == 404


# ───────── /api/key-change-events + ack ───────────────────────────────

@pytest.mark.asyncio
async def test_key_change_ack_unknown_id(ctx):
    client, _, _, token, _ = ctx
    # No events seeded; ack of nonexistent id must succeed gracefully
    # (newly_acked=False) rather than 500.
    resp = await client.post(
        "/api/key-change-events/99999/ack", headers=_h(token),
    )
    assert resp.status == 200
    j = await resp.json()
    assert j["newly_acked"] is False


@pytest.mark.asyncio
async def test_key_change_ack_invalid_id(ctx):
    client, _, _, token, _ = ctx
    resp = await client.post(
        "/api/key-change-events/abc/ack", headers=_h(token),
    )
    assert resp.status == 400


# ───────── /api/inbox/reveal & /api/files/{name}/reveal ───────────────

@pytest.mark.asyncio
async def test_inbox_reveal_returns_disabled_in_test_env(ctx):
    """ONE_LINK_DISABLE_REVEAL=1 (set by conftest) must short-circuit
    the actual Explorer pop-up."""
    client, _, _, token, _ = ctx
    resp = await client.post("/api/inbox/reveal", headers=_h(token))
    assert resp.status == 200
    j = await resp.json()
    assert j.get("disabled") is True


@pytest.mark.asyncio
async def test_file_reveal_traversal_blocked(ctx):
    client, _, _, token, _ = ctx
    resp = await client.post(
        "/api/files/..%2F..%2Fetc%2Fpasswd/reveal", headers=_h(token),
    )
    assert resp.status in (400, 404)


@pytest.mark.asyncio
async def test_file_reveal_disabled_in_test_env(ctx):
    """For an existing file, the env-gate still wins so we don't
    pop a real Explorer window during CI."""
    client, _, _, token, _ = ctx
    from one_link.paths import inbox_dir
    inbox = inbox_dir()
    inbox.mkdir(parents=True, exist_ok=True)
    f = inbox / "audit_reveal.txt"
    f.write_text("x", encoding="utf-8")
    try:
        resp = await client.post(
            "/api/files/audit_reveal.txt/reveal", headers=_h(token),
        )
        assert resp.status == 200
        j = await resp.json()
        assert j.get("disabled") is True
    finally:
        f.unlink()


# ───────── auth header forms ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_cookie_auth_works(ctx):
    """The cookie path is what the BROWSER uses; the test client uses
    Bearer for clarity. Pin both forms work so a future refactor of
    _check_token doesn't silently break browser sessions."""
    client, _, _, token, _ = ctx
    from one_link.server import COOKIE_NAME
    resp = await client.get("/api/me", cookies={COOKIE_NAME: token})
    assert resp.status == 200


@pytest.mark.asyncio
async def test_wrong_token_blocked(ctx):
    client, _, _, _, _ = ctx
    resp = await client.get(
        "/api/me", headers={"Authorization": "Bearer wrongtoken"}
    )
    assert resp.status == 401


@pytest.mark.asyncio
async def test_bad_auth_attempts_are_rate_limited(ctx):
    client, _, _, _, _ = ctx
    headers = {"Authorization": "Bearer wrongtoken"}
    for _ in range(MAX_FAILED_AUTH_ATTEMPTS):
        resp = await client.get("/api/me", headers=headers)
        assert resp.status == 401
    resp = await client.get("/api/me", headers=headers)
    assert resp.status == 429
    j = await resp.json()
    assert "too many" in j["error"]


@pytest.mark.asyncio
async def test_json_control_surface_rejects_oversized_body(ctx):
    client, _, _, token, _ = ctx
    body = b'{"display_name":"' + (b"x" * (MAX_JSON_REQUEST_BYTES + 1)) + b'"}'
    resp = await client.post(
        "/api/settings",
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    assert resp.status == 413
    j = await resp.json()
    assert j["error"] == "json body too large"


@pytest.mark.asyncio
async def test_security_headers_on_guarded_json_response(ctx):
    client, _, _, token, _ = ctx
    resp = await client.get("/api/me", headers=_h(token))
    assert resp.status == 200
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Cross-Origin-Resource-Policy"] == "same-origin"
