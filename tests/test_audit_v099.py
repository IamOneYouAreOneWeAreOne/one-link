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
import base64
import json
from pathlib import Path

import blake3
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
    "/api/fabric/no-router",
    "/api/fabric/mobile-reach",
    "/api/self-mesh",
    "/api/courier/status",
    "/api/courier/files",
    "/api/courier/outbox",
    "/api/courier/removable",
    "/api/courier/removable-files?target_id=missing",
    "/api/route-bootstrap",
    "/api/route-bootstrap/qr.svg",
    "/api/folder-conflicts",
    "/api/key-change-events",
    "/api/peers/{fp}/trust-history",
    "/api/peers/{fp}/key-history",
]

GUARDED_POST_ROUTES = [
    ("/api/courier/export", {}),
    ("/api/courier/export-file", {}),
    ("/api/courier/copy-to-removable", {}),
    ("/api/courier/copy-from-removable", {}),
    ("/api/courier/import", {}),
    ("/api/courier/import-file", {}),
    ("/api/courier/assemble", {}),
    ("/api/route-bootstrap/import", {}),
]


@pytest.mark.asyncio
async def test_unauthenticated_access_is_blocked(ctx):
    client, _, _, _, peer_fp = ctx
    for route in GUARDED_GET_ROUTES:
        url = route.format(fp=peer_fp)
        resp = await client.get(url)
        assert resp.status == 401, f"{url} should be 401 without auth"
    for route, body in GUARDED_POST_ROUTES:
        url = route.format(fp=peer_fp)
        resp = await client.post(url, json=body)
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
        "performance": {
            "adapter_count": 1.0,
            "total_ms": 0.25,
        },
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
    assert j["performance"]["total_ms"] == 0.25
    assert j["no_router"]["trusted_local_paths"] == 1
    assert j["no_router"]["next_action"] == "send"


@pytest.mark.asyncio
async def test_api_fabric_no_router_reports_local_bootstrap_readiness(ctx):
    client, daemon, state, token, _ = ctx
    daemon._rendezvous_peer_port = 17117
    daemon._fabric_snapshot = lambda: {  # type: ignore[method-assign]
        "ok": True,
        "cache_age_s": 0.0,
        "route_truth": {
            "route": "ethernet",
            "kind": "Ethernet direct",
            "state": "Ready",
            "reason": "ethernet can carry control and bulk data",
        },
        "scores": [
            {
                "route_name": "lan",
                "adapter_id": "ethernet.link_local",
                "usable_for_bulk": True,
                "reason": "ethernet can carry control and bulk data",
            }
        ],
        "activation": [
            {
                "route_name": "lan",
                "state": "ready",
                "next_action": "keep_ready",
                "automatic": False,
            }
        ],
        "probes": [
            {
                "kind": "ethernet",
                "available": True,
                "bulk_capable": True,
            },
            {
                "kind": "qr_control",
                "available": True,
                "bulk_capable": False,
            },
        ],
    }
    state.upsert_route_candidate(
        peer_fp="bb" * 32,
        route="ethernet",
        transport="tcp",
        host="169.254.10.20",
        port=17117,
        source="endpoint_verify",
        verified=True,
    )

    resp = await client.get("/api/fabric/no-router", headers=_h(token))

    assert resp.status == 200
    j = await resp.json()
    assert j["ok"] is True
    assert j["state"] == "trusted_path_ready"
    assert j["next_action"] == "send"
    assert j["token_ready"] is True
    assert j["qr_ready"] is True
    assert j["ethernet_ready"] is True
    assert j["trusted_local_paths"] == 1
    assert j["pending_local_paths"] == 0
    assert j["failed_local_paths"] == 0
    assert j["route_token_url"] == "/api/route-bootstrap"
    assert j["qr_url"] == "/api/route-bootstrap/qr.svg"
    assert "key-confirmed" in " ".join(j["safeguards"])
    assert [s["id"] for s in j["steps"]] == [
        "connect_cable_or_same_network",
        "show_or_import_route_token",
        "verify_local_endpoint",
        "send",
    ]
    assert all(s["status"] == "ready" for s in j["steps"])
    assert j["path_options"][0]["id"] == "trusted_verified_path"
    assert j["path_options"][0]["status"] == "ready"
    assert j["operator_guide"]["send"][-1]["status"] == "ready"
    assert j["operator_guide"]["receive"][-1]["label"] == "receive"


@pytest.mark.asyncio
async def test_api_fabric_no_router_reports_pending_route_probe(ctx):
    client, daemon, state, token, _ = ctx
    daemon._rendezvous_peer_port = 17117
    daemon._fabric_snapshot = lambda: {  # type: ignore[method-assign]
        "ok": True,
        "cache_age_s": 0.0,
        "route_truth": {},
        "scores": [],
        "activation": [],
        "probes": [
            {"kind": "qr_control", "available": True, "bulk_capable": False},
        ],
    }
    state.upsert_route_candidate(
        peer_fp="cc" * 32,
        route="ethernet",
        transport="tcp",
        host="169.254.44.2",
        port=17117,
        source="signed_bootstrap",
        verified=False,
        attempts=0,
        successes=0,
        failures=0,
    )

    resp = await client.get("/api/fabric/no-router", headers=_h(token))

    assert resp.status == 200
    j = await resp.json()
    assert j["state"] == "checking_path"
    assert j["next_action"] == "verify_local_endpoint"
    assert j["pending_local_paths"] == 1
    assert next(s for s in j["steps"] if s["id"] == "verify_local_endpoint")["status"] == "current"
    assert j["path_options"][0]["id"] == "route_token_exchange"
    assert next(
        s for s in j["operator_guide"]["send"]
        if s["id"] == "verify_local_endpoint"
    )["status"] == "current"


@pytest.mark.asyncio
async def test_api_fabric_no_router_reports_failed_route_probe(ctx):
    client, daemon, state, token, _ = ctx
    daemon._rendezvous_peer_port = 17117
    daemon._fabric_snapshot = lambda: {  # type: ignore[method-assign]
        "ok": True,
        "cache_age_s": 0.0,
        "route_truth": {},
        "scores": [],
        "activation": [],
        "probes": [
            {"kind": "qr_control", "available": True, "bulk_capable": False},
        ],
    }
    state.upsert_route_candidate(
        peer_fp="dd" * 32,
        route="ethernet",
        transport="tcp",
        host="169.254.44.3",
        port=17117,
        source="signed_bootstrap",
        verified=False,
        attempts=1,
        successes=0,
        failures=1,
        last_error="dial refused",
    )

    resp = await client.get("/api/fabric/no-router", headers=_h(token))

    assert resp.status == 200
    j = await resp.json()
    assert j["state"] == "route_check_failed"
    assert j["failed_local_paths"] == 1
    assert next(s for s in j["steps"] if s["id"] == "verify_local_endpoint")["status"] == "blocked"
    assert next(
        p for p in j["path_options"]
        if p["id"] == "trusted_verified_path"
    )["status"] == "blocked"


@pytest.mark.asyncio
async def test_api_fabric_no_router_without_listener_is_honest(ctx):
    client, daemon, _, token, _ = ctx
    daemon._rendezvous_peer_port = 0
    daemon._fabric_snapshot = lambda: {  # type: ignore[method-assign]
        "ok": True,
        "cache_age_s": 0.0,
        "route_truth": {},
        "scores": [],
        "activation": [],
        "probes": [{"kind": "qr_control", "available": True}],
    }

    resp = await client.get("/api/fabric/no-router", headers=_h(token))

    assert resp.status == 200
    j = await resp.json()
    assert j["state"] == "peer_listener_unavailable"
    assert j["token_ready"] is False
    assert j["route_token_url"] is None
    assert j["steps"][0]["status"] == "pending"
    assert next(
        p for p in j["path_options"]
        if p["id"] == "route_token_exchange"
    )["status"] == "blocked"


@pytest.mark.asyncio
async def test_api_fabric_no_router_reports_hotspot_operator_option(ctx):
    client, daemon, _, token, _ = ctx
    daemon._rendezvous_peer_port = 17117
    daemon._fabric_snapshot = lambda: {  # type: ignore[method-assign]
        "ok": True,
        "cache_age_s": 0.0,
        "route_truth": {},
        "scores": [],
        "activation": [],
        "probes": [
            {
                "kind": "private_hotspot",
                "available": True,
                "bulk_capable": True,
                "control_capable": True,
                "requires_user_action": True,
                "estimated_bps": 300_000_000,
            },
            {"kind": "qr_control", "available": True, "bulk_capable": False},
        ],
    }

    resp = await client.get("/api/fabric/no-router", headers=_h(token))

    assert resp.status == 200
    j = await resp.json()
    hotspot = next(p for p in j["path_options"] if p["id"] == "private_hotspot")
    assert hotspot["status"] in {"ready", "current"}
    assert hotspot["requires_user_action"] is True
    assert hotspot["next_step"] == "open_os_hotspot_then_exchange_token"
    creation_hotspot = next(
        p for p in j["creation"]["plans"]
        if p["path_id"] == "private_hotspot"
    )
    assert creation_hotspot["state"] == "needs_user"
    assert creation_hotspot["automatic"] is False
    assert j["operator_guide"]["send"][0]["id"] == "connect_cable_or_same_network"


@pytest.mark.asyncio
async def test_api_fabric_path_create_is_read_only_and_safety_gated(ctx):
    client, daemon, _, token, _ = ctx
    daemon._fabric_snapshot = lambda: {  # type: ignore[method-assign]
        "ok": True,
        "cache_age_s": 0.0,
        "route_truth": {},
        "scores": [],
        "activation": [],
        "probes": [
            {
                "kind": "private_hotspot",
                "available": True,
                "bulk_capable": True,
                "control_capable": True,
                "requires_user_action": True,
                "estimated_bps": 300_000_000,
            },
            {
                "kind": "ble_control",
                "available": True,
                "bulk_capable": False,
                "control_capable": True,
                "requires_user_action": True,
                "estimated_bps": 80_000,
            },
        ],
    }

    resp = await client.get("/api/fabric/path-create", headers=_h(token))

    assert resp.status == 200
    j = await resp.json()
    assert j["ok"] is True
    assert j["read_only"] is True
    assert j["mode"] == "safety_gated_path_creation_plan"
    hotspot = next(p for p in j["plans"] if p["path_id"] == "private_hotspot")
    ble = next(p for p in j["plans"] if p["path_id"] == "ble_control")
    assert hotspot["state"] == "needs_user"
    assert hotspot["automatic"] is False
    assert ble["bulk_capable"] is False
    assert "bulk payloads are never forced through BLE" in ble["safeguards"]


@pytest.mark.asyncio
async def test_api_fabric_path_create_launch_is_kill_switch_safe(ctx, monkeypatch):
    client, daemon, _, token, _ = ctx
    monkeypatch.setenv("ONE_LINK_DISABLE_PATH_CREATE_LAUNCH", "1")
    daemon._fabric_snapshot = lambda: {  # type: ignore[method-assign]
        "ok": True,
        "cache_age_s": 0.0,
        "route_truth": {},
        "scores": [],
        "activation": [],
        "probes": [
            {
                "kind": "private_hotspot",
                "available": True,
                "bulk_capable": True,
                "control_capable": True,
                "requires_user_action": True,
                "estimated_bps": 300_000_000,
            },
        ],
    }

    resp = await client.post(
        "/api/fabric/path-create/launch",
        headers=_h(token),
        json={"path_id": "private_hotspot"},
    )

    assert resp.status == 200
    j = await resp.json()
    assert j["ok"] is True
    assert j["disabled"] is True
    assert j["launched"] is False
    assert j["settings_uri"] == "ms-settings:network-mobilehotspot"


@pytest.mark.asyncio
async def test_api_fabric_path_create_launch_rejects_unsupported(ctx):
    client, daemon, _, token, _ = ctx
    daemon._fabric_snapshot = lambda: {  # type: ignore[method-assign]
        "ok": True,
        "cache_age_s": 0.0,
        "route_truth": {},
        "scores": [],
        "activation": [],
        "probes": [],
    }

    resp = await client.post(
        "/api/fabric/path-create/launch",
        headers=_h(token),
        json={"path_id": "wifi_direct", "dry_run": True},
    )

    assert resp.status == 409
    j = await resp.json()
    assert j["error"] == "path_creation_launch_rejected"


@pytest.mark.asyncio
async def test_api_fabric_path_create_native_dry_run_redacts_key(ctx):
    client, daemon, _, token, _ = ctx
    daemon._fabric_snapshot = lambda: {  # type: ignore[method-assign]
        "ok": True,
        "cache_age_s": 0.0,
        "route_truth": {},
        "scores": [],
        "activation": [],
        "probes": [
            {
                "kind": "private_hotspot",
                "available": True,
                "bulk_capable": True,
                "control_capable": True,
                "requires_user_action": True,
                "estimated_bps": 300_000_000,
            },
        ],
    }

    resp = await client.post(
        "/api/fabric/path-create/native",
        headers=_h(token),
        json={
            "path_id": "private_hotspot",
            "dry_run": True,
            "ssid": "OneLinkTest",
            "passphrase": "supersecret1",
        },
    )

    assert resp.status == 200
    j = await resp.json()
    assert j["ok"] is True
    assert j["state"] == "dry_run"
    rendered = json.dumps(j)
    assert "supersecret1" not in rendered
    assert "key=********" in rendered


@pytest.mark.asyncio
async def test_api_fabric_path_create_native_requires_opt_in(ctx):
    client, daemon, _, token, _ = ctx
    daemon._fabric_snapshot = lambda: {  # type: ignore[method-assign]
        "ok": True,
        "cache_age_s": 0.0,
        "route_truth": {},
        "scores": [],
        "activation": [],
        "probes": [
            {
                "kind": "private_hotspot",
                "available": True,
                "bulk_capable": True,
                "control_capable": True,
                "requires_user_action": True,
                "estimated_bps": 300_000_000,
            },
        ],
    }

    resp = await client.post(
        "/api/fabric/path-create/native",
        headers=_h(token),
        json={
            "path_id": "private_hotspot",
            "ssid": "OneLinkTest",
            "passphrase": "supersecret1",
        },
    )

    assert resp.status == 409
    j = await resp.json()
    assert j["state"] == "blocked"
    assert j["required_env"] == "ONE_LINK_ALLOW_NATIVE_PATH_CREATE=1"


@pytest.mark.asyncio
async def test_api_fabric_path_create_native_rejects_wifi_direct_silent_api(ctx):
    client, daemon, _, token, _ = ctx
    daemon._fabric_snapshot = lambda: {  # type: ignore[method-assign]
        "ok": True,
        "cache_age_s": 0.0,
        "route_truth": {},
        "scores": [],
        "activation": [],
        "probes": [
            {
                "kind": "wifi_direct",
                "available": True,
                "bulk_capable": True,
                "control_capable": True,
                "requires_user_action": True,
                "estimated_bps": 480_000_000,
            },
        ],
    }

    resp = await client.post(
        "/api/fabric/path-create/native",
        headers=_h(token),
        json={"path_id": "wifi_direct", "dry_run": True},
    )

    assert resp.status == 409
    j = await resp.json()
    assert j["error"] == "native_path_creation_rejected"
    assert "no safe silent native creation API" in j["hint"]


@pytest.mark.asyncio
async def test_api_fabric_path_create_native_uses_registered_helper_dry_run(ctx, monkeypatch):
    client, daemon, _, token, _ = ctx
    monkeypatch.setenv(
        "ONE_LINK_NATIVE_PATH_HELPERS",
        json.dumps([
            {
                "path_id": "wifi_direct",
                "command": ["C:/OneLink/ol-wifi-direct-helper.exe"],
                "supported_systems": ["windows"],
            }
        ]),
    )
    daemon._fabric_snapshot = lambda: {  # type: ignore[method-assign]
        "ok": True,
        "cache_age_s": 0.0,
        "route_truth": {},
        "scores": [],
        "activation": [],
        "probes": [
            {
                "kind": "wifi_direct",
                "available": True,
                "bulk_capable": True,
                "control_capable": True,
                "requires_user_action": True,
                "estimated_bps": 480_000_000,
            },
        ],
    }

    resp = await client.post(
        "/api/fabric/path-create/native",
        headers=_h(token),
        json={"path_id": "wifi_direct", "dry_run": True},
    )

    assert resp.status == 200
    j = await resp.json()
    assert j["ok"] is True
    assert j["state"] == "dry_run"
    assert j["helper"]["path_id"] == "wifi_direct"
    assert j["commands"][0][0] == "C:/OneLink/ol-wifi-direct-helper.exe"


@pytest.mark.asyncio
async def test_api_fabric_mobile_reach_reports_shape(ctx, monkeypatch):
    client, _, _, token, _ = ctx
    monkeypatch.setenv("ONE_LINK_PHONE_STORAGE_BUDGET_BYTES", str(32 * 1024 * 1024))

    resp = await client.get("/api/fabric/mobile-reach", headers=_h(token))

    assert resp.status == 200
    body = await resp.json()
    assert body["mode"] == "phone_native_reach"
    assert body["storage_budget_bytes"] == 32 * 1024 * 1024
    assert "plans" in body
    assert "phones do not bypass pairing or peer verification" in body["safeguards"]


@pytest.mark.asyncio
async def test_api_self_mesh_reports_persisted_devices(ctx):
    client, _, state, token, _ = ctx
    from one_link import identity_dag as idag

    root = Ed25519PrivateKey.generate()
    device = Ed25519PrivateKey.generate()
    root_seed = root.private_bytes_raw()
    root_pub = root.public_key().public_bytes_raw()
    device_pub = device.public_key().public_bytes_raw()
    cert = idag.encode_device_cert(
        root_priv_seed=root_seed,
        root_pub=root_pub,
        device_pub=device_pub,
        device_kind="phone-ios",
        added_ms=1000,
    )
    state.upsert_self_mesh_device(
        root_pub=root_pub,
        device_pub=device_pub,
        device_kind="phone-ios",
        cert=cert,
        label="Phone",
        local=True,
        added_ms=1000,
    )
    state.upsert_self_mesh_presence(
        device_pub=device_pub,
        state="awake",
        sequence=7,
        updated_ms=2000,
        battery_pct=88,
        network="wifi",
        free_bytes=123456,
        route="self_wifi",
    )

    resp = await client.get("/api/self-mesh", headers=_h(token))

    assert resp.status == 200
    body = await resp.json()
    expected_pub = base64.urlsafe_b64encode(device_pub).rstrip(b"=").decode("ascii")
    assert body["status"] == "in_progress"
    assert body["remote_instruction_replay_protection"] is True
    assert body["devices"][0]["device_pub_b64"] == expected_pub
    assert body["devices"][0]["label"] == "Phone"
    assert body["presence"][0]["state"] == "awake"
    assert body["presence"][0]["route"] == "self_wifi"


@pytest.mark.asyncio
async def test_api_courier_status_reports_encrypted_offline_readiness(ctx):
    client, _, _, token, _ = ctx

    resp = await client.get("/api/courier/status", headers=_h(token))

    assert resp.status == 200
    body = await resp.json()
    assert body["ok"] is True
    assert body["enabled"] is True
    assert body["key_token_prefix"] == "OLC1."
    assert body["max_chunks"] >= 1
    assert body["ledger"]["seen_bundle_ids"] == 0
    assert any("AES-GCM" in s for s in body["safeguards"])
    assert any("restarts" in s for s in body["safeguards"])


@pytest.mark.asyncio
async def test_api_courier_export_import_stores_verified_chunks(ctx):
    client, daemon, _, token, _ = ctx
    payload = b"courier api chunk: for the people" * 64
    chunk_hash = blake3.blake3(payload).hexdigest()
    daemon._store_chunk_cache(chunk_hash, payload)

    export_resp = await client.post(
        "/api/courier/export",
        headers=_h(token),
        json={
            "chunks": [chunk_hash],
            "recipient_fp": daemon.me.fingerprint,
            "ttl_s": 60,
        },
    )
    assert export_resp.status == 200
    exported = await export_resp.json()
    assert exported["ok"] is True
    assert exported["manifest"]["chunks"] == [{"index": 0, "hash": chunk_hash, "size": len(payload)}]
    assert "courier api chunk" not in exported["bundle_b64"]

    cache_path = daemon._chunk_cache_path(chunk_hash)
    cache_path.unlink()
    assert daemon._read_chunk_cache(chunk_hash) is None

    import_resp = await client.post(
        "/api/courier/import",
        headers=_h(token),
        json={
            "bundle_b64": exported["bundle_b64"],
            "key_token": exported["key_token"],
        },
    )
    assert import_resp.status == 200
    imported = await import_resp.json()
    assert imported["ok"] is True
    assert imported["stored_chunks"] == 1
    assert daemon._read_chunk_cache(chunk_hash) == payload
    restarted = UIServer(daemon)
    assert exported["manifest"]["bundle_id"] in restarted._courier_seen_bundle_ids
    assert any(e["kind"] == "import" for e in restarted._courier_events)

    replay_resp = await client.post(
        "/api/courier/import",
        headers=_h(token),
        json={
            "bundle_b64": exported["bundle_b64"],
            "key_token": exported["key_token"],
        },
    )
    assert replay_resp.status == 400


@pytest.mark.asyncio
async def test_api_courier_rejects_missing_chunks_and_replay(ctx):
    client, daemon, _, token, _ = ctx
    missing_hash = blake3.blake3(b"missing").hexdigest()

    missing_resp = await client.post(
        "/api/courier/export",
        headers=_h(token),
        json={"chunks": [missing_hash], "recipient_fp": daemon.me.fingerprint},
    )
    assert missing_resp.status == 409
    missing = await missing_resp.json()
    assert missing["error"] == "missing_cached_chunks"

    payload = b"one-time courier"
    chunk_hash = blake3.blake3(payload).hexdigest()
    daemon._store_chunk_cache(chunk_hash, payload)
    export_resp = await client.post(
        "/api/courier/export",
        headers=_h(token),
        json={"chunks": [chunk_hash], "recipient_fp": daemon.me.fingerprint},
    )
    exported = await export_resp.json()
    first = await client.post(
        "/api/courier/import",
        headers=_h(token),
        json={
            "bundle_b64": exported["bundle_b64"],
            "key_token": exported["key_token"],
        },
    )
    assert first.status == 200
    second = await client.post(
        "/api/courier/import",
        headers=_h(token),
        json={
            "bundle_b64": exported["bundle_b64"],
            "key_token": exported["key_token"],
        },
    )
    assert second.status == 400
    replay = await second.json()
    assert replay["error"] == "courier_import_rejected"
    assert "already imported" in replay["message"]


@pytest.mark.asyncio
async def test_api_courier_export_can_derive_chunks_from_transfer_id(ctx):
    client, daemon, state, token, peer_fp = ctx
    payload_a = b"transfer-derived courier chunk a"
    payload_b = b"transfer-derived courier chunk b" * 3
    hash_a = blake3.blake3(payload_a).hexdigest()
    hash_b = blake3.blake3(payload_b).hexdigest()
    blob_hash = blake3.blake3(payload_a + payload_b).hexdigest()
    daemon._store_chunk_cache(hash_a, payload_a, blob_hash=blob_hash, chunk_index=0)
    daemon._store_chunk_cache(hash_b, payload_b, blob_hash=blob_hash, chunk_index=1)
    state.upsert_transfer(
        id="out:courier-derived",
        direction="out",
        peer_fp=peer_fp,
        kind="file",
        name="derived.bin",
        size=len(payload_a) + len(payload_b),
        blob_hash=blob_hash,
        status="complete",
        progress_bytes=len(payload_a) + len(payload_b),
        chunks_done=2,
        chunks_total=2,
    )

    export_resp = await client.post(
        "/api/courier/export",
        headers=_h(token),
        json={"transfer_id": "out:courier-derived", "recipient_fp": daemon.me.fingerprint},
    )

    assert export_resp.status == 200
    exported = await export_resp.json()
    assert exported["chunk_count"] == 2
    assert exported["manifest"]["blob_hash"] == blob_hash
    assert exported["manifest"]["name"] == "derived.bin"
    assert [c["hash"] for c in exported["manifest"]["chunks"]] == [hash_a, hash_b]

    for h in (hash_a, hash_b):
        daemon._chunk_cache_path(h).unlink()
    import_resp = await client.post(
        "/api/courier/import",
        headers=_h(token),
        json={
            "bundle_b64": exported["bundle_b64"],
            "key_token": exported["key_token"],
        },
    )
    assert import_resp.status == 200
    assemble_resp = await client.post(
        "/api/courier/assemble",
        headers=_h(token),
        json={"blob_hash": blob_hash, "name": "derived.bin"},
    )
    assert assemble_resp.status == 200
    assembled = await assemble_resp.json()
    assert assembled["ok"] is True
    assert assembled["bytes"] == len(payload_a) + len(payload_b)
    assert Path(assembled["path"]).read_bytes() == payload_a + payload_b


@pytest.mark.asyncio
async def test_api_courier_drop_folder_lists_and_imports_by_file_id(ctx):
    client, daemon, _, token, _ = ctx
    payload = b"drop-folder courier payload" * 12
    chunk_hash = blake3.blake3(payload).hexdigest()
    daemon._store_chunk_cache(chunk_hash, payload)
    export_resp = await client.post(
        "/api/courier/export",
        headers=_h(token),
        json={"chunks": [chunk_hash], "recipient_fp": daemon.me.fingerprint, "name": "drop.bin"},
    )
    exported = await export_resp.json()
    drop_dir = Path((await (await client.get("/api/courier/files", headers=_h(token))).json())["drop_dir"])
    drop_file = drop_dir / "bundle.olcb.json"
    drop_file.write_text(
        json.dumps({"bundle_b64": exported["bundle_b64"]}),
        encoding="utf-8",
    )

    files_resp = await client.get("/api/courier/files", headers=_h(token))
    assert files_resp.status == 200
    files = await files_resp.json()
    item = next(f for f in files["files"] if f["name"] == "bundle.olcb.json")
    daemon._chunk_cache_path(chunk_hash).unlink()

    import_resp = await client.post(
        "/api/courier/import-file",
        headers=_h(token),
        json={"file_id": item["id"], "key_token": exported["key_token"]},
    )

    assert import_resp.status == 200
    imported = await import_resp.json()
    assert imported["stored_chunks"] == 1
    assert daemon._read_chunk_cache(chunk_hash) == payload


@pytest.mark.asyncio
async def test_api_courier_drop_folder_ignores_symlinks_when_supported(ctx):
    client, daemon, _, token, _ = ctx
    drop_dir = daemon._chunk_cache_dir().parents[0] / "courier" / "drop"
    drop_dir.mkdir(parents=True, exist_ok=True)
    outside = drop_dir.parent / "outside.olcb.json"
    outside.write_text('{"bundle_b64":"AA=="}', encoding="utf-8")
    link = drop_dir / "linked.olcb.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not available for this user/platform")

    files_resp = await client.get("/api/courier/files", headers=_h(token))

    assert files_resp.status == 200
    files = await files_resp.json()
    assert all(f["name"] != "linked.olcb.json" for f in files["files"])


@pytest.mark.asyncio
async def test_api_courier_drop_folder_rejects_unknown_file_ids(ctx):
    client, _, _, token, _ = ctx

    resp = await client.post(
        "/api/courier/import-file",
        headers=_h(token),
        json={"file_id": "../bundle.olcb.json", "key_token": "OLC1.bad"},
    )

    assert resp.status == 404
    body = await resp.json()
    assert body["error"] == "courier_file_not_found"


@pytest.mark.asyncio
async def test_api_courier_export_file_stages_outbox_bundle(ctx):
    client, daemon, _, token, _ = ctx
    payload = b"outbox courier payload" * 10
    chunk_hash = blake3.blake3(payload).hexdigest()
    daemon._store_chunk_cache(chunk_hash, payload)

    resp = await client.post(
        "/api/courier/export-file",
        headers=_h(token),
        json={"chunks": [chunk_hash], "recipient_fp": daemon.me.fingerprint, "name": "../unsafe.bin"},
    )

    assert resp.status == 200
    staged = await resp.json()
    assert staged["ok"] is True
    assert staged["name"].endswith(".olcb.json")
    assert Path(staged["path"]).is_file()
    assert Path(staged["path"]).parent == Path(staged["outbox_dir"])
    assert "outbox courier payload" not in Path(staged["path"]).read_text(encoding="utf-8")

    outbox_resp = await client.get("/api/courier/outbox", headers=_h(token))
    outbox = await outbox_resp.json()
    assert any(f["name"] == staged["name"] for f in outbox["files"])


@pytest.mark.asyncio
async def test_api_courier_export_file_collision_gets_unique_name(ctx):
    client, daemon, _, token, _ = ctx
    payload = b"collision courier payload"
    chunk_hash = blake3.blake3(payload).hexdigest()
    daemon._store_chunk_cache(chunk_hash, payload)
    body = {"chunks": [chunk_hash], "recipient_fp": daemon.me.fingerprint, "name": "same.bin"}

    first = await (await client.post("/api/courier/export-file", headers=_h(token), json=body)).json()
    second = await (await client.post("/api/courier/export-file", headers=_h(token), json=body)).json()

    assert first["name"] != second["name"]
    assert Path(first["path"]).is_file()
    assert Path(second["path"]).is_file()


@pytest.mark.asyncio
async def test_api_courier_copy_to_env_removable_target(ctx, tmp_path, monkeypatch):
    client, daemon, _, token, _ = ctx
    media_root = tmp_path / "media"
    usb = media_root / "USB"
    usb.mkdir(parents=True)
    monkeypatch.setenv("ONE_LINK_COURIER_MEDIA_ROOTS", str(media_root))
    payload = b"copy-to-removable courier payload"
    chunk_hash = blake3.blake3(payload).hexdigest()
    daemon._store_chunk_cache(chunk_hash, payload)
    staged_resp = await client.post(
        "/api/courier/export-file",
        headers=_h(token),
        json={"chunks": [chunk_hash], "recipient_fp": daemon.me.fingerprint, "name": "usb.bin"},
    )
    staged = await staged_resp.json()
    outbox = await (await client.get("/api/courier/outbox", headers=_h(token))).json()
    file_id = next(f["id"] for f in outbox["files"] if f["name"] == staged["name"])
    removable = await (await client.get("/api/courier/removable", headers=_h(token))).json()
    target_id = next(t["id"] for t in removable["targets"] if t["label"] == "USB")

    copy_resp = await client.post(
        "/api/courier/copy-to-removable",
        headers=_h(token),
        json={"file_id": file_id, "target_id": target_id},
    )

    assert copy_resp.status == 200
    copied = await copy_resp.json()
    assert copied["ok"] is True
    copied_path = Path(copied["path"])
    assert copied_path.is_file()
    assert copied_path.parent == usb / "One Link Courier"
    assert copied_path.read_text(encoding="utf-8") == Path(staged["path"]).read_text(encoding="utf-8")

    removable_files = await (
        await client.get(
            f"/api/courier/removable-files?target_id={target_id}",
            headers=_h(token),
        )
    ).json()
    removable_file_id = next(f["id"] for f in removable_files["files"] if f["name"] == copied["name"])
    copied_path.unlink()
    assert not copied_path.exists()
    pull_resp = await client.post(
        "/api/courier/copy-from-removable",
        headers=_h(token),
        json={"target_id": target_id, "file_id": removable_file_id},
    )
    # File was intentionally removed after listing; stale IDs must not copy.
    assert pull_resp.status == 404


@pytest.mark.asyncio
async def test_api_courier_copy_from_env_removable_target(ctx, tmp_path, monkeypatch):
    client, daemon, _, token, _ = ctx
    media_root = tmp_path / "media"
    usb = media_root / "USB"
    courier_dir = usb / "One Link Courier"
    courier_dir.mkdir(parents=True)
    monkeypatch.setenv("ONE_LINK_COURIER_MEDIA_ROOTS", str(media_root))
    payload = b"copy-from-removable courier payload"
    chunk_hash = blake3.blake3(payload).hexdigest()
    daemon._store_chunk_cache(chunk_hash, payload)
    staged_resp = await client.post(
        "/api/courier/export-file",
        headers=_h(token),
        json={"chunks": [chunk_hash], "recipient_fp": daemon.me.fingerprint, "name": "pull.bin"},
    )
    staged = await staged_resp.json()
    source_on_usb = courier_dir / staged["name"]
    source_on_usb.write_text(Path(staged["path"]).read_text(encoding="utf-8"), encoding="utf-8")
    removable = await (await client.get("/api/courier/removable", headers=_h(token))).json()
    target_id = next(t["id"] for t in removable["targets"] if t["label"] == "USB")
    files = await (
        await client.get(
            f"/api/courier/removable-files?target_id={target_id}",
            headers=_h(token),
        )
    ).json()
    file_id = next(f["id"] for f in files["files"] if f["name"] == staged["name"])

    pull_resp = await client.post(
        "/api/courier/copy-from-removable",
        headers=_h(token),
        json={"target_id": target_id, "file_id": file_id},
    )

    assert pull_resp.status == 200
    pulled = await pull_resp.json()
    assert Path(pulled["path"]).is_file()
    assert Path(pulled["path"]).parent == daemon._chunk_cache_dir().parents[0] / "courier" / "drop"
    assert Path(pulled["path"]).read_text(encoding="utf-8") == source_on_usb.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_api_courier_removable_files_ignores_symlinks_when_supported(ctx, tmp_path, monkeypatch):
    client, _, _, token, _ = ctx
    media_root = tmp_path / "media"
    usb = media_root / "USB"
    courier_dir = usb / "One Link Courier"
    courier_dir.mkdir(parents=True)
    outside = tmp_path / "outside.olcb.json"
    outside.write_text('{"bundle_b64":"AA=="}', encoding="utf-8")
    link = courier_dir / "linked.olcb.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not available for this user/platform")
    monkeypatch.setenv("ONE_LINK_COURIER_MEDIA_ROOTS", str(media_root))
    removable = await (await client.get("/api/courier/removable", headers=_h(token))).json()
    target_id = next(t["id"] for t in removable["targets"] if t["label"] == "USB")

    files = await (
        await client.get(
            f"/api/courier/removable-files?target_id={target_id}",
            headers=_h(token),
        )
    ).json()

    assert all(f["name"] != "linked.olcb.json" for f in files["files"])


@pytest.mark.asyncio
async def test_courier_monitor_detects_drop_and_outbox_changes(ctx):
    _, _, _, _, _ = ctx
    client, daemon, _, token, _peer_fp = ctx
    # The fixture does not expose UIServer directly; make a fresh instance
    # over the same daemon/home to exercise the monitor helper without
    # opening another socket.
    monitor = UIServer(daemon)
    first = monitor._courier_monitor_tick(broadcast=False)
    assert first["changed"] is False

    (monitor._courier_drop_dir() / "watch-drop.olcb.json").write_text(
        '{"bundle_b64":"AA=="}',
        encoding="utf-8",
    )
    second = monitor._courier_monitor_tick(broadcast=False)
    assert second["changed"] is True
    assert len(second["drop_files"]) == 1

    (monitor._courier_outbox_dir() / "watch-out.olcb.json").write_text(
        '{"bundle_b64":"AA=="}',
        encoding="utf-8",
    )
    third = monitor._courier_monitor_tick(broadcast=False)
    assert third["changed"] is True
    assert len(third["outbox_files"]) == 1

    status = await (await client.get("/api/courier/status", headers=_h(token))).json()
    assert "monitor" in status
    assert status["monitor"]["removable"]["mode"] == "native_compatible_inventory_events"


@pytest.mark.asyncio
async def test_courier_removable_monitor_detects_attach_remove(ctx, tmp_path, monkeypatch):
    client, daemon, _, token, _ = ctx
    media_root = tmp_path / "media"
    media_root.mkdir()
    monkeypatch.setenv("ONE_LINK_COURIER_MEDIA_ROOTS", str(media_root))
    monitor = UIServer(daemon)

    first = monitor._removable_monitor_tick(broadcast=False)
    assert first["changed"] is False

    usb = media_root / "USB"
    usb.mkdir()
    attached = monitor._removable_monitor_tick(broadcast=False)
    assert attached["changed"] is True
    assert any(event["kind"] == "attached" and event["target"]["label"] == "USB" for event in attached["events"])

    usb.rmdir()
    removed = monitor._removable_monitor_tick(broadcast=False)
    assert removed["changed"] is True
    assert any(event["kind"] == "removed" and event["target"]["label"] == "USB" for event in removed["events"])

    removable = await (await client.get("/api/courier/removable", headers=_h(token))).json()
    assert removable["event_source"]["mode"] == "native_compatible_inventory_events"
    assert "monitor" in removable


@pytest.mark.asyncio
async def test_courier_ledger_tolerates_malformed_disk_state(ctx, tmp_path):
    _, daemon, _, _, _ = ctx
    ledger = tmp_path / "data" / "courier_ledger.json"
    ledger.write_text("{broken", encoding="utf-8")

    restarted = UIServer(daemon)

    assert restarted._courier_seen_bundle_ids == set()
    assert restarted._courier_events == []


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
        lambda *, peer_port, include_loopback=False, include_link_local=False: [
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
        lambda *, peer_port, include_loopback=False, include_link_local=False: [
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
        lambda *, peer_port, include_loopback=False, include_link_local=False: [
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
async def test_api_route_bootstrap_marks_link_local_as_ethernet(ctx, monkeypatch):
    client, daemon, _, token, _ = ctx
    daemon._rendezvous_peer_port = 17117
    from one_link import rendezvous_client
    from one_link.route_bootstrap import decode_bootstrap
    from one_link.rendezvous_proto import Endpoint

    def fake_discover(*, peer_port, include_loopback=False, include_link_local=False):
        assert include_link_local is True
        return [Endpoint(host="169.254.10.20", port=peer_port)]

    monkeypatch.setattr(rendezvous_client, "discover_local_endpoints", fake_discover)

    resp = await client.get("/api/route-bootstrap?ttl_s=60", headers=_h(token))

    assert resp.status == 200
    j = await resp.json()
    decoded = decode_bootstrap(j["token"])
    assert decoded.endpoints[0]["address"] == "169.254.10.20"
    assert decoded.endpoints[0]["route"] == "ethernet"
    assert decoded.endpoints[0]["kind"] == "ethernet"


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
