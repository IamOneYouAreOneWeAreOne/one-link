"""Tests for the multi-modal discovery + invite + install endpoints.

Endpoints under test:

  GET  /api/discover/all       — buckets devices ready-to-pair /
                                 pairable / other_gear + network
                                 health.
  POST /api/discover/invite    — mints a one-shot 6-char invite
                                 code + landing URL + expiry.
  GET  /install?code=ABC123    — UA-sniffed install landing page
                                 served to the invited device.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

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
    pub = sk.public_key()
    pub_bytes = pub.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="discover-test",
    )


@pytest_asyncio.fixture
async def ctx(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None

    # Patch the heavy lan_discovery.full_scan to return a small,
    # deterministic device set — tests should not hit the real
    # network or take seconds.
    from one_link import lan_discovery as ld

    async def _fake_full_scan(timeout_s: float = 6.0, **kw):
        return [
            ld.DiscoveredDevice(
                ip="192.168.1.50", mac="aa:bb:cc:dd:ee:01",
                hostname="sarahs-iphone", vendor="Apple",
                kind="phone", sources=["mdns", "arp"],
                confidence=0.95,
            ),
            ld.DiscoveredDevice(
                ip="192.168.1.51", mac="aa:bb:cc:dd:ee:02",
                hostname="dads-tv", vendor="Sony",
                kind="tv", sources=["ssdp"],
                confidence=0.6,
            ),
            ld.DiscoveredDevice(
                ip="192.168.1.52", mac="aa:bb:cc:dd:ee:03",
                hostname="", vendor="",
                kind="unknown", sources=["arp"],
                confidence=0.3,
            ),
        ]

    monkeypatch.setattr(ld, "full_scan", _fake_full_scan)

    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client, server.token
    finally:
        await client.close()
        state.close()


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ─── /api/discover/all ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_discover_all_requires_auth(ctx):
    client, _ = ctx
    resp = await client.get("/api/discover/all")
    assert resp.status == 401


@pytest.mark.asyncio
async def test_discover_all_returns_buckets(ctx):
    client, token = ctx
    resp = await client.get("/api/discover/all", headers=_h(token))
    assert resp.status == 200
    body = await resp.json()
    # The contract is three buckets + network health.
    for key in ("ready_to_pair", "pairable", "other_gear", "network_health"):
        assert key in body, f"missing key {key} in {body!r}"
    # iPhone should land in pairable; TV in other_gear; unknown
    # gets bucketed somewhere (depends on confidence threshold).
    pairable_ips = [d["ip"] for d in body["pairable"]]
    other_ips = [d["ip"] for d in body["other_gear"]]
    assert "192.168.1.50" in pairable_ips
    assert "192.168.1.51" in other_ips


# ─── /api/discover/invite ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_invite_requires_auth(ctx):
    client, _ = ctx
    resp = await client.post("/api/discover/invite", json={})
    assert resp.status == 401


@pytest.mark.asyncio
async def test_invite_mints_short_code_and_landing(ctx):
    client, token = ctx
    resp = await client.post(
        "/api/discover/invite",
        headers=_h(token),
        json={"target_label": "Sarah's iPhone"},
    )
    assert resp.status == 200
    body = await resp.json()
    assert "code" in body and len(body["code"]) >= 6
    # Codes must avoid easily-confused characters.
    for ch in body["code"]:
        assert ch not in "O0I1", f"confusable char {ch!r} in invite code"
    assert body["landing_url"].startswith("http://")
    assert f"/install?code={body['code']}" in body["landing_url"]
    assert body["expires_in_seconds"] == 300  # 5 minutes


@pytest.mark.asyncio
async def test_invite_codes_are_unique(ctx):
    client, token = ctx
    seen = set()
    for _ in range(8):
        resp = await client.post(
            "/api/discover/invite", headers=_h(token), json={},
        )
        body = await resp.json()
        seen.add(body["code"])
    # 8 random 6-char codes from a 32-char alphabet → collision is
    # astronomically unlikely (~10^-7 birthday probability).
    assert len(seen) == 8


# ─── /install landing page ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_install_landing_does_not_require_auth(ctx):
    # The landing page must be reachable WITHOUT auth — it's served
    # to the invited device that hasn't installed One Link yet.
    client, _ = ctx
    resp = await client.get("/install?code=NONESUCH")
    assert resp.status == 200, "landing page must be public"


@pytest.mark.asyncio
async def test_install_landing_with_invalid_code_renders_expired(ctx):
    client, _ = ctx
    resp = await client.get("/install?code=NEVERMINTED")
    assert resp.status == 200
    text = await resp.text()
    # Should NOT echo the code (no leakage).
    assert "NEVERMINTED" not in text
    # Should hint at expiry / new invite.
    lower = text.lower()
    assert "expired" in lower or "ask" in lower or "invite" in lower


@pytest.mark.asyncio
async def test_install_landing_ua_sniffs_ios(ctx):
    client, token = ctx
    # First mint a valid code.
    mint = await client.post(
        "/api/discover/invite", headers=_h(token), json={},
    )
    code = (await mint.json())["code"]
    # iPhone UA.
    ios_ua = (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.0 Mobile/15E148 Safari/604.1"
    )
    resp = await client.get(
        f"/install?code={code}", headers={"User-Agent": ios_ua},
    )
    assert resp.status == 200
    text = await resp.text()
    lower = text.lower()
    # Per-OS landing must mention the device family.
    assert "iphone" in lower or "ios" in lower or "ipad" in lower
    # Code must appear on the page.
    assert code in text


@pytest.mark.asyncio
async def test_install_landing_ua_sniffs_android(ctx):
    client, token = ctx
    mint = await client.post(
        "/api/discover/invite", headers=_h(token), json={},
    )
    code = (await mint.json())["code"]
    android_ua = (
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36"
    )
    resp = await client.get(
        f"/install?code={code}", headers={"User-Agent": android_ua},
    )
    text = await resp.text()
    lower = text.lower()
    assert "android" in lower
    assert code in text


@pytest.mark.asyncio
async def test_install_landing_has_no_outside_assets(ctx):
    """Sovereignty floor: the landing page must be self-contained.
    No CDN, no font from Google, no analytics, no <script src> to
    any outside host."""
    client, token = ctx
    mint = await client.post(
        "/api/discover/invite", headers=_h(token), json={},
    )
    code = (await mint.json())["code"]
    resp = await client.get(f"/install?code={code}")
    text = await resp.text()
    forbidden = [
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com",
        "googletagmanager",
        "google-analytics",
        "unpkg.com",
        "ga.js",
        "gtag.js",
    ]
    for needle in forbidden:
        assert needle not in text, f"sovereignty floor violation: {needle}"
