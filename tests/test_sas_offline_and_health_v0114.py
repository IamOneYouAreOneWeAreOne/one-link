"""v0.11.4 — SAS works offline + diagnostics resilience.

Two bug fixes that surfaced from real screenshots:

1. SAS shows "(unavailable)" for an offline paired peer, blocking
   in-person verification. SAS is purely deterministic from the two
   pubkeys, so requiring the peer to be live on mDNS was a leftover
   constraint. Fix: api_get_sas falls back to the stored pubkey
   when mDNS doesn't have the peer right now.

2. /api/debug/health returned 401 when the auth cookie expired,
   defeating the diagnostics modal's whole purpose ("open this
   when something feels broken"). The endpoint leaks no PII and
   the daemon binds to 127.0.0.1 only, so it's safe to skip the
   token guard.

Plus belt-and-suspenders: any other 401 from the api wrapper now
triggers a clear "Session expired — relaunch" banner instead of a
cryptic per-endpoint message.
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


def _identity(host: str = "host") -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname=host,
    )


@pytest_asyncio.fixture
async def http(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    # Add a paired peer with a real pubkey but DON'T add it to mDNS —
    # this is the "offline paired peer" case.
    peer_sk = Ed25519PrivateKey.generate()
    peer_pub = peer_sk.public_key().public_bytes_raw()
    peer_fp = fingerprint_of(peer_pub)
    state.upsert_peer(
        fingerprint=peer_fp, short_id=peer_fp[:8],
        pubkey=peer_pub, hostname="bob",
    )
    state.set_peer_trust(peer_fp, "pinned")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None  # No mDNS — peer is offline.
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client, daemon, state, server.token, peer_fp, peer_pub
    finally:
        await client.close()
        state.close()


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── SAS works for offline paired peers ───────────────────────

@pytest.mark.asyncio
async def test_sas_works_for_offline_paired_peer(http):
    """The whole point of v0.11.4 — paired peer offline, SAS still
    computes from the stored pubkey."""
    client, _, _, token, peer_fp, _ = http
    resp = await client.get(
        f"/api/peers/{peer_fp}/sas", headers=_h(token),
    )
    assert resp.status == 200, await resp.text()
    j = await resp.json()
    assert "sas" in j
    assert j["sas"]
    assert "formatted" in j


@pytest.mark.asyncio
async def test_sas_is_deterministic_from_pubkeys(http):
    """SAS must be the same value across calls — both ends of the
    in-person verification need to read the same digits/art."""
    client, _, _, token, peer_fp, _ = http
    r1 = await (await client.get(
        f"/api/peers/{peer_fp}/sas", headers=_h(token),
    )).json()
    r2 = await (await client.get(
        f"/api/peers/{peer_fp}/sas", headers=_h(token),
    )).json()
    assert r1["sas"] == r2["sas"]
    assert r1["formatted"] == r2["formatted"]


@pytest.mark.asyncio
async def test_sas_404_only_when_no_pubkey_at_all(http):
    """The 404 path should ONLY fire when truly nothing is on file —
    not for an offline-but-known paired peer."""
    client, _, _, token, _, _ = http
    # Random fingerprint that's neither on mDNS nor in the peer DB.
    resp = await client.get(
        f"/api/peers/{'00' * 32}/sas", headers=_h(token),
    )
    assert resp.status == 404


@pytest.mark.asyncio
async def test_sas_matches_compute_sas_directly(http):
    """The endpoint must return exactly what the underlying
    compute_sas helper returns from the SAME pubkeys. Pin so a
    refactor can't accidentally double-hash or swap argument order."""
    client, daemon, _, token, peer_fp, peer_pub = http
    from one_link.pairing import compute_sas
    expected = compute_sas(daemon.me.public_bytes, peer_pub)
    resp = await client.get(
        f"/api/peers/{peer_fp}/sas", headers=_h(token),
    )
    j = await resp.json()
    assert j["sas"] == expected


# ───────── /api/debug/health is auth-free ───────────────────────────

@pytest.mark.asyncio
async def test_debug_health_works_without_auth(http):
    """The diagnostics surface must work even when the session
    cookie expires — that's the whole point of the modal."""
    client, _, _, _, _, _ = http
    resp = await client.get("/api/debug/health")  # No headers.
    assert resp.status == 200
    j = await resp.json()
    assert "checks" in j or "ok" in j


@pytest.mark.asyncio
async def test_debug_health_works_with_auth(http):
    """Authed requests still pass — un-guarding shouldn't make the
    endpoint reject token-bearing callers."""
    client, _, _, token, _, _ = http
    resp = await client.get("/api/debug/health", headers=_h(token))
    assert resp.status == 200


@pytest.mark.asyncio
async def test_other_endpoints_still_guarded(http):
    """Belt-and-suspenders: only /api/debug/health is auth-free.
    Confirm that some adjacent endpoint still 401s without auth."""
    client, _, _, _, _, _ = http
    resp = await client.get("/api/peers")
    assert resp.status == 401


# ───────── Frontend: 401 banner ─────────────────────────────────────

def test_global_401_handler_present(index_html: str):
    """Pin _maybe401 + the banner so a refactor can't quietly drop
    the global 401 handling."""
    assert "function _maybe401(status)" in index_html
    assert "function showSessionExpiredBanner()" in index_html


def test_session_expired_banner_class_styled(index_html: str):
    """The banner needs visible CSS or it's invisible noise."""
    assert ".session-expired-banner {" in index_html
    # Sticky to top so the user can't miss it.
    assert "position: fixed" in index_html


def test_api_wrappers_call_maybe401(index_html: str):
    """Every fetch path in the api object must invoke _maybe401 so
    a 401 from any endpoint surfaces the banner. Without this only
    /api/foo would trigger it; the global session-expired UX is
    the whole point. v0.21.x grew the per-verb bodies (AbortController
    + _apiError plumbing) so each verb now spans more chars; the
    search window needs to be wide enough to cover get + post + del
    + upload (the 4 verbs that actually hit the network)."""
    idx = index_html.find("const api = {")
    assert idx > 0
    snippet = index_html[idx:idx + 4000]
    # Each network-touching verb (get, post, del, upload) calls _maybe401.
    assert snippet.count("_maybe401(r.status)") >= 4


def test_session_expired_banner_has_relaunch_guidance(index_html: str):
    """The banner must tell the user WHAT to do, not just announce
    a problem."""
    idx = index_html.find("function showSessionExpiredBanner()")
    snippet = index_html[idx:idx + 3200]
    # The actionable instruction is the load-bearing UX: without it
    # the user is stuck staring at a banner that says "expired".
    # 2026-06-04: the banner is now case-aware — when a token is
    # stashed it offers "Reload" (which works); when none is, it tells
    # the user to re-open from the desktop shortcut / tray (the only
    # real fix) rather than a Reload button that would re-land on the
    # banner. Either way it must give a concrete next step.
    assert "Reload" in snippet
    assert "desktop shortcut" in snippet or "tray" in snippet


def test_session_expired_banner_only_shows_once(index_html: str):
    """If five endpoints all 401 in quick succession, we should
    NOT stack five banners. Pin the once-only flag."""
    assert "_sessionExpiredBannerShown" in index_html


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_bumped(index_html: str):
    from one_link import __version__
    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
