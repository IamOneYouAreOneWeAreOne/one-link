"""v0.21.x persistent UI sessions: the cookie that outlives daemon
token rotation. Tests cover:

  - state.ui_sessions table mechanics (create/touch/lookup/revoke/
    revoke_all/prune)
  - server auth path: _check_token accepts a valid ol_session cookie
    even when the ol_ui token doesn't match
  - bootstrap path: ?t=<valid> mints session cookie + JS-readable
    marker; existing session is rolled forward, not duplicated
  - revoke endpoints: single + all; clearing caller's cookie on
    own-session revoke
  - access-denied page self-heal: marker cookie triggers JS redirect
"""
from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import (
    COOKIE_NAME, SESSION_COOKIE_NAME, SESSION_PRESENT_MARKER_COOKIE,
    UIServer,
)
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    return Identity(
        private=sk, public=sk.public_key(), public_bytes=pub,
        fingerprint=fingerprint_of(pub), short_id=fingerprint_of(pub)[:8],
        hostname="sess-host",
    )


@pytest_asyncio.fixture
async def ctx(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = MagicMock()
    daemon.discovery.registry = MagicMock()
    daemon.discovery.registry.list = MagicMock(return_value=[])
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield {
            "client": client, "server": server, "daemon": daemon,
            "state": state, "token": server.token,
        }
    finally:
        await client.close()
        state.close()


# ── state-layer mechanics ─────────────────────────────────────────


def test_create_returns_64hex_uuid(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    sess = s.create_ui_session(user_agent="Mozilla/5.0 Firefox/120.0")
    sid = sess["session_uuid"]
    assert len(sid) == 64
    assert all(c in "0123456789abcdef" for c in sid)
    assert sess["label"] == "Firefox on Unknown OS"  # no OS substring
    s.close()


def test_label_recognises_modern_edge_ua(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    sess = s.create_ui_session(
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/120 Safari/537.36 Edg/120.0"
        ),
    )
    assert sess["label"] == "Edge on Windows"
    s.close()


def test_touch_updates_last_seen(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    sess = s.create_ui_session()
    initial = sess["last_seen_ms"]
    time.sleep(0.005)
    assert s.touch_ui_session(sess["session_uuid"]) is True
    after = s.lookup_ui_session(sess["session_uuid"])
    assert after["last_seen_ms"] > initial
    s.close()


def test_touch_rejects_bogus(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    assert s.touch_ui_session("") is False
    assert s.touch_ui_session("not-a-uuid") is False
    assert s.touch_ui_session(None) is False  # type: ignore[arg-type]
    s.close()


def test_revoked_session_no_longer_touches(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    sess = s.create_ui_session()
    assert s.revoke_ui_session(sess["session_uuid"]) is True
    assert s.touch_ui_session(sess["session_uuid"]) is False
    assert s.lookup_ui_session(sess["session_uuid"]) is None
    # Re-revoking a revoked session is a no-op (idempotent).
    assert s.revoke_ui_session(sess["session_uuid"]) is False
    s.close()


def test_revoke_all_counts_active(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    s.create_ui_session(user_agent="A")
    s.create_ui_session(user_agent="B")
    s.create_ui_session(user_agent="C")
    # Pre-revoke one — it shouldn't be re-counted.
    one = s.list_ui_sessions()[0]["session_uuid"]
    s.revoke_ui_session(one)
    assert s.revoke_all_ui_sessions() == 2


def test_list_excludes_revoked_by_default(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    a = s.create_ui_session()
    b = s.create_ui_session()
    s.revoke_ui_session(a["session_uuid"])
    active = s.list_ui_sessions()
    assert len(active) == 1
    assert active[0]["session_uuid"] == b["session_uuid"]
    all_rows = s.list_ui_sessions(include_revoked=True)
    assert len(all_rows) == 2
    s.close()


def test_prune_drops_stale(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    s.create_ui_session()
    old_ts = int(time.time() * 1000) + 10_000  # all rows fall under this
    pruned = s.prune_expired_ui_sessions(older_than_ms=old_ts)
    assert pruned == 1
    s.close()


# ── server auth path: cookie acceptance ──────────────────────────


@pytest.mark.asyncio
async def test_session_cookie_accepted_when_token_rotates(ctx):
    """The whole point of this feature: a browser holding ol_session
    keeps authing even after the daemon's UI token rotates to a new
    value (which would normally invalidate ol_ui)."""
    sess = ctx["state"].create_ui_session(user_agent="Mozilla/5.0")
    # Token rotation simulation: change the server token in-place.
    # The session cookie is unrelated and should still work.
    ctx["server"].token = "ROTATED-" + "x" * 50
    r = await ctx["client"].get(
        "/api/me",
        cookies={SESSION_COOKIE_NAME: sess["session_uuid"]},
    )
    assert r.status == 200, await r.text()


@pytest.mark.asyncio
async def test_bogus_session_cookie_is_rejected(ctx):
    r = await ctx["client"].get(
        "/api/me",
        cookies={SESSION_COOKIE_NAME: "not-a-real-uuid"},
    )
    assert r.status == 401


@pytest.mark.asyncio
async def test_revoked_session_cookie_rejected(ctx):
    sess = ctx["state"].create_ui_session(user_agent="Mozilla/5.0")
    assert ctx["state"].revoke_ui_session(sess["session_uuid"])
    ctx["server"].token = "ROTATED"
    r = await ctx["client"].get(
        "/api/me",
        cookies={SESSION_COOKIE_NAME: sess["session_uuid"]},
    )
    assert r.status == 401


@pytest.mark.asyncio
async def test_short_cookie_rejected_without_db_lookup(ctx):
    """Defense in depth: cookies under 32 chars short-circuit before
    hitting the SQL layer."""
    r = await ctx["client"].get(
        "/api/me",
        cookies={SESSION_COOKIE_NAME: "tooshort"},
    )
    assert r.status == 401


# ── bootstrap path: cookie issuance ──────────────────────────────


@pytest.mark.asyncio
async def test_bootstrap_with_valid_token_mints_session_cookie(ctx):
    """First visit with ?t=<valid> should set BOTH the legacy ol_ui
    cookie AND the new persistent ol_session + the JS-visible marker."""
    r = await ctx["client"].get(f"/?t={ctx['token']}")
    assert r.status == 200
    # Aiohttp test client surfaces Set-Cookie headers.
    cookie_hdrs = r.headers.getall("Set-Cookie", [])
    joined = " ".join(cookie_hdrs)
    assert COOKIE_NAME in joined, (
        "legacy ol_ui cookie must still be issued for back-compat"
    )
    assert SESSION_COOKIE_NAME in joined, (
        "persistent ol_session cookie must be issued on bootstrap"
    )
    assert SESSION_PRESENT_MARKER_COOKIE in joined, (
        "JS-readable marker must be issued so the access-denied "
        "page can self-heal silently"
    )


@pytest.mark.asyncio
async def test_bootstrap_creates_one_session_per_browser(ctx):
    """Hitting the bootstrap twice with the same browser (already
    has a session cookie) should NOT proliferate rows; the existing
    session is touched + rolled forward."""
    r1 = await ctx["client"].get(f"/?t={ctx['token']}")
    assert r1.status == 200
    sessions_after_first = ctx["state"].list_ui_sessions()
    assert len(sessions_after_first) == 1
    # Second hit (the client carries cookies from the first one).
    r2 = await ctx["client"].get(f"/?t={ctx['token']}")
    assert r2.status == 200
    sessions_after_second = ctx["state"].list_ui_sessions()
    assert len(sessions_after_second) == 1, (
        "re-hitting the bootstrap with the same browser should "
        "reuse the existing session, not mint another"
    )


# ── revoke endpoints ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_sessions_marks_own_browser(ctx):
    sess = ctx["state"].create_ui_session(user_agent="Mozilla/5.0")
    other = ctx["state"].create_ui_session(user_agent="Firefox")
    r = await ctx["client"].get(
        "/api/auth/sessions",
        cookies={SESSION_COOKIE_NAME: sess["session_uuid"]},
    )
    assert r.status == 200
    body = await r.json()
    by_prefix = {
        s["session_uuid_prefix"]: s for s in body["sessions"]
    }
    assert by_prefix[sess["session_uuid"][:8]]["is_this_browser"] is True
    assert by_prefix[other["session_uuid"][:8]]["is_this_browser"] is False


def _csrf_origin_for(client) -> dict:
    """Browser POSTs MUST carry Origin equal to the daemon's own
    bind URL — that's the CSRF gate. Tests need to spoof it the
    same way a real same-origin fetch would."""
    return {"Origin": f"http://127.0.0.1:{client.port}"}


def _auth_headers(ctx, *, csrf_client=None) -> dict:
    """Bearer for auth + Origin for CSRF on POSTs."""
    h = {"Authorization": f"Bearer {ctx['token']}"}
    if csrf_client is not None:
        h["Origin"] = f"http://127.0.0.1:{csrf_client.port}"
    return h


@pytest.mark.asyncio
async def test_revoke_all_returns_count_and_clears_cookies(ctx):
    ctx["state"].create_ui_session(user_agent="A")
    ctx["state"].create_ui_session(user_agent="B")
    caller = ctx["state"].create_ui_session(user_agent="C")
    r = await ctx["client"].post(
        "/api/auth/sessions/revoke-all",
        cookies={SESSION_COOKIE_NAME: caller["session_uuid"]},
        headers=_csrf_origin_for(ctx["client"]),
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["revoked"] == 3
    # Cookies are cleared in the response.
    cookie_hdrs = " ".join(r.headers.getall("Set-Cookie", []))
    assert SESSION_COOKIE_NAME in cookie_hdrs
    # del_cookie sets Max-Age=0 to clear.
    assert "Max-Age=0" in cookie_hdrs


@pytest.mark.asyncio
async def test_revoke_one_session(ctx):
    a = ctx["state"].create_ui_session(user_agent="A")
    b = ctx["state"].create_ui_session(user_agent="B")
    r = await ctx["client"].post(
        f"/api/auth/sessions/{a['session_uuid']}/revoke",
        cookies={SESSION_COOKIE_NAME: b["session_uuid"]},
        headers=_csrf_origin_for(ctx["client"]),
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["revoked"] == 1
    # A is gone, B still active.
    active = ctx["state"].list_ui_sessions()
    assert len(active) == 1
    assert active[0]["session_uuid"] == b["session_uuid"]


# ── access-denied self-heal page ─────────────────────────────────


def test_access_denied_page_includes_self_heal_script():
    page = UIServer._auth_failed_help_page(reason="stale_token")
    # Marker name appears in the JS check.
    assert SESSION_PRESENT_MARKER_COOKIE in page
    # Heal logic strips the query + reloads.
    assert "location.replace" in page
    assert "location.pathname" in page
    # Still shows the static fallback help text for users WITHOUT
    # a marker cookie (private windows, first-time browsers).
    assert "tray" in page.lower()


@pytest.mark.asyncio
async def test_stale_token_localhost_browser_auto_recovers(ctx):
    """v0.21.x UX win: when a localhost browser tab carries a stale
    ?t=<bad> token, the daemon doesn't show 'access denied' — it
    serves the silent recovery page that strips the query + reloads,
    AND sets a fresh cookie pair so the next request authenticates.

    This is the path most users hit when they bookmark a One Link
    URL and reopen days later. They should perceive a tiny flash,
    not an error page."""
    r = await ctx["client"].get(
        "/?t=definitely-not-a-real-token",
        headers={"Accept": "text/html"},
    )
    # Localhost recovery path returns 200 + recovery HTML + cookies.
    assert r.status == 200, await r.text()
    cookie_hdrs = " ".join(r.headers.getall("Set-Cookie", []))
    assert SESSION_COOKIE_NAME in cookie_hdrs, (
        "stale-token localhost recovery must mint a fresh persistent "
        "session so the next reload survives even another rotation"
    )
    assert SESSION_PRESENT_MARKER_COOKIE in cookie_hdrs


def test_help_page_references_marker_cookie():
    """The help page (used for non-localhost / non-document
    navigations that can't use the silent recovery) must include the
    marker-cookie self-heal script so saved-session browsers can
    still skip the dead-end."""
    page = UIServer._auth_failed_help_page(reason="stale_token")
    assert SESSION_PRESENT_MARKER_COOKIE in page
    assert "location.replace" in page


# ── privacy toggles + auto-prune ─────────────────────────────────


@pytest.mark.asyncio
async def test_persistence_toggle_off_stops_cookie_issuance(ctx):
    """Flipping persistence OFF must stop minting new ol_session
    cookies — every subsequent bootstrap should be cookie-free."""
    # Flip OFF.
    r = await ctx["client"].post(
        "/api/auth/sessions/settings",
        json={"persistence_enabled": False},
        headers=_auth_headers(ctx, csrf_client=ctx["client"]),
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["persistence_enabled"] is False
    # Fresh client (no inherited cookies) hits the bootstrap.
    fresh_client = TestClient(TestServer(ctx["server"].app))
    await fresh_client.start_server()
    try:
        r2 = await fresh_client.get(f"/?t={ctx['token']}")
        assert r2.status == 200
        cookie_hdrs = " ".join(r2.headers.getall("Set-Cookie", []))
        assert SESSION_COOKIE_NAME not in cookie_hdrs, (
            "persistence OFF must not issue ol_session"
        )
        assert SESSION_PRESENT_MARKER_COOKIE not in cookie_hdrs, (
            "persistence OFF must not issue the marker"
        )
        # Legacy ol_ui cookie still issued for in-process auth.
        assert COOKIE_NAME in cookie_hdrs
    finally:
        await fresh_client.close()


@pytest.mark.asyncio
async def test_persistence_toggle_off_wipes_table(ctx):
    """Flipping persistence OFF must hard-delete the ui_sessions
    table so historical session rows don't survive the choice."""
    ctx["state"].create_ui_session(user_agent="A")
    ctx["state"].create_ui_session(user_agent="B")
    assert len(ctx["state"].list_ui_sessions()) == 2
    r = await ctx["client"].post(
        "/api/auth/sessions/settings",
        json={"persistence_enabled": False},
        headers=_auth_headers(ctx, csrf_client=ctx["client"]),
    )
    assert r.status == 200
    body = await r.json()
    assert body["wiped_sessions"] == 2
    assert len(ctx["state"].list_ui_sessions()) == 0
    # Response also clears the caller's cookies.
    cookie_hdrs = " ".join(r.headers.getall("Set-Cookie", []))
    assert SESSION_COOKIE_NAME in cookie_hdrs
    assert "Max-Age=0" in cookie_hdrs


@pytest.mark.asyncio
async def test_labels_toggle_off_strips_existing_fingerprints(ctx):
    """Flipping labels OFF must strip the label + UA hash columns
    from EVERY existing row so the historical fingerprints don't
    linger after the user changed their mind."""
    a = ctx["state"].create_ui_session(
        user_agent="Mozilla/5.0 (Windows) Edg/120.0",
    )
    b = ctx["state"].create_ui_session(user_agent="Firefox/120")
    assert ctx["state"].lookup_ui_session(a["session_uuid"])["label"]
    r = await ctx["client"].post(
        "/api/auth/sessions/settings",
        json={"labels_enabled": False},
        headers=_auth_headers(ctx, csrf_client=ctx["client"]),
    )
    assert r.status == 200
    body = await r.json()
    assert body["stripped_labels"] == 2
    a_after = ctx["state"].lookup_ui_session(a["session_uuid"])
    b_after = ctx["state"].lookup_ui_session(b["session_uuid"])
    assert a_after["label"] is None
    assert a_after["user_agent_hash"] is None
    assert b_after["label"] is None
    assert b_after["user_agent_hash"] is None


@pytest.mark.asyncio
async def test_labels_toggle_off_skips_ua_on_future_sessions(ctx):
    """After flipping labels OFF, _set_ui_cookie must not pass
    User-Agent into create_ui_session for NEW sessions either."""
    await ctx["client"].post(
        "/api/auth/sessions/settings",
        json={"labels_enabled": False},
        headers=_auth_headers(ctx, csrf_client=ctx["client"]),
    )
    # Fresh bootstrap.
    fresh_client = TestClient(TestServer(ctx["server"].app))
    await fresh_client.start_server()
    try:
        r = await fresh_client.get(
            f"/?t={ctx['token']}",
            headers={"User-Agent": "Mozilla/5.0 (Windows) Edg/120.0"},
        )
        assert r.status == 200
    finally:
        await fresh_client.close()
    # The newest row should have no label / UA hash.
    rows = ctx["state"].list_ui_sessions()
    assert len(rows) == 1
    assert rows[0]["label"] is None
    assert rows[0]["user_agent_hash"] is None


@pytest.mark.asyncio
async def test_settings_get_returns_defaults_when_unset(ctx):
    """Out-of-the-box (no setting written), both toggles default ON
    so the just-works UX kicks in for first-time installs."""
    r = await ctx["client"].get(
        "/api/auth/sessions/settings",
        headers=_auth_headers(ctx),
    )
    assert r.status == 200
    body = await r.json()
    assert body["persistence_enabled"] is True
    assert body["labels_enabled"] is True


def test_wipe_ui_sessions_hard_deletes(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    s.create_ui_session()
    s.create_ui_session()
    assert s.wipe_ui_sessions() == 2
    assert s.list_ui_sessions(include_revoked=True) == []
    s.close()


def test_strip_labels_clears_columns_in_place(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    a = s.create_ui_session(user_agent="Mozilla/5.0 Edg/120")
    b = s.create_ui_session(user_agent="Firefox/120")
    affected = s.strip_ui_session_labels()
    assert affected == 2
    ra = s.lookup_ui_session(a["session_uuid"])
    rb = s.lookup_ui_session(b["session_uuid"])
    assert ra["label"] is None and ra["user_agent_hash"] is None
    assert rb["label"] is None and rb["user_agent_hash"] is None
    # Sessions themselves stay valid — the uuid still authenticates.
    assert s.touch_ui_session(a["session_uuid"]) is True
    s.close()


def test_prune_only_drops_old_rows(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    fresh = s.create_ui_session()
    # Backdate the second session's last_seen_ms past the cutoff.
    stale = s.create_ui_session()
    with s._write_lock:
        s._conn.execute(
            "UPDATE ui_sessions SET last_seen_ms=? WHERE session_uuid=?",
            (1, stale["session_uuid"]),
        )
        s._conn.commit()
    pruned = s.prune_expired_ui_sessions(older_than_ms=1000)
    assert pruned == 1
    assert s.lookup_ui_session(fresh["session_uuid"]) is not None
    assert s.lookup_ui_session(stale["session_uuid"]) is None
    s.close()


# ── log audit: session uuid never appears in daemon logs ─────────


def test_create_ui_session_never_logs_uuid(tmp_path: Path, caplog):
    """Defense-in-depth: a session uuid is a bearer secret. It must
    NEVER show up in a daemon log line, or a stolen log file could
    be replayed against the live daemon."""
    import logging
    s = State(db_path=tmp_path / "s.db")
    with caplog.at_level(logging.DEBUG):
        sess = s.create_ui_session(user_agent="Mozilla/5.0")
        s.touch_ui_session(sess["session_uuid"])
        s.revoke_ui_session(sess["session_uuid"])
    for rec in caplog.records:
        assert sess["session_uuid"] not in rec.getMessage(), (
            f"session uuid leaked into log at {rec.levelname}: "
            f"{rec.getMessage()!r}"
        )
    s.close()
