"""Tests for the in-app update-check flow.

Phase 2 of the production-install plan. The user-visible contract is:

    1. The daemon asks GitHub Releases on startup whether there's a
       newer build than the locally installed one_link.__version__.
    2. If yes, the UI shows an orange "Update available" banner with
       a link to the release page.
    3. If no, or if the check fails for any reason (offline,
       rate-limited, repo private, JSON malformed, response slow),
       the UI silently does nothing — no scary error, no toast.

These tests verify the version-compare math, the HTTP-layer error
swallowing, and the /api/update/check endpoint round-trip with a
mocked GitHub API. They do NOT make real network calls.
"""

from __future__ import annotations

import asyncio
import json
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest


# ─── version-compare unit tests ────────────────────────────────────────

@pytest.mark.parametrize("local,remote,expected", [
    # Newer remote
    ("0.21.0", "0.21.1", "newer"),
    ("0.21.0", "0.22.0", "newer"),
    ("0.21.0", "1.0.0", "newer"),
    ("0.21.0-alpha", "0.21.0", "newer"),
    ("0.21.0a1", "0.21.0", "newer"),
    # Same
    ("0.21.0", "0.21.0", "same"),
    ("0.21.0", "v0.21.0", "same"),  # 'v' prefix tolerated
    ("v0.21.0", "0.21.0", "same"),
    # Older remote (dev build ahead of release)
    ("0.22.0", "0.21.0", "older"),
    ("0.21.1", "0.21.0", "older"),
    ("0.21.0", "0.21.0-alpha", "older"),
    # Unparseable -> 'unknown' (never raises)
    ("garbage", "0.21.0", "unknown"),
    ("0.21.0", "not-a-version", "unknown"),
    ("", "0.21.0", "unknown"),
    ("0.21.0", "", "unknown"),
])
def test_compare_versions(local, remote, expected):
    from one_link.update_check import compare_versions
    assert compare_versions(local, remote) == expected, (
        f"compare_versions({local!r}, {remote!r})"
    )


# ─── fetch_latest with mocked HTTP ─────────────────────────────────────

def _gh_payload(tag="v0.22.0", *, prerelease=False, draft=False,
                published="2026-05-12T12:00:00Z", asset_count=4):
    return {
        "tag_name": tag,
        "name": f"One Link {tag}",
        "html_url": f"https://github.com/IamOneYouAreOneWeAreOne/one-link/releases/tag/{tag}",
        "published_at": published,
        "body": "## What's new\n\n* Native QUIC transport\n",
        "prerelease": prerelease,
        "draft": draft,
        "assets": [{"name": f"wheel-{i}.whl"} for i in range(asset_count)],
    }


def test_fetch_latest_newer_release():
    from one_link.update_check import fetch_latest

    captured = {}
    def fake_fetch(url, timeout):
        captured["url"] = url
        captured["timeout"] = timeout
        return _gh_payload(tag="v0.22.0")

    result = fetch_latest("0.21.0", fetch=fake_fetch)
    assert result.status == "newer"
    assert result.latest_version == "v0.22.0"
    assert result.latest is not None
    assert result.latest.tag == "v0.22.0"
    assert result.latest.asset_count == 4
    assert "0.22.0" in result.latest.html_url
    # The default repo coordinates flow through to the GitHub URL.
    assert "IamOneYouAreOneWeAreOne/one-link" in captured["url"]
    # Sane timeout — not 60 seconds.
    assert captured["timeout"] <= 10


def test_fetch_latest_same_version():
    from one_link.update_check import fetch_latest

    def fake_fetch(url, timeout):
        return _gh_payload(tag="v0.21.0")

    result = fetch_latest("0.21.0", fetch=fake_fetch)
    assert result.status == "same"
    assert result.latest_version == "v0.21.0"


def test_fetch_latest_local_is_newer():
    """Dev builds running off master are commonly ahead of any
    published tag. The banner must NOT show in that case."""
    from one_link.update_check import fetch_latest

    def fake_fetch(url, timeout):
        return _gh_payload(tag="v0.20.0")

    result = fetch_latest("0.21.0", fetch=fake_fetch)
    assert result.status == "older"


def test_fetch_latest_network_error_returns_unknown_not_raise():
    """An offline daemon must not crash the API. /api/update/check
    is wired to fetch_latest, and a thrown exception would surface
    as a 500."""
    from one_link.update_check import fetch_latest

    def fake_fetch(url, timeout):
        raise urllib.error.URLError("Name or service not known")

    result = fetch_latest("0.21.0", fetch=fake_fetch)
    assert result.status == "unknown"
    assert result.latest_version is None
    assert result.error and "network" in result.error.lower()


def test_fetch_latest_http_error_returns_unknown_not_raise():
    """404 (no releases yet) and 403 (rate-limited) both become
    status='unknown'. The UI stays clean in both cases."""
    from one_link.update_check import fetch_latest

    def fake_fetch(url, timeout):
        raise urllib.error.HTTPError(url, 403, "rate limited", {}, None)

    result = fetch_latest("0.21.0", fetch=fake_fetch)
    assert result.status == "unknown"
    assert "403" in (result.error or "")


def test_fetch_latest_malformed_json_returns_unknown_not_raise():
    """If GitHub returns 200 with non-JSON (e.g. a captive portal HTML
    page on a weird Wi-Fi), the daemon must not crash."""
    from one_link.update_check import fetch_latest

    def fake_fetch(url, timeout):
        raise json.JSONDecodeError("Expecting value", "doc", 0)

    result = fetch_latest("0.21.0", fetch=fake_fetch)
    assert result.status == "unknown"
    assert "parse" in (result.error or "")


def test_fetch_latest_missing_tag_field_returns_unknown():
    """If GitHub returns a payload with no tag_name (shouldn't happen
    but defense in depth), we return unknown rather than crashing."""
    from one_link.update_check import fetch_latest

    def fake_fetch(url, timeout):
        return {"name": "weird response"}

    result = fetch_latest("0.21.0", fetch=fake_fetch)
    assert result.status == "unknown"


def test_fetch_latest_prerelease_flag_preserved():
    """The UI uses prerelease=True to decide whether to show the
    banner by default (alpha/beta users want it; stable users don't).
    Make sure we don't drop that bit."""
    from one_link.update_check import fetch_latest

    def fake_fetch(url, timeout):
        return _gh_payload(tag="v0.22.0-alpha", prerelease=True)

    result = fetch_latest("0.21.0", fetch=fake_fetch)
    assert result.latest is not None
    assert result.latest.prerelease is True


def test_fetch_latest_returns_serializable_dict():
    """The /api/update/check handler json_response()s
    result.to_dict() — make sure that's a real dict with no exotic
    nested types that json.dumps would choke on."""
    from one_link.update_check import fetch_latest

    def fake_fetch(url, timeout):
        return _gh_payload(tag="v0.22.0")

    result = fetch_latest("0.21.0", fetch=fake_fetch)
    blob = json.dumps(result.to_dict())
    decoded = json.loads(blob)
    assert decoded["status"] == "newer"
    # Top-level convenience fields the UI relies on.
    assert decoded["latest_url"].startswith("https://github.com/")


# ─── /api/update/check endpoint smoke test (handler-level) ────────────

@pytest.mark.asyncio
async def test_api_update_check_returns_check_result(monkeypatch):
    """End-to-end: mock fetch_latest, hit the handler, assert the
    response shape the UI consumes."""
    from one_link.server import UIServer
    from one_link import update_check as uc_mod

    captured = {}
    def fake_fetch_latest(local_version, *, owner=None, repo=None,
                          timeout=None, fetch=None):
        captured["local"] = local_version
        return uc_mod.CheckResult(
            status="newer",
            local_version=local_version,
            latest_version="v0.22.0",
            latest=uc_mod.ReleaseInfo(
                tag="v0.22.0",
                name="One Link v0.22.0",
                html_url="https://github.com/x/y/releases/tag/v0.22.0",
                published_at="2026-05-12T12:00:00Z",
            ),
        )
    monkeypatch.setattr(uc_mod, "fetch_latest", fake_fetch_latest)

    daemon = SimpleNamespace(
        state=None,
        discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
    )
    server = UIServer(daemon)
    # Bypass the cache between subtests.
    server._update_cache = None

    req = SimpleNamespace(query={})
    resp = await server.api_update_check(req)
    assert resp.status == 200
    body = json.loads(resp.text)
    assert body["status"] == "newer"
    assert body["latest_version"] == "v0.22.0"
    assert body["latest_url"].startswith("https://github.com/")
    assert "local_version" in body
    assert body["cached"] is False


@pytest.mark.asyncio
async def test_api_update_check_caches_within_ttl(monkeypatch):
    """Two back-to-back calls must hit the cache the second time so
    we don't hammer the GitHub API on every UI reload."""
    from one_link.server import UIServer
    from one_link import update_check as uc_mod

    call_count = {"n": 0}
    def fake_fetch_latest(local_version, **kw):
        call_count["n"] += 1
        return uc_mod.CheckResult(
            status="same",
            local_version=local_version,
            latest_version=local_version,
        )
    monkeypatch.setattr(uc_mod, "fetch_latest", fake_fetch_latest)

    daemon = SimpleNamespace(
        state=None,
        discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
    )
    server = UIServer(daemon)
    server._update_cache = None

    # First call hits the network.
    resp1 = await server.api_update_check(SimpleNamespace(query={}))
    assert call_count["n"] == 1
    assert json.loads(resp1.text)["cached"] is False

    # Second call returns the cache.
    resp2 = await server.api_update_check(SimpleNamespace(query={}))
    assert call_count["n"] == 1
    assert json.loads(resp2.text)["cached"] is True


@pytest.mark.asyncio
async def test_api_update_check_fresh_bypasses_cache(monkeypatch):
    """?fresh=1 (the Settings 'Check now' button) skips the cache."""
    from one_link.server import UIServer
    from one_link import update_check as uc_mod

    call_count = {"n": 0}
    def fake_fetch_latest(local_version, **kw):
        call_count["n"] += 1
        return uc_mod.CheckResult(
            status="same",
            local_version=local_version,
            latest_version=local_version,
        )
    monkeypatch.setattr(uc_mod, "fetch_latest", fake_fetch_latest)

    daemon = SimpleNamespace(
        state=None,
        discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
    )
    server = UIServer(daemon)
    server._update_cache = None

    await server.api_update_check(SimpleNamespace(query={}))
    # Forced refresh re-fetches.
    await server.api_update_check(SimpleNamespace(query={"fresh": "1"}))
    assert call_count["n"] == 2


# ─── UI markup contract ────────────────────────────────────────────────

WEB_INDEX = (
    Path(__file__).resolve().parent.parent
    / "src" / "one_link" / "web" / "index.html"
)


def test_index_html_has_update_banner_elements():
    """The banner element + dismiss button + release link must exist
    in the served HTML. checkForUpdate() in JS looks them up by id."""
    html = WEB_INDEX.read_text(encoding="utf-8")
    for needle in [
        'id="update-banner"',
        'id="update-banner-text"',
        'id="update-banner-link"',
        'id="update-banner-dismiss"',
        ".update-banner",     # CSS rule
        "function checkForUpdate",
        '"/api/update/check"',
    ]:
        assert needle in html, f"missing UI piece: {needle!r}"


def test_index_html_check_for_update_runs_on_init():
    """init() must call checkForUpdate so the banner appears without
    the user having to navigate anywhere. A regression that drops the
    call leaves the banner code defined but unreachable."""
    html = WEB_INDEX.read_text(encoding="utf-8")
    # Find the init() function and confirm checkForUpdate is called
    # somewhere inside its body.
    init_start = html.find("async function init()")
    assert init_start >= 0, "init() not defined"
    # init() body ends at the next standalone closing brace at column 2
    # (matches the function indentation); easier proxy: just check the
    # next 8000 chars include the call.
    init_window = html[init_start:init_start + 8000]
    assert "checkForUpdate(" in init_window, (
        "init() doesn't call checkForUpdate — update banner is wired but "
        "never invoked"
    )
