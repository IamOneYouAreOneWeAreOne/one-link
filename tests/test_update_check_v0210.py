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
    ("0.21.0rc2", "0.21.0rc10", "newer"),
    ("0.21.0.dev9", "0.21.0a1", "newer"),
    ("0.21.0", "0.21.0.post1", "newer"),
    # Same
    ("0.21.0", "0.21.0", "same"),
    ("0.21.0", "v0.21.0", "same"),  # 'v' prefix tolerated
    ("v0.21.0", "0.21.0", "same"),
    ("0.21.0-alpha", "0.21.0a0", "same"),
    # Older remote (dev build ahead of release)
    ("0.22.0", "0.21.0", "older"),
    ("0.21.1", "0.21.0", "older"),
    ("0.21.0", "0.21.0-alpha", "older"),
    # Unparseable -> 'unknown' (never raises)
    ("garbage", "0.21.0", "unknown"),
    ("0.21.0", "not-a-version", "unknown"),
    ("", "0.21.0", "unknown"),
    ("0.21.0", "", "unknown"),
    ("0.21.0", "1." + "0" * 200 + ".0", "unknown"),
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


@pytest.mark.parametrize("payload", [None, [], "not an object", 42])
def test_fetch_latest_non_object_payload_returns_unknown(payload):
    from one_link.update_check import fetch_latest

    result = fetch_latest("0.21.0", fetch=lambda url, timeout: payload)
    assert result.status == "unknown"


def test_fetch_latest_unexpected_fetch_exception_never_escapes():
    from one_link.update_check import fetch_latest

    def explode(url, timeout):
        raise RuntimeError("surprise transport failure")

    result = fetch_latest("0.21.0", fetch=explode)
    assert result.status == "unknown"
    assert result.error == "fetch: RuntimeError"


def test_fetch_latest_rejects_invalid_repository_coordinates():
    from one_link.update_check import fetch_latest

    called = False

    def fake_fetch(url, timeout):
        nonlocal called
        called = True
        return _gh_payload()

    result = fetch_latest(
        "0.21.0",
        owner="owner/../../escape",
        fetch=fake_fetch,
    )
    assert result.status == "unknown"
    assert called is False


def test_fetch_latest_uses_canonical_release_url_not_payload_url():
    from one_link.update_check import fetch_latest

    payload = _gh_payload()
    payload["html_url"] = "javascript:alert(1)"
    result = fetch_latest("0.21.0", fetch=lambda url, timeout: payload)
    assert result.latest is not None
    assert result.latest.html_url == (
        "https://github.com/IamOneYouAreOneWeAreOne/"
        "one-link/releases/tag/v0.22.0"
    )


def test_fetch_latest_bounds_release_notes_and_asset_count():
    from one_link.update_check import MAX_RELEASE_NOTES_CHARS, fetch_latest

    payload = _gh_payload()
    payload["body"] = "x" * (MAX_RELEASE_NOTES_CHARS + 100)
    result = fetch_latest("0.21.0", fetch=lambda url, timeout: payload)
    assert result.latest is not None
    assert len(result.latest.body) == MAX_RELEASE_NOTES_CHARS

    payload["assets"] = [{}] * 5_001
    refused = fetch_latest("0.21.0", fetch=lambda url, timeout: payload)
    assert refused.status == "unknown"


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
    # May 15 2026 — the update check is now opt-IN for sovereignty
    # (no calls to GitHub by default). Tests that exercise the
    # check path explicitly enable it.
    monkeypatch.setenv("ONE_LINK_UPDATE_CHECK", "1")
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
async def test_tagged_newer_with_proven_capability_offers_in_app_install(monkeypatch):
    """can_self_install turns True exactly when the newer build is a TAGGED
    release and this process proved the external-helper capability — and it
    is per-response truth: losing the capability revokes the install action
    even while the 15-minute check cache is still warm."""
    monkeypatch.setenv("ONE_LINK_UPDATE_CHECK", "1")
    from one_link.server import UIServer
    from one_link import update_check as uc_mod

    def fake_fetch_latest(local_version, *, owner=None, repo=None,
                          timeout=None, fetch=None):
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
    server._update_cache = None

    async def proven_capability(*, fresh=False):
        return SimpleNamespace(
            available=True, reason="available", platform="windows-x86_64"
        )
    monkeypatch.setattr(server, "_external_update_capability", proven_capability)

    body = json.loads((await server.api_update_check(SimpleNamespace(query={}))).text)
    assert body["can_self_install"] is True
    assert body["action"] == "install"

    async def lost_capability(*, fresh=False):
        return SimpleNamespace(
            available=False,
            reason="managed_bundle_validation_failed",
            platform=None,
        )
    monkeypatch.setattr(server, "_external_update_capability", lost_capability)

    body = json.loads((await server.api_update_check(SimpleNamespace(query={}))).text)
    assert body["cached"] is True
    assert body["can_self_install"] is False
    assert body["action"] == "download"


@pytest.mark.asyncio
async def test_rolling_newer_never_offers_in_app_install(monkeypatch):
    """Even a fully proven standalone bundle must not be offered an in-app
    install of a ROLLING build: continuous builds hold no release authority
    and the install planner would fail closed. The honest action is a
    download."""
    monkeypatch.setenv("ONE_LINK_UPDATE_CHECK", "1")
    from one_link.server import UIServer
    from one_link import update_check as uc_mod

    def fake_check(*args, **kwargs):
        return uc_mod.CheckResult(
            status="newer",
            local_version="0.21.0-alpha",
            latest_version="auto-latest",
            latest=uc_mod.ReleaseInfo(
                tag="auto-latest",
                name=f"Rolling build (master {'e' * 40})",
                html_url="https://github.com/x/y/releases/tag/auto-latest",
                published_at="2026-07-27T12:00:00Z",
            ),
            local_commit="a" * 40,
            latest_commit="e" * 40,
            channel="rolling",
        )
    monkeypatch.setattr(uc_mod, "check_for_update", fake_check)

    daemon = SimpleNamespace(
        state=None,
        discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
    )
    server = UIServer(daemon)
    server._update_cache = None

    async def proven_capability(*, fresh=False):
        return SimpleNamespace(
            available=True, reason="available", platform="windows-x86_64"
        )
    monkeypatch.setattr(server, "_external_update_capability", proven_capability)

    body = json.loads((await server.api_update_check(SimpleNamespace(query={}))).text)
    assert body["status"] == "newer"
    assert body["channel"] == "rolling"
    assert body["can_self_install"] is False
    assert body["action"] == "download"
    assert "install authority" in body["action_note"]


@pytest.mark.asyncio
async def test_api_update_check_caches_within_ttl(monkeypatch):
    """Two back-to-back calls must hit the cache the second time so
    we don't hammer the GitHub API on every UI reload."""
    # See test_api_update_check_returns_check_result — opt in.
    monkeypatch.setenv("ONE_LINK_UPDATE_CHECK", "1")
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
    # See test_api_update_check_returns_check_result — opt in.
    monkeypatch.setenv("ONE_LINK_UPDATE_CHECK", "1")
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


# ─── Sovereignty default (May 15 2026) ────────────────────────────────


@pytest.mark.asyncio
async def test_api_update_check_uses_disclosed_just_works_default(monkeypatch):
    """The default preset and API must resolve to the same policy."""
    monkeypatch.delenv("ONE_LINK_UPDATE_CHECK", raising=False)
    from one_link.server import UIServer
    from one_link import update_check as uc_mod

    network_calls = {"n": 0}
    def fake_fetch(*a, **kw):
        network_calls["n"] += 1
        return uc_mod.CheckResult(
            status="same",
            local_version=a[0],
            latest_version=a[0],
        )
    monkeypatch.setattr(uc_mod, "fetch_latest", fake_fetch)

    daemon = SimpleNamespace(
        state=None,
        discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
    )
    server = UIServer(daemon)
    server._update_cache = None

    resp = await server.api_update_check(SimpleNamespace(query={}))
    assert resp.status == 200
    body = json.loads(resp.text)
    assert body["status"] == "same"
    assert network_calls["n"] == 1


@pytest.mark.asyncio
async def test_api_update_check_quiet_mode_makes_no_network_call(monkeypatch):
    monkeypatch.delenv("ONE_LINK_UPDATE_CHECK", raising=False)
    from one_link.server import UIServer
    from one_link import update_check as uc_mod

    network_calls = {"n": 0}
    monkeypatch.setattr(
        uc_mod,
        "fetch_latest",
        lambda *a, **kw: network_calls.__setitem__("n", network_calls["n"] + 1),
    )
    state = SimpleNamespace(
        get_setting=lambda key: (
            "quiet" if key == "sovereignty_preset" else None
        ),
    )
    daemon = SimpleNamespace(
        state=state,
        discovery=None,
        me=SimpleNamespace(
            fingerprint="aa" * 32,
            short_id="aaaaaaaa",
            hostname="me",
        ),
    )
    server = UIServer(daemon)
    server._update_cache = None

    resp = await server.api_update_check(SimpleNamespace(query={}))
    assert json.loads(resp.text)["status"] == "disabled"
    assert network_calls["n"] == 0


@pytest.mark.asyncio
async def test_api_update_check_enabled_via_env_var(monkeypatch):
    """ONE_LINK_UPDATE_CHECK=1 opts in."""
    monkeypatch.setenv("ONE_LINK_UPDATE_CHECK", "1")
    from one_link.server import UIServer
    from one_link import update_check as uc_mod

    monkeypatch.setattr(
        uc_mod, "fetch_latest",
        lambda v, **kw: uc_mod.CheckResult(
            status="same", local_version=v, latest_version=v,
        ),
    )
    daemon = SimpleNamespace(
        state=None,
        discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
    )
    server = UIServer(daemon)
    server._update_cache = None
    resp = await server.api_update_check(SimpleNamespace(query={}))
    body = json.loads(resp.text)
    assert body["status"] == "same"


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
