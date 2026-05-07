"""v0.11.1 — Profile + Privacy (Phase 2 of Settings overhaul).

Profile:
  - Bio (short status, max 140 chars). Persisted; surfaced in
    the device drawer in a future ship.
  - Avatar color picker (8 presets). Persisted; live-applied to
    my own avatar tile via --my-avatar CSS variable.

Privacy:
  - Blocked devices list. Backed by /api/peers?include=rejected
    + the existing /api/peers/{fp}/trust endpoint with
    trust='pinned' for the unblock action.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import (
    AVATAR_COLOR_PRESETS,
    BIO_MAX_LENGTH,
    UIServer,
)
from one_link.state import State


def _identity(host: str = "p2-host") -> Identity:
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
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client, daemon, state, server.token
    finally:
        await client.close()
        state.close()


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── settings module constants ─────────────────────────────────

def test_avatar_color_presets_have_eight_options():
    """Pin the count + the default. Adding/removing a preset is a
    coordinated change with the front-end."""
    assert len(AVATAR_COLOR_PRESETS) == 8
    assert AVATAR_COLOR_PRESETS[0] == "#7c4dff"


def test_avatar_presets_are_valid_hex():
    """All presets must be #rrggbb so the validator accepts them."""
    import re
    for c in AVATAR_COLOR_PRESETS:
        assert re.match(r"^#[0-9a-fA-F]{6}$", c), c


def test_bio_max_length_is_140():
    """Twitter/Signal/Telegram convention. Pinning prevents accidental
    drift to a different limit."""
    assert BIO_MAX_LENGTH == 140


# ───────── /api/settings — bio + avatar_color round trip ─────────────

@pytest.mark.asyncio
async def test_get_settings_includes_profile_fields(http):
    client, _, _, token = http
    resp = await client.get("/api/settings", headers=_h(token))
    j = await resp.json()
    assert "bio" in j
    assert "avatar_color" in j
    assert "avatar_color_presets" in j
    assert j["avatar_color_presets"] == list(AVATAR_COLOR_PRESETS)
    # Defaults: empty bio, default purple.
    assert j["bio"] == ""
    assert j["avatar_color"] == AVATAR_COLOR_PRESETS[0]


@pytest.mark.asyncio
async def test_set_bio_persists(http):
    client, _, state, token = http
    resp = await client.post(
        "/api/settings", headers=_h(token),
        json={"bio": "in the trenches"},
    )
    assert resp.status == 200
    g = await (await client.get("/api/settings", headers=_h(token))).json()
    assert g["bio"] == "in the trenches"


@pytest.mark.asyncio
async def test_bio_strips_whitespace(http):
    """Leading/trailing whitespace shouldn't fuzzily match different
    bios on display."""
    client, _, _, token = http
    await client.post(
        "/api/settings", headers=_h(token),
        json={"bio": "  hello world  "},
    )
    g = await (await client.get("/api/settings", headers=_h(token))).json()
    assert g["bio"] == "hello world"


@pytest.mark.asyncio
async def test_bio_blank_clears(http):
    """Saving bio="" should clear the setting, not save an empty string."""
    client, _, _, token = http
    await client.post(
        "/api/settings", headers=_h(token),
        json={"bio": "first"},
    )
    await client.post(
        "/api/settings", headers=_h(token),
        json={"bio": ""},
    )
    g = await (await client.get("/api/settings", headers=_h(token))).json()
    assert g["bio"] == ""


@pytest.mark.asyncio
async def test_bio_rejects_over_140(http):
    client, _, _, token = http
    long_bio = "x" * 141
    resp = await client.post(
        "/api/settings", headers=_h(token),
        json={"bio": long_bio},
    )
    assert resp.status == 400
    j = await resp.json()
    assert "140" in j.get("error", "")


@pytest.mark.asyncio
async def test_bio_rejects_non_string(http):
    client, _, _, token = http
    resp = await client.post(
        "/api/settings", headers=_h(token),
        json={"bio": 42},
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_set_avatar_color_persists(http):
    client, _, _, token = http
    chosen = AVATAR_COLOR_PRESETS[3]
    resp = await client.post(
        "/api/settings", headers=_h(token),
        json={"avatar_color": chosen},
    )
    assert resp.status == 200
    g = await (await client.get("/api/settings", headers=_h(token))).json()
    assert g["avatar_color"] == chosen


@pytest.mark.asyncio
async def test_avatar_color_rejects_arbitrary_hex(http):
    """A user can't sneak in a custom color outside the preset list —
    keeps the UI swatches in sync with what's actually stored."""
    client, _, _, token = http
    resp = await client.post(
        "/api/settings", headers=_h(token),
        json={"avatar_color": "#abcdef"},
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_avatar_color_null_resets_to_default(http):
    client, _, _, token = http
    # Set then clear.
    await client.post(
        "/api/settings", headers=_h(token),
        json={"avatar_color": AVATAR_COLOR_PRESETS[5]},
    )
    await client.post(
        "/api/settings", headers=_h(token),
        json={"avatar_color": None},
    )
    g = await (await client.get("/api/settings", headers=_h(token))).json()
    # Default falls back to the first preset.
    assert g["avatar_color"] == AVATAR_COLOR_PRESETS[0]


# ───────── UI: Profile pane markup ───────────────────────────────────

def test_profile_pane_has_avatar_preview(index_html: str):
    assert 'id="profile-avatar-preview"' in index_html


def test_profile_pane_has_color_swatch_host(index_html: str):
    """JS injects swatches into this host on settings load. Without
    the container, the picker silently no-ops."""
    assert 'id="profile-color-swatches"' in index_html


def test_profile_pane_has_bio_input(index_html: str):
    assert 'id="set-bio"' in index_html
    assert 'maxlength="140"' in index_html


def test_profile_pane_has_bio_counter(index_html: str):
    assert 'id="set-bio-counter"' in index_html


# ───────── UI: Profile pane JS wiring ────────────────────────────────

def test_initials_helper_present(index_html: str):
    assert "function _initialsFor(name)" in index_html


def test_initials_two_word_name():
    """Compose an isolated test — the JS function isn't accessible
    directly from Python, so we verify the algorithm via assertions
    on the function source. It must take first letter of first word
    + first letter of last word."""
    src = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    idx = src.find("function _initialsFor(name)")
    snippet = src[idx:idx + 600]
    # Single word → first 2 chars.
    assert "slice(0, 2)" in snippet
    # Multi word → first[0] + last[0].
    assert "parts[0][0]" in snippet
    assert "parts[parts.length - 1][0]" in snippet


def test_swatches_render_function_present(index_html: str):
    assert "function _renderColorSwatches(presets, current)" in index_html


def test_bio_counter_function_present(index_html: str):
    assert "function _renderBioCounter()" in index_html


def test_avatar_color_applied_via_css_var(index_html: str):
    """--my-avatar is the propagation channel. Saving a color must
    set this var so future avatar-tile renders pick it up without
    a re-fetch."""
    assert "--my-avatar" in index_html
    assert 'documentElement.style.setProperty("--my-avatar"' in index_html


def test_save_handler_includes_bio_and_color(index_html: str):
    """The settings-save payload must carry the new fields."""
    idx = index_html.find('"#settings-save").onclick')
    assert idx > 0
    snippet = index_html[idx:idx + 2000]
    assert "bio:" in snippet
    assert "avatar_color:" in snippet
    assert "profile-color-swatch" in snippet


# ───────── UI: Privacy pane Blocked list ─────────────────────────────

def test_privacy_pane_has_blocked_section(index_html: str):
    assert 'id="blocked-devices-list"' in index_html
    # Section header + helper text.
    assert "Blocked devices" in index_html


def test_blocked_list_refresh_function_present(index_html: str):
    assert "async function refreshBlockedDevicesList()" in index_html


def test_blocked_list_uses_existing_peers_endpoint(index_html: str):
    """No new endpoint needed — /api/peers already supports
    ?include=rejected."""
    idx = index_html.find("async function refreshBlockedDevicesList()")
    snippet = index_html[idx:idx + 2000]
    assert '/api/peers?include=rejected' in snippet


def test_unblock_button_calls_trust_endpoint(index_html: str):
    """Unblock = trust:'pinned'. Pin so a refactor can't quietly
    repurpose this to a different state (e.g., 'pending')."""
    idx = index_html.find("async function refreshBlockedDevicesList()")
    snippet = index_html[idx:idx + 3000]
    assert '/trust' in snippet
    assert 'trust: "pinned"' in snippet


def test_blocked_list_refreshes_on_settings_open(index_html: str):
    """Without this, the list shows stale data when reopening Settings
    after blocking/unblocking from the device drawer."""
    idx = index_html.find('$("#btn-settings").onclick')
    snippet = index_html[idx:idx + 5000]
    assert "refreshBlockedDevicesList()" in snippet


# ───────── version pin ───────────────────────────────────────────────

def test_page_version_bumped(index_html: str):
    """Don't pin a specific version so future 0.11.x ships don't
    have to update this file."""
    from one_link import __version__
    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
