"""v0.11.3 - Group settings expansion (Phase 4 of Settings overhaul).

Backend:
  - POST /api/groups/{gid}/members/{member_fp}/role to promote/
    demote a member. Owners only; reducer enforces server-side
    via sign_change_role.
  - Daemon.change_group_member_role helper to sign + persist +
    distribute the CHANGE_ROLE event.

Frontend (group settings modal):
  - Rename has its own section header (no longer orphaned at top).
  - Owner-only role dropdown next to each member.
  - Mute group: duration picker + status text (uses the
    /api/groups/{gid}/mute endpoint shipped in v0.11.2).
  - Avatar color: 8 swatches keyed by group_id_hex via
    localStorage, applied to the sidebar avatar tile.
  - Archive group: localStorage toggle that hides the group
    from the main sidebar list. Archived rows render under an
    "Archived (N)" expand toggle so they're one click away.
  - mute indicator appears next to muted group/peer names
    in the sidebar.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import groups as gmod
from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


def _identity(host: str = "owner-host") -> Identity:
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


# Reducer: promote/demote via sign_change_role

def test_owner_can_promote_member_to_admin():
    """Pin the existing CRDT primitive - phase 4's UI is just a
    surface over this. Owner promotes a member; reducer applies."""
    sk_o = Ed25519PrivateKey.generate()
    pk_o = sk_o.public_key().public_bytes_raw()
    sk_b = Ed25519PrivateKey.generate()
    pk_b = sk_b.public_key().public_bytes_raw()
    gid = gmod.new_group_id()
    base = 1_700_000_000_000
    events = [
        gmod.sign_create_group(
            private_key=sk_o, pubkey=pk_o, name="g",
            group_id=gid, timestamp_ms=base,
        ),
        gmod.sign_add_member(
            private_key=sk_o, pubkey=pk_o, group_id=gid,
            member_pubkey=pk_b, timestamp_ms=base + 1,
        ),
        gmod.sign_change_role(
            private_key=sk_o, pubkey=pk_o, group_id=gid,
            member_pubkey=pk_b, new_role="admin",
            timestamp_ms=base + 2,
        ),
    ]
    state = gmod.reduce_events(events)
    assert state.role_of(pk_b) == "admin"


def test_admin_cannot_change_roles():
    """Reducer must reject role changes from non-owners. Phase 4
    UI also gates the dropdown to owners, but defense-in-depth on
    the server matters because malicious peers could craft events."""
    sk_o = Ed25519PrivateKey.generate()
    pk_o = sk_o.public_key().public_bytes_raw()
    sk_a = Ed25519PrivateKey.generate()
    pk_a = sk_a.public_key().public_bytes_raw()
    sk_b = Ed25519PrivateKey.generate()
    pk_b = sk_b.public_key().public_bytes_raw()
    gid = gmod.new_group_id()
    base = 1_700_000_000_000
    events = [
        gmod.sign_create_group(
            private_key=sk_o, pubkey=pk_o, name="g",
            group_id=gid, timestamp_ms=base,
        ),
        gmod.sign_add_member(
            private_key=sk_o, pubkey=pk_o, group_id=gid,
            member_pubkey=pk_a, role="admin", timestamp_ms=base + 1,
        ),
        gmod.sign_add_member(
            private_key=sk_o, pubkey=pk_o, group_id=gid,
            member_pubkey=pk_b, timestamp_ms=base + 2,
        ),
        # Admin tries to promote member to admin - rejected.
        gmod.sign_change_role(
            private_key=sk_a, pubkey=pk_a, group_id=gid,
            member_pubkey=pk_b, new_role="admin",
            timestamp_ms=base + 3,
        ),
    ]
    state = gmod.reduce_events(events)
    assert state.role_of(pk_b) == "member"


# POST /api/groups/{gid}/members/{fp}/role

@pytest.mark.asyncio
async def test_endpoint_change_role_requires_existing_member(http):
    client, _, _, token = http
    # Random gid + fp - neither exists. The pubkey lookup should fail
    # (404) before we even get to the reducer.
    resp = await client.post(
        f"/api/groups/{'aa' * 16}/members/{'bb' * 32}/role",
        headers=_h(token), json={"role": "admin"},
    )
    assert resp.status == 404


@pytest.mark.asyncio
async def test_endpoint_change_role_validates_role(http):
    client, _, state, token = http
    state.upsert_peer(
        fingerprint="cc" * 32, short_id="bob",
        pubkey=b"\x00" * 32, hostname="bob",
    )
    resp = await client.post(
        f"/api/groups/{'aa' * 16}/members/{'cc' * 32}/role",
        headers=_h(token), json={"role": "godmode"},
    )
    assert resp.status == 400
    j = await resp.json()
    assert "owner, admin, or member" in j.get("error", "")


@pytest.mark.asyncio
async def test_endpoint_change_role_404_for_unknown_peer(http):
    client, _, _, token = http
    resp = await client.post(
        f"/api/groups/{'aa' * 16}/members/{'00' * 32}/role",
        headers=_h(token), json={"role": "admin"},
    )
    assert resp.status == 404


# UI: group settings modal markup

def test_group_modal_has_rename_section_header(index_html: str):
    """The rename input now has a labeled section, not just a
    floating input. Use the group-settings-backdrop scope so we
    don't match the create-group modal."""
    bd_idx = index_html.find('id="group-settings-backdrop"')
    assert bd_idx > 0
    # Take a generous window (modal markup spans ~3500 chars).
    scope = index_html[bd_idx:bd_idx + 6000]
    assert '<span>Name</span>' in scope
    assert 'id="group-rename-input"' in scope


def test_group_modal_has_avatar_color_picker(index_html: str):
    bd_idx = index_html.find('id="group-settings-backdrop"')
    scope = index_html[bd_idx:bd_idx + 6000]
    assert 'id="group-color-swatches"' in scope


def test_group_modal_has_mute_picker(index_html: str):
    bd_idx = index_html.find('id="group-settings-backdrop"')
    scope = index_html[bd_idx:bd_idx + 6000]
    assert 'id="group-mute-duration"' in scope
    assert 'id="group-mute-apply"' in scope
    assert 'id="group-mute-status"' in scope


def test_group_modal_has_archive_button(index_html: str):
    bd_idx = index_html.find('id="group-settings-backdrop"')
    scope = index_html[bd_idx:bd_idx + 6000]
    assert 'id="group-archive-toggle"' in scope


def test_create_modal_no_longer_has_orphan_rename(index_html: str):
    """The stray group-rename-input that was wrongly placed in the
    create-group modal should be gone - there should be exactly one
    instance now (in the settings modal)."""
    assert index_html.count('id="group-rename-input"') == 1


# UI: JS handlers

def test_change_group_member_role_function_present(index_html: str):
    assert "async function changeGroupMemberRole(fp, newRole)" in index_html


def test_change_role_calls_role_endpoint(index_html: str):
    idx = index_html.find("async function changeGroupMemberRole(fp, newRole)")
    snippet = index_html[idx:idx + 800]
    assert "/role" in snippet
    assert 'role: newRole' in snippet


def test_apply_group_mute_function_present(index_html: str):
    assert "async function applyGroupMute()" in index_html


def test_apply_group_mute_posts_to_endpoint(index_html: str):
    idx = index_html.find("async function applyGroupMute()")
    snippet = index_html[idx:idx + 1500]
    assert "/mute" in snippet
    assert "duration_ms" in snippet


def test_get_group_color_helper_present(index_html: str):
    assert "function getGroupColor(gid)" in index_html
    assert "function setGroupColor(gid, hex)" in index_html


def test_archive_helpers_present(index_html: str):
    assert "function isGroupArchived(gid)" in index_html
    assert "function setGroupArchived(gid, archived)" in index_html
    assert "async function toggleArchiveCurrentGroup()" in index_html


# Sidebar render: archived split + indicators

def test_render_groups_splits_archived(index_html: str):
    idx = index_html.find("function renderGroups()")
    assert idx > 0
    snippet = index_html[idx:idx + 4000]
    assert "activeGroups" in snippet
    assert "archivedGroups" in snippet
    assert "isGroupArchived" in snippet


def test_render_groups_applies_color(index_html: str):
    idx = index_html.find("function renderGroups()")
    snippet = index_html[idx:idx + 4000]
    assert "getGroupColor(g.group_id)" in snippet


def test_render_groups_emits_mute_indicator(index_html: str):
    idx = index_html.find("function renderGroups()")
    snippet = index_html[idx:idx + 4000]
    assert "muted_until_ms" in snippet
    assert "mute-indicator" in snippet


def test_render_peers_emits_mute_indicator(index_html: str):
    idx = index_html.find("function renderPeers()")
    snippet = index_html[idx:idx + 6000]
    assert "muted_until_ms" in snippet
    assert "mute-indicator" in snippet


def test_archived_header_collapsible(index_html: str):
    """Pin the expand-toggle behavior so a regression doesn't auto-
    expand archived groups (defeating the point of archiving)."""
    idx = index_html.find("function renderGroups()")
    snippet = index_html[idx:idx + 4000]
    assert "_archivedExpanded" in snippet
    assert "Archived (" in snippet


def test_open_group_settings_loads_color_swatches(index_html: str):
    idx = index_html.find("function openGroupSettings()")
    snippet = index_html[idx:idx + 5000]
    assert "_renderGroupColorSwatches(state.selectedGroup)" in snippet


def test_open_group_settings_loads_mute_status(index_html: str):
    idx = index_html.find("function openGroupSettings()")
    snippet = index_html[idx:idx + 5000]
    assert "_renderMuteStatus(" in snippet
    assert "group-mute-status" in snippet


def test_open_group_settings_owner_only_role_picker(index_html: str):
    """Members who aren't owners should not see the role dropdown.
    Pin the gate so a refactor can't accidentally show it to everyone."""
    idx = index_html.find("function openGroupSettings()")
    snippet = index_html[idx:idx + 5000]
    assert "isOwner && !m.is_me" in snippet
    assert "group-role-picker" in snippet


# Version pin

def test_page_version_bumped(index_html: str):
    from one_link import __version__
    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
