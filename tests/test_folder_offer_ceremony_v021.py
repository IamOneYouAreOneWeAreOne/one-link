"""v0.21.x folder-share ceremony.

Pre-v0.21.x the receiver's daemon SILENTLY DROPPED MANIFEST_PUSH
frames for folders it didn't already have registered (with the same
sharing peer in its shared_with list). That meant clicking 'Share'
on the sender's UI looked like it worked but nothing ever appeared
on the other device — there was no mechanism to PROPOSE sharing a
new folder.

v0.21.x introduces a proper offer ceremony:

  Receiver daemon caches the unknown-folder MANIFEST_PUSH as a
  pending_folder_offers row + broadcasts a folder_offer_received
  WS event. The receiver's UI surfaces an 'Incoming shares' card
  with the sender's name, folder name, file count, total bytes,
  a path-picker input, and Accept / Decline buttons.

  On Accept the daemon creates the folder at the chosen path,
  adds the sender to shared_with, grants folder-sync capabilities,
  and dials back via the existing FOLDER_SYNC_BIDI_V1 path so the
  sender streams the actual blobs.

  On Decline the row is marked declined; the sender is NOT
  notified (their transfer view reports the receiver as pending).

This file pins the contract end to end so a future refactor can't
silently revert any of it.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from one_link.state import State


@pytest.fixture
def state(tmp_path):
    return State(db_path=tmp_path / "state.db")


# ── state.py: pending_folder_offers schema + helpers ──────────────


def test_v25_migration_creates_pending_folder_offers_table(state):
    """v0.21.x schema bump pins the new table; without it the
    receiver daemon has nowhere to cache incoming offers."""
    # The schema version stamp must include 25.
    assert state.schema_version() >= 25, (
        "missing v25 migration — pending_folder_offers table won't "
        "exist and the ceremony has no backing store"
    )
    # The table must exist and contain the expected columns.
    cols = {
        row["name"]
        for row in state._conn.execute(
            "PRAGMA table_info(pending_folder_offers)"
        )
    }
    for required in (
        "id", "peer_fp", "folder_name", "merkle_root",
        "entries_json", "entry_count", "total_bytes",
        "offered_ms", "state", "decided_ms", "local_path",
    ):
        assert required in cols, f"pending_folder_offers missing column {required!r}"


def test_upsert_pending_folder_offer_inserts(state):
    o = state.upsert_pending_folder_offer(
        peer_fp="aa" * 32,
        folder_name="paper",
        merkle_root="deadbeef",
        entries=[
            {"file_path": "a.txt", "blob_hash": "ab", "size": 100,
             "mtime_ms": 1, "vclock": {}},
            {"file_path": "b.txt", "blob_hash": "cd", "size": 250,
             "mtime_ms": 2, "vclock": {}},
        ],
    )
    assert o["state"] == "pending"
    assert o["entry_count"] == 2
    assert o["total_bytes"] == 350
    assert o["folder_name"] == "paper"


def test_upsert_re_offer_resets_decided_state(state):
    """A sender re-pushing the same folder after we declined gives
    the user a fresh chance to accept (the re-push IS deliberate
    user intent on the sender's side)."""
    o = state.upsert_pending_folder_offer(
        peer_fp="aa" * 32, folder_name="x", merkle_root="r1",
        entries=[{"file_path": "a", "blob_hash": "h", "size": 1, "mtime_ms": 1, "vclock": {}}],
    )
    state.mark_folder_offer_declined(o["id"])
    declined = state.get_folder_offer(o["id"])
    assert declined["state"] == "declined"
    # Re-offer (same peer, same folder name)
    o2 = state.upsert_pending_folder_offer(
        peer_fp="aa" * 32, folder_name="x", merkle_root="r2",
        entries=[{"file_path": "a", "blob_hash": "h2", "size": 2, "mtime_ms": 2, "vclock": {}}],
    )
    assert o2["id"] == o["id"], "re-offer must update the existing row, not insert a duplicate"
    assert o2["state"] == "pending"
    assert o2["merkle_root"] == "r2"


def test_list_folder_offers_default_filter_is_pending(state):
    """Default listing returns only pending offers — accepted /
    declined ones are audit history, not user-actionable."""
    state.upsert_pending_folder_offer(
        peer_fp="aa" * 32, folder_name="p1", merkle_root="r1",
        entries=[{"file_path": "a", "blob_hash": "h", "size": 1, "mtime_ms": 1, "vclock": {}}],
    )
    o2 = state.upsert_pending_folder_offer(
        peer_fp="bb" * 32, folder_name="p2", merkle_root="r2",
        entries=[{"file_path": "b", "blob_hash": "h2", "size": 2, "mtime_ms": 2, "vclock": {}}],
    )
    state.mark_folder_offer_declined(o2["id"])
    pending = state.list_folder_offers()
    assert {o["folder_name"] for o in pending} == {"p1"}
    everything = state.list_folder_offers(state_filter=None)
    assert {o["folder_name"] for o in everything} == {"p1", "p2"}


def test_mark_offer_accepted_records_decided_ms_and_local_path(state):
    o = state.upsert_pending_folder_offer(
        peer_fp="aa" * 32, folder_name="paper", merkle_root="r",
        entries=[{"file_path": "a", "blob_hash": "h", "size": 1, "mtime_ms": 1, "vclock": {}}],
    )
    accepted = state.mark_folder_offer_accepted(o["id"], local_path="C:/tmp/paper")
    assert accepted["state"] == "accepted"
    assert accepted["local_path"] == "C:/tmp/paper"
    assert accepted["decided_ms"] is not None


def test_mark_offer_decided_idempotent(state):
    """Marking an already-decided offer accepted/declined must
    silently no-op (UPDATE ... WHERE state='pending')."""
    o = state.upsert_pending_folder_offer(
        peer_fp="aa" * 32, folder_name="paper", merkle_root="r",
        entries=[{"file_path": "a", "blob_hash": "h", "size": 1, "mtime_ms": 1, "vclock": {}}],
    )
    state.mark_folder_offer_declined(o["id"])
    # Second decline doesn't flip state to accepted, doesn't move decided_ms.
    after_first = state.get_folder_offer(o["id"])
    state.mark_folder_offer_declined(o["id"])
    after_second = state.get_folder_offer(o["id"])
    assert after_first == after_second


# ── daemon.py: _handle_manifest_push caches offers + broadcasts ───


def test_handle_manifest_push_caches_unknown_folder_offer_in_source():
    """Pin the structural change in the daemon's MANIFEST_PUSH
    handler so a refactor can't bring back the silent drop."""
    src = (
        Path(__file__).resolve().parents[1]
        / "src" / "one_link" / "daemon.py"
    ).read_text(encoding="utf-8")
    idx = src.find("async def _handle_manifest_push(")
    assert idx > 0
    body = src[idx:idx + 5000]
    # Must call upsert_pending_folder_offer when the folder is unknown.
    assert "upsert_pending_folder_offer" in body, (
        "_handle_manifest_push must cache unknown-folder offers "
        "via upsert_pending_folder_offer — without it, Share from "
        "peer A does nothing on peer B"
    )
    # Must broadcast folder_offer_received so the UI gets live notification.
    assert "folder_offer_received" in body, (
        "_handle_manifest_push must broadcast the WS event so the "
        "receiver's UI surfaces the offer card live"
    )
    # Must reply with MANIFEST_WANTS pending_offer=True so the
    # sender doesn't time out waiting for a response.
    assert "pending_offer" in body, (
        "_handle_manifest_push must signal 'pending' back to the "
        "sender via MANIFEST_WANTS so the sender's transfer doesn't "
        "fail with a 15s timeout"
    )


# ── server.py: API endpoints wired ─────────────────────────────────


def test_folder_offer_routes_registered():
    src = (
        Path(__file__).resolve().parents[1]
        / "src" / "one_link" / "server.py"
    ).read_text(encoding="utf-8")
    assert '"/api/folder-offers"' in src, (
        "GET /api/folder-offers route missing"
    )
    assert '"/api/folder-offers/{offer_id}/accept"' in src, (
        "POST accept route missing"
    )
    assert '"/api/folder-offers/{offer_id}/decline"' in src, (
        "POST decline route missing"
    )
    # Handlers themselves must exist.
    assert "async def api_list_folder_offers(" in src
    assert "async def api_accept_folder_offer(" in src
    assert "async def api_decline_folder_offer(" in src


def test_accept_handler_requires_local_path():
    src = (
        Path(__file__).resolve().parents[1]
        / "src" / "one_link" / "server.py"
    ).read_text(encoding="utf-8")
    idx = src.find("async def api_accept_folder_offer(")
    assert idx > 0
    body = src[idx:idx + 12000]
    # Must validate local_path is supplied.
    assert "local_path required" in body, (
        "accept handler must require a local_path; without one we "
        "don't know WHERE to create the folder"
    )
    # Must require the offer's sender to be pinned.
    assert "unpinned" in body, (
        "accept handler must refuse offers from unpinned peers; "
        "otherwise an attacker who poisoned mDNS could trick the "
        "user into accepting a folder share from a stranger"
    )
    # Must reject when a folder with that name already exists.
    assert "folder_name_conflict" in body or "already exists" in body, (
        "accept handler must reject offers when a folder with the "
        "same name already exists locally — silently merging would "
        "let the offer write into an unrelated folder"
    )
    # Must dial back via bidirectional push to pull the blobs.
    assert "bidirectional=True" in body, (
        "accept handler must invoke push_folder_to_peer with "
        "bidirectional=True so the existing FOLDER_SYNC_BIDI_V1 "
        "path streams the sender's blobs back to us"
    )


def test_decline_handler_marks_offer_only(monkeypatch):
    """Decline must NOT modify peer caps or shared_with; it's a
    purely receiver-side audit decision."""
    src = (
        Path(__file__).resolve().parents[1]
        / "src" / "one_link" / "server.py"
    ).read_text(encoding="utf-8")
    idx = src.find("async def api_decline_folder_offer(")
    assert idx > 0
    body = src[idx:idx + 2200]
    assert "mark_folder_offer_declined" in body
    # Decline does NOT add to shared_with / grant caps / dial back.
    assert "_ensure_folder_caps_for" not in body
    assert "push_folder_to_peer" not in body
    assert "share_with" not in body


# ── UI: offers section + render helpers ───────────────────────────


@pytest.fixture(scope="module")
def index_html() -> str:
    return (
        Path(__file__).resolve().parents[1]
        / "src" / "one_link" / "web" / "index.html"
    ).read_text(encoding="utf-8")


def test_folders_panel_has_offers_section(index_html):
    """The Folders panel must render the offers section ABOVE the
    folder list so incoming offers are the first thing the user
    sees when they open the panel."""
    assert 'id="folder-offers-section"' in index_html
    assert 'id="folder-offers-list"' in index_html
    assert 'id="folder-offers-count"' in index_html


def test_offer_render_helper_present(index_html):
    """_renderFolderOffer + refreshFolderOffers must exist so the
    section actually populates."""
    assert "function _renderFolderOffer(" in index_html
    assert "async function refreshFolderOffers(" in index_html


def test_init_refreshes_folder_offers(index_html):
    """The initial /api/me / refreshFolders / refreshFolderOffers
    chain must include the offers call so the UI is populated on
    boot, not only after a folder_offer_received WS event."""
    idx = index_html.find("async function init() {")
    assert idx > 0
    body = index_html[idx:idx + 6000]
    assert "refreshFolderOffers()" in body, (
        "init() must call refreshFolderOffers — otherwise the offers "
        "panel stays empty until a new offer arrives live"
    )


def test_ws_handler_for_folder_offer_received(index_html):
    """The WS dispatcher must react to folder_offer_received so the
    user gets live notification of incoming shares + the offers
    section updates without a manual refresh."""
    assert 'm.type === "folder_offer_received"' in index_html
    assert 'm.type === "folder_offer_pull_complete"' in index_html
    assert 'm.type === "folder_offer_pull_failed"' in index_html


def test_offer_card_uses_path_picker(index_html):
    """Each offer card must let the user pick where to save the
    folder via the same /api/fs/pick-folder endpoint the Add form
    uses — typing a path by hand is friction."""
    idx = index_html.find("function _renderFolderOffer(")
    body = index_html[idx:idx + 6000]
    assert "/api/fs/pick-folder" in body, (
        "offer card missing Browse... button that opens the native "
        "folder picker"
    )
    # Accept button POSTs to the right endpoint.
    assert "/api/folder-offers/${o.id}/accept" in body
    assert "/api/folder-offers/${o.id}/decline" in body
