"""v0.21.x activity-feed Phase B (findability + clean grouping):
search box, day-grouping headers, new chips (folder/offer), failed-only
toggle, click-peer-to-filter, and per-file rollup under folder summary.

These tests assert the HTML/JS shapes are present so the Phase B
features can't silently regress to the pre-v0.21.x flat-list UX.
"""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return (
        Path(__file__).resolve().parents[1]
        / "src" / "one_link" / "web" / "index.html"
    ).read_text(encoding="utf-8")


# ── chips ─────────────────────────────────────────────────────────


def test_folder_chip_present(index_html: str):
    assert 'data-activity-filter="folder"' in index_html, (
        "Folders chip missing — sender-side folder lifecycle "
        "(send_started/complete/failed/retry) needs its own filter "
        "so users can isolate folder events from per-file transfers"
    )


def test_offer_chip_present(index_html: str):
    assert 'data-activity-filter="offer"' in index_html, (
        "Offers chip missing — folder offer ceremony events "
        "(offer_sent/received/accepted/declined) need their own "
        "filter so users can audit the pre-transfer handshake"
    )


def test_failed_only_chip_present(index_html: str):
    assert 'id="activity-failed-only-chip"' in index_html
    assert "Issues only" in index_html, (
        "Issues-only chip label missing — users should be able to "
        "one-click hide info-level events to see only problems"
    )


def test_failed_only_toggles_local_state(index_html: str):
    """Issues-only is a CLIENT-side filter — toggling it must NOT
    re-fetch the feed (would be wasteful + slow), only re-render."""
    idx = index_html.find("activity-failed-only-chip")
    # Skip past the HTML declaration to find the JS handler block.
    handler_idx = index_html.find(
        "activity-failed-only-chip", idx + 1,
    )
    assert handler_idx > 0
    block = index_html[handler_idx:handler_idx + 1500]
    assert "renderActivityFeed()" in block, (
        "Issues-only toggle should call renderActivityFeed (local "
        "re-filter) not refreshActivityFeed (network re-fetch)"
    )
    assert "activityFailedOnly" in block


# ── search box ────────────────────────────────────────────────────


def test_search_box_present(index_html: str):
    assert 'id="activity-search-input"' in index_html
    assert 'type="search"' in index_html


def test_search_filters_on_label_detail_peer(index_html: str):
    idx = index_html.find("function _activityMatchesSearch(")
    assert idx > 0
    body = index_html[idx:idx + 700]
    for field in ("label", "detail", "peer_display_name", "peer_fp",
                  "folder_name"):
        assert field in body, (
            f"search must match {field} so users can find events by "
            f"that field name"
        )


def test_search_is_debounced(index_html: str):
    """Search should not re-render on every keystroke — debounced
    re-render keeps typing snappy on big feeds."""
    idx = index_html.find("activity-search-input")
    # Skip past the HTML id= occurrence to land on the JS handler.
    handler_idx = index_html.find(
        "activity-search-input", idx + 1,
    )
    assert handler_idx > 0
    block = index_html[handler_idx:handler_idx + 1500]
    assert "setTimeout" in block, (
        "search input handler should debounce via setTimeout"
    )
    assert "activitySearch" in block


# ── day-grouping headers ──────────────────────────────────────────


def test_day_bucket_function_present(index_html: str):
    assert "function _activityDayBucket(" in index_html


def test_day_bucket_returns_today_yesterday_weekdays(index_html: str):
    idx = index_html.find("function _activityDayBucket(")
    body = index_html[idx:idx + 1200]
    assert '"Today"' in body
    assert '"Yesterday"' in body
    assert "weekday" in body, (
        "older-than-yesterday-but-under-a-week should label by "
        "weekday so the user sees 'Monday' / 'Tuesday'"
    )


# ── per-file rollup under folder summary ──────────────────────────


def test_fold_helper_groups_transfers_under_folder_summary(index_html: str):
    assert "function _foldActivityRows(" in index_html
    idx = index_html.find("function _foldActivityRows(")
    body = index_html[idx:idx + 2000]
    # Must link via folder_send_group AND only group children of
    # folder kind summaries (offer-only groups shouldn't suck in
    # unrelated transfer rows).
    assert "folder_send_group" in body
    assert "childrenByGroup" in body


def test_folder_summary_row_has_expand_toggle(index_html: str):
    idx = index_html.find("function renderActivityFeed(")
    body = index_html[idx:idx + 7000]
    assert "av-folder-toggle" in body, (
        "folder summary rows must offer an expand button so users "
        "can drill into the per-file detail when they want"
    )
    assert "activityExpandedGroups" in body


def test_expand_state_persists_across_renders(index_html: str):
    """Expanded/collapsed state should survive a re-render (toggling
    search, switching chips). Otherwise the user re-expands every
    time something refreshes."""
    assert "state.activityExpandedGroups" in index_html


# ── click-peer-to-filter ──────────────────────────────────────────


def test_peer_row_is_clickable(index_html: str):
    idx = index_html.find("function renderActivityFeed(")
    body = index_html[idx:idx + 7000]
    assert "av-peer.clickable" in index_html or "clickable" in body
    assert "activityPeerFilter" in body, (
        "clicking a peer line must filter the feed to events "
        "involving that peer — set state.activityPeerFilter"
    )


def test_peer_filter_banner_clears_on_click(index_html: str):
    idx = index_html.find("function renderActivityFeed(")
    body = index_html[idx:idx + 7000]
    assert "Filtering by peer" in body, (
        "when a peer filter is active, the feed must surface a "
        "banner so the user knows they're seeing a slice + can "
        "clear with one click"
    )


# ── icons for new kinds ───────────────────────────────────────────


def test_folder_kind_has_icon(index_html: str):
    idx = index_html.find("function activityIcon(")
    body = index_html[idx:idx + 1200]
    assert 'kind === "folder"' in body
    assert 'kind === "offer"' in body


# ── existing chips preserved ──────────────────────────────────────


def test_legacy_chips_still_present(index_html: str):
    """Phase B should ADD chips, not remove the existing ones."""
    for legacy in ("all", "trust", "key_change", "transfer",
                   "conflict", "peer"):
        assert f'data-activity-filter="{legacy}"' in index_html, (
            f"legacy chip {legacy!r} removed — Phase B must add, "
            f"not replace"
        )
