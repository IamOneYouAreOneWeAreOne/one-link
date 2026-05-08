"""v0.19.0 — browser adaptive transport selector.

This is the first browser-side path brain: WebTransport when both
peers support it, WebRTC when that is best, manual WebRTC when zero
server automation is desired, with route memory persisted in IDB.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def peer_html() -> str:
    return Path("src/one_link/web/peer.html").read_text(encoding="utf-8")


def _snippet(html: str, needle: str, size: int = 2600) -> str:
    idx = html.find(needle)
    assert idx >= 0, f"missing {needle!r}"
    return html[idx:idx + size]


def test_browser_peer_surface_exposes_version(peer_html: str):
    """The v0.19.0 transport selector must stay exposed across later
    peer-page releases. Newer layers are allowed to bump the page version,
    but the test surface still needs a concrete semantic version string."""
    assert 'version: "' in peer_html


def test_browser_transport_capabilities_advertise_paths(peer_html: str):
    snippet = _snippet(peer_html, "function browserTransportCapabilities", 900)
    assert '"browser_peer"' in snippet
    assert "manual_signal_v1" in snippet
    assert "RTCPeerConnection" in snippet
    assert "webrtc_v1" in snippet
    assert "WebTransport" in snippet
    assert "webtransport_v1" in snippet


def test_register_includes_transport_caps(peer_html: str):
    snippet = _snippet(peer_html, "async function _buildSignedRegister", 2600)
    assert "browserTransportCapabilities()" in snippet
    assert "transport_caps" in snippet


def test_path_stats_idb_store_pinned(peer_html: str):
    assert 'PATH_STATS_DB = "one-link-peer-path-stats"' in peer_html
    assert 'PATH_STATS_STORE = "path_stats.v1"' in peer_html
    snippet = _snippet(peer_html, "function _openPathStatsDb", 1900)
    assert "indexedDB.open(PATH_STATS_DB" in snippet
    assert "createObjectStore(PATH_STATS_STORE" in snippet
    assert 'keyPath: "id"' in snippet


def test_path_stats_load_and_save_present(peer_html: str):
    assert "async function loadPathStats(peerFp)" in peer_html
    save = _snippet(peer_html, "async function savePathStat", 1500)
    assert "transaction(PATH_STATS_STORE, \"readwrite\")" in save
    assert "_pathStatKey" in save
    assert "store.put" in save


def test_observe_path_result_uses_ewma_for_speed_and_failures(peer_html: str):
    snippet = _snippet(peer_html, "function observePathResult", 2200)
    assert "PATH_EWMA_ALPHA" in snippet
    assert "ewma_throughput_bps" in snippet
    assert "ewma_failure_rate" in snippet
    assert "bytes * 8 * 1000" in snippet
    assert "samples" in snippet
    assert "last_used_ms" in snippet


def test_selector_requires_shared_caps(peer_html: str):
    snippet = _snippet(peer_html, "function _pathSupported", 1900)
    assert "webtransport_v1" in snippet
    assert "webrtc_v1" in snippet
    assert "manual_signal_v1" in snippet
    assert "window.WebTransport" in snippet
    assert "window.RTCPeerConnection" in snippet


def test_selector_scores_paths_with_failure_penalty(peer_html: str):
    snippet = _snippet(peer_html, "function pathScore", 1800)
    assert "PATH_FAILURE_PENALTY" in snippet
    assert "ewma_throughput_bps" in snippet
    assert "ewma_failure_rate" in snippet
    assert "webtransport" in snippet
    assert "webrtc" in snippet


def test_choose_transport_path_uses_epsilon_greedy(peer_html: str):
    snippet = _snippet(peer_html, "function chooseTransportPath", 2800)
    assert "PATH_EPSILON_BASE" in snippet
    assert "Math.random() < epsilon" in snippet
    assert "explore alternate path" in snippet
    assert "best observed path" in snippet
    assert '"unavailable"' in snippet


def test_webtransport_open_requires_https(peer_html: str):
    snippet = _snippet(peer_html, "async function openWebTransport", 1000)
    assert "new WebTransport(url)" in snippet
    assert "await wt.ready" in snippet
    assert "https://" in snippet
    assert "WebTransport unavailable" in snippet


def test_select_transport_for_peer_loads_persisted_stats(peer_html: str):
    snippet = _snippet(peer_html, "async function selectTransportForPeer", 1200)
    assert "loadPathStats(peerFp)" in snippet
    assert "statsByPath" in snippet
    assert "chooseTransportPath" in snippet


def test_test_surface_exposes_selector_helpers(peer_html: str):
    snippet = _snippet(peer_html, "window.__oneLinkPeer", 2600)
    for name in (
        "browserTransportCapabilities",
        "loadPathStats",
        "savePathStat",
        "observePathResult",
        "chooseTransportPath",
        "pathScore",
        "openWebTransport",
        "selectTransportForPeer",
    ):
        assert name in snippet
