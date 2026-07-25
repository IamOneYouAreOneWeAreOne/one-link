"""Regression gates for browser-side request fan-out and idle polling."""

from __future__ import annotations

from pathlib import Path


INDEX = Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "index.html"


def _html() -> str:
    return INDEX.read_text(encoding="utf-8")


def _function_body(html: str, marker: str, next_marker: str, *, span: int = 8000) -> str:
    start = html.index(marker)
    end = html.find(next_marker, start + len(marker))
    if end < 0 or end - start > span:
        end = start + span
    return html[start:end]


def test_gets_are_coalesced_only_while_in_flight() -> None:
    html = _html()
    body = _function_body(html, "async get(p, opts = {})", "async post(p, body")
    assert "const _apiGetInFlight = new Map()" in html
    assert "_apiGetInFlight.has(requestKey)" in body
    assert "_apiGetInFlight.set(requestKey, operation)" in body
    assert "_apiGetInFlight.delete(requestKey)" in body
    assert "opts.coalesce !== false" in body


def test_boot_snapshots_are_parallel_and_failure_isolated() -> None:
    html = _html()
    body = _function_body(html, "async function init()", "function refreshPeers")
    assert "const bootTasks = [" in body
    assert "await Promise.allSettled" in body
    assert '["peers", refreshPeers()]' in body
    assert '["settings", loadAndApplySettings()]' in body
    assert "await maybeShowOnboarding()" in body


def test_transfer_poll_does_not_cascade_into_status_health_poll() -> None:
    html = _html()
    transfers = _function_body(
        html,
        "async function refreshTransfers()",
        "function _renderTransferGroup",
    )
    status = _function_body(
        html,
        "async function refreshStatus()",
        "async function refreshFabricTruth",
    )
    assert "refreshStatus()" not in transfers
    assert "await Promise.allSettled" in status
    assert "api.status()" in status
    assert "api.selfMesh()" in status
    assert 'api.get("/api/rendezvous")' in status


def test_boot_subsystem_fanout_starts_independent_requests_together() -> None:
    html = _html()
    courier = _function_body(
        html,
        "async function refreshCourierStatus()",
        "function aggregateActiveTransferStats",
    )
    fabric = _function_body(
        html,
        "async function refreshFabricTruth()",
        "async function copyRouteBootstrapToken",
    )
    assert "await Promise.allSettled" in courier
    assert "api.courierStatus()" in courier
    assert "api.courierFiles()" in courier
    assert "api.courierOutbox()" in courier
    assert "api.courierRemovable()" in courier
    assert "await Promise.allSettled" in fabric
    assert "api.fabric()" in fabric
    assert "api.noRouter()" in fabric
    assert "api.mobileReach()" in fabric


def test_setup_snapshot_is_not_refetched_after_boot() -> None:
    html = _html()
    init = _function_body(html, "async function init()", "function refreshPeers")
    onboarding = _function_body(
        html,
        "async function maybeShowOnboarding()",
        "function showOnboardingStep",
    )
    assert '["setup", refreshOneSetup()]' in init
    assert "state.oneSetup || await refreshOneSetup()" in onboarding


def test_html_compression_excludes_bearer_bootstrap_response() -> None:
    server = (
        INDEX.parents[1] / "server.py"
    ).read_text(encoding="utf-8")
    assert "if not bootstrap_ok:" in server
    assert "resp.enable_compression()" in server
    enable = server.index("resp.enable_compression()")
    guard = server.rfind("if not bootstrap_ok:", 0, enable)
    response = server.rfind("resp = web.Response(text=html", 0, enable)
    assert response < guard < enable


def test_call_reconciliation_is_single_flight_and_visibility_adaptive() -> None:
    html = _html()
    assert "let _callBackfillRunning = false" in html
    assert "if (_callBackfillRunning) return" in html
    assert 'document.getElementById("peers-count")' in html
    assert "return peerCount > 0 ? 5000 : 10000" in html
    assert "document.hidden" in html
    assert 'addEventListener("pagehide"' in html
    assert 'addEventListener("pageshow"' in html
