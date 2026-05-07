"""v0.8.7 — pair-time verify integration.

The pair-confirm flow used to close the modal the instant both
devices confirmed SAS match. v0.8.7 adds a second stage: while the
SAS is still on screen and the user has just compared it side-by-
side, prompt them to ALSO mark the device verified-in-person. That's
the highest-trust moment we'll ever have with this peer; capturing
it as `verified` here saves a later trip to the device drawer.

Pure UI + flow change — no schema, no new endpoint. These tests pin
the surface contract.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


def test_pair_modal_has_two_stages(index_html: str):
    assert 'id="pair-stage-compare"' in index_html
    assert 'id="pair-stage-verified"' in index_html


def test_verified_stage_has_action_buttons(index_html: str):
    assert 'id="pair-skip-verify"' in index_html
    assert 'id="pair-verify-now"' in index_html


def test_show_pair_stage_helper_present(index_html: str):
    assert "function showPairStage(" in index_html
    assert "function enterPairVerifyStage(" in index_html


def test_pair_match_pivots_to_verify_stage(index_html: str):
    """pairMatch.onclick must call enterPairVerifyStage() (not
    closePairModal) when both_confirmed."""
    start = index_html.find("pairMatch.onclick = async ()")
    assert start > 0
    snippet = index_html[start:start + 1200]
    assert "both_confirmed" in snippet
    assert "enterPairVerifyStage()" in snippet


def test_verify_now_button_calls_verify_endpoint(index_html: str):
    """The 'Verify in person now' click must POST /api/peers/{fp}/verify."""
    # Find the verify-now click handler.
    start = index_html.find('"#pair-verify-now"')
    assert start > 0
    snippet = index_html[start:start + 800]
    assert "/api/peers/" in snippet and "/verify" in snippet
    assert "sas-digits" in snippet
    assert "Confirmed during pair flow" in snippet


def test_skip_verify_just_closes_modal(index_html: str):
    """Skip should NOT call /verify."""
    start = index_html.find('"#pair-skip-verify"')
    assert start > 0
    snippet = index_html[start:start + 400]
    assert "closePairModal(true)" in snippet
    assert "/verify" not in snippet


def test_open_pair_modals_reset_to_compare_stage(index_html: str):
    """Both openPairModal entry points must reset stage to 'compare'
    so a previous flow's verify stage doesn't leak."""
    out = index_html.find("async function openPairModal(peer)")
    incoming = index_html.find("function openPairModalIncoming(peer, sas)")
    assert out > 0 and incoming > 0
    out_snippet = index_html[out:out + 1200]
    incoming_snippet = index_html[incoming:incoming + 800]
    assert 'showPairStage("compare")' in out_snippet
    assert 'showPairStage("compare")' in incoming_snippet


def test_peer_trust_ws_pivots_to_verify_when_we_confirmed(index_html: str):
    """If the peer_trust WS event arrives AFTER we've already
    confirmed locally, the modal must pivot to the verify stage
    instead of being closed."""
    # The block lives inside the WS dispatch — find peer_trust + state.pairing.weConfirmed.
    idx = index_html.find('"peer_trust"')
    assert idx > 0
    snippet = index_html[idx:idx + 800]
    assert "weConfirmed" in snippet
    assert "enterPairVerifyStage()" in snippet


def test_page_version_bumped(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
