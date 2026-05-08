"""v0.14.7 — Phone-friendly pair flow (SAS art primary).

Ship-spec from `docs/PHONE_TIER.md`:

  Reach:  phone users can compare a 6-cell visual SAS-art grid
          across two devices instead of reading 6 digits twice
          on a small screen. The art is deterministic from the
          digits, so it's the same security primitive — just a
          faster human-comparison surface.
  Hide:   none — pair flow is universal; this ship CHANGES the
          default presentation on phone but keeps everything
          else accessible.
  Async:  none.
  Depth:  the helper `_applyPhonePairFlow()` runs at modal-open
          time and (a) auto-shows the SAS art container, (b)
          flips the toggle button to its "on" state, (c) shortens
          "Codes match" → "Match" / "Codes don't match" → "Don't
          match" so the buttons fit phone widths and read like
          the user is being asked a yes/no question.

Tests pin the helper + verify both pair-modal entry points wire it.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── helper present + branches on form-factor ─────────────────

def test_apply_phone_pair_flow_helper_present(index_html: str):
    """The single-source-of-truth phone-tier customizer for the pair
    modal. Don't rename — both openPairModal and
    openPairModalIncoming call it."""
    assert "function _applyPhonePairFlow()" in index_html


def test_helper_no_ops_off_phone(index_html: str):
    """Desktop + tablet pair flow MUST stay unchanged. The helper
    early-returns on non-phone form-factors."""
    idx = index_html.find("function _applyPhonePairFlow()")
    snippet = index_html[idx:idx + 1500]
    assert 'data-form-factor' in snippet
    assert '!== "phone"' in snippet
    assert "return;" in snippet


# ───────── SAS art auto-shown on phone ──────────────────────────────

def test_helper_reveals_sas_art(index_html: str):
    """On phone, the 6-cell visual grid MUST appear without a tap."""
    idx = index_html.find("function _applyPhonePairFlow()")
    snippet = index_html[idx:idx + 1500]
    assert '#pair-sas-art' in snippet
    assert 'art.style.display = "grid"' in snippet


def test_helper_marks_toggle_on(index_html: str):
    """The 🎨 Visual button must show its `.on` state so the user
    sees that the art is already showing (not invite a re-toggle)."""
    idx = index_html.find("function _applyPhonePairFlow()")
    snippet = index_html[idx:idx + 1500]
    assert '#pair-sas-art-toggle' in snippet
    assert 'classList.add("on")' in snippet


# ───────── Match / Don't match button reframing ─────────────────────

def test_helper_shortens_match_button(index_html: str):
    """Phones get a direct "Match" framing — fits narrow widths and
    reads like the actual question being asked."""
    idx = index_html.find("function _applyPhonePairFlow()")
    snippet = index_html[idx:idx + 1500]
    assert '#pair-match' in snippet
    assert 'textContent = "Match"' in snippet


def test_helper_shortens_mismatch_button(index_html: str):
    idx = index_html.find("function _applyPhonePairFlow()")
    snippet = index_html[idx:idx + 1500]
    assert '#pair-mismatch' in snippet
    assert 'textContent = "Don\'t match"' in snippet


# ───────── both pair-modal entry points wire the helper ─────────────

def test_open_pair_modal_calls_helper(index_html: str):
    """The outgoing-pair flow must invoke the customizer just before
    showing the modal — `_applyPhonePairFlow()` between
    `showPairStage("compare")` and `pairBackdrop.classList.add("show")`."""
    idx = index_html.find("async function openPairModal(peer)")
    assert idx > 0
    snippet = index_html[idx:idx + 2000]
    show_idx = snippet.find('showPairStage("compare")')
    apply_idx = snippet.find("_applyPhonePairFlow()")
    backdrop_idx = snippet.find('pairBackdrop.classList.add("show")')
    assert show_idx > 0
    assert apply_idx > show_idx
    assert backdrop_idx > apply_idx


def test_open_pair_modal_incoming_calls_helper(index_html: str):
    """The incoming-pair flow must do the same."""
    idx = index_html.find("function openPairModalIncoming(peer, sas)")
    assert idx > 0
    snippet = index_html[idx:idx + 2000]
    show_idx = snippet.find('showPairStage("compare")')
    apply_idx = snippet.find("_applyPhonePairFlow()")
    backdrop_idx = snippet.find('pairBackdrop.classList.add("show")')
    assert show_idx > 0
    assert apply_idx > show_idx
    assert backdrop_idx > apply_idx


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_matches_package(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
