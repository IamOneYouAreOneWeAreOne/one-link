"""v0.7.9 — multi-modal SAS verification (audio readback + visual art).

The SAS art generator and the audio readback are both browser-side
helpers — there's no Python code path. These tests pin the surface
contract: HTML structure exists, deterministic-mapping JS is present,
and the constants we promised (number of cells = 6, etc.) match.

If a future refactor renames the helper or drops the art toggle, the
sidebar / pair modal will silently regress. These string-asserts
catch that on the next CI run.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── pair modal surfaces ───────────────────────────────────────

def test_pair_modal_has_speak_button(index_html: str):
    assert 'id="pair-sas-speak"' in index_html


def test_pair_modal_has_visual_art_toggle(index_html: str):
    assert 'id="pair-sas-art-toggle"' in index_html
    assert 'id="pair-sas-art"' in index_html


def test_pair_modal_has_copy_button(index_html: str):
    assert 'id="pair-sas-copy"' in index_html


# ───────── device drawer surfaces ────────────────────────────────────

def test_device_drawer_has_speak_button(index_html: str):
    assert 'id="dev-sas-speak"' in index_html


def test_device_drawer_has_visual_art_toggle(index_html: str):
    assert 'id="dev-sas-art-toggle"' in index_html
    assert 'id="dev-sas-art"' in index_html


# ───────── helpers wired up ──────────────────────────────────────────

def test_sas_art_helper_present(index_html: str):
    assert "function sasArtCells(" in index_html
    assert "function renderSasArt(" in index_html


def test_speak_sas_uses_speech_synthesis(index_html: str):
    assert "function speakSas(" in index_html
    assert "speechSynthesis" in index_html
    assert "SpeechSynthesisUtterance" in index_html


def test_speak_sas_spells_digits_with_words(index_html: str):
    """Audio readback spells digit-by-digit (not 'forty-three'),
    so phone-call confirmation is unambiguous."""
    m = re.search(r'const words = \[([^\]]+)\]', index_html)
    assert m is not None, "missing digit-word table"
    digits = [d.strip().strip('"') for d in m.group(1).split(",")]
    assert digits[0] == "zero"
    assert digits[9] == "nine"
    assert len(digits) == 10


def test_sas_art_emoji_table_has_24_entries(index_html: str):
    m = re.search(r'const SAS_ART_EMOJI = \[([^\]]+)\]', index_html, re.DOTALL)
    assert m is not None, "missing emoji table"
    entries = [
        e.strip().strip('"')
        for e in m.group(1).split(",") if e.strip().strip('"')
    ]
    # 24 entries × 6 cells ≈ enough variety that two different SAS
    # values are very unlikely to share all 6 emoji slots.
    assert len(entries) == 24


def test_sas_art_bg_table_has_12_entries(index_html: str):
    m = re.search(r'const SAS_ART_BG = \[([^\]]+)\]', index_html, re.DOTALL)
    assert m is not None, "missing bg color table"
    entries = [
        e.strip().strip('"')
        for e in m.group(1).split(",") if e.strip().strip('"')
    ]
    assert len(entries) == 12


def test_close_pair_modal_cancels_speech(index_html: str):
    """Closing the modal must stop any in-flight readback so the
    speaker doesn't keep saying '…six' after dismiss."""
    # find the closePairModal body and check that it includes the cancel().
    start = index_html.find("function closePairModal(")
    assert start > 0
    snippet = index_html[start:start + 600]
    assert "speechSynthesis" in snippet
    assert "cancel()" in snippet


def test_close_device_drawer_cancels_speech(index_html: str):
    """Same hygiene for the drawer."""
    start = index_html.find("function closeDeviceDrawer(")
    assert start > 0
    snippet = index_html[start:start + 600]
    assert "speechSynthesis" in snippet
    assert "cancel()" in snippet


def test_page_version_bumped(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
